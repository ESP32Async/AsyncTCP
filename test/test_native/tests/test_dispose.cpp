// "One connection, one dispose": the application gets exactly one terminal notification
// per connection, and a client that is owed one cannot start another until it arrives.
//
// The awkward cases all come from the same place.  connect() promises a callback before
// there is anything to hang it on, tcp_error() fires after LwIP has already freed the
// pcb, and the notification can therefore be owed across a window in which the
// application may close, abort, reconnect, or destroy the client.

#include "fixtures.h"

using namespace mocklwip;

static void test_dispose_a_failed_tcp_connect_owes_nothing_and_does_not_wedge(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);

  // No route - the WiFi dropped, say.  connect() reports failure, so it promised nothing.
  faults().connect_result = ERR_RTE;
  TEST_ASSERT_FALSE(c.connect(kPeer, kPort));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());  // disposed of, not left attached
  TEST_ASSERT_EQUAL_size_t(0, bound_ports().size());
  TEST_ASSERT_TRUE(count("tcp_close") + count("tcp_abort") > 0);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, t.count('E'));
  TEST_ASSERT_EQUAL_INT(0, t.count('D'));  // nothing was owed, so nothing is reported

  // The retry every application writes must still work.
  faults().connect_result = ERR_OK;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  c.close();
}

static void test_dispose_superseding_a_lookup_with_a_cached_answer_still_connects(void) {
  // The displaced lookup will never report, so the report it owed must not outlive it:
  // a connect() answered from cache would otherwise be refused as if one were still
  // outstanding.
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));

  faults().dns_result = ERR_OK;  // answered from cache this time
  faults().dns_addr = kResolved;
  TEST_ASSERT_TRUE(c.connect("fast.test", kPort));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));

  c.close();
  fire_dns(kResolved);  // the displaced lookup answers late and is dropped
  asynctcp_test_pump();
}

static void test_dispose_superseding_a_lookup_that_fails_leaves_the_client_usable(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));

  faults().dns_result = ERR_VAL;  // the new name is rejected outright
  TEST_ASSERT_FALSE(c.connect("bad..test", kPort));

  faults().dns_result = ERR_OK;  // and the client is not wedged by that
  faults().dns_addr = kResolved;
  TEST_ASSERT_TRUE(c.connect("retry.test", kPort));
  c.close();
  fire_dns(kResolved);
  asynctcp_test_pump();
}

static void test_dispose_abort_during_a_lookup_reports_and_leaves_the_client_usable(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  Recorder t;
  t.attach(c);

  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));
  c.abort();  // abandons the lookup
  asynctcp_test_pump();

  // connect() returned true, so a callback was promised.  The pair fires, as it does for
  // any other terminal error.
  TEST_ASSERT_EQUAL_INT(1, t.count('E'));
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_INT(0, t.count('C'));

  faults().dns_result = ERR_OK;
  faults().dns_addr = kResolved;
  TEST_ASSERT_TRUE(c.connect("other.test", kPort));
  c.close();
  fire_dns(kResolved);
  asynctcp_test_pump();
}

static void test_dispose_a_lookup_that_resolves_but_cannot_dial_still_reports(void) {
  // connect() returned true on the strength of the lookup, so the attempt owes exactly one
  // of onConnect or onError - and the dispose that pairs with it.  The dial happens inside
  // the resolver callback, where a failure is nobody's return value to report.
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  Recorder t;
  t.attach(c);

  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));
  faults().connect_result = ERR_RTE;  // resolved fine, but there is no route
  fire_dns(kResolved);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(0, t.count('C'));
  TEST_ASSERT_EQUAL_INT(1, t.count('E'));
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());

  // And the client is not wedged by the failed attempt.
  faults().connect_result = ERR_OK;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  c.close();
}

static void test_dispose_abort_on_an_idle_client_reports_nothing(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  c.abort();  // never attempted anything, so nothing is owed
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, t.count('E'));
  TEST_ASSERT_EQUAL_INT(0, t.count('D'));
}

static void test_dispose_reconnecting_inside_on_error_behaves_the_same_by_name_or_address(void) {
  // A callback that starts a new attempt owes a report for that attempt, so an
  // onDisconnect for the old one would be about the wrong connection.  A reconnect by
  // address dials at once; one by name waits for the resolver, and the two must not
  // diverge.
  for (int by_name = 0; by_name < 2; ++by_name) {
    AsyncClient c;
    Recorder t;
    bool reconnected = false, connected_at_dispose = false;
    c.onDisconnect([&](void *, AsyncClient *cl) {
      t.seq += 'D';
      connected_at_dispose = cl->connected();
    });
    c.onError([&](void *, AsyncClient *cl, int8_t) {
      t.seq += 'E';
      if (by_name) {
        faults().dns_result = ERR_INPROGRESS;
        reconnected = cl->connect("again.test", kPort);
      } else {
        reconnected = cl->connect(kPeer, kPort);
      }
    });

    faults().dns_result = ERR_OK;
    tcp_pcb *first = establish(c);

    fire_error(first, ERR_RST);
    asynctcp_test_pump();

    TEST_ASSERT_EQUAL_INT(1, t.count('E'));
    TEST_ASSERT_TRUE(reconnected);
    if (!by_name) {
      TEST_ASSERT_EQUAL_size_t(2, count("tcp_connect"));
    }
    TEST_ASSERT_EQUAL_INT(0, t.count('D'));  // onError covered it; the new attempt owns the next one
    TEST_ASSERT_FALSE(connected_at_dispose);

    c.close();
    fire_dns(kResolved);
    asynctcp_test_pump();
  }
}

static void test_dispose_destroying_a_live_client_reports_one_disconnect(void) {
  AsyncClient *c = new AsyncClient();
  int disconnects = 0;
  c->onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  establish(*c);
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  delete c;
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, bound_ports().size());
  // Nothing may reach a client after it is destroyed, so the destructor is the only
  // place left to deliver it.
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
}

static void test_dispose_connect_is_refused_while_a_terminal_event_is_undelivered(void) {
  AsyncClient c;
  int errors = 0, disconnects = 0;
  bool connected_at_dispose = false;
  c.onError([&](void *, AsyncClient *, int8_t) {
    errors++;
  });
  c.onDisconnect([&](void *, AsyncClient *cl) {
    disconnects++;
    connected_at_dispose = cl->connected();
  });

  tcp_pcb *first = establish(c);

  // Reset: the terminal event is queued, but the application has not been told yet.
  fire_error(first, ERR_RST);

  // Connecting now would have that event delivered against the new connection.
  TEST_ASSERT_FALSE(c.connect(kPeer, kPort));
  TEST_ASSERT_NULL(c.pcb());

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_FALSE(connected_at_dispose);  // never told "disconnected" about a live connection

  // Reported, so the client is idle and connectable again.
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  c.close();
}

static void test_dispose_reconnect_from_inside_on_disconnect_is_allowed(void) {
  AsyncClient c;
  bool allowed = false;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *cl) {
    if (++disconnects == 1) {
      // By the time onDisconnect runs, the client is already idle.
      allowed = cl->connect(kPeer, kPort);
    }
  });
  tcp_pcb *first = establish(c);

  fire_fin(first);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_TRUE(allowed);
  c.close();
}

static void test_dispose_is_delivered_once_for_an_explicit_close(void) {
  AsyncClient *c = new AsyncClient();
  int disconnects = 0;
  c->onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  tcp_pcb *pcb = establish(*c);

  // Data arrives and queues, but is not delivered yet.
  fire_recv(pcb, "hello", 5);

  // The application closes: one notification.  The data still waiting to be delivered
  // goes with the connection.
  c->close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);

  // The destructor closes again unconditionally.  Whatever that second pass finds, the
  // application must not hear about the same connection twice.
  delete c;
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
}

static void test_dispose_is_delivered_exactly_once_when_the_peer_closes_first(void) {
  AsyncClient *c = new AsyncClient();
  int disconnects = 0;
  c->onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  tcp_pcb *pcb = establish(*c);

  // The peer hangs up: the library closes, and that is the one notification.
  fire_fin(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);

  // Destroying afterwards must not report the same connection a second time, even though
  // the destructor closes unconditionally.
  delete c;
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dispose_is_still_delivered_when_a_reset_beats_the_destructor(void) {
  AsyncClient *c = new AsyncClient();
  int disconnects = 0;
  c->onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  tcp_pcb *pcb = establish(*c);

  // Reset arrives and queues a terminal event, but the application destroys the client
  // before the async task delivers it.  The notification is still owed, and nothing may
  // reach a client after it is destroyed, so destruction is the last chance to make it.
  fire_error(pcb, ERR_RST);
  TEST_ASSERT_EQUAL_INT(0, disconnects);

  delete c;
  TEST_ASSERT_EQUAL_INT(1, disconnects);

  // Draining the queue afterwards must not produce a second one.
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
}

void run_dispose_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_dispose_a_failed_tcp_connect_owes_nothing_and_does_not_wedge);
  RUN_TEST(test_dispose_superseding_a_lookup_with_a_cached_answer_still_connects);
  RUN_TEST(test_dispose_superseding_a_lookup_that_fails_leaves_the_client_usable);
  RUN_TEST(test_dispose_abort_during_a_lookup_reports_and_leaves_the_client_usable);
  RUN_TEST(test_dispose_a_lookup_that_resolves_but_cannot_dial_still_reports);
  RUN_TEST(test_dispose_abort_on_an_idle_client_reports_nothing);
  RUN_TEST(test_dispose_reconnecting_inside_on_error_behaves_the_same_by_name_or_address);
  RUN_TEST(test_dispose_destroying_a_live_client_reports_one_disconnect);
  RUN_TEST(test_dispose_connect_is_refused_while_a_terminal_event_is_undelivered);
  RUN_TEST(test_dispose_reconnect_from_inside_on_disconnect_is_allowed);
  RUN_TEST(test_dispose_is_delivered_once_for_an_explicit_close);
  RUN_TEST(test_dispose_is_delivered_exactly_once_when_the_peer_closes_first);
  RUN_TEST(test_dispose_is_still_delivered_when_a_reset_beats_the_destructor);
}
