// Object-lifetime tests.
//
// These cover the awkward lifetimes: destroying a client from inside its own callbacks,
// or while it still has queued events or a name lookup outstanding.  LiveProbe
// below is the leak check.

#include "fixtures.h"

#include <memory>
#include <utility>

using namespace mocklwip;

namespace {

/*
  Answers "has this client let go of everything it was given yet?" without the library
  carrying a counter for us.  A client holds the callbacks it was given until it is done
  with them, so a shared_ptr captured by one of them is released at exactly that moment -
  and a weak_ptr to it then expires.  It reports per client rather than as a global count,
  which is what these tests actually want to assert.

  Every handler a test registers goes through wrap(), so the probe stays alive while the
  client holds any of them and replacing one cannot release it early.  attach() is for a
  client with no handlers of its own: it registers a wrapped no-op.
*/
class LiveProbe {
public:
  template<class F> auto wrap(F f) {
    std::shared_ptr<int> tag = _weak.lock();
    if (!tag) {
      tag = std::make_shared<int>(0);
      _weak = tag;
    }
    return [tag, f](auto &&...args) {
      return f(std::forward<decltype(args)>(args)...);
    };
  }
  void attach(AsyncClient &c) {
    c.onTimeout(wrap([](void *, AsyncClient *, uint32_t) {}));
  }
  bool alive() const {
    return !_weak.expired();
  }

private:
  std::weak_ptr<int> _weak;
};

}  // namespace

// ---------------------------------------------------------------------------

static void test_lifetime_client_releases_its_callbacks(void) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    TEST_ASSERT_TRUE(probe.alive());
  }
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_connected_client_releases_on_close(void) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    establish(c);
    c.close();
  }
  asynctcp_test_pump();
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_destroy_inside_onData_is_safe(void) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  c->onData(probe.wrap([&](void *, AsyncClient *client, void *, size_t) {
    ran = true;
    delete client;  // destroys the std::function we are executing inside
  }));

  tcp_pcb *pcb = establish(*c);

  fire_recv(pcb, "hello", 5);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(ran);
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_destroy_inside_onError_is_safe(void) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  c->onError(probe.wrap([&](void *, AsyncClient *client, int8_t) {
    ran = true;
    delete client;
  }));

  tcp_pcb *pcb = establish(*c);

  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(ran);
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_destroy_inside_onConnect_is_safe(void) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  c->onConnect(probe.wrap([&](void *, AsyncClient *client) {
    ran = true;
    delete client;
  }));

  TEST_ASSERT_TRUE(c->connect(kPeer, kPort));
  fire_connected(dialled_pcb());  // c is destroyed inside onConnect
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(ran);
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_destroy_with_a_queued_event_delivers_nothing(void) {
  LiveProbe probe;
  bool ran = false;
  {
    AsyncClient c;
    c.onData(probe.wrap([&](void *, AsyncClient *, void *, size_t) {
      ran = true;
    }));
    tcp_pcb *pcb = establish(c);

    // Queue an event, then destroy the client before the async task runs
    fire_recv(pcb, "hello", 5);
  }

  asynctcp_test_pump();  // the event is still queued, and must simply drain
  TEST_ASSERT_FALSE(ran);
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_close_inside_onData_acks_the_packet(void) {
  LiveProbe probe;
  // Without the ack the peer gets an RST for data the application did process.
  {
    AsyncClient c;
    c.onData(probe.wrap([](void *, AsyncClient *client, void *, size_t) {
      client->close();
    }));
    tcp_pcb *pcb = establish(c);

    fire_recv(pcb, "hello", 5);
    asynctcp_test_pump();

    TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
    TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
    TEST_ASSERT_TRUE(saw("tcp_recved", pcb, 5));  // the packet onData was handed
    TEST_ASSERT_EQUAL_size_t(1, count("tcp_close"));
  }
  TEST_ASSERT_FALSE(probe.alive());
}

static void test_lifetime_destroy_during_a_lookup_releases_the_callbacks(void) {
  LiveProbe probe;
  faults().dns_result = ERR_INPROGRESS;
  {
    AsyncClient c;
    probe.attach(c);
    TEST_ASSERT_TRUE(c.connect("slow.test", kPort));
    TEST_ASSERT_TRUE(dns_pending());
  }
  // An answer nobody wants must not keep the client's resources alive until the
  // resolver gives up.
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  // The callback still arrives - LwIP cannot cancel one - and must find nothing to do.
  fire_dns(0x0A000001);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));  // the client is gone; do not dial out
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_self_owned_client_deletes_itself_in_onDisconnect(void) {
  // The ESPAsyncWebServer shape: the client owns itself and the handler is its undertaker.
  LiveProbe probe;
  int disconnects = 0;
  AsyncClient *c = new AsyncClient();
  c->onDisconnect(probe.wrap([&](void *, AsyncClient *self) {
    disconnects++;
    delete self;
  }));
  tcp_pcb *pcb = establish(*c);

  fire_fin(pcb);  // peer hangs up; onDisconnect runs and destroys the client
  asynctcp_test_pump();

  // Exactly once, although destruction closes again - and without re-entering the
  // handler that is destroying the client.
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_destroy_inside_onError_raised_by_abort(void) {
  // abort() reports the error synchronously, on the calling task rather than the async
  // task, and the callback destroys the client while abort() is still on the stack.
  LiveProbe probe;
  int errors = 0, disconnects = 0;
  AsyncClient *c = new AsyncClient();
  c->onError(probe.wrap([&](void *, AsyncClient *self, int8_t) {
    errors++;
    delete self;
  }));
  c->onDisconnect(probe.wrap([&](void *, AsyncClient *) {
    disconnects++;
  }));

  establish(*c);

  c->abort();  // c is destroyed inside the error callback; do not touch it after this
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_EQUAL_INT(0, disconnects);  // the client is gone, so it must not be handed to onDisconnect
  TEST_ASSERT_FALSE(probe.alive());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_reconnect_after_close_starts_clean(void) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    tcp_pcb *first = establish(c);

    // Withhold an ack, then close: the debt must not survive into the next connection
    c.ackLater();
    fire_recv(first, "hello", 5);
    asynctcp_test_pump();
    c.close();
    asynctcp_test_pump();

    const size_t recved_before = count("tcp_recved");
    TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
    tcp_pcb *second = dialled_pcb();
    TEST_ASSERT_NOT_NULL(second);
    fire_connected(second);
    asynctcp_test_pump();

    TEST_ASSERT_EQUAL_size_t(0, c.ack(5));                         // nothing outstanding on the new pcb
    TEST_ASSERT_EQUAL_size_t(recved_before, count("tcp_recved"));  // and nothing acked against it

    c.close();
    asynctcp_test_pump();
  }
  TEST_ASSERT_FALSE(probe.alive());
}

// ---------------------------------------------------------------------------
// Tearing down one client from inside another's callback
// ---------------------------------------------------------------------------

static void test_lifetime_closing_another_client_from_onData_drops_its_queued_events(void) {
  AsyncClient a;
  AsyncClient b;
  Recorder ta;
  Recorder tb;
  ta.attach(a, "CEDR");
  tb.attach(b, "CEDR");
  a.onData([&](void *, AsyncClient *cl, void *d, size_t n) {
    ta.note('R', cl);
    ta.data.append((const char *)d, n);
    if (ta.count('R') == 1) {
      b.close();
    }
  });
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(b);

  fire_recv(pa, "a1", 2);
  fire_recv(pb, "b1", 2);
  fire_fin(pb);
  fire_recv(pa, "a2", 2);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("a1a2", ta.data.c_str());
  TEST_ASSERT_EQUAL_STRING("CD", tb.seq.c_str());
  TEST_ASSERT_TRUE(a.connected());
  TEST_ASSERT_FALSE(is_live(pb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  a.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_destroying_another_client_from_onData_drops_its_queued_events(void) {
  AsyncClient a;
  AsyncClient *b = new AsyncClient();
  Recorder ta;
  Recorder tb;
  ta.attach(a, "CED");
  tb.attach(*b, "CEDR");
  a.onData([&](void *, AsyncClient *cl, void *d, size_t n) {
    ta.note('R', cl);
    ta.data.append((const char *)d, n);
    if (b) {
      delete b;
      b = nullptr;
    }
  });
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(*b);

  fire_recv(pa, "a1", 2);
  fire_recv(pb, "b1", 2);
  fire_fin(pb);
  fire_recv(pa, "a2", 2);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("a1a2", ta.data.c_str());
  TEST_ASSERT_EQUAL_STRING("CD", tb.seq.c_str());  // the connection was up, so onDisconnect is owed
  TEST_ASSERT_TRUE(a.connected());
  TEST_ASSERT_FALSE(is_live(pb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  a.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_lifetime_aborting_another_client_from_onDisconnect_reports_it_once(void) {
  // b was reset before a's callback aborts it: b is owed one onError and one onDisconnect,
  // whichever of the two reports them.
  AsyncClient a;
  AsyncClient b;
  Recorder ta;
  Recorder tb;
  ta.attach(a, "CE");
  tb.attach(b, "CEDR");
  a.onDisconnect([&](void *, AsyncClient *cl) {
    ta.note('D', cl);
    b.abort();
  });
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(b);

  fire_fin(pa);
  fire_recv(pb, "b1", 2);
  fire_error(pb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CD", ta.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("CED", tb.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_destroying_another_client_from_onError_drops_its_queued_events(void) {
  AsyncClient a;
  AsyncClient *b = new AsyncClient();
  Recorder ta;
  Recorder tb;
  ta.attach(a, "CD");
  tb.attach(*b, "CEDR");
  a.onError([&](void *, AsyncClient *cl, int8_t e) {
    ta.note('E', cl, e);
    delete b;
    b = nullptr;
  });
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(*b);

  fire_error(pa, ERR_RST);
  fire_recv(pb, "b1", 2);
  fire_fin(pb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CED", ta.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("CD", tb.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_destroying_another_client_with_a_queued_error_reports_its_disconnect(void) {
  // b's reset is queued when a's callback destroys it.  Nothing may reach b once it is
  // destroyed, so the onDisconnect it is owed comes from its destructor.
  AsyncClient a;
  AsyncClient *b = new AsyncClient();
  Recorder ta;
  Recorder tb;
  ta.attach(a, "CED");
  tb.attach(*b);
  a.onData([&](void *, AsyncClient *cl, void *, size_t) {
    ta.note('R', cl);
    if (b) {
      delete b;
      b = nullptr;
    }
  });
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(*b);

  fire_recv(pa, "a1", 2);
  fire_error(pb, ERR_RST);
  fire_recv(pa, "a2", 2);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CRR", ta.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("CD", tb.seq.c_str());
  TEST_ASSERT_TRUE(a.connected());

  a.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_destroy_closes_a_connection_made_from_onDisconnect(void) {
  TEST_IGNORE_MESSAGE("~AsyncClient() leaves open a connection dialled from onDisconnect");
  // ~AsyncClient() runs onDisconnect, which dials again.
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c, "CER");
  c->onDisconnect([&](void *, AsyncClient *cl) {
    t.note('D', cl);
    cl->connect(kPeer, kPort);
  });
  establish(*c);
  delete c;

  // A connection left behind would hear from the peer.
  tcp_pcb *again = dialled_pcb();
  if (is_live(again)) {
    fire_connected(again);
    fire_recv(again, "late", 4);
    asynctcp_test_pump();
  }
  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_lifetime_destroy_abandons_a_lookup_started_from_onDisconnect(void) {
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c, "CER");
  c->onDisconnect([&](void *, AsyncClient *cl) {
    t.note('D', cl);
    cl->connect("late.test", kPort);
  });
  establish(*c);
  faults().dns_result = ERR_INPROGRESS;
  delete c;

  fire_dns(kResolved);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));  // only the first dial
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

void run_lifetime_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_lifetime_client_releases_its_callbacks);
  RUN_TEST(test_lifetime_connected_client_releases_on_close);
  RUN_TEST(test_lifetime_destroy_inside_onData_is_safe);
  RUN_TEST(test_lifetime_destroy_inside_onError_is_safe);
  RUN_TEST(test_lifetime_destroy_inside_onConnect_is_safe);
  RUN_TEST(test_lifetime_destroy_with_a_queued_event_delivers_nothing);
  RUN_TEST(test_lifetime_close_inside_onData_acks_the_packet);
  RUN_TEST(test_lifetime_destroy_during_a_lookup_releases_the_callbacks);
  RUN_TEST(test_lifetime_self_owned_client_deletes_itself_in_onDisconnect);
  RUN_TEST(test_lifetime_destroy_inside_onError_raised_by_abort);
  RUN_TEST(test_lifetime_reconnect_after_close_starts_clean);
  RUN_TEST(test_lifetime_closing_another_client_from_onData_drops_its_queued_events);
  RUN_TEST(test_lifetime_destroying_another_client_from_onData_drops_its_queued_events);
  RUN_TEST(test_lifetime_aborting_another_client_from_onDisconnect_reports_it_once);
  RUN_TEST(test_lifetime_destroying_another_client_from_onError_drops_its_queued_events);
  RUN_TEST(test_lifetime_destroying_another_client_with_a_queued_error_reports_its_disconnect);
  RUN_TEST(test_lifetime_destroy_closes_a_connection_made_from_onDisconnect);
  RUN_TEST(test_lifetime_destroy_abandons_a_lookup_started_from_onDisconnect);
}
