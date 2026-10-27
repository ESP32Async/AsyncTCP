// How a failure is reported to the application.
//
// Two things are checked here.  errorToString() has to name every code the library can
// hand to onError, because the string is all the application gets.  And every way a
// connection can end has to report it exactly once: onError when there was an error,
// onDisconnect when the connection had been established, onError first when both.
//
// The tests below record the callbacks with a Recorder, so order, count and exactly-once
// are one assertion rather than three.
//
// stateToString() is not here: test_state.cpp walks the whole table already.

#include "fixtures.h"

#include <algorithm>
#include <string>

using namespace mocklwip;

// ---------------------------------------------------------------------------
// errorToString
// ---------------------------------------------------------------------------

static void test_error_errorToString_names_every_lwip_code(void) {
  // Every code LwIP defines, plus -55, which the library raises for a failed lookup.
  TEST_ASSERT_EQUAL_STRING("OK", AsyncClient::errorToString(ERR_OK));
  TEST_ASSERT_EQUAL_STRING("Out of memory error", AsyncClient::errorToString(ERR_MEM));
  TEST_ASSERT_EQUAL_STRING("Buffer error", AsyncClient::errorToString(ERR_BUF));
  TEST_ASSERT_EQUAL_STRING("Timeout", AsyncClient::errorToString(ERR_TIMEOUT));
  TEST_ASSERT_EQUAL_STRING("Routing problem", AsyncClient::errorToString(ERR_RTE));
  TEST_ASSERT_EQUAL_STRING("Operation in progress", AsyncClient::errorToString(ERR_INPROGRESS));
  TEST_ASSERT_EQUAL_STRING("Illegal value", AsyncClient::errorToString(ERR_VAL));
  TEST_ASSERT_EQUAL_STRING("Operation would block", AsyncClient::errorToString(ERR_WOULDBLOCK));
  TEST_ASSERT_EQUAL_STRING("Address in use", AsyncClient::errorToString(ERR_USE));
  TEST_ASSERT_EQUAL_STRING("Already connecting", AsyncClient::errorToString(ERR_ALREADY));
  TEST_ASSERT_EQUAL_STRING("Already connected", AsyncClient::errorToString(ERR_ISCONN));
  TEST_ASSERT_EQUAL_STRING("Not connected", AsyncClient::errorToString(ERR_CONN));
  TEST_ASSERT_EQUAL_STRING("Low-level netif error", AsyncClient::errorToString(ERR_IF));
  TEST_ASSERT_EQUAL_STRING("Connection aborted", AsyncClient::errorToString(ERR_ABRT));
  TEST_ASSERT_EQUAL_STRING("Connection reset", AsyncClient::errorToString(ERR_RST));
  TEST_ASSERT_EQUAL_STRING("Connection closed", AsyncClient::errorToString(ERR_CLSD));
  TEST_ASSERT_EQUAL_STRING("Illegal argument", AsyncClient::errorToString(ERR_ARG));
  TEST_ASSERT_EQUAL_STRING("DNS failed", AsyncClient::errorToString(-55));
}

static void test_error_errorToString_says_unknown_for_codes_it_has_no_name_for(void) {
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(1));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(127));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(ERR_ARG - 1));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(-54));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(-56));
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", AsyncClient::errorToString(-128));
}

// ---------------------------------------------------------------------------
// Which callbacks a failure runs, in what order, how many times
// ---------------------------------------------------------------------------

static void test_error_reset_is_reported_once_however_often_the_queue_is_pumped(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  t.seq.clear();  // drop the 'C'

  fire_error(pcb, ERR_RST);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_STRING("", t.seq.c_str());  // not delivered yet
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_RST, t.err);

  // Nothing is left owed: neither a further pump nor a close can produce a second report.
  asynctcp_test_pump();
  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
}

static void test_error_refused_connect_reports_the_error_and_never_onConnect(void) {
  // A refused SYN arrives as tcp_err on a pcb still in SYN_SENT, so there is a connection
  // attempt to report against but no connection.
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT8(SYN_SENT, pcb->state);

  fire_error(pcb, ERR_ABRT);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, t.err);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_error_reset_overtaking_an_undelivered_connect_reports_only_the_error(void) {
  // The handshake landed but the async task had not run yet.  Reporting both would tell
  // the application it was connected to something already gone.
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);

  fire_connected(pcb);
  fire_error(pcb, ERR_RST);  // both events queued, neither delivered
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
}

static void test_error_pcb_allocation_failure_reports_nothing(void) {
  // connect() returns false before anything is owed, so reporting a failure the caller
  // already knows about would be a callback against a connection that never existed.
  faults().fail_tcp_new = 1;

  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_FALSE(c.connect(kPeer, kPort));
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_error_dns_failure_is_reported_once_and_leaves_nothing_owed(void) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("nx.test", kPort));

  fire_dns_failure();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(-55, t.err);

  // The client never held a pcb, so the close that follows has nothing to report either.
  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
}

static void test_error_dial_failing_after_a_lookup_reports_error_before_disconnect(void) {
  // The dial happens inside the resolver callback, where the failure is nobody's return
  // value; it has to come back as the same ordered pair as any other terminal error.
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));

  faults().connect_result = ERR_RTE;
  fire_dns(kResolved);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_CONN, t.err);  // resolved, so not the -55 "DNS failed" code
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_error_abort_reports_abrt_then_disconnect(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  establish(c);
  t.seq.clear();

  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, c.abort());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_NULL(c.pcb());
  asynctcp_test_pump();

  // abort() raises the error itself -- LwIP does not call tcp_err for a pcb we aborted --
  // so that a connection the application tore down still gets its one report.
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, t.err);
}

static void test_error_peer_fin_disconnects_without_an_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  t.seq.clear();

  fire_fin(pcb);
  asynctcp_test_pump();

  // An orderly close is not a failure, so onError must stay out of it.
  TEST_ASSERT_EQUAL_STRING("D", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_error_close_disconnects_without_an_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  establish(c);
  t.seq.clear();

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("D", t.seq.c_str());
}

static void test_error_rx_timeout_disconnects_without_an_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  t.seq.clear();

  c.setRxTimeout(2);
  mockclock::advance(2500);
  fire_poll(pcb);
  asynctcp_test_pump();

  // The library closes the connection itself, which is a disconnect and not an error.
  TEST_ASSERT_EQUAL_STRING("D", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_error_ack_timeout_reports_onTimeout_and_nothing_else(void) {
  // An unacked send is reported to onTimeout, and that is all.  Tearing the connection
  // down is the application's call, so neither onError nor onDisconnect may fire on its
  // own.
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDT");
  tcp_pcb *pcb = establish(c);
  t.seq.clear();

  c.setAckTimeout(100);
  c.write("x", 1);
  mockclock::advance(250);
  fire_poll(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("T", t.seq.c_str());
  TEST_ASSERT_TRUE(c.connected());

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("TD", t.seq.c_str());
}

static void test_error_accepted_client_reset_reports_error_then_disconnect(void) {
  AsyncServer s(kServerPort);
  Recorder t;
  Accepted accepted(s, [&](AsyncClient *c) {
    t.attach(*c);
  });
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());

  fire_error(conn, ERR_RST);
  asynctcp_test_pump();

  // An accepted client was never connect()ed, but it holds a pcb, so it is owed the same
  // pair as any other established connection.
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_RST, t.err);

  accepted.clear();
  s.end();
}

// ---------------------------------------------------------------------------
// What the error callback is told
// ---------------------------------------------------------------------------

static void test_error_callback_is_handed_a_usable_client(void) {
  // LwIP freed the pcb before tcp_err ran, so every accessor here is reading state the
  // library must already have detached; under the sanitized build a miss is a crash.
  AsyncClient c;
  bool checked = false;
  c.onError([&](void *, AsyncClient *cl, int8_t e) {
    checked = true;
    TEST_ASSERT_EQUAL_PTR(&c, cl);
    TEST_ASSERT_NULL(cl->pcb());
    TEST_ASSERT_EQUAL_UINT8(CLOSED, cl->state());
    TEST_ASSERT_EQUAL_STRING("Closed", cl->stateToString());
    TEST_ASSERT_FALSE(cl->connected());
    TEST_ASSERT_TRUE(cl->disconnected());
    TEST_ASSERT_TRUE(cl->freeable());
    TEST_ASSERT_EQUAL_STRING("Connection reset", AsyncClient::errorToString(e));
    TEST_ASSERT_EQUAL_UINT32(0, cl->getRemoteAddress());
    TEST_ASSERT_EQUAL_UINT16(0, cl->getRemotePort());
    TEST_ASSERT_EQUAL_size_t(0, cl->space());
    TEST_ASSERT_FALSE(cl->canSend());
    TEST_ASSERT_EQUAL_size_t(0, cl->write("late", 4));
  });

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(checked);
}

static void test_error_closing_from_inside_on_error_still_disconnects_once(void) {
  // The obvious thing for an application to do, and the one that could double-report:
  // close() reports a dispose of its own when one is owed.
  AsyncClient c;
  Recorder t;
  t.attach(c);
  c.onError([&](void *, AsyncClient *cl, int8_t) {
    t.seq += 'E';
    cl->close();
  });

  tcp_pcb *pcb = establish(c);
  t.seq.clear();

  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
}

// ---------------------------------------------------------------------------
// Missing, shared and late-registered handlers
// ---------------------------------------------------------------------------

static void test_error_reset_with_no_handlers_does_not_crash_or_leak(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_error_abort_with_no_handlers_does_not_crash_or_leak(void) {
  AsyncClient c;
  establish(c);

  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, c.abort());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_error_dns_failure_with_no_handlers_does_not_crash_or_leak(void) {
  // The failure is owed to a client with no error handler at all; it still has to be
  // settled, so the client can connect again.
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect("nx.test", kPort));
  fire_dns_failure();
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));  // not wedged: the failure was reported
  c.close();
}

static void test_error_only_onDisconnect_registered_still_hears_about_a_reset(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "D");

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  // The error has nowhere to go, but the connection still ended and that is still owed.
  TEST_ASSERT_EQUAL_STRING("D", t.seq.c_str());
}

static void test_error_only_onError_registered_hears_just_the_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "E");

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("E", t.seq.c_str());
}

static void test_error_one_handler_registered_for_both_is_called_twice(void) {
  // Sharing a handler is common in application code.  It must be entered once per
  // callback, error first -- not coalesced, and not entered re-entrantly.
  AsyncClient c;
  std::string seq;
  int depth = 0, max_depth = 0;
  auto handler = [&](void *, AsyncClient *, auto &&...rest) {
    max_depth = std::max(max_depth, ++depth);
    seq += (sizeof...(rest) == 1) ? 'E' : 'D';  // only onError carries the code
    --depth;
  };
  c.onError(handler);
  c.onDisconnect(handler);

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", seq.c_str());
  TEST_ASSERT_EQUAL_INT(1, max_depth);
}

static void test_error_handlers_registered_after_the_failure_is_queued_still_fire(void) {
  // The error happens on the LwIP thread but is delivered by the async task, so
  // handlers set in between still count.
  AsyncClient c;
  Recorder t;
  tcp_pcb *pcb = establish(c);

  fire_error(pcb, ERR_RST);
  t.attach(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_RST, t.err);
}

static void test_error_replacing_a_handler_after_the_failure_is_queued_uses_the_new_one(void) {
  AsyncClient c;
  std::string seq;
  c.onError([&](void *, AsyncClient *, int8_t) {
    seq += 'x';
  });

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);

  c.onError([&](void *, AsyncClient *, int8_t) {
    seq += 'E';
  });
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("E", seq.c_str());
}

void run_error_tests(void) {
  UnitySetTestFile(__FILE__);

  RUN_TEST(test_error_errorToString_names_every_lwip_code);
  RUN_TEST(test_error_errorToString_says_unknown_for_codes_it_has_no_name_for);

  RUN_TEST(test_error_reset_is_reported_once_however_often_the_queue_is_pumped);
  RUN_TEST(test_error_refused_connect_reports_the_error_and_never_onConnect);
  RUN_TEST(test_error_reset_overtaking_an_undelivered_connect_reports_only_the_error);
  RUN_TEST(test_error_pcb_allocation_failure_reports_nothing);
  RUN_TEST(test_error_dns_failure_is_reported_once_and_leaves_nothing_owed);
  RUN_TEST(test_error_dial_failing_after_a_lookup_reports_error_before_disconnect);
  RUN_TEST(test_error_abort_reports_abrt_then_disconnect);
  RUN_TEST(test_error_peer_fin_disconnects_without_an_error);
  RUN_TEST(test_error_close_disconnects_without_an_error);
  RUN_TEST(test_error_rx_timeout_disconnects_without_an_error);
  RUN_TEST(test_error_ack_timeout_reports_onTimeout_and_nothing_else);
  RUN_TEST(test_error_accepted_client_reset_reports_error_then_disconnect);

  RUN_TEST(test_error_callback_is_handed_a_usable_client);
  RUN_TEST(test_error_closing_from_inside_on_error_still_disconnects_once);

  RUN_TEST(test_error_reset_with_no_handlers_does_not_crash_or_leak);
  RUN_TEST(test_error_abort_with_no_handlers_does_not_crash_or_leak);
  RUN_TEST(test_error_dns_failure_with_no_handlers_does_not_crash_or_leak);
  RUN_TEST(test_error_only_onDisconnect_registered_still_hears_about_a_reset);
  RUN_TEST(test_error_only_onError_registered_hears_just_the_error);
  RUN_TEST(test_error_one_handler_registered_for_both_is_called_twice);
  RUN_TEST(test_error_handlers_registered_after_the_failure_is_queued_still_fire);
  RUN_TEST(test_error_replacing_a_handler_after_the_failure_is_queued_uses_the_new_one);
}
