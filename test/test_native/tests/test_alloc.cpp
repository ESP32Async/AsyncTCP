// Running out of memory: each lwIP callback, with the allocation it makes failing.

#include "fixtures.h"

#include <cstdio>
#include <deque>
#include <string>

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#endif

using namespace mocklwip;

namespace {

// More allocations than either exchange below makes.
const unsigned kMaxAllocations = 64;

// Ends one run of an exchange.  Under ASan, fails if anything is unreachable.  The
// mock's call log holds the pointers the library gave lwIP, which would hide a leaked
// client, so the mock is reset first -- after the checks the runner would otherwise make
// of it at the end of the test.
void assert_nothing_leaked(const char *msg) {
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, mocklwip::unlocked_calls(), mocklwip::first_unlocked_call());
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, mocklwip::reentrant_api_calls(), msg);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, mocklwip::core_lock_depth(), msg);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, mocklwip::callback_return_violations(), mocklwip::first_callback_return_violation());
  mocklwip::reset();
#if defined(__SANITIZE_ADDRESS__)
  TEST_ASSERT_FALSE_MESSAGE(__lsan_do_recoverable_leak_check(), msg);
#else
  (void)msg;
#endif
}

// A client's side of one exchange: it answers the request with a reply.
void answer(AsyncClient &c, Recorder &t) {
  t.attach(c, "CEDA");
  c.onData([&t](void *, AsyncClient *cl, void *d, size_t n) {
    t.seq += 'R';
    t.data.append((const char *)d, n);
    cl->write("reply", 5);
  });
}

// The peer's side: a request, an ack for the reply, then it hangs up.
void exchange(tcp_pcb *pcb) {
  fire_recv(pcb, "request", 7);
  asynctcp_test_pump();
  retry_refused(pcb);
  asynctcp_test_pump();
  fire_sent(pcb, 5);
  asynctcp_test_pump();
  fire_fin(pcb);
  asynctcp_test_pump();
  fire_poll(pcb);
  asynctcp_test_pump();
}

// Fails unless a connect or lookup the application was told is under way has ended:
// onConnect, or one error report.
void assert_connect_concluded(const Recorder &t) {
  const std::string msg = "callbacks were \"" + t.seq + "\"";
  TEST_ASSERT_TRUE_MESSAGE(t.seq == "C" || t.seq == "ED", msg.c_str());
}

}  // namespace

// ---------------------------------------------------------------------------
// Connection events
// ---------------------------------------------------------------------------

static void test_alloc_connected_still_concludes_the_connect(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the connect");
  // lwIP ignores what the connected callback returns unless it is ERR_ABRT
  // (tcp_process), so it will not say again that the connection is up.  It still polls
  // the connection.
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c);
  TEST_ASSERT_TRUE(c->connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();

  mockalloc::fail_next();
  fire_connected(pcb);
  asynctcp_test_pump();
  fire_poll(pcb);
  asynctcp_test_pump();

  assert_connect_concluded(t);

  delete c;
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_recv_is_delivered_once_lwip_offers_it_again(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_recv(pcb, "hello", 5);
  asynctcp_test_pump();
  retry_refused(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CR", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("hello", t.data.c_str());
  TEST_ASSERT_EQUAL_size_t(5, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_alloc_recv_of_a_chain_is_delivered_whole_once(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);
  pbuf *chain = make_pbuf("aaa", 3);
  pbuf_cat(chain, make_pbuf("bb", 2));

  mockalloc::fail_next();
  fire_recv_pbuf(pcb, chain);
  asynctcp_test_pump();
  retry_refused(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("aaabb", t.data.c_str());
  TEST_ASSERT_EQUAL_size_t(5, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_alloc_recv_keeps_its_place_ahead_of_later_data(void) {
  // lwIP offers the refused data again before the next segment.
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_recv(pcb, "first ", 6);
  asynctcp_test_pump();
  fire_recv(pcb, "second", 6);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("first second", t.data.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_alloc_recv_then_fin_delivers_the_data_then_the_disconnect(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_recv(pcb, "last", 4);
  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CRD", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("last", t.data.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_alloc_recv_then_close_leaks_nothing(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_recv(pcb, "unread", 6);
  asynctcp_test_pump();
  c.close();
  asynctcp_test_pump();

  // The data may be dropped, but only whole.
  TEST_ASSERT_EQUAL_STRING(t.data.empty() ? "CD" : "CRD", t.seq.c_str());
  TEST_ASSERT_TRUE(t.data.empty() || t.data == "unread");
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_alloc_recv_then_reset_leaks_nothing(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_recv(pcb, "unread", 6);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CED", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_alloc_recv_then_destroy_leaks_nothing(void) {
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c, "CEDR");
  tcp_pcb *pcb = establish(*c);

  mockalloc::fail_next();
  fire_recv(pcb, "unread", 6);
  delete c;
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_alloc_fin_still_ends_the_connection_once(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the FIN");
  // lwIP reports a FIN once, whatever the callback returns (tcp_input), so the close has
  // to be noticed some other way; lwIP keeps polling the half-closed connection.
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_fin(pcb);
  asynctcp_test_pump();
  fire_poll(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_fin_leaves_a_client_that_closes_cleanly(void) {
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c);
  tcp_pcb *pcb = establish(*c);

  mockalloc::fail_next();
  fire_fin(pcb);
  asynctcp_test_pump();

  delete c;
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_sent_leaves_later_acks_flowing(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDA");
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(6, c.write("abcdef", 6));

  mockalloc::fail_next();
  fire_sent(pcb, 2);
  asynctcp_test_pump();

  fire_sent(pcb, 4);
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(t.count('A') >= 1);
  TEST_ASSERT_EQUAL_size_t(4, t.acked);

  c.close();
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_poll_leaves_later_polls_flowing(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDP");
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_poll(pcb);
  asynctcp_test_pump();
  const int before = t.count('P');

  fire_poll(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(before + 1, t.count('P'));

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_poll_still_times_out_an_idle_connection(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(1);
  mockclock::advance(1500);

  mockalloc::fail_next();
  fire_poll(pcb);
  asynctcp_test_pump();

  fire_poll(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Errors: the pcb is gone, and lwIP will never call again
// ---------------------------------------------------------------------------

static void test_alloc_error_is_still_reported(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the error");
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);

  mockalloc::fail_next();
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT(ERR_RST, t.err);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_error_while_connecting_is_still_reported(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the error");
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();

  mockalloc::fail_next();
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_error_then_destroy_reports_once(void) {
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c);
  tcp_pcb *pcb = establish(*c);

  mockalloc::fail_next();
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();
  delete c;

  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_TRUE(t.count('E') <= 1);
}

// ---------------------------------------------------------------------------
// Accepts: nothing is owed to the application until onClient runs
// ---------------------------------------------------------------------------

static void test_alloc_accept_without_a_client_drops_the_connection(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  mockalloc::fail_next();
  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  TEST_ASSERT_FALSE(is_live(conn));

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_accept_without_an_event_drops_the_connection(void) {
  // The client is allocated, the event announcing it is not.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  mockalloc::fail_nth(2);
  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  TEST_ASSERT_FALSE(is_live(conn));

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_accept_failure_leaves_later_accepts_working(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  mockalloc::fail_next();
  fire_accept(listen_pcb());
  asynctcp_test_pump();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_EQUAL_PTR(conn, accepted[0]->pcb());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Lookups: lwIP calls back once, and connect() has already said yes
// ---------------------------------------------------------------------------

static void test_alloc_dns_answer_still_concludes_the_connect(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the lookup's answer");
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c);
  TEST_ASSERT_TRUE(c->connect("example.test", kPort));

  mockalloc::fail_next();
  fire_dns(kResolved);
  asynctcp_test_pump();
  tcp_pcb *pcb = dialled_pcb();
  if (pcb) {
    fire_connected(pcb);
    asynctcp_test_pump();
  }

  assert_connect_concluded(t);

  delete c;
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_alloc_dns_failure_is_still_reported(void) {
  TEST_IGNORE_MESSAGE("a failed allocation loses the lookup's failure");
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("example.test", kPort));

  mockalloc::fail_next();
  fire_dns_failure();
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
}

// ---------------------------------------------------------------------------
// Every allocation in a whole exchange, failed one at a time
// ---------------------------------------------------------------------------

static void test_alloc_any_failure_in_a_client_exchange_is_survived(void) {
  for (unsigned k = 1; k <= kMaxAllocations; k++) {
    mockalloc::reset();
    mockalloc::fail_nth(k);

    Recorder t;
    AsyncClient *c = new AsyncClient();
    answer(*c, t);
    const bool promised = c->connect(kPeer, kPort);
    tcp_pcb *pcb = dialled_pcb();
    fire_connected(pcb);
    asynctcp_test_pump();
    fire_poll(pcb);
    asynctcp_test_pump();
    exchange(pcb);
    delete c;

    char msg[64];
    snprintf(msg, sizeof(msg), "allocation %u failed", k);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, live_pcbs(), msg);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, live_pbufs(), msg);
    TEST_ASSERT_EQUAL_INT_MESSAGE(promised ? 1 : 0, t.count('D'), msg);
    assert_nothing_leaked(msg);
    if (mockalloc::failures() == 0) {
      return;  // the exchange made fewer than k allocations
    }
  }
  TEST_FAIL_MESSAGE("the exchange never ran without a failure");
}

static void test_alloc_any_failure_in_a_server_exchange_is_survived(void) {
  for (unsigned k = 1; k <= kMaxAllocations; k++) {
    mockalloc::reset();
    mockalloc::fail_nth(k);

    std::deque<Recorder> clients;
    {
      AsyncServer s(kServerPort);
      Accepted accepted(s, [&](AsyncClient *c) {
        clients.emplace_back();
        answer(*c, clients.back());
      });
      s.begin();
      tcp_pcb *pcb = fire_accept(listen_pcb(kServerPort));
      asynctcp_test_pump();
      exchange(pcb);
      accepted.clear();
      s.end();
    }

    char msg[64];
    snprintf(msg, sizeof(msg), "allocation %u failed", k);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, live_pcbs(), msg);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, live_pbufs(), msg);
    TEST_ASSERT_TRUE_MESSAGE(clients.size() <= 1, msg);
    for (const Recorder &t : clients) {
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, t.count('D'), msg);
    }
    assert_nothing_leaked(msg);
    if (mockalloc::failures() == 0) {
      return;
    }
  }
  TEST_FAIL_MESSAGE("the exchange never ran without a failure");
}

void run_alloc_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_alloc_connected_still_concludes_the_connect);
  RUN_TEST(test_alloc_recv_is_delivered_once_lwip_offers_it_again);
  RUN_TEST(test_alloc_recv_of_a_chain_is_delivered_whole_once);
  RUN_TEST(test_alloc_recv_keeps_its_place_ahead_of_later_data);
  RUN_TEST(test_alloc_recv_then_fin_delivers_the_data_then_the_disconnect);
  RUN_TEST(test_alloc_recv_then_close_leaks_nothing);
  RUN_TEST(test_alloc_recv_then_reset_leaks_nothing);
  RUN_TEST(test_alloc_recv_then_destroy_leaks_nothing);
  RUN_TEST(test_alloc_fin_still_ends_the_connection_once);
  RUN_TEST(test_alloc_fin_leaves_a_client_that_closes_cleanly);
  RUN_TEST(test_alloc_sent_leaves_later_acks_flowing);
  RUN_TEST(test_alloc_poll_leaves_later_polls_flowing);
  RUN_TEST(test_alloc_poll_still_times_out_an_idle_connection);
  RUN_TEST(test_alloc_error_is_still_reported);
  RUN_TEST(test_alloc_error_while_connecting_is_still_reported);
  RUN_TEST(test_alloc_error_then_destroy_reports_once);
  RUN_TEST(test_alloc_accept_without_a_client_drops_the_connection);
  RUN_TEST(test_alloc_accept_without_an_event_drops_the_connection);
  RUN_TEST(test_alloc_accept_failure_leaves_later_accepts_working);
  RUN_TEST(test_alloc_dns_answer_still_concludes_the_connect);
  RUN_TEST(test_alloc_dns_failure_is_still_reported);
  RUN_TEST(test_alloc_any_failure_in_a_client_exchange_is_survived);
  RUN_TEST(test_alloc_any_failure_in_a_server_exchange_is_survived);
}
