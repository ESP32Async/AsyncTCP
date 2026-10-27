// AsyncServer's listening session: begin(), end(), status(), restarts, and what a failed
// bind or listen leaves behind.

#include "fixtures.h"

using namespace mocklwip;

static void test_server_listen_begin_binds_and_listens(void) {
  AsyncServer s(kServerPort);
  s.begin();

  TEST_ASSERT_EQUAL_size_t(1, count("tcp_bind"));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_listen_with_backlog"));
  TEST_ASSERT_TRUE(port_is_bound(kServerPort));

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(lp);
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  TEST_ASSERT_NOT_NULL(lp->accept);
  // What the library passes as the argument is its own business, so we can only check
  // that one is set.
  TEST_ASSERT_NOT_NULL(lp->callback_arg);

  // tcp_listen_with_backlog swapped the bound pcb for a listen pcb, so exactly
  // one should be alive.
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
}

static void test_server_listen_destructor_releases_the_port(void) {
  {
    AsyncServer s(kServerPort);
    s.begin();
    TEST_ASSERT_TRUE(port_is_bound(kServerPort));
  }
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
}

static void test_server_listen_begin_bails_out_when_pcb_allocation_fails(void) {
  faults().fail_tcp_new = 1;

  AsyncServer s(kServerPort);
  s.begin();

  TEST_ASSERT_EQUAL_INT(0, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_bind"));
}

static void test_server_listen_begin_frees_the_pcb_when_bind_fails(void) {
  faults().bind_result = ERR_USE;

  AsyncServer s(kServerPort);
  s.begin();

  TEST_ASSERT_EQUAL_INT(0, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_bind"));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_listen_with_backlog"));
  // A failed bind must not leave the pcb behind.
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_close"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_listen_bind_conflicts_with_an_already_bound_port(void) {
  AsyncServer a(kServerPort);
  a.begin();
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)a.status());

  AsyncServer b(kServerPort);
  b.begin();
  TEST_ASSERT_EQUAL_INT(0, (int)b.status());  // ERR_USE from tcp_bind

  a.end();
  b.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// lwIP does NOT free the caller's pcb when it cannot allocate a listen pcb, so begin()
// still owns the bound one and has to close it, or both the pcb and its port leak for
// the life of the process.
static void test_server_listen_begin_frees_the_bound_pcb_when_listen_fails(void) {
  faults().listen_returns_null = true;

  {
    AsyncServer s(kServerPort);
    s.begin();
    TEST_ASSERT_EQUAL_INT(0, (int)s.status());
    TEST_ASSERT_EQUAL_size_t(1, count("tcp_listen_with_backlog"));
  }

  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
}

static void test_server_listen_end_is_idempotent(void) {
  AsyncServer s(kServerPort);
  s.begin();
  s.end();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_INT(0, (int)s.status());
}

static void test_server_listen_begin_twice_does_not_double_bind(void) {
  AsyncServer s(kServerPort);
  s.begin();
  s.begin();  // second call must be a no-op: already listening
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_bind"));
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());
  s.end();
}

// ---------------------------------------------------------------------------
// status()
// ---------------------------------------------------------------------------

static void test_server_listen_status_is_closed_before_begin(void) {
  // Not listening yet, so status() has nothing to report but CLOSED.
  AsyncServer s(kServerPort);
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
}

static void test_server_listen_status_follows_the_listening_session(void) {
  AsyncServer s(kServerPort);
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  s.begin();
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  s.end();
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  s.begin();
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  s.end();
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
}

static void test_server_listen_status_is_closed_after_end_aborts_the_listen_pcb(void) {
  // tcp_close() can fail on a listen pcb; end() falls back to tcp_abort(), and either way
  // the server has stopped listening and owns nothing.
  faults().close_result = ERR_MEM;

  AsyncServer s(kServerPort);
  s.begin();
  s.end();

  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_abort"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
}

// ---------------------------------------------------------------------------
// Restarting, and taking a port over
// ---------------------------------------------------------------------------

static void test_server_listen_restart_accepts_on_a_fresh_listen_pcb(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();
  tcp_pcb *first = listen_pcb();
  s.end();
  TEST_ASSERT_FALSE(is_live(first));

  s.begin();
  tcp_pcb *second = listen_pcb();
  TEST_ASSERT_NOT_NULL(second);
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  TEST_ASSERT_TRUE(port_is_bound(kServerPort));
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  tcp_pcb *conn = fire_accept(second);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_EQUAL_PTR(conn, accepted[0]->pcb());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_listen_the_port_is_reusable_once_the_holder_ends(void) {
  // A failed begin() leaves nothing behind, so a server can take the port over as soon as
  // the one holding it lets go, with no intervening teardown of its own.
  AsyncServer a(kServerPort);
  AsyncServer b(kServerPort);
  a.begin();
  b.begin();
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)b.status());

  a.end();
  b.begin();
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)b.status());
  TEST_ASSERT_TRUE(port_is_bound(kServerPort));
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  b.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// The address listened on
// ---------------------------------------------------------------------------

static void test_server_listen_by_port_alone_binds_to_any_address(void) {
  AsyncServer s(kServerPort);
  s.begin();

  const Call *bind = nth("tcp_bind", 0);
  TEST_ASSERT_NOT_NULL(bind);
  TEST_ASSERT_EQUAL_INT(kServerPort, (int)bind->a);
  TEST_ASSERT_EQUAL_INT(0, (int)bind->b);
  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(lp);
  TEST_ASSERT_EQUAL_UINT32(0, ip_addr_get_ip4_u32(&lp->local_ip));
#if LWIP_IPV6
  TEST_ASSERT_EQUAL_UINT8(IPADDR_TYPE_ANY, lp->local_ip.type);  // both families
#endif

  s.end();
}

static void test_server_listen_by_ip_addr_t_binds_that_address(void) {
  const uint32_t kBind = 0x0A000007;  // 10.0.0.7
  ip_addr_t addr = IPADDR4_INIT(kBind);
  AsyncServer s(addr, kServerPort);
  s.begin();

  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  tcp_pcb *lp = listen_pcb(kServerPort);
  TEST_ASSERT_NOT_NULL(lp);
  TEST_ASSERT_EQUAL_UINT32(kBind, ip_addr_get_ip4_u32(&lp->local_ip));

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

#if LWIP_IPV6
static void test_server_listen_by_ipv6_address_binds_that_address(void) {
  const uint32_t kWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000007};
  AsyncServer s(IPv6Address(kWords), kServerPort);
  s.begin();

  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  tcp_pcb *lp = listen_pcb(kServerPort);
  TEST_ASSERT_NOT_NULL(lp);
  TEST_ASSERT_EQUAL_UINT8(IPADDR_TYPE_V6, lp->local_ip.type);
  for (int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT32(kWords[i], lp->local_ip.u_addr.ip6.addr[i]);
  }

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}
#endif

void run_server_listen_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_server_listen_begin_binds_and_listens);
  RUN_TEST(test_server_listen_destructor_releases_the_port);
  RUN_TEST(test_server_listen_begin_bails_out_when_pcb_allocation_fails);
  RUN_TEST(test_server_listen_begin_frees_the_pcb_when_bind_fails);
  RUN_TEST(test_server_listen_bind_conflicts_with_an_already_bound_port);
  RUN_TEST(test_server_listen_begin_frees_the_bound_pcb_when_listen_fails);
  RUN_TEST(test_server_listen_end_is_idempotent);
  RUN_TEST(test_server_listen_begin_twice_does_not_double_bind);
  RUN_TEST(test_server_listen_status_is_closed_before_begin);
  RUN_TEST(test_server_listen_status_follows_the_listening_session);
  RUN_TEST(test_server_listen_status_is_closed_after_end_aborts_the_listen_pcb);
  RUN_TEST(test_server_listen_restart_accepts_on_a_fresh_listen_pcb);
  RUN_TEST(test_server_listen_the_port_is_reusable_once_the_holder_ends);
  RUN_TEST(test_server_listen_by_port_alone_binds_to_any_address);
  RUN_TEST(test_server_listen_by_ip_addr_t_binds_that_address);
#if LWIP_IPV6
  RUN_TEST(test_server_listen_by_ipv6_address_binds_that_address);
#endif
}
