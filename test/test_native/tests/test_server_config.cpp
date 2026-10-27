// AsyncServer's configuration: setNoDelay()/getNoDelay() and how it reaches the
// connections the server accepts.

#include "fixtures.h"

using namespace mocklwip;

namespace {

const uint16_t kOtherPort = 8082;

}  // namespace

static void test_server_config_getNoDelay_defaults_to_false(void) {
  AsyncServer s(kServerPort);
  TEST_ASSERT_FALSE(s.getNoDelay());
}

static void test_server_config_getNoDelay_reports_what_was_set(void) {
  // Pure state on the server, readable with no pcb in existence either side of begin().
  AsyncServer s(kServerPort);
  s.setNoDelay(true);
  TEST_ASSERT_TRUE(s.getNoDelay());
  s.setNoDelay(false);
  TEST_ASSERT_FALSE(s.getNoDelay());

  s.begin();
  s.setNoDelay(true);
  TEST_ASSERT_TRUE(s.getNoDelay());
  s.end();
  TEST_ASSERT_TRUE(s.getNoDelay());  // survives the listening session
}

static void test_server_config_default_accepts_leave_nagle_enabled(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_FALSE(tcp_nagle_disabled(conn));
  TEST_ASSERT_FALSE(accepted[0]->getNoDelay());

  accepted.clear();
  s.end();
}

static void test_server_config_setNoDelay_propagates_to_accepted_clients(void) {
  AsyncServer s(kServerPort);
  s.setNoDelay(true);
  TEST_ASSERT_TRUE(s.getNoDelay());

  Accepted accepted(s);
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_TRUE(accepted[0]->getNoDelay());
  TEST_ASSERT_TRUE(tcp_nagle_disabled(conn));

  accepted.clear();
  s.end();
}

static void test_server_config_setNoDelay_after_begin_reaches_later_accepts(void) {
  // A change made while already listening has to apply to everything accepted from then
  // on.
  AsyncServer s(kServerPort);
  Accepted clients(s);
  s.begin();

  tcp_pcb *before = fire_accept(listen_pcb());
  asynctcp_test_pump();

  s.setNoDelay(true);
  tcp_pcb *after = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(2, clients.size());
  TEST_ASSERT_TRUE(tcp_nagle_disabled(after));
  TEST_ASSERT_TRUE(clients[1]->getNoDelay());
  // The earlier connection belongs to the application now; the server must not reach back
  // into a client it has already handed over.
  TEST_ASSERT_FALSE(tcp_nagle_disabled(before));

  clients.clear();
  s.end();
}

static void test_server_config_setNoDelay_applies_across_a_restart(void) {
  // end() drops the listening session, not the server's configuration.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.setNoDelay(true);
  s.begin();
  s.end();
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_TRUE(s.getNoDelay());
  TEST_ASSERT_TRUE(tcp_nagle_disabled(conn));

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_config_noDelay_is_per_server(void) {
  // Two servers listening at once must not share the setting.
  AsyncServer a(kServerPort);
  AsyncServer b(kOtherPort);
  Accepted from_a(a);
  Accepted from_b(b);
  a.setNoDelay(true);
  a.begin();
  b.begin();

  tcp_pcb *pa = fire_accept(listen_pcb(kServerPort));
  tcp_pcb *pb = fire_accept(listen_pcb(kOtherPort));
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, from_a.size());
  TEST_ASSERT_EQUAL_size_t(1, from_b.size());
  TEST_ASSERT_TRUE(tcp_nagle_disabled(pa));
  TEST_ASSERT_FALSE(tcp_nagle_disabled(pb));
  TEST_ASSERT_FALSE(b.getNoDelay());

  from_a.clear();
  from_b.clear();
  a.end();
  b.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

void run_server_config_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_server_config_getNoDelay_defaults_to_false);
  RUN_TEST(test_server_config_getNoDelay_reports_what_was_set);
  RUN_TEST(test_server_config_default_accepts_leave_nagle_enabled);
  RUN_TEST(test_server_config_setNoDelay_propagates_to_accepted_clients);
  RUN_TEST(test_server_config_setNoDelay_after_begin_reaches_later_accepts);
  RUN_TEST(test_server_config_setNoDelay_applies_across_a_restart);
  RUN_TEST(test_server_config_noDelay_is_per_server);
}
