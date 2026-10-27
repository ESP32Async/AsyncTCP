// End-to-end smoke tests: one pass down each main path.  The topic files hold the detail.

#include "fixtures.h"

#include <string>

using namespace mocklwip;

static void test_client_connects_exchanges_data_and_closes(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDRA");

  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_STRING("C", t.seq.c_str());

  TEST_ASSERT_EQUAL_size_t(4, c.write("ping", 4));
  TEST_ASSERT_EQUAL_STRING("ping", written(pcb).c_str());
  fire_sent(pcb, 4);
  fire_recv(pcb, "pong", 4);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("CAR", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(4, t.acked);
  TEST_ASSERT_EQUAL_STRING("pong", t.data.c_str());
  TEST_ASSERT_EQUAL_size_t(4, recved(pcb));

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("CARD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_client_reset_reports_the_error_then_the_disconnect(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT8(ERR_RST, t.err);
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_client_server_answers_a_request(void) {
  AsyncServer s(kServerPort);
  std::string request;
  Accepted accepted(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *cl, void *d, size_t n) {
      request.append((const char *)d, n);
      cl->write("pong", 4);
    });
  });
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());

  fire_recv(conn, "ping", 4);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ping", request.c_str());
  TEST_ASSERT_EQUAL_STRING("pong", written(conn).c_str());

  fire_fin(conn);  // the peer hangs up
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(accepted[0]->disconnected());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

void run_client_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_client_connects_exchanges_data_and_closes);
  RUN_TEST(test_client_reset_reports_the_error_then_the_disconnect);
  RUN_TEST(test_client_server_answers_a_request);
}
