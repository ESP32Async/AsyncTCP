// Starting the library: what clients and servers do when FreeRTOS cannot create the queue
// mutex or the async task, and that a later start still succeeds.

#include "fixtures.h"

using namespace mocklwip;

namespace {

// Whether the library ever handed <pcb> a callback or an argument.
bool bound(const tcp_pcb *pcb) {
  for (const Call &call : calls()) {
    if (call.pcb == pcb && call.a != 0
        && (call.fn == "tcp_arg" || call.fn == "tcp_recv" || call.fn == "tcp_sent" || call.fn == "tcp_err" || call.fn == "tcp_poll")) {
      return true;
    }
  }
  return false;
}

// An AsyncClient made in the application's own accept callback closes the pcb it was
// handed, without taking it on.
void assert_adoption_refused() {
  AsyncClient *c = nullptr;
  tcp_pcb *pcb = fire_raw_accept([&](tcp_pcb *p) {
    c = new AsyncClient(p);
    return (err_t)ERR_OK;
  });
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_FALSE(c->connected());
  TEST_ASSERT_NULL(c->pcb());
  TEST_ASSERT_FALSE(bound(pcb));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_close", pcb));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_abort", pcb));
  TEST_ASSERT_FALSE(is_live(pcb));

  app_delete(c);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_close", pcb));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_abort", pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

}  // namespace

static void test_start_client_that_never_connects_is_destructible_without_a_mutex(void) {
  mockrtos::faults().fail_mutex_create = true;
  AsyncClient *c = new AsyncClient();
  TEST_ASSERT_FALSE(c->connected());
  app_delete(c);

  AsyncServer *s = new AsyncServer(kServerPort);
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s->status());
  delete s;
}

static void test_start_connect_is_refused_without_a_task(void) {
  mockrtos::faults().fail_task_create = true;
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c);
  TEST_ASSERT_FALSE(c->connect(kPeer, kPort));
  TEST_ASSERT_FALSE(c->connected());
  TEST_ASSERT_NULL(c->pcb());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());

  app_close(*c);
  app_abort(*c);
  asynctcp_test_pump();
  app_delete(c);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_start_client_does_not_adopt_a_pcb_without_a_task(void) {
  mockrtos::faults().fail_task_create = true;
  assert_adoption_refused();
}

static void test_start_client_adopts_a_pcb_once_the_task_can_be_created(void) {
  mockrtos::faults().fail_task_create = true;
  assert_adoption_refused();
  mockrtos::faults().fail_task_create = false;

  AsyncClient *c = nullptr;
  tcp_pcb *pcb = fire_raw_accept([&](tcp_pcb *p) {
    c = new AsyncClient(p);
    return (err_t)ERR_OK;
  });
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_TRUE(c->connected());
  TEST_ASSERT_EQUAL_PTR(pcb, c->pcb());
  TEST_ASSERT_NOT_NULL(pcb->errf);
  app_delete(c);
  asynctcp_test_pump();
  TEST_ASSERT_FALSE(is_live(pcb));
}

void run_start_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_start_client_that_never_connects_is_destructible_without_a_mutex);
  RUN_TEST(test_start_connect_is_refused_without_a_task);
  RUN_TEST(test_start_client_does_not_adopt_a_pcb_without_a_task);
  RUN_TEST(test_start_client_adopts_a_pcb_once_the_task_can_be_created);
}
