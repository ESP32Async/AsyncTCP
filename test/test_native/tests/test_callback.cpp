// What each handler is handed: the argument it was registered with.

#include "fixtures.h"

#include <map>

using namespace mocklwip;

namespace {

// The nine handlers, by Recorder letter; K is onPacket and S is onClient.
const char kHandlers[] = "CDAERKTPS";

// One distinct argument per handler, and what each handler was given.
struct Args {
  int marker[sizeof(kHandlers) - 1] = {};
  std::map<char, void *> seen;

  void *arg(char e) {
    return &marker[strchr(kHandlers, e) - kHandlers];
  }
  void record(char e, void *a) {
    seen[e] = a;
  }
  void check(char e) {
    char msg[] = "handler ? was not given its argument";
    msg[8] = e;
    TEST_ASSERT_TRUE_MESSAGE(seen.count(e) != 0, msg);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(arg(e), seen[e], msg);
  }
};

}  // namespace

static void test_callback_each_client_handler_is_given_its_own_argument(void) {
  AsyncClient c;
  Args a;
  c.onConnect(
    [&](void *arg, AsyncClient *) {
      a.record('C', arg);
    },
    a.arg('C')
  );
  c.onDisconnect(
    [&](void *arg, AsyncClient *) {
      a.record('D', arg);
    },
    a.arg('D')
  );
  c.onAck(
    [&](void *arg, AsyncClient *, size_t, uint32_t) {
      a.record('A', arg);
    },
    a.arg('A')
  );
  c.onError(
    [&](void *arg, AsyncClient *, int8_t) {
      a.record('E', arg);
    },
    a.arg('E')
  );
  c.onData(
    [&](void *arg, AsyncClient *, void *, size_t) {
      a.record('R', arg);
    },
    a.arg('R')
  );
  c.onTimeout(
    [&](void *arg, AsyncClient *, uint32_t) {
      a.record('T', arg);
    },
    a.arg('T')
  );
  c.onPoll(
    [&](void *arg, AsyncClient *) {
      a.record('P', arg);
    },
    a.arg('P')
  );

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  fire_recv(pcb, "data", 4);  // onData
  asynctcp_test_pump();
  fire_poll(pcb);  // onPoll: nothing outstanding
  asynctcp_test_pump();
  c.write("x", 1);
  fire_sent(pcb, 1);  // onAck
  asynctcp_test_pump();
  mockclock::advance(10);
  c.write("y", 1);
  mockclock::advance(150);
  fire_poll(pcb);  // onTimeout
  asynctcp_test_pump();

  // onPacket takes over from onData once registered.
  c.onPacket(
    [&](void *arg, AsyncClient *cl, pbuf *pb) {
      a.record('K', arg);
      cl->ackPacket(pb);
    },
    a.arg('K')
  );
  fire_recv(pcb, "pkt", 3);
  asynctcp_test_pump();

  fire_error(pcb, ERR_RST);  // onError, onDisconnect
  asynctcp_test_pump();

  for (char e : std::string("CRPATKED")) {
    a.check(e);
  }
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_callback_onDisconnect_after_close_is_given_its_argument(void) {
  AsyncClient c;
  Args a;
  c.onDisconnect(
    [&](void *arg, AsyncClient *) {
      a.record('D', arg);
    },
    a.arg('D')
  );
  establish(c);

  c.close();
  asynctcp_test_pump();
  a.check('D');
}

static void test_callback_onClient_is_given_its_argument(void) {
  AsyncServer s(kServerPort);
  Args a;
  AsyncClient *client = nullptr;
  s.onClient(
    [&](void *arg, AsyncClient *c) {
      a.record('S', arg);
      client = c;
    },
    a.arg('S')
  );
  s.begin();

  TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
  asynctcp_test_pump();
  a.check('S');

  delete client;
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

void run_callback_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_callback_each_client_handler_is_given_its_own_argument);
  RUN_TEST(test_callback_onDisconnect_after_close_is_given_its_argument);
  RUN_TEST(test_callback_onClient_is_given_its_argument);
}
