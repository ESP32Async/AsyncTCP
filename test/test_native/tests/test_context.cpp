// Where callbacks run: on the async task, never inside a call the application makes into
// the library -- except that close() and ~AsyncClient() may run the client's own
// onDisconnect, and abort() its own onError(ERR_ABRT) then onDisconnect.
//
// Every call below is made inside an AppCall, and the Recorder notes any callback that
// runs inside one that does not allow it.  Events are queued before the calls, so a call
// that delivered them would be caught doing it.

#include "fixtures.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace mocklwip;

namespace {

// Every call that neither ends the connection nor starts one, each as its own AppCall.
void poke(AsyncClient &c, Recorder &t, const char *events) {
  app("add", [&] {
    return c.add("a", 1);
  });
  app("send", [&] {
    return c.send();
  });
  app("write", [&] {
    return c.write("w", 1);
  });
  app("write", [&] {
    return c.write("s");
  });
  app("ack", [&] {
    return c.ack(1);
  });
  app("ackLater", [&] {
    c.ackLater();
  });
  app("setRxTimeout", [&] {
    c.setRxTimeout(c.getRxTimeout());
  });
  app("setAckTimeout", [&] {
    c.setAckTimeout(c.getAckTimeout());
  });
  app("setNoDelay", [&] {
    c.setNoDelay(c.getNoDelay());
  });
  if (c.pcb()) {
    app("setKeepAlive", [&] {
      c.setKeepAlive(0, 0);
    });
  }
  app("handler setters", [&] {
    t.attach(c, events);
  });
  app("getters", [&] {
    return c.state() + c.connecting() + c.connected() + c.disconnecting() + c.disconnected() + c.freeable() + c.free() + c.canSend() + c.space() + c.getMss()
           + c.getRemoteAddress() + c.getRemotePort() + c.getLocalAddress() + c.getLocalPort() + (uint32_t)c.remoteIP() + (uint32_t)c.localIP()
           + c.getRemoteAddress4().addr + c.getLocalAddress4().addr + strlen(c.stateToString());
  });
#if LWIP_IPV6
  app("getters6", [&] {
    return c.getRemoteAddress6().addr[0] + c.getLocalAddress6().addr[0] + ((const uint32_t *)c.remoteIP6())[0] + ((const uint32_t *)c.localIP6())[0];
  });
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// Calls made from the application's own task
// ---------------------------------------------------------------------------

static void test_context_calls_do_not_deliver_a_queued_connect(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDRAPT");
  TEST_ASSERT_TRUE(app("connect", [&] {
    return c.connect(kPeer, kPort);
  }));
  fire_connected(dialled_pcb());

  poke(c, t, "CEDRAPT");
  app("connect", [&] {
    return c.connect(kPeer, kPort);
  });
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("C", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  app_close(c);
}

static void test_context_calls_do_not_deliver_queued_traffic(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDRAPT");
  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(0);  // polls report onPoll only

  app("write", [&] {
    return c.write("x", 1);
  });
  fire_recv(pcb, "in", 2);
  fire_poll(pcb);
  fire_sent(pcb, 1);
  fire_recv(pcb, "more", 4);

  poke(c, t, "CEDRAPT");
  asynctcp_test_pump();

  // All of it, on the task; the kinds may interleave in any order.
  TEST_ASSERT_EQUAL_CHAR('C', t.seq[0]);
  std::string kinds = t.seq.substr(1);
  std::sort(kinds.begin(), kinds.end());
  TEST_ASSERT_EQUAL_STRING("APRR", kinds.c_str());
  TEST_ASSERT_EQUAL_STRING("inmore", t.data.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  app_close(c);
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_context_calls_do_not_deliver_queued_packets(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDK");
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "in", 2);
  fire_recv(pcb, "more", 4);

  poke(c, t, "CEDK");
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CKK", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  app_close(c);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_context_calls_do_not_deliver_a_queued_timeout(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDT");
  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  app("write", [&] {
    return c.write("x", 1);
  });
  mockclock::advance(150);
  fire_poll(pcb);

  poke(c, t, "CEDT");
  mockclock::advance(150);  // poke() sent too
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CT", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  app_close(c);
}

static void test_context_calls_do_not_deliver_a_queued_fin(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);
  fire_recv(pcb, "last", 4);
  fire_fin(pcb);

  poke(c, t, "CEDR");
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
  TEST_ASSERT_EQUAL_INT(0, t.count('E'));
}

static void test_context_calls_do_not_deliver_a_queued_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");
  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);

  poke(c, t, "CEDR");
  app("connect", [&] {
    return c.connect(kPeer, kPort);
  });
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  TEST_ASSERT_EQUAL_INT(1, t.count('E'));
  app_close(c);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_context_close_with_a_queued_error_runs_no_onError(void) {
  // close() may settle the connection with onDisconnect; the reset's onError is not its
  // own to run.
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);

  app_close(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_context_abort_with_a_queued_error_runs_no_other_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);

  app_abort(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_context_close_runs_nothing_but_onDisconnect(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDRAPT");
  tcp_pcb *pcb = establish(c);
  app("write", [&] {
    return c.write("x", 1);
  });
  fire_recv(pcb, "in", 2);
  fire_poll(pcb);
  fire_sent(pcb, 1);

  app_close(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  TEST_ASSERT_EQUAL_INT(1, t.count('D'));
}

static void test_context_abort_runs_nothing_but_its_own_error(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDRAPT");
  tcp_pcb *pcb = establish(c);
  app("write", [&] {
    return c.write("x", 1);
  });
  fire_recv(pcb, "in", 2);
  fire_poll(pcb);
  fire_sent(pcb, 1);

  app_abort(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  TEST_ASSERT_EQUAL_INT(1, t.count('E'));
  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, t.err);
}

static void test_context_destructor_runs_nothing_but_onDisconnect(void) {
  AsyncClient *c = new AsyncClient();
  Recorder t;
  t.attach(*c, "CEDRAPT");
  tcp_pcb *pcb = establish(*c);
  app("write", [&] {
    return c->write("x", 1);
  });
  fire_recv(pcb, "in", 2);
  fire_poll(pcb);
  fire_sent(pcb, 1);

  app_delete(c);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_context_connecting_runs_no_callbacks(void) {
  // Every way to start a connection, with each outcome the call itself can see.
  AsyncClient c;
  Recorder t;
  t.attach(c);

  auto settle = [&] {
    app_close(c);
    fire_dns(kResolved);  // any lookup still outstanding answers, and is dropped
    asynctcp_test_pump();
  };

  app("connect", [&] {
    return c.connect(kPeer, kPort);
  });
  settle();

  ip_addr_t addr = IPADDR4_INIT((uint32_t)kPeer);
  app("connect", [&] {
    return c.connect(addr, kPort);
  });
  settle();

#if LWIP_IPV6
  const uint32_t kWords[4] = {0x20010db8, 0, 0, 1};
  app("connect", [&] {
    return c.connect(IPv6Address(kWords), kPort);
  });
  settle();
#endif

  faults().dns_result = ERR_OK;
  faults().dns_addr = kResolved;
  app("connect", [&] {
    return c.connect("cached.test", kPort);
  });
  settle();

  faults().dns_result = ERR_INPROGRESS;
  app("connect", [&] {
    return c.connect("slow.test", kPort);
  });
  app("connect", [&] {
    return c.connect("slower.test", kPort);  // supersedes the first
  });
  settle();

  faults().dns_result = ERR_VAL;
  app("connect", [&] {
    return c.connect("bad..test", kPort);
  });
  settle();

  faults().connect_result = ERR_RTE;
  app("connect", [&] {
    return c.connect(kPeer, kPort);
  });
  settle();

  faults().fail_tcp_new = 1;
  faults().connect_result = ERR_OK;
  app("connect", [&] {
    return c.connect(kPeer, kPort);
  });
  settle();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

// ---------------------------------------------------------------------------
// Calls made from inside callbacks
// ---------------------------------------------------------------------------

static void test_context_calls_from_inside_callbacks_run_no_callbacks(void) {
  // Each handler answers the way an application would.  Nothing it calls may run another
  // callback -- not even the one it is inside, as write() from onAck would.
  AsyncClient c;
  Recorder t;
  t.attach(c, "ED");
  int acks = 0;
  c.onConnect([&](void *, AsyncClient *cl) {
    t.note('C', cl);
    app("write", [&] {
      return cl->write("hello", 5);
    });
  });
  c.onData([&](void *, AsyncClient *cl, void *, size_t n) {
    t.note('R', cl);
    app("ackLater", [&] {
      cl->ackLater();
    });
    app("ack", [&] {
      return cl->ack(n);
    });
    app("write", [&] {
      return cl->write("reply", 5);
    });
  });
  c.onAck([&](void *, AsyncClient *cl, size_t, uint32_t) {
    t.note('A', cl);
    if (++acks == 1) {
      app("write", [&] {
        return cl->write("more", 4);
      });
      app("send", [&] {
        return cl->send();
      });
    }
  });
  c.onPoll([&](void *, AsyncClient *cl) {
    t.note('P', cl);
    app("write", [&] {
      return cl->write("tick", 4);
    });
  });
  c.onTimeout([&](void *, AsyncClient *cl, uint32_t) {
    t.note('T', cl);
    app_close(*cl);
  });

  TEST_ASSERT_TRUE(app("connect", [&] {
    return c.connect(kPeer, kPort);
  }));
  tcp_pcb *pcb = dialled_pcb();
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_sent(pcb, 5);
  asynctcp_test_pump();
  fire_sent(pcb, 4);
  asynctcp_test_pump();
  mockclock::advance(10);
  fire_recv(pcb, "request", 7);
  asynctcp_test_pump();
  app("setAckTimeout", [&] {
    c.setAckTimeout(100);
  });
  fire_poll(pcb);
  asynctcp_test_pump();

  mockclock::advance(150);
  fire_poll(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("CAARPTD", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

static void test_context_reconnecting_from_inside_onError_runs_no_callbacks(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CD");
  int errors = 0;
  c.onError([&](void *, AsyncClient *cl, int8_t e) {
    t.note('E', cl, e);
    if (++errors == 1) {
      app("connect", [&] {
        return cl->connect(kPeer, kPort);
      });
    }
  });
  tcp_pcb *pcb = establish(c);

  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  app_close(c);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

// ---------------------------------------------------------------------------
// AsyncServer
// ---------------------------------------------------------------------------

static void test_context_server_calls_do_not_deliver_a_queued_accept(void) {
  AsyncServer s(kServerPort);
  Recorder t;
  std::vector<AsyncClient *> clients;
  auto on_client = [&](void *, AsyncClient *c) {
    t.note('S', nullptr);
    clients.push_back(c);
  };
  app("onClient", [&] {
    s.onClient(on_client, nullptr);
  });
  app("begin", [&] {
    s.begin();
  });

  fire_accept(listen_pcb());
  fire_accept(listen_pcb());
  app("begin", [&] {
    s.begin();  // already listening
  });
  app("setNoDelay", [&] {
    s.setNoDelay(!s.getNoDelay());
  });
  app("status", [&] {
    return s.status();
  });
  app("onClient", [&] {
    s.onClient(on_client, nullptr);
  });
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("SS", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
  for (AsyncClient *c : clients) {
    app_delete(c);
  }
  app("end", [&] {
    s.end();
  });
}

static void test_context_server_teardown_runs_no_onClient(void) {
  // What becomes of the accepts left queued is test_server_accept.cpp's business.
  Recorder t;
  AsyncServer *s = new AsyncServer(kServerPort);
  s->onClient(
    [&](void *, AsyncClient *) {
      t.note('S', nullptr);
    },
    nullptr
  );
  s->begin();

  fire_accept(listen_pcb());
  app("end", [&] {
    s->end();
  });
  app("begin", [&] {
    s->begin();
  });
  fire_accept(listen_pcb());
  app("~AsyncServer", [&] {
    delete s;
  });

  TEST_ASSERT_EQUAL_STRING("", t.violations.c_str());
}

void run_context_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_context_calls_do_not_deliver_a_queued_connect);
  RUN_TEST(test_context_calls_do_not_deliver_queued_traffic);
  RUN_TEST(test_context_calls_do_not_deliver_queued_packets);
  RUN_TEST(test_context_calls_do_not_deliver_a_queued_timeout);
  RUN_TEST(test_context_calls_do_not_deliver_a_queued_fin);
  RUN_TEST(test_context_calls_do_not_deliver_a_queued_error);
  RUN_TEST(test_context_close_with_a_queued_error_runs_no_onError);
  RUN_TEST(test_context_abort_with_a_queued_error_runs_no_other_error);
  RUN_TEST(test_context_close_runs_nothing_but_onDisconnect);
  RUN_TEST(test_context_abort_runs_nothing_but_its_own_error);
  RUN_TEST(test_context_destructor_runs_nothing_but_onDisconnect);
  RUN_TEST(test_context_connecting_runs_no_callbacks);
  RUN_TEST(test_context_calls_from_inside_callbacks_run_no_callbacks);
  RUN_TEST(test_context_reconnecting_from_inside_onError_runs_no_callbacks);
  RUN_TEST(test_context_server_calls_do_not_deliver_a_queued_accept);
  RUN_TEST(test_context_server_teardown_runs_no_onClient);
}
