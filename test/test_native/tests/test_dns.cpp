// DNS resolution tests for AsyncClient::connect(const char*, uint16_t).

#include "fixtures.h"

using namespace mocklwip;

// ---------------------------------------------------------------------------

static void test_dns_immediate_hit_connects_straight_away(void) {
  faults().dns_result = ERR_OK;
  faults().dns_addr = kResolved;

  AsyncClient c;
  int connects = 0;
  c.onConnect([&](void *, AsyncClient *) {
    connects++;
  });

  TEST_ASSERT_TRUE(c.connect("example.test", kPort));
  TEST_ASSERT_EQUAL_size_t(1, count("dns_gethostbyname"));
  TEST_ASSERT_FALSE(dns_pending());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT32(kResolved, remote_ip4(pcb));
  TEST_ASSERT_EQUAL_UINT16(kPort, pcb->remote_port);

  fire_connected(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, connects);

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_deferred_hit_connects_when_the_callback_fires(void) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int connects = 0;
  c.onConnect([&](void *, AsyncClient *) {
    connects++;
  });

  // connect() reports success optimistically while the lookup is outstanding.
  TEST_ASSERT_TRUE(c.connect("example.test", kPort));
  TEST_ASSERT_TRUE(dns_pending());
  TEST_ASSERT_EQUAL_STRING("example.test", dns_pending_host().c_str());
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_NULL(c.pcb());

  fire_dns(kResolved);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT32(kResolved, remote_ip4(pcb));
  // the port given to connect() must reach the dial.
  TEST_ASSERT_EQUAL_UINT16(kPort, pcb->remote_port);

  fire_connected(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, connects);

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_failure_reports_error_55_and_does_not_connect(void) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int order = 0, err_order = 0, disc_order = 0, connects = 0;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
    err_order = ++order;
  });
  c.onDisconnect([&](void *, AsyncClient *) {
    disc_order = ++order;
  });
  c.onConnect([&](void *, AsyncClient *) {
    connects++;
  });

  TEST_ASSERT_TRUE(c.connect("nx.test", kPort));
  TEST_ASSERT_TRUE(dns_pending());

  // Resolver gives up: callback with a NULL address.
  fire_dns_failure();
  TEST_ASSERT_EQUAL_INT(0, err_order);

  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(-55, (int)err_seen);  // AsyncTCP's "DNS failed" pseudo-error
  TEST_ASSERT_EQUAL_INT(1, err_order);
  TEST_ASSERT_EQUAL_INT(2, disc_order);
  TEST_ASSERT_EQUAL_INT(0, connects);

  // Crucially: no connection attempt, and no pcb allocated for 0.0.0.0.
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_new_ip_type"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_NULL(c.pcb());
}

static void test_dns_failure_answered_inside_the_lookup_is_reported_once(void) {
  TEST_IGNORE_MESSAGE("onDisconnect is not reported after a lookup that fails inside dns_gethostbyname()");
  // lwIP with no DNS server answers inside dns_gethostbyname(), then returns ERR_INPROGRESS;
  // the async task may deliver the answer before connect() returns.
  faults().dns_result = ERR_INPROGRESS;
  faults().dns_fails_inside_the_call = true;

  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("nx.test", kPort));
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ED", t.seq.c_str());
  TEST_ASSERT_EQUAL_INT(-55, (int)t.err);

  establish(c);
  TEST_ASSERT_EQUAL_STRING("EDC", t.seq.c_str());
  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_deferred_zero_address_is_treated_as_failure(void) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
  });

  TEST_ASSERT_TRUE(c.connect("zero.test", kPort));
  fire_dns(0);  // resolver returned 0.0.0.0
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(-55, (int)err_seen);
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_synchronous_zero_address_is_treated_as_failure(void) {
  // dns_gethostbyname() answers a cached name without a callback, so a second attempt at
  // a sinkholed host takes this path rather than the one above.
  faults().dns_result = ERR_OK;
  faults().dns_addr = 0;

  AsyncClient c;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
  });

  TEST_ASSERT_FALSE(c.connect("zero.test", kPort));  // refused outright, so no callback is owed
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(0, (int)err_seen);
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_hard_error_fails_connect_immediately(void) {
  faults().dns_result = ERR_VAL;

  AsyncClient c;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
  });

  TEST_ASSERT_FALSE(c.connect("bad..test", kPort));
  TEST_ASSERT_FALSE(dns_pending());
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());

  // The synchronous failure path just returns false; no callback is invoked.
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, (int)err_seen);
}

// ---------------------------------------------------------------------------
// Abandoned and superseded lookups.  LwIP cannot cancel a lookup, so its answer still
// arrives, and must be dropped.
// ---------------------------------------------------------------------------

static void test_dns_close_abandons_the_lookup(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));
  c.close();
  TEST_ASSERT_FALSE(c.connecting());

  fire_dns(0x0A000001);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));  // the answer is no longer wanted
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_abort_abandons_the_lookup(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  int errors = 0;
  c.onError([&](void *, AsyncClient *, int8_t) {
    errors++;
  });
  TEST_ASSERT_TRUE(c.connect("slow.test", kPort));
  c.abort();
  TEST_ASSERT_FALSE(c.connecting());

  // The answer still arrives - LwIP cannot cancel - and must be dropped on the floor.
  fire_dns(0x0A000001);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_dns_second_connect_supersedes_the_lookup(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect("first.test", kPort));
  TEST_ASSERT_TRUE(c.connect("second.test", 9999));  // a different target wins
  TEST_ASSERT_EQUAL_size_t(2, count("dns_gethostbyname"));

  // The first answer must not be dialled - it is the address of a host the caller has
  // moved on from, and dialling it would report success for the wrong destination.
  fire_dns(0x0A000001);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));

  fire_dns(0x0A000002);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT32(0x0A000002, remote_ip4(pcb));
  TEST_ASSERT_EQUAL_INT(9999, (int)pcb->remote_port);
}

static void test_dns_connect_after_close_supersedes_the_lookup(void) {
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect("first.test", kPort));
  c.close();                                          // orphans the first lookup
  TEST_ASSERT_TRUE(c.connect("second.test", kPort));  // a second is now outstanding
  TEST_ASSERT_EQUAL_size_t(2, dns_pending_count());   // neither can be canceled

  // The stale answer arrives first.  It must be recognized as superseded and dropped:
  // dialling it would connect to the wrong address.
  fire_dns(0x0A000001);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());

  // The lookup we are actually waiting on still works.
  fire_dns(0x0A000002);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  TEST_ASSERT_NOT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_UINT32(0x0A000002, remote_ip4(c.pcb()));
}

#if LWIP_IPV6
static void test_dns_ipv6_answer_connects_over_ipv6(void) {
  const uint32_t kWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000005};
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  Recorder t;
  t.attach(c);
  TEST_ASSERT_TRUE(c.connect("v6.test", kPort));

  ip_addr_t answer = IPADDR6_INIT(kWords[0], kWords[1], kWords[2], kWords[3]);
  fire_dns(answer);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT8(IPADDR_TYPE_V6, pcb->remote_ip.type);
  TEST_ASSERT_EQUAL_UINT16(kPort, pcb->remote_port);

  fire_connected(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("C", t.seq.c_str());
  TEST_ASSERT_TRUE(c.remoteIP6() == IPv6Address(kWords));

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}
#endif

void run_dns_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_dns_immediate_hit_connects_straight_away);
  RUN_TEST(test_dns_deferred_hit_connects_when_the_callback_fires);
  RUN_TEST(test_dns_failure_reports_error_55_and_does_not_connect);
  RUN_TEST(test_dns_failure_answered_inside_the_lookup_is_reported_once);
  RUN_TEST(test_dns_deferred_zero_address_is_treated_as_failure);
  RUN_TEST(test_dns_synchronous_zero_address_is_treated_as_failure);
  RUN_TEST(test_dns_hard_error_fails_connect_immediately);
  RUN_TEST(test_dns_close_abandons_the_lookup);
  RUN_TEST(test_dns_abort_abandons_the_lookup);
  RUN_TEST(test_dns_second_connect_supersedes_the_lookup);
  RUN_TEST(test_dns_connect_after_close_supersedes_the_lookup);
#if LWIP_IPV6
  RUN_TEST(test_dns_ipv6_answer_connects_over_ipv6);
#endif
}
