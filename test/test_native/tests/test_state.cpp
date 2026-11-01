// AsyncClient's connection state machine and its accessors.
//
// Two things are checked here: that the five state predicates agree with each other at
// every point in a connection's life, and that the address/port accessors report what
// was actually dialled -- and report zero, rather than whatever is left in a freed pcb,
// when there is no connection at all.

#include "fixtures.h"

using namespace mocklwip;

namespace {

// connecting/connected/disconnecting/disconnected are four names for "where in its life
// is this connection".  They partition it: exactly one must hold at any moment.
void assert_one_phase(const AsyncClient &c, const char *where) {
  const int n = (int)c.connecting() + (int)c.connected() + (int)c.disconnecting() + (int)c.disconnected();
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, n, where);
}

// freeable() is documented as "disconnected or disconnecting", and free() asks the same
// question under a different name.
void assert_freeable_agrees(AsyncClient &c, const char *where) {
  TEST_ASSERT_EQUAL_INT_MESSAGE((int)(c.disconnected() || c.disconnecting()), (int)c.freeable(), where);
  TEST_ASSERT_EQUAL_INT_MESSAGE((int)c.freeable(), (int)c.free(), where);
}

}  // namespace

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

static void test_state_fresh_client_is_closed_and_disconnected(void) {
  AsyncClient c;
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_UINT8(CLOSED, c.state());
  TEST_ASSERT_EQUAL_STRING("Closed", c.stateToString());
  TEST_ASSERT_FALSE(c.connecting());
  TEST_ASSERT_FALSE(c.connected());
  TEST_ASSERT_FALSE(c.disconnecting());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  TEST_ASSERT_TRUE(c.free());
}

static void test_state_connect_dials_the_peer_on_one_pcb(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));

  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_INT((int)SYN_SENT, (int)pcb->state);
  TEST_ASSERT_EQUAL_UINT16(kPort, pcb->remote_port);
  TEST_ASSERT_EQUAL_UINT32((uint32_t)kPeer, remote_ip4(pcb));

  // Every callback should be wired up.  What the library passes as the argument is its
  // own business, so we can only check that one is set.
  TEST_ASSERT_NOT_NULL(pcb->callback_arg);
  TEST_ASSERT_NOT_NULL(pcb->recv);
  TEST_ASSERT_NOT_NULL(pcb->sent);
  TEST_ASSERT_NOT_NULL(pcb->errf);
  TEST_ASSERT_NOT_NULL(pcb->poll);

  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  TEST_ASSERT_TRUE(asynctcp_test_task_started());
}

static void test_state_connect_reports_syn_sent_until_the_handshake_lands(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));

  TEST_ASSERT_EQUAL_UINT8(SYN_SENT, c.state());
  TEST_ASSERT_EQUAL_STRING("SYN Sent", c.stateToString());
  TEST_ASSERT_TRUE(c.connecting());
  TEST_ASSERT_FALSE(c.connected());
  TEST_ASSERT_FALSE(c.disconnecting());
  TEST_ASSERT_FALSE(c.disconnected());
  // A half-open connection is still lwIP's; nothing to reclaim yet.
  TEST_ASSERT_FALSE(c.freeable());

  c.close();
}

static void test_state_established_once_the_connected_event_is_delivered(void) {
  AsyncClient c;
  int connects = 0;
  AsyncClient *seen = nullptr;
  c.onConnect([&](void *, AsyncClient *cl) {
    connects++;
    seen = cl;
  });

  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);

  // lwIP completes the handshake, but nothing reaches the application until the async
  // task runs.
  TEST_ASSERT_EQUAL_INT((int)ERR_OK, (int)fire_connected(pcb));
  TEST_ASSERT_EQUAL_INT(0, connects);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, connects);
  TEST_ASSERT_EQUAL_PTR(&c, seen);

  TEST_ASSERT_EQUAL_UINT8(ESTABLISHED, c.state());
  TEST_ASSERT_EQUAL_STRING("Established", c.stateToString());
  TEST_ASSERT_FALSE(c.connecting());
  TEST_ASSERT_TRUE(c.connected());
  TEST_ASSERT_FALSE(c.disconnecting());
  TEST_ASSERT_FALSE(c.disconnected());
  TEST_ASSERT_FALSE(c.freeable());

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_close_returns_the_client_to_closed(void) {
  AsyncClient c;
  establish(c);

  c.close();
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_UINT8(CLOSED, c.state());
  TEST_ASSERT_EQUAL_STRING("Closed", c.stateToString());
  TEST_ASSERT_FALSE(c.connecting());
  TEST_ASSERT_FALSE(c.connected());
  TEST_ASSERT_FALSE(c.disconnecting());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
}

static void test_state_predicates_partition_the_whole_connection_life(void) {
  AsyncClient c;
  assert_one_phase(c, "fresh");

  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  assert_one_phase(c, "connecting");

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  fire_connected(pcb);
  assert_one_phase(c, "established, undelivered");
  asynctcp_test_pump();
  assert_one_phase(c, "established");

  c.close();
  assert_one_phase(c, "closed");
}

static void test_state_connected_and_disconnected_are_never_both_true(void) {
  AsyncClient c;
  TEST_ASSERT_FALSE(c.connected() && c.disconnected());

  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  TEST_ASSERT_FALSE(c.connected() && c.disconnected());

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  fire_connected(pcb);
  asynctcp_test_pump();
  TEST_ASSERT_FALSE(c.connected() && c.disconnected());

  // The peer hangs up: the transition runs on the lwIP thread, so check both sides of
  // the queue, not just the settled result.
  fire_fin(pcb);
  TEST_ASSERT_FALSE(c.connected() && c.disconnected());
  asynctcp_test_pump();
  TEST_ASSERT_FALSE(c.connected() && c.disconnected());
  TEST_ASSERT_TRUE(c.disconnected());
}

static void test_state_freeable_means_disconnected_or_disconnecting(void) {
  AsyncClient c;
  assert_freeable_agrees(c, "fresh");

  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  assert_freeable_agrees(c, "connecting");

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  fire_connected(pcb);
  asynctcp_test_pump();
  assert_freeable_agrees(c, "established");

  c.close();
  assert_freeable_agrees(c, "closed");
}

static void test_state_disconnecting_while_a_fin_is_outstanding(void) {
  // lwIP moves the pcb to FIN_WAIT_1 when our FIN goes out; the library never leaves a
  // pcb attached in that state itself, so drive it directly.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  pcb->state = FIN_WAIT_1;
  TEST_ASSERT_EQUAL_STRING("FIN Wait 1", c.stateToString());
  TEST_ASSERT_FALSE(c.connecting());
  TEST_ASSERT_FALSE(c.connected());
  TEST_ASSERT_TRUE(c.disconnecting());
  TEST_ASSERT_FALSE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  assert_one_phase(c, "FIN_WAIT_1");

  pcb->state = ESTABLISHED;
  c.close();
}

static void test_state_time_wait_is_disconnected_not_disconnecting(void) {
  // TIME_WAIT is past the close, not part of it: disconnecting() stops at TIME_WAIT and
  // disconnected() picks it up.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  pcb->state = TIME_WAIT;
  TEST_ASSERT_EQUAL_STRING("Time Wait", c.stateToString());
  TEST_ASSERT_FALSE(c.disconnecting());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  assert_one_phase(c, "TIME_WAIT");

  pcb->state = ESTABLISHED;
  c.close();
}

static void test_state_stateToString_names_every_lwip_state(void) {
  static const char *const kNames[] = {"Closed",     "Listen",     "SYN Sent", "SYN Received", "Established", "FIN Wait 1",
                                       "FIN Wait 2", "Close Wait", "Closing",  "Last ACK",     "Time Wait"};

  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  for (uint8_t s = 0; s <= (uint8_t)TIME_WAIT; ++s) {
    pcb->state = (tcp_state)s;
    TEST_ASSERT_EQUAL_UINT8(s, c.state());
    TEST_ASSERT_EQUAL_STRING(kNames[s], c.stateToString());
  }

  pcb->state = (tcp_state)(TIME_WAIT + 1);  // nothing lwIP defines
  TEST_ASSERT_EQUAL_STRING("UNKNOWN", c.stateToString());

  pcb->state = ESTABLISHED;
  c.close();
}

static void test_state_connect_is_refused_while_already_connecting(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *first = dialled_pcb();

  TEST_ASSERT_FALSE(c.connect(kPeer, kPort));
  // Refused means untouched, not torn down and retried.
  TEST_ASSERT_EQUAL_PTR(first, c.pcb());
  TEST_ASSERT_EQUAL_UINT8(SYN_SENT, c.state());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_connect"));
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  c.close();
}

static void test_state_connect_is_refused_while_connected(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_FALSE(c.connect(kPeer, kPort));
  TEST_ASSERT_EQUAL_PTR(pcb, c.pcb());
  TEST_ASSERT_TRUE(c.connected());
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());

  c.close();
}

static void test_state_close_twice_reports_one_disconnect(void) {
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  establish(c);

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_TRUE(c.disconnected());

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_abort_twice_reports_one_error(void) {
  AsyncClient c;
  int errors = 0;
  c.onError([&](void *, AsyncClient *, int8_t) {
    errors++;
  });
  establish(c);

  TEST_ASSERT_EQUAL_INT8(ERR_ABRT, c.abort());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_TRUE(c.disconnected());

  // Nothing left to abort and nothing left to report.
  TEST_ASSERT_EQUAL_INT8(ERR_CONN, c.abort());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_TRUE(c.freeable());
}

static void test_state_stop_closes_like_close(void) {
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  establish(c);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  c.stop();  // deprecated alias for close()
#pragma GCC diagnostic pop
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_close_bool_closes_like_close(void) {
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  establish(c);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  c.close(true);  // deprecated; the argument is ignored
#pragma GCC diagnostic pop
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_connect_by_ip_addr_t_dials_that_address(void) {
  AsyncClient c;
  ip_addr_t addr = IPADDR4_INIT((uint32_t)kPeer);
  TEST_ASSERT_TRUE(c.connect(addr, kPort));

  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT32((uint32_t)kPeer, remote_ip4(pcb));
  TEST_ASSERT_EQUAL_UINT16(kPort, pcb->remote_port);
  fire_connected(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(c.connected());
  TEST_ASSERT_TRUE(c.remoteIP() == kPeer);
  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_a_client_equals_itself(void) {
  AsyncClient c;
  establish(c);
  TEST_ASSERT_TRUE(c == c);
  TEST_ASSERT_FALSE(c != c);
  c.close();
}

static void test_state_clients_on_different_connections_are_unequal(void) {
  AsyncClient a;
  AsyncClient b;
  establish(a);
  establish(b);
  TEST_ASSERT_FALSE(a == b);
  TEST_ASSERT_TRUE(a != b);
  a.close();
  b.close();
}

static void test_state_peer_fin_leaves_the_client_closed_and_freeable(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_UINT8(CLOSED, c.state());
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  TEST_ASSERT_TRUE(c.free());
  assert_one_phase(c, "after FIN");
}

static void test_state_reset_leaves_the_client_closed_and_freeable(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  // lwIP frees the pcb before the error callback, so the library must have forgotten it
  // by the time any of this can be asked.
  fire_error(pcb, ERR_RST);
  TEST_ASSERT_NULL(c.pcb());
  assert_one_phase(c, "reset, undelivered");
  TEST_ASSERT_TRUE(c.disconnected());

  asynctcp_test_pump();
  TEST_ASSERT_TRUE(c.disconnected());
  TEST_ASSERT_TRUE(c.freeable());
  assert_one_phase(c, "reset, delivered");
}

// A client with a lookup in flight is not idle: it will dial when the answer arrives,
// so it must not report itself freeable().
static void test_state_freeable_is_false_while_a_hostname_lookup_is_in_flight(void) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect("example.test", kPort));
  TEST_ASSERT_TRUE(dns_pending());

  TEST_ASSERT_FALSE(c.freeable());
  TEST_ASSERT_FALSE(c.free());

  c.close();
  fire_dns_failure();  // LwIP always answers, eventually
  asynctcp_test_pump();
}

static void test_state_accepted_client_is_established_when_delivered(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(lp);
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  AsyncClient *client = accepted[0];

  TEST_ASSERT_EQUAL_UINT8(ESTABLISHED, client->state());
  TEST_ASSERT_EQUAL_STRING("Established", client->stateToString());
  TEST_ASSERT_FALSE(client->connecting());
  TEST_ASSERT_TRUE(client->connected());
  TEST_ASSERT_FALSE(client->disconnecting());
  TEST_ASSERT_FALSE(client->disconnected());
  TEST_ASSERT_FALSE(client->freeable());
  assert_one_phase(*client, "accepted");

  accepted.clear();
  s.end();
}

static void test_state_accepted_client_walks_to_closed_on_close(void) {
  AsyncServer s(kServerPort);
  int disconnects = 0;
  Accepted accepted(s, [&](AsyncClient *c) {
    c->onDisconnect([&](void *, AsyncClient *) {
      disconnects++;
    });
  });
  s.begin();
  TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  AsyncClient *client = accepted[0];

  assert_freeable_agrees(*client, "accepted");
  client->close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_NULL(client->pcb());
  TEST_ASSERT_EQUAL_UINT8(CLOSED, client->state());
  TEST_ASSERT_TRUE(client->disconnected());
  assert_one_phase(*client, "accepted, closed");
  assert_freeable_agrees(*client, "accepted, closed");

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_state_accepted_client_reset_leaves_it_closed(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();
  tcp_pcb *conn = fire_accept(listen_pcb());
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  AsyncClient *client = accepted[0];

  fire_error(conn, ERR_RST);
  TEST_ASSERT_NULL(client->pcb());
  TEST_ASSERT_TRUE(client->disconnected());
  asynctcp_test_pump();
  assert_one_phase(*client, "accepted, reset");
  assert_freeable_agrees(*client, "accepted, reset");

  accepted.clear();
  s.end();
}

// ---------------------------------------------------------------------------
// The accessors
// ---------------------------------------------------------------------------

static void test_state_accessors_report_zero_before_connecting(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getRemotePort());
  TEST_ASSERT_EQUAL_UINT16(0, c.remotePort());
  TEST_ASSERT_EQUAL_UINT32(0, c.getLocalAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getLocalPort());
  TEST_ASSERT_EQUAL_UINT16(0, c.localPort());
  TEST_ASSERT_TRUE(c.remoteIP() == IPAddress());
  TEST_ASSERT_TRUE(c.localIP() == IPAddress());
  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress4().addr);
  TEST_ASSERT_EQUAL_UINT32(0, c.getLocalAddress4().addr);
}

static void test_state_remote_accessors_match_the_dialled_peer(void) {
  AsyncClient c;
  establish(c);

  TEST_ASSERT_EQUAL_UINT32((uint32_t)kPeer, c.getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(kPort, c.getRemotePort());
  TEST_ASSERT_EQUAL_UINT16(kPort, c.remotePort());
  TEST_ASSERT_TRUE(c.remoteIP() == kPeer);
  TEST_ASSERT_EQUAL_UINT32((uint32_t)kPeer, c.getRemoteAddress4().addr);

  c.close();
}

static void test_state_connect_assigns_a_local_port(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  fire_connected(pcb);
  asynctcp_test_pump();

  // lwIP picks an ephemeral port for an unbound pcb as part of connecting.
  TEST_ASSERT_NOT_EQUAL(0, c.getLocalPort());
  TEST_ASSERT_EQUAL_UINT16(pcb->local_port, c.getLocalPort());
  TEST_ASSERT_EQUAL_UINT16(c.getLocalPort(), c.localPort());

  c.close();
}

static void test_state_ip_wrappers_agree_with_the_raw_accessors(void) {
  AsyncClient c;
  establish(c);

  TEST_ASSERT_EQUAL_UINT32(c.getRemoteAddress(), (uint32_t)c.remoteIP());
  TEST_ASSERT_EQUAL_UINT32(c.getLocalAddress(), (uint32_t)c.localIP());
  TEST_ASSERT_EQUAL_UINT32(c.getRemoteAddress(), c.getRemoteAddress4().addr);

  c.close();
}

static void test_state_accessors_report_zero_after_close(void) {
  AsyncClient c;
  establish(c);
  c.close();

  // The pcb is gone; none of these may read it.
  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getRemotePort());
  TEST_ASSERT_EQUAL_UINT32(0, c.getLocalAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getLocalPort());
  TEST_ASSERT_TRUE(c.remoteIP() == IPAddress());
  TEST_ASSERT_TRUE(c.localIP() == IPAddress());
  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress4().addr);
  TEST_ASSERT_EQUAL_UINT32(0, c.getLocalAddress4().addr);
  TEST_ASSERT_EQUAL_UINT16(0, c.getMss());
}

static void test_state_accessors_report_zero_after_a_reset(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  // The pcb was freed by lwIP before the callback ran, so anything still reading it is a
  // use-after-free -- which the sanitized build catches outright.
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getRemotePort());
  TEST_ASSERT_EQUAL_UINT32(0, c.getLocalAddress());
  TEST_ASSERT_EQUAL_UINT16(0, c.getLocalPort());
  TEST_ASSERT_EQUAL_UINT16(0, c.getMss());
  TEST_ASSERT_FALSE(c.getNoDelay());
}

static void test_state_accepted_client_reports_the_peer_that_connected(void) {
  const IPAddress kBind(10, 0, 0, 7);
  AsyncServer s(kBind, kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  AsyncClient *client = accepted[0];

  // The accepted side reports the peer as remote and the listening socket as local.
  TEST_ASSERT_EQUAL_UINT32(remote_ip4(conn), client->getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(conn->remote_port, client->getRemotePort());
  TEST_ASSERT_EQUAL_UINT32((uint32_t)kBind, client->getLocalAddress());
  TEST_ASSERT_EQUAL_UINT16(kServerPort, client->getLocalPort());
  TEST_ASSERT_TRUE(client->localIP() == kBind);
  TEST_ASSERT_TRUE(client->remoteIP() == IPAddress(remote_ip4(conn)));

  client->close();
  TEST_ASSERT_EQUAL_UINT32(0, client->getRemoteAddress());
  TEST_ASSERT_EQUAL_UINT16(0, client->getLocalPort());

  accepted.clear();
  s.end();
}

static void test_state_getMss_reports_the_connection_mss(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_EQUAL_UINT16(TCP_MSS, c.getMss());
  pcb->mss = 536;  // the peer advertised something smaller
  TEST_ASSERT_EQUAL_UINT16(536, c.getMss());

  c.close();
}

static void test_state_getMss_is_zero_without_a_connection(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_UINT16(0, c.getMss());
}

static void test_state_setNoDelay_round_trips_while_connected(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_FALSE(c.getNoDelay());
  c.setNoDelay(true);
  TEST_ASSERT_TRUE(c.getNoDelay());
  TEST_ASSERT_TRUE(tcp_nagle_disabled(pcb));
  c.setNoDelay(false);
  TEST_ASSERT_FALSE(c.getNoDelay());
  TEST_ASSERT_FALSE(tcp_nagle_disabled(pcb));

  c.close();
}

static void test_state_getNoDelay_is_false_without_a_connection(void) {
  AsyncClient c;
  c.setNoDelay(true);  // no pcb to set it on
  TEST_ASSERT_FALSE(c.getNoDelay());
}

// ---------------------------------------------------------------------------
// IPv6.  IPv6Address.h is on the mock include path, so the pre-IDF5 IPv6Address
// flavor of these accessors is what the native build compiles when LWIP_IPV6 is 1.
// ---------------------------------------------------------------------------
#if LWIP_IPV6

static void test_state_ipv6_accessors_are_zero_without_a_connection(void) {
  AsyncClient c;
  ip6_addr_t remote = c.getRemoteAddress6();
  ip6_addr_t local = c.getLocalAddress6();
  for (int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT32(0, remote.addr[i]);
    TEST_ASSERT_EQUAL_UINT32(0, local.addr[i]);
  }
  TEST_ASSERT_TRUE(c.remoteIP6() == IPv6Address());
  TEST_ASSERT_TRUE(c.localIP6() == IPv6Address());
}

static void test_state_ipv6_connect_reports_the_v6_peer(void) {
  const uint32_t kWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000001};
  const IPv6Address kPeer6(kWords);

  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer6, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT8(IPADDR_TYPE_V6, pcb->remote_ip.type);
  fire_connected(pcb);
  asynctcp_test_pump();

  ip6_addr_t remote = c.getRemoteAddress6();
  for (int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT32(kWords[i], remote.addr[i]);
  }
  TEST_ASSERT_TRUE(c.remoteIP6() == kPeer6);
  TEST_ASSERT_EQUAL_UINT16(kPort, c.getRemotePort());

  c.close();
}

static void test_state_ipv6_connect_by_ip_addr_t_dials_that_address(void) {
  const uint32_t kWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000002};

  AsyncClient c;
  ip_addr_t addr = IPADDR6_INIT(kWords[0], kWords[1], kWords[2], kWords[3]);
  TEST_ASSERT_TRUE(c.connect(addr, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_UINT8(IPADDR_TYPE_V6, pcb->remote_ip.type);
  fire_connected(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(c.connected());
  TEST_ASSERT_TRUE(c.remoteIP6() == IPv6Address(kWords));
  c.close();
}

static void test_state_ipv6_accessors_are_zero_for_an_ipv4_peer(void) {
  AsyncClient c;
  establish(c);

  // The v6 accessors check the address family before reading the union.
  ip6_addr_t remote = c.getRemoteAddress6();
  for (int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT32(0, remote.addr[i]);
  }
  TEST_ASSERT_TRUE(c.remoteIP6() == IPv6Address());

  c.close();
}

// getRemoteAddress4()/getLocalAddress4() return the null address when the pcb is not an
// IPv4 one; getRemoteAddress()/getLocalAddress() read the union unconditionally, so on a
// v6 connection they hand back the first 32 bits of the IPv6 address as if it were an
// IPv4 one -- and remoteIP()/localIP() pass that straight to the application.
static void test_state_ipv4_accessors_are_zero_for_an_ipv6_peer(void) {
  const uint32_t kWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000001};
  const IPv6Address kPeer6(kWords);

  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer6, kPort));
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  fire_connected(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress4().addr);  // guarded on the address family
  TEST_ASSERT_EQUAL_UINT32(0, c.getRemoteAddress());        // not guarded
  TEST_ASSERT_TRUE(c.remoteIP() == IPAddress());

  c.close();
}
#endif  // LWIP_IPV6

void run_state_tests(void) {
  UnitySetTestFile(__FILE__);

  RUN_TEST(test_state_fresh_client_is_closed_and_disconnected);
  RUN_TEST(test_state_connect_dials_the_peer_on_one_pcb);
  RUN_TEST(test_state_connect_reports_syn_sent_until_the_handshake_lands);
  RUN_TEST(test_state_established_once_the_connected_event_is_delivered);
  RUN_TEST(test_state_close_returns_the_client_to_closed);
  RUN_TEST(test_state_predicates_partition_the_whole_connection_life);
  RUN_TEST(test_state_connected_and_disconnected_are_never_both_true);
  RUN_TEST(test_state_freeable_means_disconnected_or_disconnecting);
  RUN_TEST(test_state_disconnecting_while_a_fin_is_outstanding);
  RUN_TEST(test_state_time_wait_is_disconnected_not_disconnecting);
  RUN_TEST(test_state_stateToString_names_every_lwip_state);
  RUN_TEST(test_state_connect_is_refused_while_already_connecting);
  RUN_TEST(test_state_connect_is_refused_while_connected);
  RUN_TEST(test_state_close_twice_reports_one_disconnect);
  RUN_TEST(test_state_abort_twice_reports_one_error);
  RUN_TEST(test_state_stop_closes_like_close);
  RUN_TEST(test_state_close_bool_closes_like_close);
  RUN_TEST(test_state_connect_by_ip_addr_t_dials_that_address);
  RUN_TEST(test_state_a_client_equals_itself);
  RUN_TEST(test_state_clients_on_different_connections_are_unequal);
  RUN_TEST(test_state_peer_fin_leaves_the_client_closed_and_freeable);
  RUN_TEST(test_state_reset_leaves_the_client_closed_and_freeable);
  RUN_TEST(test_state_freeable_is_false_while_a_hostname_lookup_is_in_flight);
  RUN_TEST(test_state_accepted_client_is_established_when_delivered);
  RUN_TEST(test_state_accepted_client_walks_to_closed_on_close);
  RUN_TEST(test_state_accepted_client_reset_leaves_it_closed);

  RUN_TEST(test_state_accessors_report_zero_before_connecting);
  RUN_TEST(test_state_remote_accessors_match_the_dialled_peer);
  RUN_TEST(test_state_connect_assigns_a_local_port);
  RUN_TEST(test_state_ip_wrappers_agree_with_the_raw_accessors);
  RUN_TEST(test_state_accessors_report_zero_after_close);
  RUN_TEST(test_state_accessors_report_zero_after_a_reset);
  RUN_TEST(test_state_accepted_client_reports_the_peer_that_connected);
  RUN_TEST(test_state_getMss_reports_the_connection_mss);
  RUN_TEST(test_state_getMss_is_zero_without_a_connection);
  RUN_TEST(test_state_setNoDelay_round_trips_while_connected);
  RUN_TEST(test_state_getNoDelay_is_false_without_a_connection);

#if LWIP_IPV6
  RUN_TEST(test_state_ipv6_accessors_are_zero_without_a_connection);
  RUN_TEST(test_state_ipv6_connect_reports_the_v6_peer);
  RUN_TEST(test_state_ipv6_connect_by_ip_addr_t_dials_that_address);
  RUN_TEST(test_state_ipv6_accessors_are_zero_for_an_ipv4_peer);
  RUN_TEST(test_state_ipv4_accessors_are_zero_for_an_ipv6_peer);
#endif
}
