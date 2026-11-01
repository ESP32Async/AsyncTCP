// AsyncServer's accepted connections: delivery to onClient, the ones never delivered,
// several at once, and how each outlives or dies with the server.

#include "fixtures.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace mocklwip;

static void test_server_accept_delivers_a_client_to_onClient(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(lp);

  tcp_pcb *conn = fire_accept(lp);
  TEST_ASSERT_NOT_NULL(conn);
  TEST_ASSERT_EQUAL_size_t(0, accepted.size());  // queued, not yet delivered

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());

  TEST_ASSERT_EQUAL_PTR(conn, accepted[0]->pcb());
  TEST_ASSERT_TRUE(accepted[0]->connected());
  TEST_ASSERT_EQUAL_INT(40000, (int)accepted[0]->remotePort());

  // AsyncServer hands ownership of the client to the application.
  accepted.drop(0);
  TEST_ASSERT_FALSE(is_live(conn));

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_without_a_handler_closes_the_connection(void) {
  AsyncServer s(kServerPort);
  s.begin();  // no onClient()

  tcp_pcb *lp = listen_pcb();
  tcp_pcb *conn = fire_accept(lp);
  TEST_ASSERT_NOT_NULL(conn);
  TEST_ASSERT_FALSE(is_live(conn));  // closed straight away
  asynctcp_test_pump();

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_delivered_client_receives_data(void) {
  AsyncServer s(kServerPort);
  std::string got;
  Accepted accepted(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      got.assign((const char *)d, n);
    });
  });
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());

  fire_recv(conn, "GET /", 5);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("GET /", got.c_str());
  TEST_ASSERT_TRUE(saw("tcp_recved", conn, 5));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Accepts that are never delivered
// ---------------------------------------------------------------------------

static void test_server_accept_drops_a_client_the_peer_resets_first(void) {
  // A connection reset between lwIP accepting it and the async task delivering it must
  // simply cease to exist - it was never visible to the application.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(lp);
  tcp_pcb *conn = fire_accept(lp);
  TEST_ASSERT_NOT_NULL(conn);

  fire_error(conn, ERR_RST);  // before the accept is delivered
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_an_accept_lwip_could_not_allocate_delivers_nothing(void) {
  // lwIP ran out of pcbs for an incoming SYN.  There is no connection to deliver, and the
  // server goes on listening.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  fire_accept_failure(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());  // the listen pcb alone

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_EQUAL_PTR(conn, accepted[0]->pcb());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_end_drops_clients_never_delivered(void) {
  // Connections accepted but not yet delivered when end() is called are never
  // delivered; they are closed once the async task reaches them.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  tcp_pcb *lp = listen_pcb();
  tcp_pcb *conn = fire_accept(lp);
  TEST_ASSERT_NOT_NULL(conn);
  TEST_ASSERT_EQUAL_size_t(0, accepted.size());  // queued, not yet delivered

  s.end();               // orphans the queued accept
  asynctcp_test_pump();  // ...which the async task then drops

  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_destroying_the_server_drops_an_accept_in_flight(void) {
  // Destroying the AsyncServer with a connection still waiting to be delivered must
  // neither crash nor deliver it.  The single-threaded harness can only reach the
  // queued case; a destructor running concurrently with delivery needs two threads and
  // is not expressible here.
  int accepted = 0;
  {
    AsyncServer s(kServerPort);
    s.onClient(
      [&](void *, AsyncClient *) {
        accepted++;
      },
      nullptr
    );
    s.begin();
    TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
    TEST_ASSERT_EQUAL_INT(0, accepted);  // queued, not yet delivered
  }  // server destroyed with the accept still outstanding

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, accepted);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_restart_does_not_resurrect_a_queued_accept(void) {
  // end() disowns connections accepted on the session it closes.  Restarting must not
  // undo that: the queued connection belongs to the previous listening session, and
  // listening again must not let it through.
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
  TEST_ASSERT_EQUAL_size_t(0, accepted.size());  // queued, not yet delivered

  s.end();
  s.begin();  // listening again, on a fresh pcb
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, accepted.size());
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Several connections at once
// ---------------------------------------------------------------------------

static void test_server_accept_takes_more_connections_than_the_backlog(void) {
  // The backlog bounds lwIP's queue of half-open connections, not how many established
  // ones AsyncServer will hand over.  Offering more than that in one go must deliver all
  // of them; the library imposes no ceiling of its own.
  const size_t kCount = (size_t)kExpectedBacklog + 3;

  AsyncServer s(kServerPort);
  Accepted clients(s);
  s.begin();

  std::vector<tcp_pcb *> conns;
  for (size_t i = 0; i < kCount; i++) {
    tcp_pcb *conn = fire_accept(listen_pcb());
    TEST_ASSERT_NOT_NULL(conn);
    conns.push_back(conn);
  }
  TEST_ASSERT_EQUAL_size_t(0, clients.size());  // all queued, none delivered yet

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(kCount, clients.size());

  // One client per connection, and no connection delivered twice.
  for (tcp_pcb *conn : conns) {
    TEST_ASSERT_NOT_NULL(clients.holding(conn));
  }
  TEST_ASSERT_EQUAL_size_t(kCount + 1, live_pcbs());  // the clients, plus the listen pcb

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_concurrent_clients_get_their_own_pcbs(void) {
  AsyncServer s(kServerPort);
  Accepted clients(s);
  s.begin();

  tcp_pcb *a = fire_accept(listen_pcb());
  asynctcp_test_pump();
  tcp_pcb *b = fire_accept(listen_pcb());
  asynctcp_test_pump();
  tcp_pcb *c = fire_accept(listen_pcb());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(3, clients.size());
  TEST_ASSERT_TRUE(a != b && b != c && a != c);
  TEST_ASSERT_EQUAL_PTR(a, clients[0]->pcb());
  TEST_ASSERT_EQUAL_PTR(b, clients[1]->pcb());
  TEST_ASSERT_EQUAL_PTR(c, clients[2]->pcb());
  TEST_ASSERT_TRUE(clients[0]->connected());
  TEST_ASSERT_TRUE(clients[1]->connected());
  TEST_ASSERT_TRUE(clients[2]->connected());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_data_reaches_only_the_addressed_client(void) {
  AsyncServer s(kServerPort);
  std::vector<std::string> got(3);
  size_t slots = 0;
  Accepted clients(s, [&](AsyncClient *c) {
    const size_t slot = slots++;
    c->onData([&got, slot](void *, AsyncClient *, void *d, size_t n) {
      got[slot].append((const char *)d, n);
    });
  });
  s.begin();

  std::vector<tcp_pcb *> conns;
  for (int i = 0; i < 3; i++) {
    conns.push_back(fire_accept(listen_pcb()));
    asynctcp_test_pump();
  }
  TEST_ASSERT_EQUAL_size_t(3, clients.size());

  fire_recv(conns[1], "middle", 6);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("", got[0].c_str());
  TEST_ASSERT_EQUAL_STRING("middle", got[1].c_str());
  TEST_ASSERT_EQUAL_STRING("", got[2].c_str());
  TEST_ASSERT_TRUE(saw("tcp_recved", conns[1], 6));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_recved", conns[0]));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_closing_one_client_leaves_the_others_running(void) {
  AsyncServer s(kServerPort);
  std::string tail;
  Accepted clients(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      tail.append((const char *)d, n);
    });
  });
  s.begin();

  std::vector<tcp_pcb *> conns;
  for (int i = 0; i < 3; i++) {
    conns.push_back(fire_accept(listen_pcb()));
    asynctcp_test_pump();
  }

  clients.drop(0);
  TEST_ASSERT_FALSE(is_live(conns[0]));
  TEST_ASSERT_TRUE(is_live(conns[1]));
  TEST_ASSERT_TRUE(is_live(conns[2]));

  // The survivors keep their callbacks and their pcbs.
  fire_recv(conns[2], "still here", 10);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("still here", tail.c_str());
  TEST_ASSERT_TRUE(clients[1]->connected());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_one_client_reset_leaves_the_others_running(void) {
  // A fatal error frees one connection's pcb behind the library's back.  The other
  // connections share nothing with it but the server, so they must be untouched.
  AsyncServer s(kServerPort);
  int errors = 0;
  std::string tail;
  Accepted clients(s, [&](AsyncClient *c) {
    c->onError([&](void *, AsyncClient *, int8_t) {
      errors++;
    });
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      tail.append((const char *)d, n);
    });
  });
  s.begin();

  std::vector<tcp_pcb *> conns;
  for (int i = 0; i < 3; i++) {
    conns.push_back(fire_accept(listen_pcb()));
    asynctcp_test_pump();
  }

  fire_error(conns[0], ERR_RST);  // conns[0] is dangling from here on
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_FALSE(clients[0]->connected());
  TEST_ASSERT_TRUE(clients[1]->connected());

  fire_recv(conns[2], "ok", 2);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ok", tail.c_str());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// end(), restart and destruction order with live clients
// ---------------------------------------------------------------------------

static void test_server_accept_end_leaves_established_clients_running(void) {
  // end() closes the listen pcb only.  A connection already handed to the application is
  // the application's to close.
  AsyncServer s(kServerPort);
  std::string tail;
  Accepted clients(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      tail.append((const char *)d, n);
    });
  });
  s.begin();

  std::vector<tcp_pcb *> conns;
  for (int i = 0; i < 2; i++) {
    conns.push_back(fire_accept(listen_pcb()));
    asynctcp_test_pump();
  }

  s.end();
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
  TEST_ASSERT_EQUAL_size_t(2, live_pcbs());  // the two connections, and nothing else
  TEST_ASSERT_TRUE(clients[0]->connected());
  TEST_ASSERT_TRUE(clients[1]->connected());

  fire_recv(conns[0], "after end", 9);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("after end", tail.c_str());

  clients.clear();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_restart_does_not_disturb_an_earlier_client(void) {
  // Disowning the queued accepts must not touch a connection that was already delivered
  // on the previous session.
  AsyncServer s(kServerPort);
  std::string tail;
  Accepted clients(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      tail.append((const char *)d, n);
    });
  });
  s.begin();
  tcp_pcb *old_conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, clients.size());

  s.end();
  s.begin();
  tcp_pcb *new_conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(2, clients.size());

  TEST_ASSERT_TRUE(is_live(old_conn));
  TEST_ASSERT_TRUE(clients[0]->connected());
  fire_recv(old_conn, "old", 3);
  fire_recv(new_conn, "new", 3);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("oldnew", tail.c_str());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_server_destroyed_before_its_client(void) {
  // ~AsyncServer() stops listening and detaches; a connection already delivered has no
  // dependency on the server left and keeps working.
  AsyncClient *client = nullptr;
  std::string tail;
  tcp_pcb *conn = nullptr;
  {
    AsyncServer s(kServerPort);
    s.onClient(
      [&](void *, AsyncClient *c) {
        client = c;
        c->onData([&](void *, AsyncClient *, void *d, size_t n) {
          tail.append((const char *)d, n);
        });
      },
      nullptr
    );
    s.begin();
    conn = fire_accept(listen_pcb());
    asynctcp_test_pump();
    TEST_ASSERT_NOT_NULL(client);
  }  // server destroyed, connection still open

  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());
  TEST_ASSERT_TRUE(client->connected());

  fire_recv(conn, "orphan", 6);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("orphan", tail.c_str());

  delete client;
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_client_destroyed_before_its_server(void) {
  // The other order: the server outlives the connection and goes on accepting.
  AsyncServer s(kServerPort);
  Accepted clients(s);
  s.begin();

  tcp_pcb *first = fire_accept(listen_pcb());
  asynctcp_test_pump();
  clients.drop(0);
  TEST_ASSERT_FALSE(is_live(first));
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());

  tcp_pcb *second = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, clients.size());
  TEST_ASSERT_EQUAL_PTR(second, clients[0]->pcb());

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Turning connections away
// ---------------------------------------------------------------------------

static void test_server_accept_a_queued_accept_precedes_its_own_data(void) {
  // Delivery order between two connections is not guaranteed -- but a connection must
  // be delivered to onClient before anything is delivered for it.
  AsyncServer s(kServerPort);
  tcp_pcb *first = nullptr;
  std::vector<std::string> log;
  Accepted clients(s, [&](AsyncClient *c) {
    log.push_back(c->pcb() == first ? "accept:first" : "accept:second");
    c->onData([&](void *, AsyncClient *, void *d, size_t n) {
      log.push_back(std::string("data:") + std::string((const char *)d, n));
    });
  });
  s.begin();

  first = fire_accept(listen_pcb());
  fire_recv(first, "early", 5);
  TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(3, log.size());
  auto at = [&](const char *entry) {
    return std::find(log.begin(), log.end(), entry) - log.begin();
  };
  TEST_ASSERT_TRUE(at("accept:second") < 3);
  TEST_ASSERT_TRUE(at("accept:first") < at("data:early"));
  TEST_ASSERT_TRUE(at("data:early") < 3);

  clients.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_rejecting_a_client_from_onClient_closes_it(void) {
  // How an application enforces a connection cap of its own: take delivery and destroy the
  // client on the spot.  The connection has to go, and the server has to stay listening.
  AsyncServer s(kServerPort);
  int accepted = 0;
  s.onClient(
    [&](void *, AsyncClient *c) {
      accepted++;
      delete c;
    },
    nullptr
  );
  s.begin();

  tcp_pcb *rejected = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, accepted);
  TEST_ASSERT_FALSE(is_live(rejected));
  TEST_ASSERT_EQUAL_INT((int)LISTEN, (int)s.status());
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());  // the listen pcb alone

  tcp_pcb *next = fire_accept(listen_pcb());
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(2, accepted);
  TEST_ASSERT_FALSE(is_live(next));

  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_end_from_inside_onClient_drops_the_rest(void) {
  // The other way to cap connections: close the door as the last one wanted arrives.
  // end() disowns whatever else was accepted on that session -- and end() from the
  // async task must not deadlock against the delivery that called it.
  AsyncServer s(kServerPort);
  Accepted clients(s, [&](AsyncClient *) {
    s.end();
  });
  s.begin();

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  asynctcp_test_pump();

  // Whichever of the two is delivered first shuts the server; the other is disowned.
  TEST_ASSERT_EQUAL_size_t(1, clients.size());
  TEST_ASSERT_EQUAL_INT((int)CLOSED, (int)s.status());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
  TEST_ASSERT_TRUE(clients[0]->connected());
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());  // only the connection that was kept
  TEST_ASSERT_EQUAL_UINT(0, mockrtos::deadlocks());

  clients.clear();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_destroying_the_server_from_onClient_drops_the_rest(void) {
  // Nothing may reach a server once it is destroyed; the accepts still queued go with it.
  AsyncServer *s = new AsyncServer(kServerPort);
  std::vector<AsyncClient *> clients;
  s->onClient(
    [&](void *, AsyncClient *c) {
      clients.push_back(c);
      delete s;
      s = nullptr;
    },
    nullptr
  );
  s->begin();

  tcp_pcb *lp = listen_pcb();
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  TEST_ASSERT_NOT_NULL(fire_accept(lp));
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, clients.size());
  TEST_ASSERT_FALSE(port_is_bound(kServerPort));
  TEST_ASSERT_TRUE(clients[0]->connected());
  TEST_ASSERT_EQUAL_size_t(1, live_pcbs());  // only the connection that was delivered

  delete clients[0];
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// Who connected, and on what address
// ---------------------------------------------------------------------------

static void test_server_accept_client_reports_the_peer_that_connected(void) {
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  ip_addr_t peer = IPADDR4_INIT(0x0A000009);  // 10.0.0.9
  tcp_pcb *conn = fire_accept(listen_pcb(), peer, 41234);
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());

  TEST_ASSERT_TRUE(accepted[0]->remoteIP() == IPAddress(10, 0, 0, 9));
  TEST_ASSERT_EQUAL_UINT16(41234, accepted[0]->remotePort());
  TEST_ASSERT_EQUAL_UINT16(kServerPort, accepted[0]->localPort());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_server_accept_on_an_ip_addr_t_server_reports_that_address(void) {
  const uint32_t kBind = 0x0A000007;  // 10.0.0.7
  ip_addr_t addr = IPADDR4_INIT(kBind);
  AsyncServer s(addr, kServerPort);
  Accepted accepted(s);
  s.begin();

  TEST_ASSERT_NOT_NULL(fire_accept(listen_pcb()));
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  TEST_ASSERT_TRUE(accepted[0]->localIP() == IPAddress(kBind));
  TEST_ASSERT_EQUAL_UINT32(kBind, accepted[0]->getLocalAddress4().addr);

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

#if LWIP_IPV6
static void test_server_accept_ipv6_connection_end_to_end(void) {
  const uint32_t kBind[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000007};
  const uint32_t kPeerWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000009};
  AsyncServer s(IPv6Address(kBind), kServerPort);
  std::string got;
  Accepted accepted(s, [&](AsyncClient *c) {
    c->onData([&](void *, AsyncClient *cl, void *d, size_t n) {
      got.append((const char *)d, n);
      cl->write("pong", 4);
    });
  });
  s.begin();

  ip_addr_t peer = IPADDR6_INIT(kPeerWords[0], kPeerWords[1], kPeerWords[2], kPeerWords[3]);
  tcp_pcb *conn = fire_accept(listen_pcb(), peer, 41234);
  TEST_ASSERT_NOT_NULL(conn);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, accepted.size());
  AsyncClient *client = accepted[0];

  TEST_ASSERT_TRUE(client->connected());
  TEST_ASSERT_TRUE(client->remoteIP6() == IPv6Address(kPeerWords));
  TEST_ASSERT_TRUE(client->localIP6() == IPv6Address(kBind));
  ip6_addr_t local = client->getLocalAddress6();
  ip6_addr_t remote = client->getRemoteAddress6();
  for (int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT32(kBind[i], local.addr[i]);
    TEST_ASSERT_EQUAL_UINT32(kPeerWords[i], remote.addr[i]);
  }
  TEST_ASSERT_EQUAL_UINT16(41234, client->remotePort());
  TEST_ASSERT_EQUAL_UINT16(kServerPort, client->localPort());

  fire_recv(conn, "ping", 4);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("ping", got.c_str());
  TEST_ASSERT_EQUAL_STRING("pong", written(conn).c_str());

  fire_fin(conn);
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(client->disconnected());

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_server_accept_any_address_takes_both_families(void) {
  const uint32_t kPeerWords[4] = {0x20010db8, 0x00000000, 0x00000000, 0x00000009};
  AsyncServer s(kServerPort);
  Accepted accepted(s);
  s.begin();

  ip_addr_t peer4 = IPADDR4_INIT(0x0A000009);
  ip_addr_t peer6 = IPADDR6_INIT(kPeerWords[0], kPeerWords[1], kPeerWords[2], kPeerWords[3]);
  tcp_pcb *conn4 = fire_accept(listen_pcb(), peer4, 41234);
  asynctcp_test_pump();
  tcp_pcb *conn6 = fire_accept(listen_pcb(), peer6, 41235);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(2, accepted.size());

  AsyncClient *c4 = accepted.holding(conn4);
  AsyncClient *c6 = accepted.holding(conn6);
  TEST_ASSERT_NOT_NULL(c4);
  TEST_ASSERT_NOT_NULL(c6);
  TEST_ASSERT_TRUE(c4->remoteIP() == IPAddress(10, 0, 0, 9));
  TEST_ASSERT_TRUE(c6->remoteIP6() == IPv6Address(kPeerWords));

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}
#endif  // LWIP_IPV6

void run_server_accept_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_server_accept_delivers_a_client_to_onClient);
  RUN_TEST(test_server_accept_without_a_handler_closes_the_connection);
  RUN_TEST(test_server_accept_delivered_client_receives_data);
  RUN_TEST(test_server_accept_drops_a_client_the_peer_resets_first);
  RUN_TEST(test_server_accept_an_accept_lwip_could_not_allocate_delivers_nothing);
  RUN_TEST(test_server_accept_end_drops_clients_never_delivered);
  RUN_TEST(test_server_accept_destroying_the_server_drops_an_accept_in_flight);
  RUN_TEST(test_server_accept_restart_does_not_resurrect_a_queued_accept);
  RUN_TEST(test_server_accept_takes_more_connections_than_the_backlog);
  RUN_TEST(test_server_accept_concurrent_clients_get_their_own_pcbs);
  RUN_TEST(test_server_accept_data_reaches_only_the_addressed_client);
  RUN_TEST(test_server_accept_closing_one_client_leaves_the_others_running);
  RUN_TEST(test_server_accept_one_client_reset_leaves_the_others_running);
  RUN_TEST(test_server_accept_end_leaves_established_clients_running);
  RUN_TEST(test_server_accept_restart_does_not_disturb_an_earlier_client);
  RUN_TEST(test_server_accept_server_destroyed_before_its_client);
  RUN_TEST(test_server_accept_client_destroyed_before_its_server);
  RUN_TEST(test_server_accept_a_queued_accept_precedes_its_own_data);
  RUN_TEST(test_server_accept_rejecting_a_client_from_onClient_closes_it);
  RUN_TEST(test_server_accept_end_from_inside_onClient_drops_the_rest);
  RUN_TEST(test_server_accept_destroying_the_server_from_onClient_drops_the_rest);
  RUN_TEST(test_server_accept_client_reports_the_peer_that_connected);
  RUN_TEST(test_server_accept_on_an_ip_addr_t_server_reports_that_address);
#if LWIP_IPV6
  RUN_TEST(test_server_accept_ipv6_connection_end_to_end);
  RUN_TEST(test_server_accept_any_address_takes_both_families);
#endif
}
