// AsyncClient's timers: the rx timeout, the ack timeout, onPoll and TCP keepalive.
//
// All three are driven by lwIP's poll callback, which lwIP calls on a timer and which the
// harness stands in for with fire_poll() + a pump.  Time only moves when a test moves it, so an
// "idle connection" here is a fire_poll() after a mockclock::advance().

#include "fixtures.h"

using namespace mocklwip;

namespace {

// One round of "lwIP's poll timer went off".
void poll(tcp_pcb *pcb) {
  fire_poll(pcb);
  asynctcp_test_pump();
}

}  // namespace

// ---------------------------------------------------------------------------
// The accessors
// ---------------------------------------------------------------------------

static void test_timeout_rx_timeout_defaults_to_disabled(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_UINT32(0, c.getRxTimeout());
}

static void test_timeout_rx_timeout_round_trips(void) {
  AsyncClient c;
  c.setRxTimeout(30);
  TEST_ASSERT_EQUAL_UINT32(30, c.getRxTimeout());
  c.setRxTimeout(0);  // 0 is the "off" value, not a zero-length timeout
  TEST_ASSERT_EQUAL_UINT32(0, c.getRxTimeout());
}

static void test_timeout_ack_timeout_defaults_to_the_configured_maximum(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_UINT32(CONFIG_ASYNC_TCP_MAX_ACK_TIME, c.getAckTimeout());
}

static void test_timeout_ack_timeout_round_trips(void) {
  AsyncClient c;
  c.setAckTimeout(250);
  TEST_ASSERT_EQUAL_UINT32(250, c.getAckTimeout());
  c.setAckTimeout(0);
  TEST_ASSERT_EQUAL_UINT32(0, c.getAckTimeout());
}

static void test_timeout_settings_survive_a_connection(void) {
  // Both are properties of the client, not of the connection, so connecting and closing
  // must not reset them.
  AsyncClient c;
  c.setRxTimeout(7);
  c.setAckTimeout(123);

  establish(c);
  TEST_ASSERT_EQUAL_UINT32(7, c.getRxTimeout());
  TEST_ASSERT_EQUAL_UINT32(123, c.getAckTimeout());

  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_UINT32(7, c.getRxTimeout());
  TEST_ASSERT_EQUAL_UINT32(123, c.getAckTimeout());
}

// ---------------------------------------------------------------------------
// The rx timeout
// ---------------------------------------------------------------------------

static void test_timeout_rx_timeout_closes_an_idle_connection(void) {
  AsyncClient c;
  int disconnects = 0;
  int errors = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  c.onError([&](void *, AsyncClient *, int8_t) {
    errors++;
  });

  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);

  mockclock::advance(2000);
  poll(pcb);

  // An orderly close, not an abort: the application hears onDisconnect only.
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_INT(0, errors);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_TRUE(c.disconnected());
}

static void test_timeout_rx_timeout_is_measured_in_seconds(void) {
  // setRxTimeout() takes seconds while setAckTimeout() takes milliseconds; the
  // boundary is inclusive.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);

  mockclock::advance(1999);
  poll(pcb);
  TEST_ASSERT_TRUE(is_live(pcb));

  mockclock::advance(1);
  poll(pcb);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_rx_timeout_of_zero_never_closes(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(0);

  mockclock::advance(3600000);  // an hour of silence
  poll(pcb);

  TEST_ASSERT_TRUE(c.connected());
  c.close();
}

static void test_timeout_rx_timeout_is_refreshed_by_arriving_data(void) {
  // Each packet counts as activity, so a connection that keeps receiving is never idle
  // however long it lives.
  AsyncClient c;
  int disconnects = 0;
  c.onData([&](void *, AsyncClient *, void *, size_t) {});
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);

  for (int i = 0; i < 4; i++) {
    mockclock::advance(1500);
    fire_recv(pcb, "alive", 5);
    asynctcp_test_pump();
    poll(pcb);
    TEST_ASSERT_TRUE(is_live(pcb));
  }
  TEST_ASSERT_EQUAL_INT(0, disconnects);
  TEST_ASSERT_TRUE(c.connected());

  // 6s of traffic, then 2s of silence, and it goes.
  mockclock::advance(2000);
  poll(pcb);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_rx_timeout_is_refreshed_by_an_ack(void) {
  // A bare ack is still a packet from the peer, so it proves the peer is alive.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);
  c.write("x", 1);

  mockclock::advance(1500);
  fire_sent(pcb, 1);
  asynctcp_test_pump();

  mockclock::advance(1000);  // 2500ms since connect, 1000ms since the ack
  poll(pcb);
  TEST_ASSERT_TRUE(is_live(pcb));

  c.close();
}

static void test_timeout_rx_timeout_runs_from_the_handshake_not_the_dial(void) {
  // The idle period starts when the handshake lands, not at connect(); a slow handshake
  // must not eat into it.
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();

  mockclock::advance(3000);
  fire_connected(pcb);
  asynctcp_test_pump();
  c.setRxTimeout(2);

  mockclock::advance(1500);  // 4500ms since connect(), 1500ms since ESTABLISHED
  poll(pcb);
  TEST_ASSERT_TRUE(is_live(pcb));

  mockclock::advance(500);
  poll(pcb);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_rx_timeout_is_not_applied_while_connecting(void) {
  // No rx timeout before ESTABLISHED: lwIP owns the SYN timeout.
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = dialled_pcb();
  c.setRxTimeout(1);

  mockclock::advance(30000);
  poll(pcb);

  TEST_ASSERT_TRUE(is_live(pcb));
  c.close();
}

// ---------------------------------------------------------------------------
// The ack timeout
// ---------------------------------------------------------------------------

static void test_timeout_ack_timeout_reports_the_age_of_the_unacked_send(void) {
  AsyncClient c;
  uint32_t reported = 0;
  AsyncClient *seen = nullptr;
  c.onTimeout([&](void *, AsyncClient *self, uint32_t t) {
    reported = t;
    seen = self;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(250);
  poll(pcb);

  TEST_ASSERT_EQUAL_UINT32(250, reported);
  TEST_ASSERT_EQUAL_PTR(&c, seen);
  c.close();
}

static void test_timeout_ack_timeout_passes_the_callback_argument(void) {
  AsyncClient c;
  int marker = 0;
  void *arg = nullptr;
  c.onTimeout(
    [&](void *a, AsyncClient *, uint32_t) {
      arg = a;
    },
    &marker
  );

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(250);
  poll(pcb);

  TEST_ASSERT_EQUAL_PTR(&marker, arg);
  c.close();
}

static void test_timeout_ack_timeout_falls_between_the_deadlines_of_two_unacked_sends(void) {
  // With two sends unacked, the timeout may run from either: not before the first is a
  // full period old, and no later than the second is.
  AsyncClient c;
  uint32_t reported = 0;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t t) {
    reported = t;
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(350);
  c.write("a", 1);

  mockclock::advance(300);
  c.write("b", 1);

  mockclock::advance(40);  // 340ms since the first send
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(0, timeouts);

  mockclock::advance(310);  // 650ms since the first send, 350ms since the second
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, timeouts);
  TEST_ASSERT_UINT32_WITHIN(150, 500, reported);  // 350..650ms

  c.close();
}

static void test_timeout_ack_timeout_does_not_fire_once_the_peer_acks(void) {
  // An ack newer than the last send means nothing is outstanding to time out.
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(10);
  fire_sent(pcb, 1);
  asynctcp_test_pump();

  mockclock::advance(5000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, timeouts);
  TEST_ASSERT_TRUE(c.connected());
  c.close();
}

static void test_timeout_ack_timeout_does_not_fire_without_a_send(void) {
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  mockclock::advance(5000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, timeouts);
  c.close();
}

static void test_timeout_ack_timeout_of_zero_disables_it(void) {
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(0);
  c.write("x", 1);

  mockclock::advance(3600000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, timeouts);
  TEST_ASSERT_TRUE(c.connected());
  c.close();
}

static void test_timeout_ack_timeout_leaves_the_connection_up(void) {
  // onTimeout is a report, not a teardown: the library never closes on its own, so
  // with no handler registered the connection simply stays up.
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(5000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, disconnects);
  TEST_ASSERT_TRUE(c.connected());
  c.close();
}

static void test_timeout_ack_timeout_repeats_until_the_handler_acts(void) {
  // Nothing clears the condition but an ack or a close, so every poll re-reports it
  // with a longer elapsed time.
  AsyncClient c;
  int timeouts = 0;
  uint32_t last = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t t) {
    timeouts++;
    last = t;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(150);
  poll(pcb);
  mockclock::advance(150);
  poll(pcb);
  mockclock::advance(150);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(3, timeouts);
  TEST_ASSERT_EQUAL_UINT32(450, last);
  c.close();
}

static void test_timeout_ack_timeout_handler_may_close_the_connection(void) {
  // The usual handler: close from inside the callback, which runs on the async task
  // with the poll event still in flight.
  AsyncClient c;
  int timeouts = 0;
  int disconnects = 0;
  c.onTimeout([&](void *, AsyncClient *self, uint32_t) {
    timeouts++;
    self->close();
  });
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(150);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(1, timeouts);
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_TRUE(c.disconnected());
}

static void test_timeout_ack_timeout_handler_may_abort_the_connection(void) {
  AsyncClient c;
  int errors = 0;
  c.onTimeout([&](void *, AsyncClient *self, uint32_t) {
    self->abort();
  });
  c.onError([&](void *, AsyncClient *, int8_t err) {
    errors++;
    TEST_ASSERT_EQUAL_INT(ERR_ABRT, err);
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(150);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(1, errors);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_ack_timeout_arms_for_a_send_at_millis_zero(void) {
  // A send that lands on millis() == 0 must be timed out like any other.  millis() is 0
  // at boot and again every 49.7 days when it wraps.
  mockclock::set_millis(0);
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(5000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(1, timeouts);
  c.close();
}

// ---------------------------------------------------------------------------
// What starts the ack timeout
// ---------------------------------------------------------------------------

static void test_timeout_queuing_without_sending_does_not_arm_the_ack_timeout(void) {
  // add() fills the send buffer; send() is what puts it on the wire and starts the
  // clock on it.
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  // A completed round trip first, so the "disarmed" state below is a real ack rather
  // than the never-sent-anything default.
  c.write("a", 1);
  mockclock::advance(10);
  fire_sent(pcb, 1);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(1, c.add("b", 1));
  mockclock::advance(500);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(0, timeouts);

  TEST_ASSERT_TRUE(c.send());
  mockclock::advance(500);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, timeouts);

  c.close();
}

static void test_timeout_a_send_lwip_cannot_output_still_times_out(void) {
  // lwIP keeps data it couldn't output and retries it, so that data waits on an ack like
  // any other.  A connection that never gets it out times out.
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  c.write("a", 1);
  mockclock::advance(10);
  fire_sent(pcb, 1);
  asynctcp_test_pump();

  faults().output_result = ERR_MEM;
  mockclock::advance(100);
  c.write("b", 1);

  mockclock::advance(100);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, timeouts);

  c.close();
}

static void test_timeout_an_unacked_send_does_not_carry_into_the_next_connection(void) {
  // An unacked write on the previous connection must not time out the new one.
  AsyncClient c;
  int timeouts = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);  // never acked
  c.close();
  asynctcp_test_pump();

  mockclock::advance(10000);
  tcp_pcb *pcb = establish(c);
  mockclock::advance(500);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, timeouts);
  c.close();
}

// ---------------------------------------------------------------------------
// onPoll
// ---------------------------------------------------------------------------

static void test_timeout_onPoll_runs_once_per_delivered_poll(void) {
  AsyncClient c;
  int polls = 0;
  c.onPoll([&](void *, AsyncClient *) {
    polls++;
  });

  tcp_pcb *pcb = establish(c);

  for (int i = 0; i < 3; i++) {
    poll(pcb);
    TEST_ASSERT_EQUAL_INT(i + 1, polls);
  }

  c.close();
}

static void test_timeout_onPoll_needs_the_async_task(void) {
  // fire_poll() only queues; nothing reaches the application until the task runs.
  AsyncClient c;
  int polls = 0;
  c.onPoll([&](void *, AsyncClient *) {
    polls++;
  });

  tcp_pcb *pcb = establish(c);
  fire_poll(pcb);
  TEST_ASSERT_EQUAL_INT(0, polls);

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, polls);

  c.close();
}

static void test_timeout_queued_polls_coalesce_into_one(void) {
  // A backlog of polls means the task fell behind; replaying them all would only make
  // it worse, so consecutive polls for one client run onPoll once.
  AsyncClient c;
  int polls = 0;
  c.onPoll([&](void *, AsyncClient *) {
    polls++;
  });

  tcp_pcb *pcb = establish(c);
  fire_poll(pcb);
  fire_poll(pcb);
  fire_poll(pcb);

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, polls);

  c.close();
}

static void test_timeout_polls_split_by_an_ack_neither_swallow_it_nor_multiply(void) {
  // The polls may merge across the ack, but the ack survives.
  AsyncClient c;
  int polls = 0;
  int acks = 0;
  c.onPoll([&](void *, AsyncClient *) {
    polls++;
  });
  c.onAck([&](void *, AsyncClient *, size_t, uint32_t) {
    acks++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(0);  // keep the ack timeout out of the way
  c.write("x", 1);

  fire_poll(pcb);
  fire_sent(pcb, 1);
  fire_poll(pcb);

  asynctcp_test_pump();
  TEST_ASSERT_TRUE(polls == 1 || polls == 2);
  TEST_ASSERT_EQUAL_INT(1, acks);

  c.close();
}

static void test_timeout_polls_for_different_clients_do_not_coalesce(void) {
  // Coalescing is per connection; one busy client must not swallow another's poll.
  AsyncClient a;
  AsyncClient b;
  int a_polls = 0;
  int b_polls = 0;
  a.onPoll([&](void *, AsyncClient *) {
    a_polls++;
  });
  b.onPoll([&](void *, AsyncClient *) {
    b_polls++;
  });

  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(b);

  fire_poll(pa);
  fire_poll(pa);
  fire_poll(pb);

  // a's two merge; b's survives.
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, a_polls);
  TEST_ASSERT_EQUAL_INT(1, b_polls);

  a.close();
  b.close();
}

static void test_timeout_onPoll_is_skipped_while_the_ack_timeout_is_firing(void) {
  // onPoll is the "everything is fine" callback, so while the ack timeout is being
  // reported it is suppressed, until the peer acks.
  AsyncClient c;
  int polls = 0;
  int timeouts = 0;
  c.onPoll([&](void *, AsyncClient *) {
    polls++;
  });
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });

  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(150);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, timeouts);
  TEST_ASSERT_EQUAL_INT(0, polls);

  fire_sent(pcb, 1);
  asynctcp_test_pump();
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, timeouts);
  TEST_ASSERT_EQUAL_INT(1, polls);

  c.close();
}

// ---------------------------------------------------------------------------
// setKeepAlive
// ---------------------------------------------------------------------------

static void test_timeout_setKeepAlive_reaches_the_pcb(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_UINT8(0, pcb->so_options & SOF_KEEPALIVE);

  c.setKeepAlive(7000, 4);

  TEST_ASSERT_EQUAL_UINT8(SOF_KEEPALIVE, pcb->so_options & SOF_KEEPALIVE);
  // One interval serves as both the idle period and the probe spacing.
  TEST_ASSERT_EQUAL_UINT32(7000, pcb->keep_idle);
  TEST_ASSERT_EQUAL_UINT32(7000, pcb->keep_intvl);
  TEST_ASSERT_EQUAL_UINT32(4, pcb->keep_cnt);

  c.close();
}

static void test_timeout_setKeepAlive_zero_turns_it_off(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.setKeepAlive(7000, 4);

  c.setKeepAlive(0, 0);
  TEST_ASSERT_EQUAL_UINT8(0, pcb->so_options & SOF_KEEPALIVE);

  c.close();
}

static void test_timeout_setKeepAlive_zero_ignores_the_count(void) {
  // ms == 0 means off whatever the count says.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.setKeepAlive(7000, 4);

  c.setKeepAlive(0, 9);
  TEST_ASSERT_EQUAL_UINT8(0, pcb->so_options & SOF_KEEPALIVE);

  c.close();
}

static void test_timeout_setKeepAlive_leaves_other_socket_options_alone(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  pcb->so_options |= SOF_REUSEADDR;

  c.setKeepAlive(7000, 4);
  TEST_ASSERT_EQUAL_UINT8(SOF_REUSEADDR, pcb->so_options & SOF_REUSEADDR);

  c.setKeepAlive(0, 0);
  TEST_ASSERT_EQUAL_UINT8(SOF_REUSEADDR, pcb->so_options & SOF_REUSEADDR);

  c.close();
}

static void test_timeout_setKeepAlive_before_connect_is_a_no_op(void) {
  // It writes straight through to the pcb and keeps no copy, so it has to be called on
  // a live connection -- before connect() it is silently lost.
  AsyncClient c;
  c.setKeepAlive(7000, 4);

  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_UINT8(0, pcb->so_options & SOF_KEEPALIVE);
  TEST_ASSERT_EQUAL_UINT32(0, pcb->keep_idle);

  c.close();
}

static void test_timeout_setKeepAlive_after_close_is_a_no_op(void) {
  AsyncClient c;
  establish(c);
  c.close();
  asynctcp_test_pump();
  TEST_ASSERT_NULL(c.pcb());

  c.setKeepAlive(7000, 4);  // must not touch the pcb it no longer owns
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// The two timeouts together
// ---------------------------------------------------------------------------

static void test_timeout_rx_timeout_wins_when_it_expires_first(void) {
  // Unacked data present, but the rx timeout is the shorter of the two: the
  // connection is torn down rather than merely reported.
  AsyncClient c;
  int timeouts = 0;
  int disconnects = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t) {
    timeouts++;
  });
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });

  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(1);
  c.setAckTimeout(5000);
  c.write("x", 1);

  mockclock::advance(1000);
  poll(pcb);

  TEST_ASSERT_EQUAL_INT(0, timeouts);
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_rx_timeout_closes_an_idle_connection_with_unacked_data(void) {
  // The rx timeout is the dead-peer backstop, and an unacked send is evidence *for* a
  // dead peer -- so having one outstanding must not exempt the connection from it.
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });

  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);
  c.setAckTimeout(100);  // fires first, and no handler is registered to act on it
  c.write("x", 1);

  for (int i = 0; i < 10; i++) {
    mockclock::advance(1000);
    if (live_pcbs() == 0) {
      break;
    }
    poll(pcb);
  }

  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// ---------------------------------------------------------------------------
// millis() wrapping, every 49.7 days
// ---------------------------------------------------------------------------

static void test_timeout_rx_timeout_runs_across_a_millis_wrap(void) {
  mockclock::set_millis(0xFFFFFFFFu - 999);  // 1000ms before the wrap
  AsyncClient c;
  Recorder t;
  t.attach(c);
  tcp_pcb *pcb = establish(c);
  c.setRxTimeout(2);

  mockclock::advance(1999);  // past the wrap, 1ms short
  poll(pcb);
  TEST_ASSERT_TRUE(is_live(pcb));
  TEST_ASSERT_EQUAL_STRING("C", t.seq.c_str());

  mockclock::advance(1);
  poll(pcb);
  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_timeout_ack_timeout_runs_across_a_millis_wrap(void) {
  mockclock::set_millis(0xFFFFFFFFu - 199);
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDT");
  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  // A completed round trip first, so the send below is the only thing outstanding.
  c.write("a", 1);
  mockclock::advance(10);
  fire_sent(pcb, 1);
  asynctcp_test_pump();

  mockclock::advance(140);  // 50ms before the wrap
  c.write("b", 1);
  mockclock::advance(99);  // past the wrap, 1ms short
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(0, t.count('T'));

  mockclock::advance(1);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, t.count('T'));
  TEST_ASSERT_EQUAL_UINT32(100, t.timed_out);
  c.close();
}

static void test_timeout_ack_timeout_arms_for_a_send_just_after_a_wrap(void) {
  mockclock::set_millis(0xFFFFFFFFu - 49);
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDT");
  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  c.write("a", 1);
  mockclock::advance(10);
  fire_sent(pcb, 1);  // acked before the wrap
  asynctcp_test_pump();

  mockclock::advance(50);  // just past it
  c.write("b", 1);
  mockclock::advance(100);
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(1, t.count('T'));
  c.close();
}

// ---------------------------------------------------------------------------
// An ack of part of a send holds the ack timeout off
// ---------------------------------------------------------------------------

static void test_timeout_partial_ack_holds_off_the_ack_timeout(void) {
  // A partial ack is progress: the timeout can't expire within a full period of it.
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDT");
  tcp_pcb *pcb = establish(c);
  c.setAckTimeout(100);

  TEST_ASSERT_EQUAL_size_t(10, c.write("0123456789", 10));
  mockclock::advance(10);
  fire_sent(pcb, 4);
  asynctcp_test_pump();

  mockclock::advance(99);  // 109ms since the send, 99ms since the ack
  poll(pcb);
  TEST_ASSERT_EQUAL_INT(0, t.count('T'));
  c.close();
}

void run_timeout_tests(void) {
  UnitySetTestFile(__FILE__);

  RUN_TEST(test_timeout_rx_timeout_defaults_to_disabled);
  RUN_TEST(test_timeout_rx_timeout_round_trips);
  RUN_TEST(test_timeout_ack_timeout_defaults_to_the_configured_maximum);
  RUN_TEST(test_timeout_ack_timeout_round_trips);
  RUN_TEST(test_timeout_settings_survive_a_connection);

  RUN_TEST(test_timeout_rx_timeout_closes_an_idle_connection);
  RUN_TEST(test_timeout_rx_timeout_is_measured_in_seconds);
  RUN_TEST(test_timeout_rx_timeout_of_zero_never_closes);
  RUN_TEST(test_timeout_rx_timeout_is_refreshed_by_arriving_data);
  RUN_TEST(test_timeout_rx_timeout_is_refreshed_by_an_ack);
  RUN_TEST(test_timeout_rx_timeout_runs_from_the_handshake_not_the_dial);
  RUN_TEST(test_timeout_rx_timeout_is_not_applied_while_connecting);

  RUN_TEST(test_timeout_ack_timeout_reports_the_age_of_the_unacked_send);
  RUN_TEST(test_timeout_ack_timeout_passes_the_callback_argument);
  RUN_TEST(test_timeout_ack_timeout_falls_between_the_deadlines_of_two_unacked_sends);
  RUN_TEST(test_timeout_ack_timeout_does_not_fire_once_the_peer_acks);
  RUN_TEST(test_timeout_ack_timeout_does_not_fire_without_a_send);
  RUN_TEST(test_timeout_ack_timeout_of_zero_disables_it);
  RUN_TEST(test_timeout_ack_timeout_leaves_the_connection_up);
  RUN_TEST(test_timeout_ack_timeout_repeats_until_the_handler_acts);
  RUN_TEST(test_timeout_ack_timeout_handler_may_close_the_connection);
  RUN_TEST(test_timeout_ack_timeout_handler_may_abort_the_connection);
  RUN_TEST(test_timeout_ack_timeout_arms_for_a_send_at_millis_zero);

  RUN_TEST(test_timeout_queuing_without_sending_does_not_arm_the_ack_timeout);
  RUN_TEST(test_timeout_a_send_lwip_cannot_output_still_times_out);
  RUN_TEST(test_timeout_an_unacked_send_does_not_carry_into_the_next_connection);

  RUN_TEST(test_timeout_onPoll_runs_once_per_delivered_poll);
  RUN_TEST(test_timeout_onPoll_needs_the_async_task);
  RUN_TEST(test_timeout_queued_polls_coalesce_into_one);
  RUN_TEST(test_timeout_polls_split_by_an_ack_neither_swallow_it_nor_multiply);
  RUN_TEST(test_timeout_polls_for_different_clients_do_not_coalesce);
  RUN_TEST(test_timeout_onPoll_is_skipped_while_the_ack_timeout_is_firing);

  RUN_TEST(test_timeout_setKeepAlive_reaches_the_pcb);
  RUN_TEST(test_timeout_setKeepAlive_zero_turns_it_off);
  RUN_TEST(test_timeout_setKeepAlive_zero_ignores_the_count);
  RUN_TEST(test_timeout_setKeepAlive_leaves_other_socket_options_alone);
  RUN_TEST(test_timeout_setKeepAlive_before_connect_is_a_no_op);
  RUN_TEST(test_timeout_setKeepAlive_after_close_is_a_no_op);

  RUN_TEST(test_timeout_rx_timeout_wins_when_it_expires_first);
  RUN_TEST(test_timeout_rx_timeout_closes_an_idle_connection_with_unacked_data);

  RUN_TEST(test_timeout_rx_timeout_runs_across_a_millis_wrap);
  RUN_TEST(test_timeout_ack_timeout_runs_across_a_millis_wrap);
  RUN_TEST(test_timeout_ack_timeout_arms_for_a_send_just_after_a_wrap);
  RUN_TEST(test_timeout_partial_ack_holds_off_the_ack_timeout);
}
