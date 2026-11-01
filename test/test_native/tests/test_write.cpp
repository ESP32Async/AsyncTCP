// AsyncClient's outbound path: space(), canSend(), add(), send(), write(), onAck.

#include "fixtures.h"

#include <string>
#include <vector>

using namespace mocklwip;

namespace {

// The apiflags argument of the nth (0-based) tcp_write() call.
long write_flags(size_t n) {
  const Call *call = nth("tcp_write", n);
  TEST_ASSERT_NOT_NULL(call);
  return call->b;
}

}  // namespace

// ---------------------------------------------------------------------------
// space()
// ---------------------------------------------------------------------------

static void test_write_space_is_zero_before_connect(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_size_t(0, c.space());
}

static void test_write_space_is_zero_while_connecting(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  // The pcb is in SYN_SENT: there is nowhere for data to go yet.
  tcp_pcb *pcb = dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_INT((int)SYN_SENT, (int)pcb->state);
  TEST_ASSERT_EQUAL_size_t(0, c.space());
  c.close();
}

static void test_write_space_is_the_lwip_send_buffer_once_connected(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(tcp_sndbuf(pcb), c.space());
  TEST_ASSERT_TRUE(c.space() > 0);
  c.close();
}

static void test_write_space_is_zero_after_close(void) {
  AsyncClient c;
  establish(c);
  c.close();
  TEST_ASSERT_NULL(c.pcb());
  TEST_ASSERT_EQUAL_size_t(0, c.space());
}

static void test_write_space_shrinks_by_what_was_queued(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  const size_t before = c.space();

  TEST_ASSERT_EQUAL_size_t(5, c.add("hello", 5));
  TEST_ASSERT_EQUAL_size_t(before - 5, c.space());
  TEST_ASSERT_EQUAL_size_t(before - 5, tcp_sndbuf(pcb));

  c.close();
}

static void test_write_space_is_restored_when_the_peer_acks(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  const size_t sndbuf = c.space();

  std::string full(sndbuf, 'x');
  TEST_ASSERT_EQUAL_size_t(sndbuf, c.write(full.data(), full.size()));
  TEST_ASSERT_EQUAL_size_t(0, c.space());

  // lwIP frees send-buffer space as the peer acks it.
  fire_sent(pcb, 100);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(100, c.space());

  c.close();
}

// ---------------------------------------------------------------------------
// canSend()
// ---------------------------------------------------------------------------

static void test_write_canSend_is_false_before_connect(void) {
  AsyncClient c;
  TEST_ASSERT_FALSE(c.canSend());
}

static void test_write_canSend_is_false_while_connecting(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  TEST_ASSERT_FALSE(c.canSend());
  c.close();
}

static void test_write_canSend_is_true_once_connected(void) {
  AsyncClient c;
  establish(c);
  TEST_ASSERT_TRUE(c.canSend());
  c.close();
}

static void test_write_canSend_is_false_when_the_send_buffer_is_full(void) {
  AsyncClient c;
  establish(c);
  std::string full(c.space(), 'x');
  TEST_ASSERT_EQUAL_size_t(full.size(), c.add(full.data(), full.size()));
  TEST_ASSERT_FALSE(c.canSend());
  c.close();
}

static void test_write_canSend_is_false_after_close(void) {
  AsyncClient c;
  establish(c);
  c.close();
  TEST_ASSERT_FALSE(c.canSend());
}

// ---------------------------------------------------------------------------
// add()
// ---------------------------------------------------------------------------

static void test_write_add_returns_what_it_queued(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(5, c.add("hello", 5));
  TEST_ASSERT_EQUAL_STRING("hello", written(pcb).c_str());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_write", pcb));
  c.close();
}

static void test_write_add_does_not_output(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(5, c.add("hello", 5));
  // add() is tcp_write() only; nothing goes on the wire until send().
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_output", pcb));
  c.close();
}

static void test_write_add_beyond_space_queues_only_what_fits(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  const size_t sndbuf = c.space();

  std::string big(sndbuf + 100, 'x');
  TEST_ASSERT_EQUAL_size_t(sndbuf, c.add(big.data(), big.size()));
  TEST_ASSERT_EQUAL_size_t(sndbuf, written(pcb).size());
  TEST_ASSERT_EQUAL_size_t(0, c.space());

  c.close();
}

static void test_write_add_queues_nothing_when_the_buffer_is_full(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  std::string full(c.space(), 'x');
  c.add(full.data(), full.size());

  TEST_ASSERT_EQUAL_size_t(0, c.add("more", 4));
  // The full-buffer case is rejected before lwIP is asked.
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_write", pcb));

  c.close();
}

static void test_write_add_of_zero_bytes_queues_nothing(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(0, c.add("hello", 0));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write", pcb));
  c.close();
}

static void test_write_add_of_null_queues_nothing(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(0, c.add(nullptr, 4));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write", pcb));
  c.close();
}

static void test_write_add_before_connect_queues_nothing(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_size_t(0, c.add("hello", 5));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
}

static void test_write_add_while_connecting_queues_nothing(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  TEST_ASSERT_EQUAL_size_t(0, c.add("hello", 5));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
  c.close();
}

static void test_write_add_after_close_queues_nothing(void) {
  AsyncClient c;
  establish(c);
  c.close();
  TEST_ASSERT_EQUAL_size_t(0, c.add("hello", 5));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
}

static void test_write_add_queues_nothing_when_lwip_rejects_the_write(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  faults().write_result = ERR_MEM;

  TEST_ASSERT_EQUAL_size_t(0, c.add("hello", 5));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_write", pcb));
  TEST_ASSERT_EQUAL_STRING("", written(pcb).c_str());

  c.close();
}

static void test_write_add_defaults_to_copying_the_data(void) {
  AsyncClient c;
  establish(c);
  c.add("hello", 5);
  // The default apiflags reach lwIP as TCP_WRITE_FLAG_COPY, so the caller's buffer
  // need not outlive the call.
  TEST_ASSERT_EQUAL_INT(TCP_WRITE_FLAG_COPY, (int)write_flags(0));
  c.close();
}

static void test_write_add_without_the_copy_flag_passes_it_through_unset(void) {
  AsyncClient c;
  establish(c);
  // Zero apiflags: lwIP keeps a reference to the caller's buffer rather than copying.
  c.add("hello", 5, 0);
  TEST_ASSERT_EQUAL_INT(0, (int)write_flags(0));
  c.close();
}

static void test_write_add_passes_the_more_flag_through(void) {
  AsyncClient c;
  establish(c);
  c.add("hello", 5, ASYNC_WRITE_FLAG_COPY | ASYNC_WRITE_FLAG_MORE);
  // ASYNC_WRITE_FLAG_MORE is lwIP's TCP_WRITE_FLAG_MORE: suppress PSH, more to come.
  TEST_ASSERT_EQUAL_INT(TCP_WRITE_FLAG_COPY | TCP_WRITE_FLAG_MORE, (int)write_flags(0));
  c.close();
}

// ---------------------------------------------------------------------------
// send()
// ---------------------------------------------------------------------------

static void test_write_several_adds_reach_the_pcb_in_order_on_one_send(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_EQUAL_size_t(3, c.add("one", 3));
  TEST_ASSERT_EQUAL_size_t(3, c.add("two", 3));
  TEST_ASSERT_EQUAL_size_t(5, c.add("three", 5));
  TEST_ASSERT_TRUE(c.send());

  TEST_ASSERT_EQUAL_STRING("onetwothree", written(pcb).c_str());
  TEST_ASSERT_EQUAL_size_t(3, count("tcp_write", pcb));
  // One flush for the batch, which is the whole point of add() + send().
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_output", pcb));

  c.close();
}

static void test_write_send_with_nothing_added_succeeds(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  // tcp_output() on a pcb with an empty send queue is a successful no-op in lwIP.
  TEST_ASSERT_TRUE(c.send());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_output", pcb));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write", pcb));
  c.close();
}

static void test_write_send_before_connect_fails(void) {
  AsyncClient c;
  TEST_ASSERT_FALSE(c.send());
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_output"));
}

static void test_write_send_after_close_fails(void) {
  AsyncClient c;
  establish(c);
  c.close();
  TEST_ASSERT_FALSE(c.send());
}

static void test_write_send_fails_when_tcp_output_fails(void) {
  AsyncClient c;
  establish(c);
  faults().output_result = ERR_MEM;
  TEST_ASSERT_FALSE(c.send());
  c.close();
}

// ---------------------------------------------------------------------------
// write()
// ---------------------------------------------------------------------------

static void test_write_queues_and_flushes_in_one_call(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_EQUAL_size_t(4, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_STRING("abcd", written(pcb).c_str());
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_write", pcb));
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_output", pcb));

  c.close();
}

static void test_write_truncates_to_the_available_space(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  const size_t sndbuf = c.space();

  std::string big(sndbuf * 2, 'x');
  TEST_ASSERT_EQUAL_size_t(sndbuf, c.write(big.data(), big.size()));
  TEST_ASSERT_EQUAL_size_t(sndbuf, written(pcb).size());

  // The rest is the caller's problem, and there is no room for it yet.
  TEST_ASSERT_EQUAL_size_t(0, c.write(big.data(), big.size()));
  TEST_ASSERT_EQUAL_size_t(sndbuf, written(pcb).size());

  c.close();
}

static void test_write_returns_zero_when_the_buffer_is_full(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  std::string full(c.space(), 'x');
  c.write(full.data(), full.size());

  TEST_ASSERT_EQUAL_size_t(0, c.write("more", 4));
  // Nothing was queued, so nothing should have been flushed for it either.
  TEST_ASSERT_EQUAL_size_t(1, count("tcp_output", pcb));

  c.close();
}

static void test_write_cstring_writes_the_whole_string(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(11, c.write("hello world"));
  TEST_ASSERT_EQUAL_STRING("hello world", written(pcb).c_str());
  c.close();
}

static void test_write_cstring_of_null_writes_nothing(void) {
  AsyncClient c;
  establish(c);
  TEST_ASSERT_EQUAL_size_t(0, c.write((const char *)nullptr));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
  c.close();
}

static void test_write_before_connect_writes_nothing(void) {
  AsyncClient c;
  TEST_ASSERT_EQUAL_size_t(0, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_output"));
}

static void test_write_while_connecting_writes_nothing(void) {
  AsyncClient c;
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  TEST_ASSERT_EQUAL_size_t(0, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
  c.close();
}

static void test_write_after_close_writes_nothing(void) {
  AsyncClient c;
  establish(c);
  c.close();
  TEST_ASSERT_EQUAL_size_t(0, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_write"));
}

static void test_write_after_a_reset_writes_nothing(void) {
  AsyncClient c;
  bool wrote = true;
  c.onError([&](void *, AsyncClient *cl, int8_t) {
    // The pcb is already freed by the time lwIP reports a fatal error, so the write
    // path has to notice that rather than follow a dangling pointer.
    wrote = cl->write("abcd", 4) != 0;
  });

  tcp_pcb *pcb = establish(c);
  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  TEST_ASSERT_FALSE(wrote);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_write_from_inside_on_disconnect_writes_nothing(void) {
  AsyncClient c;
  bool wrote = true;
  c.onDisconnect([&](void *, AsyncClient *cl) {
    wrote = cl->write("abcd", 4) != 0;
  });

  tcp_pcb *pcb = establish(c);
  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_FALSE(wrote);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

// tcp_output() failing does not unqueue what tcp_write() already accepted -- lwIP
// keeps it on the pcb and sends it with the next output or ack.  Reporting 0 tells
// the caller those bytes were dropped, so a caller that retries sends them twice.
static void test_write_reports_the_bytes_it_queued_when_output_fails(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  faults().output_result = ERR_MEM;

  TEST_ASSERT_EQUAL_size_t(4, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_STRING("abcd", written(pcb).c_str());

  c.close();
}

// lwIP also refuses a write when too many segments are already queued, however much
// buffer is left.  What write() reports has to be exactly what lwIP took.
static void test_write_reports_only_what_lwip_took_when_its_queue_is_full(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  size_t total = 0, n = 0;
  do {
    n = c.write("x", 1);
    total += n;
  } while (n && total < 1000);

  TEST_ASSERT_TRUE(total < 1000);
  TEST_ASSERT_EQUAL_size_t(written(pcb).size(), total);
  c.close();
}

static void test_write_succeeds_again_once_the_peer_acks_a_full_queue(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  size_t total = 0;
  while (total < 1000 && c.write("x", 1)) {
    total++;
  }

  fire_sent(pcb, 1);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(1, c.write("y", 1));
  TEST_ASSERT_EQUAL_size_t(total + 1, written(pcb).size());

  c.close();
}

static void test_write_after_the_peer_half_closes_is_queued(void) {
  // A request that ends with the peer's FIN still gets its reply: lwIP takes writes in
  // CLOSE_WAIT.
  AsyncClient c;
  size_t replied = 0;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    replied = cl->write("reply", 5);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "request", 7);
  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(5, replied);
  TEST_ASSERT_EQUAL_STRING("reply", written(pcb).c_str());
}

static void test_write_once_our_fin_is_out_writes_nothing(void) {
  // lwIP refuses writes once it has sent our FIN.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  pcb->state = FIN_WAIT_1;

  TEST_ASSERT_EQUAL_size_t(0, c.write("abcd", 4));
  TEST_ASSERT_EQUAL_STRING("", written(pcb).c_str());

  pcb->state = ESTABLISHED;
  c.close();
}

#if LWIP_WND_SCALE
// tcp_write() takes at most 65535 bytes at a time, though with window scaling the send
// buffer can hold more.
static void test_write_add_reports_what_lwip_took_from_a_wide_send_buffer(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  set_send_buffer(pcb, 100000);

  std::string big(100000, 'x');
  const size_t n = c.add(big.data(), big.size());
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_size_t(written(pcb).size(), n);

  c.close();
}

static void test_write_reports_what_lwip_took_from_a_wide_send_buffer(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  set_send_buffer(pcb, 70000);

  std::string big(70000, 'x');
  const size_t n = c.write(big.data(), big.size());
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_size_t(written(pcb).size(), n);

  c.close();
}

static void test_write_wide_send_buffer_is_filled_by_successive_writes(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  set_send_buffer(pcb, 100000);

  std::string big(100000, 'x');
  size_t total = 0, n = 0;
  do {
    n = c.write(big.data() + total, big.size() - total);
    total += n;
  } while (n && total < big.size());

  TEST_ASSERT_EQUAL_size_t(big.size(), total);
  TEST_ASSERT_EQUAL_size_t(big.size(), written(pcb).size());

  c.close();
}
#endif

// ---------------------------------------------------------------------------
// onAck
// ---------------------------------------------------------------------------

static void test_write_onAck_reports_the_acked_length(void) {
  AsyncClient c;
  size_t acked = 0;
  c.onAck([&](void *, AsyncClient *, size_t len, uint32_t) {
    acked = len;
  });

  tcp_pcb *pcb = establish(c);
  TEST_ASSERT_EQUAL_size_t(4, c.write("abcd", 4));

  fire_sent(pcb, 4);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(4, acked);

  c.close();
}

static void test_write_onAck_waits_for_the_async_task(void) {
  AsyncClient c;
  int acks = 0;
  c.onAck([&](void *, AsyncClient *, size_t, uint32_t) {
    acks++;
  });

  tcp_pcb *pcb = establish(c);
  c.write("abcd", 4);

  fire_sent(pcb, 4);
  TEST_ASSERT_EQUAL_INT(0, acks);  // queued, not delivered
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(1, acks);

  c.close();
}

static void test_write_onAck_fires_once_per_ack_across_several_sends(void) {
  AsyncClient c;
  std::vector<size_t> acked;
  c.onAck([&](void *, AsyncClient *, size_t len, uint32_t) {
    acked.push_back(len);
  });

  tcp_pcb *pcb = establish(c);

  TEST_ASSERT_EQUAL_size_t(3, c.write("abc", 3));
  fire_sent(pcb, 3);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(2, c.write("de", 2));
  fire_sent(pcb, 2);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(2, acked.size());
  TEST_ASSERT_EQUAL_size_t(3, acked[0]);
  TEST_ASSERT_EQUAL_size_t(2, acked[1]);

  c.close();
}

static void test_write_onAck_loses_nothing_when_two_acks_queue_together(void) {
  AsyncClient c;
  std::vector<size_t> acked;
  c.onAck([&](void *, AsyncClient *, size_t len, uint32_t) {
    acked.push_back(len);
  });

  tcp_pcb *pcb = establish(c);
  c.write("abcde", 5);

  // Unlike polls, no ack may be dropped: they may be merged, but every byte is reported.
  fire_sent(pcb, 2);
  fire_sent(pcb, 3);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(acked == std::vector<size_t>({5}) || acked == std::vector<size_t>({2, 3}));

  c.close();
}

static void test_write_onAck_reports_the_time_since_the_send(void) {
  AsyncClient c;
  uint32_t elapsed = 0xFFFFFFFF;
  c.onAck([&](void *, AsyncClient *, size_t, uint32_t t) {
    elapsed = t;
  });

  tcp_pcb *pcb = establish(c);

  mockclock::advance(100);
  c.write("abc", 3);  // onAck's elapsed time runs from here
  mockclock::advance(40);
  fire_sent(pcb, 3);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_UINT32(40, elapsed);

  // The start moves with each send, so the second ack is timed from the second one.
  mockclock::advance(500);
  c.write("de", 2);
  mockclock::advance(7);
  fire_sent(pcb, 2);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_UINT32(7, elapsed);

  c.close();
}

static void test_write_from_inside_onAck_does_not_deadlock(void) {
  AsyncClient c;
  int acks = 0;
  c.onAck([&](void *, AsyncClient *cl, size_t, uint32_t) {
    if (++acks == 1) {
      // Re-entering the write path from a callback is the classic deadlock shape.
      cl->write("more", 4);
    }
  });

  tcp_pcb *pcb = establish(c);
  c.write("abc", 3);
  fire_sent(pcb, 3);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("abcmore", written(pcb).c_str());
  TEST_ASSERT_EQUAL_UINT(0, mockrtos::deadlocks());

  c.close();
}

void run_write_tests(void) {
  UnitySetTestFile(__FILE__);

  RUN_TEST(test_write_space_is_zero_before_connect);
  RUN_TEST(test_write_space_is_zero_while_connecting);
  RUN_TEST(test_write_space_is_the_lwip_send_buffer_once_connected);
  RUN_TEST(test_write_space_is_zero_after_close);
  RUN_TEST(test_write_space_shrinks_by_what_was_queued);
  RUN_TEST(test_write_space_is_restored_when_the_peer_acks);

  RUN_TEST(test_write_canSend_is_false_before_connect);
  RUN_TEST(test_write_canSend_is_false_while_connecting);
  RUN_TEST(test_write_canSend_is_true_once_connected);
  RUN_TEST(test_write_canSend_is_false_when_the_send_buffer_is_full);
  RUN_TEST(test_write_canSend_is_false_after_close);

  RUN_TEST(test_write_add_returns_what_it_queued);
  RUN_TEST(test_write_add_does_not_output);
  RUN_TEST(test_write_add_beyond_space_queues_only_what_fits);
  RUN_TEST(test_write_add_queues_nothing_when_the_buffer_is_full);
  RUN_TEST(test_write_add_of_zero_bytes_queues_nothing);
  RUN_TEST(test_write_add_of_null_queues_nothing);
  RUN_TEST(test_write_add_before_connect_queues_nothing);
  RUN_TEST(test_write_add_while_connecting_queues_nothing);
  RUN_TEST(test_write_add_after_close_queues_nothing);
  RUN_TEST(test_write_add_queues_nothing_when_lwip_rejects_the_write);
  RUN_TEST(test_write_add_defaults_to_copying_the_data);
  RUN_TEST(test_write_add_without_the_copy_flag_passes_it_through_unset);
  RUN_TEST(test_write_add_passes_the_more_flag_through);

  RUN_TEST(test_write_several_adds_reach_the_pcb_in_order_on_one_send);
  RUN_TEST(test_write_send_with_nothing_added_succeeds);
  RUN_TEST(test_write_send_before_connect_fails);
  RUN_TEST(test_write_send_after_close_fails);
  RUN_TEST(test_write_send_fails_when_tcp_output_fails);

  RUN_TEST(test_write_queues_and_flushes_in_one_call);
  RUN_TEST(test_write_truncates_to_the_available_space);
  RUN_TEST(test_write_returns_zero_when_the_buffer_is_full);
  RUN_TEST(test_write_cstring_writes_the_whole_string);
  RUN_TEST(test_write_cstring_of_null_writes_nothing);
  RUN_TEST(test_write_before_connect_writes_nothing);
  RUN_TEST(test_write_while_connecting_writes_nothing);
  RUN_TEST(test_write_after_close_writes_nothing);
  RUN_TEST(test_write_after_a_reset_writes_nothing);
  RUN_TEST(test_write_from_inside_on_disconnect_writes_nothing);
  RUN_TEST(test_write_reports_the_bytes_it_queued_when_output_fails);
  RUN_TEST(test_write_reports_only_what_lwip_took_when_its_queue_is_full);
  RUN_TEST(test_write_succeeds_again_once_the_peer_acks_a_full_queue);
  RUN_TEST(test_write_after_the_peer_half_closes_is_queued);
  RUN_TEST(test_write_once_our_fin_is_out_writes_nothing);
#if LWIP_WND_SCALE
  RUN_TEST(test_write_add_reports_what_lwip_took_from_a_wide_send_buffer);
  RUN_TEST(test_write_reports_what_lwip_took_from_a_wide_send_buffer);
  RUN_TEST(test_write_wide_send_buffer_is_filled_by_successive_writes);
#endif

  RUN_TEST(test_write_onAck_reports_the_acked_length);
  RUN_TEST(test_write_onAck_waits_for_the_async_task);
  RUN_TEST(test_write_onAck_fires_once_per_ack_across_several_sends);
  RUN_TEST(test_write_onAck_loses_nothing_when_two_acks_queue_together);
  RUN_TEST(test_write_onAck_reports_the_time_since_the_send);
  RUN_TEST(test_write_from_inside_onAck_does_not_deadlock);
}
