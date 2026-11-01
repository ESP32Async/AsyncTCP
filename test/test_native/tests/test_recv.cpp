// AsyncClient inbound data path: onData, onPacket, and window management.

#include "fixtures.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "lwip/pbuf.h"
}

using namespace mocklwip;

namespace {

// Position of the first call to <fn> in the log, or SIZE_MAX if it never happened.
size_t call_index(const char *fn) {
  const std::vector<Call> &log = calls();
  for (size_t i = 0; i < log.size(); i++) {
    if (log[i].fn == fn) {
      return i;
    }
  }
  return SIZE_MAX;
}

// "aaa" + "bb" + "c": a three-segment chain, as lwIP would hand over reassembled
// out-of-order segments.
pbuf *three_segment_chain() {
  pbuf *p = make_pbuf("aaa", 3);
  pbuf_cat(p, make_pbuf("bb", 2));
  pbuf_cat(p, make_pbuf("c", 1));
  TEST_ASSERT_EQUAL_UINT16(6, p->tot_len);
  return p;
}

}  // namespace

// ---------------------------------------------------------------------------
// onData
// ---------------------------------------------------------------------------

static void test_recv_onData_delivers_the_payload_and_acks_the_window(void) {
  AsyncClient c;
  std::string got;
  c.onData([&](void *, AsyncClient *, void *data, size_t len) {
    got.assign((const char *)data, len);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "hello world", 11);
  TEST_ASSERT_EQUAL_STRING("", got.c_str());  // still queued
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("hello world", got.c_str());
  TEST_ASSERT_EQUAL_size_t(11, recved(pcb));
  // The library owns the pbuf in the onData path and must release it.
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_recv_with_no_handler_still_acks_the_window(void) {
  // No onData, no onPacket.  The data is dropped, but the window has to reopen or the
  // peer stalls for good.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "unwanted", 8);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(8, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_recv_delivers_each_packet_separately(void) {
  AsyncClient c;
  std::vector<std::string> got;
  c.onData([&](void *, AsyncClient *, void *data, size_t len) {
    got.push_back(std::string((const char *)data, len));
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "one", 3);
  fire_recv(pcb, "two", 3);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(2, got.size());
  TEST_ASSERT_EQUAL_STRING("one", got[0].c_str());
  TEST_ASSERT_EQUAL_STRING("two", got[1].c_str());
  TEST_ASSERT_EQUAL_size_t(6, recved(pcb));

  c.close();
}

static void test_recv_chain_is_delivered_in_order_and_in_full(void) {
  // A chain is split: onData runs once per segment, and between them the payload must
  // read back as the original byte stream.
  AsyncClient c;
  std::string got;
  int calls_made = 0;
  c.onData([&](void *, AsyncClient *, void *data, size_t len) {
    calls_made++;
    got.append((const char *)data, len);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv_pbuf(pcb, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(3, calls_made);
  TEST_ASSERT_EQUAL_STRING("aaabbc", got.c_str());
  TEST_ASSERT_EQUAL_size_t(6, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

// ---------------------------------------------------------------------------
// ackLater() / ack()
// ---------------------------------------------------------------------------

static void test_recv_ackLater_withholds_the_ack_until_ack_is_called(void) {
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    cl->ackLater();
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "0123456789", 10);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(0, recved(pcb));
  // Withholding the ack must not hold on to the pbuf: onData copied what it wanted.
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  TEST_ASSERT_EQUAL_size_t(10, c.ack(10));
  TEST_ASSERT_EQUAL_size_t(10, recved(pcb));

  c.close();
}

static void test_recv_partial_ack_leaves_the_rest_owed(void) {
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    cl->ackLater();
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "0123456789", 10);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(4, c.ack(4));
  TEST_ASSERT_EQUAL_size_t(4, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(6, c.ack(6));
  TEST_ASSERT_EQUAL_size_t(10, recved(pcb));

  c.close();
}

static void test_recv_ack_is_clamped_to_what_is_owed(void) {
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    cl->ackLater();
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "0123456789", 10);
  asynctcp_test_pump();

  // Acking more than arrived would reopen a window the peer never filled.
  TEST_ASSERT_EQUAL_size_t(10, c.ack(1000));
  TEST_ASSERT_EQUAL_size_t(10, recved(pcb));
  // ...and nothing is left owed.
  TEST_ASSERT_EQUAL_size_t(0, c.ack(10));
  TEST_ASSERT_EQUAL_size_t(10, recved(pcb));

  c.close();
}

static void test_recv_ack_without_ackLater_acks_nothing(void) {
  // The packet was already acked automatically; a stray ack() must not double-count it.
  AsyncClient c;
  c.onData([&](void *, AsyncClient *, void *, size_t) {});
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "abcde", 5);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_size_t(5, recved(pcb));

  TEST_ASSERT_EQUAL_size_t(0, c.ack(5));
  TEST_ASSERT_EQUAL_size_t(5, recved(pcb));

  c.close();
}

static void test_recv_ackLater_applies_only_to_the_current_packet(void) {
  // ackLater() is armed per packet, so the next one acks by itself.
  AsyncClient c;
  int packets = 0;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    if (++packets == 1) {
      cl->ackLater();
    }
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "abc", 3);
  fire_recv(pcb, "defg", 4);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(2, packets);
  TEST_ASSERT_EQUAL_size_t(4, recved(pcb));  // only the second

  TEST_ASSERT_EQUAL_size_t(3, c.ack(3));
  TEST_ASSERT_EQUAL_size_t(7, recved(pcb));

  c.close();
}

static void test_recv_close_from_onData_acks_the_packet_in_flight(void) {
  // Closing without acking what the application just consumed makes lwIP send an RST
  // rather than a FIN, so close() has to flush the packet it is standing on.
  AsyncClient c;
  tcp_pcb *pcb = establish(c);
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    cl->ackLater();
    cl->close();
  });

  fire_recv(pcb, "abcde", 5);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(5, recved(pcb));
  TEST_ASSERT_TRUE(call_index("tcp_recved") < call_index("tcp_close"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

// ---------------------------------------------------------------------------
// onPacket / ackPacket
// ---------------------------------------------------------------------------

static void test_recv_onPacket_receives_the_raw_pbuf(void) {
  AsyncClient c;
  std::string got;
  int packets = 0;
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    packets++;
    got.assign((const char *)pb->payload, pb->len);
    cl->ackPacket(pb);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "raw bytes", 9);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, packets);
  TEST_ASSERT_EQUAL_STRING("raw bytes", got.c_str());

  c.close();
}

static void test_recv_ackPacket_frees_the_pbuf_exactly_once(void) {
  // The whole point of the zero-copy path: the callback owns the pbuf, and ackPacket()
  // is the one and only release.  A second free shows up as a use-after-free under
  // ASan; a missing one shows up as a non-zero live_pbufs().
  AsyncClient c;
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    cl->ackPacket(pb);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "zero copy", 9);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(9, recved(pcb));

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_recv_onPacket_leaves_the_pbuf_to_the_callback(void) {
  // Documented contract: without ackPacket() nothing is freed and nothing is acked --
  // the application is holding the packet.
  AsyncClient c;
  pbuf *held = nullptr;
  c.onPacket([&](void *, AsyncClient *, pbuf *pb) {
    held = pb;
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "held", 4);
  asynctcp_test_pump();

  TEST_ASSERT_NOT_NULL(held);
  TEST_ASSERT_EQUAL_size_t(1, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(0, recved(pcb));

  c.ackPacket(held);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(4, recved(pcb));

  c.close();
}

static void test_recv_onPacket_takes_precedence_over_onData(void) {
  // "called if onPacket is not used" -- onData must stay silent, and the pbuf stays the
  // packet handler's, so nothing is freed or acked behind its back.
  AsyncClient c;
  int packets = 0, data_calls = 0;
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    packets++;
    cl->ackPacket(pb);
  });
  c.onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "either", 6);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, packets);
  TEST_ASSERT_EQUAL_INT(0, data_calls);
  TEST_ASSERT_EQUAL_size_t(6, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_recv_onPacket_sees_each_chain_segment_singly(void) {
  AsyncClient c;
  std::string got;
  int packets = 0;
  bool all_detached = true;
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    packets++;
    // Each segment is handed over on its own, so the callback can free it without
    // dragging the rest of the chain with it.
    all_detached = all_detached && (pb->next == nullptr);
    got.append((const char *)pb->payload, pb->len);
    cl->ackPacket(pb);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv_pbuf(pcb, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(3, packets);
  TEST_ASSERT_TRUE(all_detached);
  TEST_ASSERT_EQUAL_STRING("aaabbc", got.c_str());
  TEST_ASSERT_EQUAL_size_t(6, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
}

static void test_recv_onPacket_delivers_each_chain_unbroken_by_another_connection(void) {
  // Two chains on one connection, then a packet on another: that packet may come before,
  // between or after the chains, but never inside one.
  std::string log;
  auto record = [&](void *, AsyncClient *cl, pbuf *pb) {
    log.append((const char *)pb->payload, pb->len);
    cl->ackPacket(pb);
  };
  AsyncClient a;
  AsyncClient b;
  a.onPacket(record);
  b.onPacket(record);
  tcp_pcb *pa = establish(a);
  tcp_pcb *pb = establish(b);

  auto chain = [](const char *x, const char *y, const char *z) {
    pbuf *p = make_pbuf(x, 2);
    pbuf_cat(p, make_pbuf(y, 2));
    pbuf_cat(p, make_pbuf(z, 2));
    return p;
  };
  fire_recv_pbuf(pa, chain("a1", "a2", "a3"));
  fire_recv_pbuf(pa, chain("a4", "a5", "a6"));
  fire_recv(pb, "b1", 2);
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(log == "b1a1a2a3a4a5a6" || log == "a1a2a3b1a4a5a6" || log == "a1a2a3a4a5a6b1");
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  a.close();
  b.close();
}

static void test_recv_onPacket_delivers_a_self_consistent_pbuf(void) {
  // lwIP's invariant: tot_len is this pbuf plus everything chained after it, so the
  // last (here: only) pbuf of a chain has tot_len == len.  Splitting a chain is
  // pbuf_dechain(), which fixes tot_len up; a segment handed to onPacket with a stale
  // tot_len tells the application there are bytes after it that it can no longer reach.
  AsyncClient c;
  std::vector<uint16_t> lens, tot_lens;
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    lens.push_back(pb->len);
    tot_lens.push_back(pb->tot_len);
    cl->ackPacket(pb);
  });
  tcp_pcb *pcb = establish(c);

  fire_recv_pbuf(pcb, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(3, lens.size());
  for (size_t i = 0; i < lens.size(); i++) {
    TEST_ASSERT_EQUAL_UINT16(lens[i], tot_lens[i]);
  }

  c.close();
}

static void test_recv_ackPacket_after_close_still_frees_the_pbuf(void) {
  // There is no window left to reopen, but the packet is still the application's to
  // give back, and ackPacket() is the only way it can.
  AsyncClient c;
  pbuf *held = nullptr;
  c.onPacket([&](void *, AsyncClient *, pbuf *pb) {
    held = pb;
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "late", 4);
  asynctcp_test_pump();
  TEST_ASSERT_NOT_NULL(held);

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(1, live_pbufs());

  c.ackPacket(held);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(0, recved(pcb));
}

static void test_recv_ackPacket_ignores_a_null_pbuf(void) {
  AsyncClient c;
  tcp_pcb *pcb = establish(c);

  c.ackPacket(nullptr);
  TEST_ASSERT_EQUAL_size_t(0, count("tcp_recved", pcb));

  c.close();
}

// ---------------------------------------------------------------------------
// FIN and teardown
// ---------------------------------------------------------------------------

static void test_recv_data_before_fin_is_delivered_before_the_disconnect(void) {
  AsyncClient c;
  int order = 0, data_order = 0, disc_order = 0;
  std::string got;
  c.onData([&](void *, AsyncClient *, void *data, size_t len) {
    data_order = ++order;
    got.assign((const char *)data, len);
  });
  c.onDisconnect([&](void *, AsyncClient *) {
    disc_order = ++order;
  });
  tcp_pcb *pcb = establish(c);

  // Both arrive from lwIP before the async task gets a turn.
  fire_recv(pcb, "last words", 10);
  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_STRING("last words", got.c_str());
  TEST_ASSERT_EQUAL_INT(1, data_order);
  TEST_ASSERT_EQUAL_INT(2, disc_order);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_recv_fin_acks_data_withheld_by_ackLater(void) {
  // The application did consume the data, so the close has to carry the ack with it --
  // otherwise the peer sees unacknowledged data on a closing connection and resets.
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    cl->ackLater();
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "consumed", 8);
  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(8, recved(pcb));
  TEST_ASSERT_TRUE(call_index("tcp_recved") < call_index("tcp_close"));
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_recv_fin_alone_delivers_no_data(void) {
  // A NULL pbuf is lwIP's end-of-stream marker, not a zero-length packet.
  AsyncClient c;
  int data_calls = 0, packets = 0, disconnects = 0;
  c.onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    packets++;
    cl->ackPacket(pb);
  });
  c.onDisconnect([&](void *, AsyncClient *) {
    disconnects++;
  });
  tcp_pcb *pcb = establish(c);

  fire_fin(pcb);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(0, data_calls);
  TEST_ASSERT_EQUAL_INT(0, packets);
  TEST_ASSERT_EQUAL_INT(1, disconnects);
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_recv_queued_data_is_released_when_the_application_closes(void) {
  // The data is still waiting for the async task.  Closing drops it, and the pbuf has
  // to go with it.
  AsyncClient c;
  int data_calls = 0;
  c.onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "in flight", 9);
  TEST_ASSERT_EQUAL_size_t(1, live_pbufs());

  c.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, data_calls);
}

static void test_recv_queued_data_is_released_when_the_peer_resets(void) {
  AsyncClient c;
  int data_calls = 0, errors = 0;
  c.onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  c.onError([&](void *, AsyncClient *, int8_t) {
    errors++;
  });
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, "in flight", 9);
  TEST_ASSERT_EQUAL_size_t(1, live_pbufs());

  // The reset ends the connection before the data is delivered, so it never is.
  fire_error(pcb, ERR_RST);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, data_calls);
  TEST_ASSERT_EQUAL_INT(1, errors);
}

static void test_recv_after_close_reaches_nobody(void) {
  // close() takes the library's recv callback off the pcb and hands the pcb to lwIP, so
  // a late arrival has nowhere to go and nothing to leak.
  AsyncClient c;
  int data_calls = 0;
  c.onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  tcp_pcb *pcb = establish(c);

  c.close();
  TEST_ASSERT_NULL(c.pcb());

  TEST_ASSERT_EQUAL_INT((int)ERR_ARG, (int)fire_recv(pcb, "too late", 8));
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, data_calls);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

// ---------------------------------------------------------------------------
// The rest of a chain, when the callback tears the connection down partway through
// ---------------------------------------------------------------------------

static void test_recv_chain_is_abandoned_when_onData_closes(void) {
  AsyncClient c;
  int data_calls = 0;
  tcp_pcb *pcb = establish(c);
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    if (++data_calls == 1) {
      cl->close();
    }
  });

  fire_recv_pbuf(pcb, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, data_calls);
  // The two segments never delivered are the library's to free.
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  // Only the segment the application actually saw is acked.
  TEST_ASSERT_EQUAL_size_t(3, recved(pcb));
}

static void test_recv_chain_is_abandoned_when_onPacket_closes(void) {
  AsyncClient c;
  int packets = 0;
  tcp_pcb *pcb = establish(c);
  c.onPacket([&](void *, AsyncClient *cl, pbuf *pb) {
    packets++;
    cl->ackPacket(pb);
    cl->close();
  });

  fire_recv_pbuf(pcb, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_INT(1, packets);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(3, recved(pcb));
}

static void test_recv_chain_is_not_delivered_to_a_reconnected_client(void) {
  // The callback closes and reconnects, so the rest of the chain belongs to a pcb the
  // client has let go.  It must not be delivered, and its bytes must not be acked
  // against the connection that replaced it.
  AsyncClient c;
  AsyncClient decoy;
  int data_calls = 0;
  bool reconnected = false;
  tcp_pcb *first = establish(c);
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    if (++data_calls == 1) {
      cl->close();
      // The decoy takes the pcb address the close just freed.  Without it the allocator
      // hands the same address straight back, and the two connections' acks could not
      // be told apart.
      decoy.connect(kPeer, 9999);
      reconnected = cl->connect(kPeer, kPort);
    }
  });

  fire_recv_pbuf(first, three_segment_chain());
  asynctcp_test_pump();

  TEST_ASSERT_TRUE(reconnected);
  tcp_pcb *second = dialled_pcb();
  TEST_ASSERT_NOT_NULL(second);
  TEST_ASSERT_TRUE(second != first);

  TEST_ASSERT_EQUAL_INT(1, data_calls);
  TEST_ASSERT_EQUAL_size_t(3, recved(first));
  TEST_ASSERT_EQUAL_size_t(0, recved(second));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());

  c.close();
  decoy.close();
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

static void test_recv_empty_pbuf_is_not_acked_and_does_not_leak(void) {
  // Real lwIP never delivers a zero-length data pbuf, but the API takes one: it must
  // not reopen a window nobody consumed, and it must not leak.
  AsyncClient c;
  c.onData([&](void *, AsyncClient *, void *, size_t) {});
  tcp_pcb *pcb = establish(c);

  fire_recv(pcb, nullptr, 0);
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(0, recved(pcb));
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_TRUE(c.connected());

  c.close();
}

static void test_recv_client_destroyed_with_data_queued_leaks_nothing(void) {
  AsyncClient *c = new AsyncClient();
  int data_calls = 0;
  c->onData([&](void *, AsyncClient *, void *, size_t) {
    data_calls++;
  });
  tcp_pcb *pcb = establish(*c);

  fire_recv(pcb, "orphaned", 8);
  delete c;

  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_INT(0, data_calls);
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

void run_recv_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_recv_onData_delivers_the_payload_and_acks_the_window);
  RUN_TEST(test_recv_with_no_handler_still_acks_the_window);
  RUN_TEST(test_recv_delivers_each_packet_separately);
  RUN_TEST(test_recv_chain_is_delivered_in_order_and_in_full);
  RUN_TEST(test_recv_ackLater_withholds_the_ack_until_ack_is_called);
  RUN_TEST(test_recv_partial_ack_leaves_the_rest_owed);
  RUN_TEST(test_recv_ack_is_clamped_to_what_is_owed);
  RUN_TEST(test_recv_ack_without_ackLater_acks_nothing);
  RUN_TEST(test_recv_ackLater_applies_only_to_the_current_packet);
  RUN_TEST(test_recv_close_from_onData_acks_the_packet_in_flight);
  RUN_TEST(test_recv_onPacket_receives_the_raw_pbuf);
  RUN_TEST(test_recv_ackPacket_frees_the_pbuf_exactly_once);
  RUN_TEST(test_recv_onPacket_leaves_the_pbuf_to_the_callback);
  RUN_TEST(test_recv_onPacket_takes_precedence_over_onData);
  RUN_TEST(test_recv_onPacket_sees_each_chain_segment_singly);
  RUN_TEST(test_recv_onPacket_delivers_each_chain_unbroken_by_another_connection);
  RUN_TEST(test_recv_onPacket_delivers_a_self_consistent_pbuf);
  RUN_TEST(test_recv_ackPacket_after_close_still_frees_the_pbuf);
  RUN_TEST(test_recv_ackPacket_ignores_a_null_pbuf);
  RUN_TEST(test_recv_data_before_fin_is_delivered_before_the_disconnect);
  RUN_TEST(test_recv_fin_acks_data_withheld_by_ackLater);
  RUN_TEST(test_recv_fin_alone_delivers_no_data);
  RUN_TEST(test_recv_queued_data_is_released_when_the_application_closes);
  RUN_TEST(test_recv_queued_data_is_released_when_the_peer_resets);
  RUN_TEST(test_recv_after_close_reaches_nobody);
  RUN_TEST(test_recv_chain_is_abandoned_when_onData_closes);
  RUN_TEST(test_recv_chain_is_abandoned_when_onPacket_closes);
  RUN_TEST(test_recv_chain_is_not_delivered_to_a_reconnected_client);
  RUN_TEST(test_recv_empty_pbuf_is_not_acked_and_does_not_leak);
  RUN_TEST(test_recv_client_destroyed_with_data_queued_leaks_nothing);
}
