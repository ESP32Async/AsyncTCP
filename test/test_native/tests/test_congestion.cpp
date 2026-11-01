// A flooded event queue: many more events waiting than CONFIG_ASYNC_TCP_QUEUE_SIZE.
// Polls may be dropped or merged, and acks merged and moved among the data; nothing else
// may be dropped, repeated or reordered within a connection.

#include "fixtures.h"

#include <cstdio>
#include <deque>
#include <string>
#include <vector>

using namespace mocklwip;

namespace {

// Far more events than the queue is sized for.
const int kRounds = 4 * CONFIG_ASYNC_TCP_QUEUE_SIZE;

// Records like Recorder, and keeps every onData and every ack length.
struct Flooded {
  Recorder t;
  std::vector<std::string> got;   // each onData
  std::vector<size_t> acks;       // each onAck
  std::vector<std::string> sent;  // what the peer sent, in order
  size_t acked = 0;               // ... and how much of ours it acked

  void attach(AsyncClient &c) {
    t.attach(c, "CEDRP");
    c.onData([this](void *, AsyncClient *, void *d, size_t n) {
      t.seq += 'R';
      t.data.append((const char *)d, n);
      got.push_back(std::string((const char *)d, n));
    });
    c.onAck([this](void *, AsyncClient *, size_t n, uint32_t) {
      t.seq += 'A';
      acks.push_back(n);
    });
  }

  // The callbacks other than onPoll, in order.
  std::string without_polls() const {
    std::string s;
    for (char e : t.seq) {
      if (e != 'P') {
        s += e;
      }
    }
    return s;
  }

  // Every chunk arrived once and in order, the acks sum to what was acked, and the
  // connection opened first and ended with <end>.
  void check_lossless(const std::string &end, const char *msg) const {
    TEST_ASSERT_TRUE_MESSAGE(got == sent, msg);
    size_t sum = 0;
    for (size_t n : acks) {
      TEST_ASSERT_NOT_EQUAL_MESSAGE(0, n, msg);
      sum += n;
    }
    TEST_ASSERT_EQUAL_size_t_MESSAGE(acked, sum, msg);
    const std::string s = without_polls();
    const size_t traffic = got.size() + acks.size();
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1 + traffic + end.size(), s.size(), msg);
    TEST_ASSERT_EQUAL_CHAR_MESSAGE('C', s[0], msg);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(end.c_str(), s.substr(1 + traffic).c_str(), msg);
  }
};

// The i-th chunk a peer sends: varied in length so a dropped or repeated one shows.
std::string chunk(int i) {
  char buf[16];
  snprintf(buf, sizeof(buf), "<%d>", i);
  return std::string(buf) + std::string(i % 7, (char)('a' + i % 26));
}

// One round of traffic on one connection: data, an ack, a poll.
void round(tcp_pcb *pcb, Flooded &f, int i) {
  std::string d = chunk(i);
  fire_recv(pcb, d.data(), d.size());
  f.sent.push_back(d);
  const uint16_t n = (uint16_t)(1 + i % 13);
  fire_sent(pcb, n);
  f.acked += n;
  fire_poll(pcb);
}

}  // namespace

static void test_congestion_one_connection_loses_nothing_but_polls(void) {
  AsyncClient c;
  Flooded f;
  f.attach(c);
  tcp_pcb *pcb = establish(c);

  for (int i = 0; i < kRounds; i++) {
    round(pcb, f, i);
  }
  asynctcp_test_pump();
  size_t bytes = 0;
  for (const std::string &d : f.sent) {
    bytes += d.size();
  }
  TEST_ASSERT_EQUAL_size_t(bytes, recved(pcb));

  for (int i = 0; i < kRounds; i++) {
    fire_poll(pcb);
  }
  fire_fin(pcb);
  asynctcp_test_pump();

  f.check_lossless("D", "");
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_congestion_several_connections_each_lose_nothing_but_polls(void) {
  // Interleaved, and each ends differently: the peer closes, the peer resets, the
  // application closes, the application destroys the client.
  const int kClients = 4;
  std::deque<Flooded> f(kClients);
  AsyncClient *c[kClients];
  tcp_pcb *pcb[kClients];
  for (int k = 0; k < kClients; k++) {
    c[k] = new AsyncClient();
    f[k].attach(*c[k]);
    pcb[k] = establish(*c[k]);
  }

  for (int i = 0; i < kRounds; i++) {
    for (int k = 0; k < kClients; k++) {
      round(pcb[k], f[k], i * kClients + k);
    }
  }
  fire_fin(pcb[0]);
  asynctcp_test_pump();
  fire_error(pcb[1], ERR_RST);
  asynctcp_test_pump();
  c[2]->close();
  delete c[3];

  for (int k = 0; k < kClients; k++) {
    char msg[32];
    snprintf(msg, sizeof(msg), "client %d", k);
    f[k].check_lossless(k == 1 ? "ED" : "D", msg);
  }
  TEST_ASSERT_EQUAL_INT(ERR_RST, f[1].t.err);

  delete c[0];
  delete c[1];
  delete c[2];
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_congestion_terminal_events_queued_in_a_flood_arrive_once(void) {
  // Every connection's end is queued behind the flood before the task runs at all.
  const int kClients = 4;
  std::deque<Flooded> f(kClients);
  AsyncClient *c[kClients];
  tcp_pcb *pcb[kClients];
  for (int k = 0; k < kClients; k++) {
    c[k] = new AsyncClient();
    f[k].attach(*c[k]);
    pcb[k] = establish(*c[k]);
  }

  for (int i = 0; i < kRounds; i++) {
    for (int k = 0; k < kClients; k++) {
      fire_sent(pcb[k], 1);
      fire_poll(pcb[k]);
    }
  }
  fire_fin(pcb[0]);
  fire_error(pcb[1], ERR_RST);
  fire_fin(pcb[2]);
  fire_error(pcb[3], ERR_ABRT);
  asynctcp_test_pump();

  for (int k = 0; k < kClients; k++) {
    char msg[32];
    snprintf(msg, sizeof(msg), "client %d", k);
    const std::string s = f[k].without_polls();
    const std::string end = (k % 2) ? "ED" : "D";
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, f[k].t.count('D'), msg);
    TEST_ASSERT_TRUE_MESSAGE(s.size() >= end.size() && s.compare(s.size() - end.size(), end.size(), end) == 0, msg);
    delete c[k];
  }
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

static void test_congestion_accepts_and_their_data_all_arrive(void) {
  const int kConnections = 2 * CONFIG_ASYNC_TCP_QUEUE_SIZE;
  AsyncServer s(kServerPort);
  std::deque<Flooded> f;
  Accepted accepted(s, [&](AsyncClient *c) {
    f.emplace_back();
    f.back().attach(*c);
  });
  s.begin();

  std::vector<tcp_pcb *> conns;
  std::vector<std::string> sent;
  for (int i = 0; i < kConnections; i++) {
    tcp_pcb *pcb = fire_accept(listen_pcb(kServerPort));
    conns.push_back(pcb);
    sent.push_back(chunk(i));
    fire_recv(pcb, sent.back().data(), sent.back().size());
    fire_poll(pcb);
  }
  asynctcp_test_pump();

  TEST_ASSERT_EQUAL_size_t(kConnections, accepted.size());
  for (int i = 0; i < kConnections; i++) {
    AsyncClient *c = accepted.holding(conns[i]);
    TEST_ASSERT_NOT_NULL(c);
    size_t k = 0;
    while (accepted[k] != c) {
      k++;
    }
    TEST_ASSERT_EQUAL_STRING(sent[i].c_str(), f[k].t.data.c_str());
    TEST_ASSERT_EQUAL_STRING("R", f[k].without_polls().c_str());
  }

  accepted.clear();
  s.end();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
  TEST_ASSERT_EQUAL_size_t(0, live_pbufs());
}

static void test_congestion_idle_connection_is_polled_once_the_queue_drains(void) {
  AsyncClient busy;
  Flooded b;
  b.attach(busy);
  tcp_pcb *bp = establish(busy);
  AsyncClient idle;
  Recorder t;
  t.attach(idle, "CEDP");
  tcp_pcb *ip = establish(idle);

  for (int i = 0; i < kRounds; i++) {
    round(bp, b, i);
    fire_poll(ip);
  }
  asynctcp_test_pump();

  // lwIP polls every connection every poll interval, whatever the library did with the
  // last one.
  for (int i = 0; i < 4; i++) {
    fire_poll(ip);
    asynctcp_test_pump();
  }
  TEST_ASSERT_TRUE(t.count('P') >= 1);

  busy.close();
  idle.close();
}

static void test_congestion_idle_connection_times_out_once_the_queue_drains(void) {
  AsyncClient busy;
  Flooded b;
  b.attach(busy);
  tcp_pcb *bp = establish(busy);
  AsyncClient idle;
  Recorder t;
  t.attach(idle);
  tcp_pcb *ip = establish(idle);
  idle.setRxTimeout(1);
  mockclock::advance(1500);

  for (int i = 0; i < kRounds; i++) {
    round(bp, b, i);
    fire_poll(ip);
  }
  asynctcp_test_pump();
  for (int i = 0; i < 4 && is_live(ip); i++) {
    fire_poll(ip);
    asynctcp_test_pump();
  }

  TEST_ASSERT_EQUAL_STRING("CD", t.seq.c_str());
  TEST_ASSERT_FALSE(is_live(ip));

  busy.close();
  TEST_ASSERT_EQUAL_size_t(0, live_pcbs());
}

void run_congestion_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_congestion_one_connection_loses_nothing_but_polls);
  RUN_TEST(test_congestion_several_connections_each_lose_nothing_but_polls);
  RUN_TEST(test_congestion_terminal_events_queued_in_a_flood_arrive_once);
  RUN_TEST(test_congestion_accepts_and_their_data_all_arrive);
  RUN_TEST(test_congestion_idle_connection_is_polled_once_the_queue_drains);
  RUN_TEST(test_congestion_idle_connection_times_out_once_the_queue_drains);
}
