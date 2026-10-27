// Implementation of the mock lwIP stack.
//
// Behavior is modeled on real lwIP wherever it matters for AsyncTCP:
//   * tcp_abort() frees the pcb and *then* runs the error callback
//   * tcp_close() frees the pcb only when it returns ERR_OK, and what was written still
//     reaches the peer
//   * tcp_listen_with_backlog() frees the old pcb and returns a NEW one on
//     success, and returns NULL *without* freeing on failure
//   * a fatal error frees the pcb before the error callback sees it
//   * data the recv callback refuses stays with lwIP and is offered again
//   * a callback handed a pcb returns ERR_ABRT exactly when it aborted that pcb
// Those are exactly the edges AsyncTCP's lifetime handling gets wrong or right.

#include "mock_lwip.h"
#include "mock_rtos.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

extern "C" {
#include "lwip/inet.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/tcpip.h"
}

namespace {

std::vector<mocklwip::Call> g_calls;
std::set<tcp_pcb *> g_pcbs;
std::set<pbuf *> g_pbufs;
std::map<const tcp_pcb *, std::string> g_written;

// What tcp_write() has queued on a pcb and the peer has not yet acked, one entry per
// segment.  ESP-IDF builds lwIP with LWIP_NETIF_TX_SINGLE_PBUF, so every segment is one
// pbuf and every write is copied.
struct Segment {
  u16_t len;
  bool sent;  // handed to tcp_output(), so later writes start a new segment
};
struct SendQueue {
  std::deque<Segment> segs;
  size_t acked = 0;  // of the first segment
  // As lwIP built with TCP_SND_BUF == size would have them.
  tcpwnd_size_t size = TCP_SND_BUF;
  size_t max_segs = TCP_SND_QUEUELEN;
};
std::map<const tcp_pcb *, SendQueue> g_sendq;
std::set<uint16_t> g_ports;
std::map<const tcp_pcb *, uint16_t> g_pcb_port;  // ports this pcb holds
mocklwip::Faults g_faults;
uint16_t g_next_ephemeral = 49152;
int g_core_lock_depth = 0;
int g_on_lwip_thread = 0;  // inside tcpip_api_call() or a fire_* helper
unsigned g_reentrant_api_calls = 0;
unsigned g_unlocked_calls = 0;
std::string g_first_unlocked_call;
std::vector<const tcp_pcb *> g_aborted;  // every pcb tcp_abort() freed, in order
unsigned g_return_violations = 0;
std::string g_first_return_violation;

struct PendingDns {
  std::string host;
  dns_found_callback cb = nullptr;
  void *arg = nullptr;
};
std::vector<PendingDns> g_dns_queue;  // LwIP cannot cancel a lookup, so these accumulate

void rec(const char *fn, const void *pcb = nullptr, long a = 0, long b = 0) {
  g_calls.push_back(mocklwip::Call{fn, pcb, a, b});
}

// The raw API is only safe on the LwIP thread or under the TCPIP core lock.  Only the
// library calls tcp_* and dns_* functions; tests reach the mock through mocklwip.
void check_context(const char *fn) {
  if (g_on_lwip_thread > 0 || g_core_lock_depth > 0) {
    return;
  }
  if (g_unlocked_calls++ == 0) {
    g_first_unlocked_call = fn;
  }
}

void release_port(const tcp_pcb *pcb) {
  auto it = g_pcb_port.find(pcb);
  if (it != g_pcb_port.end()) {
    g_ports.erase(it->second);
    g_pcb_port.erase(it);
  }
}

tcp_pcb *alloc_pcb() {
  tcp_pcb *pcb = new tcp_pcb();
  memset(pcb, 0, sizeof(*pcb));
  pcb->state = CLOSED;
  pcb->mss = TCP_MSS;
  pcb->snd_buf = TCP_SND_BUF;
  IP_SET_TYPE_VAL(pcb->local_ip, IPADDR_TYPE_V4);
  IP_SET_TYPE_VAL(pcb->remote_ip, IPADDR_TYPE_V4);
  g_pcbs.insert(pcb);
  g_written.erase(pcb);  // left by a closed pcb at the same address
  return pcb;
}

void free_pcb(tcp_pcb *pcb) {
  if (!pcb) {
    return;
  }
  // tcp_pcb_purge()
  if (pcb->refused_data) {
    pbuf_free(pcb->refused_data);
  }
  release_port(pcb);
  g_written.erase(pcb);
  g_sendq.erase(pcb);
  g_pcbs.erase(pcb);
  delete pcb;
}

// tcp_abort(): frees the pcb and then reports ERR_ABRT through the error callback (except
// for LISTEN pcbs, which have no error callback path).
void abort_pcb(tcp_pcb *pcb) {
  tcp_err_fn errf = (pcb->state == LISTEN) ? nullptr : pcb->errf;
  void *arg = pcb->callback_arg;
  g_aborted.push_back(pcb);
  free_pcb(pcb);
  if (errf) {
    errf(arg, ERR_ABRT);
  }
}

const char *err_name(err_t err) {
  static const char *const names[] = {"ERR_OK",  "ERR_MEM",        "ERR_BUF", "ERR_TIMEOUT", "ERR_RTE",    "ERR_INPROGRESS",
                                      "ERR_VAL", "ERR_WOULDBLOCK", "ERR_USE", "ERR_ALREADY", "ERR_ISCONN", "ERR_CONN",
                                      "ERR_IF",  "ERR_ABRT",       "ERR_RST", "ERR_CLSD",    "ERR_ARG"};
  return (err <= 0 && err >= ERR_ARG) ? names[-err] : "an unknown err_t";
}

// A callback handed a pcb tells lwIP by its return whether the pcb survived: ERR_ABRT
// if and only if it called tcp_abort() on it (tcp_abort() in tcp.c).  On anything else
// lwIP goes on using the pcb -- tcp_input(), tcp_process(), tcp_slowtmr() -- and on
// ERR_ABRT it never touches it again.  Returns whether <pcb> was aborted since g_aborted
// held <mark> entries.
bool check_return(const char *cb, const tcp_pcb *pcb, size_t mark, err_t r) {
  const bool aborted = std::find(g_aborted.begin() + mark, g_aborted.end(), pcb) != g_aborted.end();
  if (aborted != (r == ERR_ABRT) && g_return_violations++ == 0) {
    g_first_return_violation = std::string(cb) + " callback returned " + err_name(r) + ", pcb "
                               + (aborted ? "freed (lwIP would use it after free)" : "alive (lwIP would treat it as freed)");
  }
  return aborted;
}

}  // namespace

// ===========================================================================
// pbuf
// ===========================================================================
extern "C" struct pbuf *pbuf_alloc(pbuf_layer, u16_t length, pbuf_type) {
  pbuf *p = new pbuf();
  memset(p, 0, sizeof(*p));
  p->payload = length ? ::operator new(length) : nullptr;
  if (p->payload) {
    memset(p->payload, 0, length);
  }
  p->len = length;
  p->tot_len = length;
  p->ref = 1;
  g_pbufs.insert(p);
  rec("pbuf_alloc", nullptr, length);
  return p;
}

extern "C" u8_t pbuf_free(struct pbuf *p) {
  u8_t freed = 0;
  while (p) {
    if (p->ref > 0) {
      p->ref--;
    }
    if (p->ref != 0) {
      break;
    }
    pbuf *next = p->next;
    if (p->payload) {
      ::operator delete(p->payload);
    }
    g_pbufs.erase(p);
    delete p;
    freed++;
    p = next;
  }
  return freed;
}

extern "C" void pbuf_cat(struct pbuf *head, struct pbuf *tail) {
  if (!head || !tail) {
    return;
  }
  pbuf *p = head;
  while (p->next) {
    p->tot_len = (u16_t)(p->tot_len + tail->tot_len);
    p = p->next;
  }
  p->tot_len = (u16_t)(p->tot_len + tail->tot_len);
  p->next = tail;
}

// ===========================================================================
// tcp
// ===========================================================================
extern "C" struct tcp_pcb *tcp_new_ip_type(u8_t type) {
  check_context("tcp_new_ip_type");
  if (g_faults.fail_tcp_new > 0) {
    g_faults.fail_tcp_new--;
    rec("tcp_new_ip_type", nullptr, type);
    return nullptr;
  }
  tcp_pcb *pcb = alloc_pcb();
  IP_SET_TYPE_VAL(pcb->local_ip, type);
  IP_SET_TYPE_VAL(pcb->remote_ip, type);
  rec("tcp_new_ip_type", pcb, type);
  return pcb;
}

extern "C" void tcp_arg(struct tcp_pcb *pcb, void *arg) {
  check_context("tcp_arg");
  rec("tcp_arg", pcb, (long)(intptr_t)arg);
  if (pcb) {
    pcb->callback_arg = arg;
  }
}

extern "C" void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv) {
  check_context("tcp_recv");
  rec("tcp_recv", pcb, recv ? 1 : 0);
  if (pcb) {
    pcb->recv = recv;
  }
}

extern "C" void tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent) {
  check_context("tcp_sent");
  rec("tcp_sent", pcb, sent ? 1 : 0);
  if (pcb) {
    pcb->sent = sent;
  }
}

extern "C" void tcp_err(struct tcp_pcb *pcb, tcp_err_fn err) {
  check_context("tcp_err");
  rec("tcp_err", pcb, err ? 1 : 0);
  if (pcb) {
    pcb->errf = err;
  }
}

extern "C" void tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept) {
  check_context("tcp_accept");
  rec("tcp_accept", pcb, accept ? 1 : 0);
  if (pcb) {
    pcb->accept = accept;
  }
}

extern "C" void tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval) {
  check_context("tcp_poll");
  rec("tcp_poll", pcb, poll ? 1 : 0, interval);
  if (pcb) {
    pcb->poll = poll;
  }
}

extern "C" err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
  check_context("tcp_bind");
  rec("tcp_bind", pcb, port, ipaddr ? (long)ip_addr_get_ip4_u32(ipaddr) : 0);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.bind_result != ERR_OK) {
    return g_faults.bind_result;
  }
  if (port == 0) {
    port = g_next_ephemeral++;
  }
  if (g_ports.count(port)) {
    return ERR_USE;
  }
  if (ipaddr) {
    pcb->local_ip = *ipaddr;
  }
  pcb->local_port = port;
  g_ports.insert(port);
  g_pcb_port[pcb] = port;
  return ERR_OK;
}

extern "C" struct tcp_pcb *tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog) {
  check_context("tcp_listen_with_backlog");
  rec("tcp_listen_with_backlog", pcb, backlog);
  if (!pcb) {
    return nullptr;
  }
  if (g_faults.listen_returns_null) {
    // Real lwIP leaves the caller's pcb alone when it cannot allocate the
    // listen pcb. Whoever called us still owns it.
    return nullptr;
  }
  // Real lwIP swaps the pcb for a smaller listen pcb and frees the original.
  tcp_pcb *lpcb = alloc_pcb();
  lpcb->local_ip = pcb->local_ip;
  lpcb->local_port = pcb->local_port;
  lpcb->callback_arg = pcb->callback_arg;
  lpcb->state = LISTEN;
  // Move the port reservation across before freeing the old pcb.
  auto it = g_pcb_port.find(pcb);
  if (it != g_pcb_port.end()) {
    g_pcb_port[lpcb] = it->second;
    g_pcb_port.erase(it);
  }
  g_written.erase(pcb);
  g_sendq.erase(pcb);
  g_pcbs.erase(pcb);
  delete pcb;
  return lpcb;
}

extern "C" err_t tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port, tcp_connected_fn connected) {
  check_context("tcp_connect");
  rec("tcp_connect", pcb, port, ipaddr ? (long)ip_addr_get_ip4_u32(ipaddr) : 0);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.connect_result != ERR_OK) {
    // lwIP does NOT free the pcb on a failed connect; the caller still owns it.
    return g_faults.connect_result;
  }
  if (ipaddr) {
    pcb->remote_ip = *ipaddr;
  }
  pcb->remote_port = port;
  pcb->connected = connected;
  pcb->state = SYN_SENT;
  if (pcb->local_port == 0) {
    uint16_t p = g_next_ephemeral++;
    pcb->local_port = p;
    g_ports.insert(p);
    g_pcb_port[pcb] = p;
  }
  return ERR_OK;
}

extern "C" err_t tcp_close(struct tcp_pcb *pcb) {
  check_context("tcp_close");
  rec("tcp_close", pcb, pcb ? (long)pcb->state : -1);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.close_result != ERR_OK) {
    return g_faults.close_result;  // pcb stays allocated, as on the target
  }
  // lwIP keeps the pcb until the peer acks our FIN, so queued data goes out first.
  auto sent = g_written.extract(pcb);
  free_pcb(pcb);
  if (sent) {
    g_written.insert(std::move(sent));
  }
  return ERR_OK;
}

extern "C" void tcp_abort(struct tcp_pcb *pcb) {
  check_context("tcp_abort");
  rec("tcp_abort", pcb, pcb ? (long)pcb->state : -1);
  if (pcb) {
    abort_pcb(pcb);
  }
}

extern "C" err_t tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len, u8_t apiflags) {
  check_context("tcp_write");
  rec("tcp_write", pcb, len, apiflags);
  if (!pcb || !dataptr) {
    return ERR_ARG;
  }
  if (g_faults.write_result != ERR_OK) {
    return g_faults.write_result;
  }
  // tcp_write_checks()
  if (pcb->state != ESTABLISHED && pcb->state != CLOSE_WAIT && pcb->state != SYN_SENT && pcb->state != SYN_RCVD) {
    return ERR_CONN;
  }
  if (len == 0) {
    return ERR_OK;
  }
  SendQueue &q = g_sendq[pcb];
  if (len > pcb->snd_buf || pcb->snd_queuelen >= q.max_segs) {
    return ERR_MEM;
  }
  // tcp_write(): top up the last unsent segment to the MSS, then add segments, failing
  // with nothing queued if that takes more than TCP_SND_QUEUELEN.
  u16_t topup = 0;
  if (!q.segs.empty() && !q.segs.back().sent) {
    topup = (u16_t)std::min<int>(pcb->mss - q.segs.back().len, len);
  }
  std::vector<u16_t> added;
  for (int left = len - topup; left > 0; left -= pcb->mss) {
    added.push_back((u16_t)std::min<int>(left, pcb->mss));
  }
  if (pcb->snd_queuelen + added.size() > q.max_segs) {
    return ERR_MEM;
  }
  if (topup) {
    q.segs.back().len = (u16_t)(q.segs.back().len + topup);
  }
  for (u16_t n : added) {
    q.segs.push_back(Segment{n, false});
  }
  pcb->snd_queuelen = (u16_t)(pcb->snd_queuelen + added.size());
  g_written[pcb].append((const char *)dataptr, len);
  pcb->snd_buf -= len;
  return ERR_OK;
}

extern "C" err_t tcp_output(struct tcp_pcb *pcb) {
  check_context("tcp_output");
  rec("tcp_output", pcb);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.output_result == ERR_OK) {
    for (Segment &seg : g_sendq[pcb].segs) {
      seg.sent = true;
    }
  }
  return g_faults.output_result;
}

extern "C" void tcp_recved(struct tcp_pcb *pcb, u16_t len) {
  check_context("tcp_recved");
  rec("tcp_recved", pcb, len);
}

// ===========================================================================
// dns
// ===========================================================================
extern "C" err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg) {
  check_context("dns_gethostbyname");
  rec("dns_gethostbyname");
  if (g_faults.dns_result == ERR_OK) {
    if (addr) {
      memset(addr, 0, sizeof(*addr));
      ip_addr_set_ip4_u32(addr, g_faults.dns_addr);
    }
    return ERR_OK;
  }
  if (g_faults.dns_result == ERR_INPROGRESS && g_faults.dns_fails_inside_the_call) {
    // dns_enqueue() -> dns_call_found(NULL); the task, on another core, need not wait.
    found(hostname, nullptr, callback_arg);
    asynctcp_test_pump();
    return ERR_INPROGRESS;
  }
  if (g_faults.dns_result == ERR_INPROGRESS) {
    PendingDns p;
    p.host = hostname ? hostname : "";
    p.cb = found;
    p.arg = callback_arg;
    g_dns_queue.push_back(p);
    return ERR_INPROGRESS;
  }
  return g_faults.dns_result;
}

// ===========================================================================
// tcpip_api_call and the core lock
// ===========================================================================
/*
  Real tcpip_api_call() either takes the core lock or posts to the LwIP mailbox and waits
  for it.  Called from the LwIP thread itself it deadlocks - on the lock, or waiting for a
  message only that thread could drain.  Here it just calls straight through, so nothing
  would go wrong and the bug would be invisible.  Count it instead; the runner fails the
  test if it ever happens.
*/
extern "C" err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *call) {
  rec("tcpip_api_call");
  if (g_on_lwip_thread) {
    ++g_reentrant_api_calls;
  }
  ++g_on_lwip_thread;
  err_t r = fn(call);
  --g_on_lwip_thread;
#if !LWIP_TCPIP_CORE_LOCKING
  // The LwIP thread ran fn and posts its result back.
  call->err = r;
#endif
  return r;
}

// Scope guard for the fire_* helpers: while one runs we are standing in for the LwIP
// thread, so an api call made underneath it is the same deadlock.
namespace {
struct on_lwip_thread {
  on_lwip_thread() {
    ++g_on_lwip_thread;
  }
  ~on_lwip_thread() {
    --g_on_lwip_thread;
  }
};
}  // namespace

extern "C" int sys_thread_tcpip(int) {
  // The LwIP thread holds the core lock while it runs callbacks.
  return (g_on_lwip_thread > 0 || g_core_lock_depth > 0) ? 1 : 0;
}

extern "C" void mock_lock_tcpip_core(void) {
  g_core_lock_depth++;
}

extern "C" void mock_unlock_tcpip_core(void) {
  if (g_core_lock_depth > 0) {
    g_core_lock_depth--;
  }
}

int mocklwip::core_lock_depth() {
  return g_core_lock_depth;
}

// ===========================================================================
// Test-facing API
// ===========================================================================
namespace mocklwip {

const std::vector<Call> &calls() {
  return g_calls;
}

size_t count(const char *fn) {
  size_t n = 0;
  for (const Call &c : g_calls) {
    if (c.fn == fn) {
      n++;
    }
  }
  return n;
}

size_t count(const char *fn, const void *pcb) {
  size_t n = 0;
  for (const Call &c : g_calls) {
    if (c.fn == fn && c.pcb == pcb) {
      n++;
    }
  }
  return n;
}

bool saw(const char *fn, const void *pcb, long a) {
  for (const Call &c : g_calls) {
    if (c.fn == fn && c.pcb == pcb && c.a == a) {
      return true;
    }
  }
  return false;
}

const Call *nth(const char *fn, size_t n) {
  for (const Call &c : g_calls) {
    if (c.fn == fn && n-- == 0) {
      return &c;
    }
  }
  return nullptr;
}

size_t recved(const tcp_pcb *pcb) {
  size_t total = 0;
  for (const Call &c : g_calls) {
    if (c.fn == "tcp_recved" && c.pcb == pcb) {
      total += (size_t)c.a;
    }
  }
  return total;
}

void reset() {
  // Swapped rather than cleared: a stale pointer left in the buffer would hide a leak.
  std::vector<mocklwip::Call>().swap(g_calls);
  for (pbuf *p : std::set<pbuf *>(g_pbufs)) {
    if (p->payload) {
      ::operator delete(p->payload);
    }
    delete p;
  }
  g_pbufs.clear();
  for (tcp_pcb *p : std::set<tcp_pcb *>(g_pcbs)) {
    delete p;
  }
  g_pcbs.clear();
  g_written.clear();
  g_sendq.clear();
  g_ports.clear();
  g_pcb_port.clear();
  g_faults = Faults{};
  std::vector<PendingDns>().swap(g_dns_queue);
  g_reentrant_api_calls = 0;
  g_unlocked_calls = 0;
  g_first_unlocked_call.clear();
  std::vector<const tcp_pcb *>().swap(g_aborted);
  g_return_violations = 0;
  g_first_return_violation.clear();
  g_on_lwip_thread = 0;
  g_next_ephemeral = 49152;
  g_core_lock_depth = 0;
}

size_t live_pcbs() {
  return g_pcbs.size();
}

std::vector<tcp_pcb *> pcbs() {
  return std::vector<tcp_pcb *>(g_pcbs.begin(), g_pcbs.end());
}

bool is_live(const tcp_pcb *pcb) {
  return g_pcbs.count(const_cast<tcp_pcb *>(pcb)) != 0;
}

tcp_pcb *dialled_pcb() {
  for (auto it = g_calls.rbegin(); it != g_calls.rend(); ++it) {
    if (it->fn == "tcp_connect") {
      return const_cast<tcp_pcb *>(static_cast<const tcp_pcb *>(it->pcb));
    }
  }
  return nullptr;
}

size_t live_pbufs() {
  return g_pbufs.size();
}

std::vector<uint16_t> bound_ports() {
  return std::vector<uint16_t>(g_ports.begin(), g_ports.end());
}

bool port_is_bound(uint16_t port) {
  return g_ports.count(port) != 0;
}

std::string written(const tcp_pcb *pcb) {
  auto it = g_written.find(pcb);
  return it == g_written.end() ? std::string() : it->second;
}

Faults &faults() {
  return g_faults;
}

void set_send_buffer(tcp_pcb *pcb, uint32_t size) {
  SendQueue &q = g_sendq[pcb];
  q.size = (tcpwnd_size_t)size;
  q.max_segs = (4 * size + (TCP_MSS - 1)) / TCP_MSS;  // lwIP's default TCP_SND_QUEUELEN
  pcb->snd_buf = (tcpwnd_size_t)size;
}

pbuf *make_pbuf(const void *data, size_t len) {
  pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
  if (p && data && len) {
    memcpy(p->payload, data, len);
  }
  return p;
}

err_t fire_connected(tcp_pcb *pcb, err_t err) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  if (err == ERR_OK) {
    pcb->state = ESTABLISHED;
  }
  if (!pcb->connected) {
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->connected(pcb->callback_arg, pcb, err);
  check_return("connected", pcb, mark, r);
  return r;
}

void fire_error(tcp_pcb *pcb, err_t err) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    return;
  }
  tcp_err_fn errf = pcb->errf;
  void *arg = pcb->callback_arg;
  // lwIP has already released the pcb by the time the callback runs.
  free_pcb(pcb);
  if (errf) {
    errf(arg, err);
  }
}

// tcp_process_refused_data()
err_t retry_refused(tcp_pcb *pcb) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb) || !pcb->refused_data) {
    return ERR_OK;
  }
  pbuf *p = pcb->refused_data;
  pcb->refused_data = nullptr;
  if (!pcb->recv) {
    pbuf_free(p);
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->recv(pcb->callback_arg, pcb, p, ERR_OK);
  check_return("recv", pcb, mark, r);
  if (r != ERR_OK && r != ERR_ABRT && is_live(pcb)) {
    pcb->refused_data = p;
    return ERR_INPROGRESS;
  }
  return r;
}

err_t fire_recv_pbuf(tcp_pcb *pcb, pbuf *p, err_t err) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    if (p) {
      pbuf_free(p);
    }
    return ERR_ARG;
  }
  // tcp_input(): refused data goes first, and while it is still refused a new segment is
  // dropped for the peer to send again.
  if (pcb->refused_data) {
    err_t r = retry_refused(pcb);
    if (r != ERR_OK) {
      if (p) {
        pbuf_free(p);
      }
      return r;
    }
  }
  if (!pcb->recv) {
    if (p) {
      pbuf_free(p);
    }
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->recv(pcb->callback_arg, pcb, p, err);
  check_return("recv", pcb, mark, r);
  // tcp_input(): anything but ERR_OK or ERR_ABRT leaves the pbuf with lwIP.
  if (r != ERR_OK && r != ERR_ABRT && is_live(pcb)) {
    pcb->refused_data = p;
  }
  return r;
}

err_t fire_recv(tcp_pcb *pcb, const void *data, size_t len, err_t err) {
  return fire_recv_pbuf(pcb, make_pbuf(data, len), err);
}

err_t fire_fin(tcp_pcb *pcb, err_t err) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  // As for data, a FIN behind refused data is dropped until that data is taken.
  if (pcb->refused_data) {
    err_t r = retry_refused(pcb);
    if (r != ERR_OK) {
      return r;
    }
  }
  if (pcb->state == ESTABLISHED) {
    pcb->state = CLOSE_WAIT;
  }
  if (!pcb->recv) {
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->recv(pcb->callback_arg, pcb, nullptr, err);
  check_return("recv", pcb, mark, r);
  return r;
}

err_t fire_sent(tcp_pcb *pcb, uint16_t len) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  // tcp_receive(): a segment leaves the queue once all of it is acked.
  SendQueue &q = g_sendq[pcb];
  pcb->snd_buf = (pcb->snd_buf + len > q.size) ? q.size : pcb->snd_buf + len;
  q.acked += len;
  while (!q.segs.empty() && q.acked >= q.segs.front().len) {
    q.acked -= q.segs.front().len;
    q.segs.pop_front();
    pcb->snd_queuelen--;
  }
  if (q.segs.empty()) {
    q.acked = 0;
  }
  if (!pcb->sent) {
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->sent(pcb->callback_arg, pcb, len);
  check_return("sent", pcb, mark, r);
  return r;
}

err_t fire_poll(tcp_pcb *pcb) {
  on_lwip_thread lwip;
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  if (!pcb->poll) {
    return ERR_OK;
  }
  const size_t mark = g_aborted.size();
  err_t r = pcb->poll(pcb->callback_arg, pcb);
  check_return("poll", pcb, mark, r);
  return r;
}

tcp_pcb *fire_accept(tcp_pcb *listen_pcb, err_t err) {
  ip_addr_t peer;
  memset(&peer, 0, sizeof(peer));
  ip_addr_set_ip4_u32_val(peer, 0x0A000002);  // 10.0.0.2
  return fire_accept(listen_pcb, peer, 40000, err);
}

tcp_pcb *fire_accept(tcp_pcb *listen_pcb, const ip_addr_t &peer, uint16_t port, err_t err) {
  on_lwip_thread lwip;
  if (!listen_pcb || !is_live(listen_pcb) || !listen_pcb->accept) {
    return nullptr;
  }
  tcp_pcb *newpcb = alloc_pcb();
  newpcb->state = ESTABLISHED;
  newpcb->local_ip = listen_pcb->local_ip;
#if LWIP_IPV6
  if (listen_pcb->local_ip.type == IPADDR_TYPE_ANY) {
    newpcb->local_ip.type = peer.type;  // a dual-stack listener answers in the peer's family
  }
#endif
  newpcb->local_port = listen_pcb->local_port;
  newpcb->remote_ip = peer;
  newpcb->remote_port = port;
  rec("accept_offered", newpcb, err);
  const size_t mark = g_aborted.size();
  err_t r = listen_pcb->accept(listen_pcb->callback_arg, newpcb, err);
  // tcp_process(), SYN_RCVD: any other error and lwIP aborts the pcb itself.
  if (!check_return("accept", newpcb, mark, r) && r != ERR_OK && r != ERR_ABRT && is_live(newpcb)) {
    abort_pcb(newpcb);
  }
  return newpcb;
}

void fire_accept_failure(tcp_pcb *listen_pcb, err_t err) {
  on_lwip_thread lwip;
  if (!listen_pcb || !is_live(listen_pcb) || !listen_pcb->accept) {
    return;
  }
  rec("accept_offered", nullptr, err);
  listen_pcb->accept(listen_pcb->callback_arg, nullptr, err);
}

tcp_pcb *fire_raw_accept(const std::function<err_t(tcp_pcb *)> &accept) {
  on_lwip_thread lwip;
  tcp_pcb *newpcb = alloc_pcb();
  newpcb->state = ESTABLISHED;
  ip_addr_set_ip4_u32_val(newpcb->remote_ip, 0x0A000002);  // 10.0.0.2
  newpcb->remote_port = 40000;
  rec("accept_offered", newpcb, ERR_OK);
  const size_t mark = g_aborted.size();
  err_t r = accept(newpcb);
  if (!check_return("accept", newpcb, mark, r) && r != ERR_OK && r != ERR_ABRT && is_live(newpcb)) {
    abort_pcb(newpcb);
  }
  return newpcb;
}

unsigned reentrant_api_calls() {
  return g_reentrant_api_calls;
}

unsigned unlocked_calls() {
  return g_unlocked_calls;
}

const char *first_unlocked_call() {
  return g_first_unlocked_call.c_str();
}

unsigned callback_return_violations() {
  return g_return_violations;
}

const char *first_callback_return_violation() {
  return g_first_return_violation.c_str();
}

bool dns_pending() {
  return !g_dns_queue.empty();
}

size_t dns_pending_count() {
  return g_dns_queue.size();
}

std::string dns_pending_host() {
  return g_dns_queue.empty() ? std::string() : g_dns_queue.front().host;
}

// Fires the oldest outstanding lookup, as a resolver working through its queue would.
void fire_dns(uint32_t addr) {
  ip_addr_t a;
  memset(&a, 0, sizeof(a));
  ip_addr_set_ip4_u32_val(a, addr);
  fire_dns(a);
}

void fire_dns(const ip_addr_t &addr) {
  on_lwip_thread lwip;
  if (g_dns_queue.empty()) {
    return;
  }
  ip_addr_t a = addr;
  PendingDns p = g_dns_queue.front();
  g_dns_queue.erase(g_dns_queue.begin());
  if (p.cb) {
    p.cb(p.host.c_str(), &a, p.arg);
  }
}

void fire_dns_failure() {
  on_lwip_thread lwip;
  if (g_dns_queue.empty()) {
    return;
  }
  PendingDns p = g_dns_queue.front();
  g_dns_queue.erase(g_dns_queue.begin());
  if (p.cb) {
    p.cb(p.host.c_str(), nullptr, p.arg);
  }
}

}  // namespace mocklwip
