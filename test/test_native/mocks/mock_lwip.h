// Test-facing control surface for the mock lwIP stack.
//
// This header is for tests only -- the library never sees it.
#ifndef ASYNCTCP_MOCK_LWIP_H
#define ASYNCTCP_MOCK_LWIP_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

extern "C" {
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
}

namespace mocklwip {

// ---------------------------------------------------------------------------
// Call recording
// ---------------------------------------------------------------------------
struct Call {
  std::string fn;   // "tcp_close", "tcp_recved", ...
  const void *pcb;  // pcb the call targeted, or nullptr
  long a;           // first scalar argument (len, port, backlog, err, ...)
  long b;           // second scalar argument (apiflags, ...)
};

const std::vector<Call> &calls();
size_t count(const char *fn);
size_t count(const char *fn, const void *pcb);
// True if <fn> was called on <pcb> with first scalar argument == a.
bool saw(const char *fn, const void *pcb, long a);
// Nth (0-based) recorded call to <fn>, or nullptr.
const Call *nth(const char *fn, size_t n);
// Total bytes handed to tcp_recved() for <pcb>: how much window was reopened.
size_t recved(const tcp_pcb *pcb);

// ---------------------------------------------------------------------------
// Resource accounting
// ---------------------------------------------------------------------------
void reset();  // free everything and clear the log; call between tests

size_t live_pcbs();
std::vector<tcp_pcb *> pcbs();
bool is_live(const tcp_pcb *pcb);
// The pcb handed to the most recent tcp_connect(), or nullptr. It may since have been
// freed, so check is_live() before dereferencing.
tcp_pcb *dialled_pcb();
size_t live_pbufs();
// Ports currently held by a bound or listening pcb.
std::vector<uint16_t> bound_ports();
bool port_is_bound(uint16_t port);

// Everything a pcb was handed to tcp_write(), in order, kept after tcp_close().
std::string written(const tcp_pcb *pcb);

// A pcb's remote IPv4 address, whether or not lwIP is built with IPv6.
inline uint32_t remote_ip4(const tcp_pcb *pcb) {
  return ip_addr_get_ip4_u32(&pcb->remote_ip);
}

// Empties <pcb>'s send buffer and resizes it, with the queue limit lwIP would derive
// for that TCP_SND_BUF.  Above 65535 only with LWIP_WND_SCALE.
void set_send_buffer(tcp_pcb *pcb, uint32_t size);

// How many times the TCPIP core lock is held.  0 whenever no api call is running.
int core_lock_depth();

// ---------------------------------------------------------------------------
// Failure injection. All are reset by reset().
// ---------------------------------------------------------------------------
struct Faults {
  int fail_tcp_new = 0;      // >0: that many tcp_new_ip_type() calls return NULL
  err_t connect_result = 0;  // ERR_OK; set e.g. ERR_RTE to fail tcp_connect
  err_t bind_result = 0;     // ERR_OK
  err_t write_result = 0;    // ERR_OK; set ERR_MEM to fail tcp_write
  err_t output_result = 0;   // ERR_OK
  err_t close_result = 0;    // ERR_OK; non-OK leaves the pcb allocated
  bool listen_returns_null = false;
  err_t dns_result = 0;   // ERR_OK (immediate), ERR_INPROGRESS, or an error
  uint32_t dns_addr = 0;  // address returned for an immediate ERR_OK lookup
  // With ERR_INPROGRESS: answers NULL, and lets the async task run, before returning --
  // as lwIP with no DNS server does, with the task on another core.
  bool dns_fails_inside_the_call = false;
};
Faults &faults();

// ---------------------------------------------------------------------------
// Driving lwIP callbacks (i.e. playing the part of the lwIP thread).
//
// These call straight into the callbacks the library registered, exactly as
// lwIP would. Nothing is delivered to the application until you then call
// asynctcp_test_pump().
// ---------------------------------------------------------------------------

// Completes a connect: moves the pcb to ESTABLISHED (when err == ERR_OK) and
// invokes the tcp_connected_fn passed to tcp_connect().
err_t fire_connected(tcp_pcb *pcb, err_t err = 0);

// Fatal error. Models lwIP faithfully: the pcb is freed *and then* the error
// callback runs, so the pcb pointer is dangling by the time the library sees
// it. Any pointer you hold to `pcb` is invalid after this returns.
void fire_error(tcp_pcb *pcb, err_t err);

// Delivers <len> bytes to tcp_recv_fn. Allocates the pbuf for you.
//
// As in lwIP, if the callback returns anything but ERR_OK or ERR_ABRT, the pbuf stays
// with lwIP as the pcb's refused data, to be offered again by retry_refused() or before
// the next segment.  Until it is taken, later segments are dropped: the peer sends them
// again.
err_t fire_recv(tcp_pcb *pcb, const void *data, size_t len, err_t err = 0);
// Delivers an already-built pbuf chain (ownership passes to the library).
err_t fire_recv_pbuf(tcp_pcb *pcb, pbuf *p, err_t err = 0);
// Remote FIN: tcp_recv_fn with a NULL pbuf.  lwIP reports it once, whatever the
// callback returns.
err_t fire_fin(tcp_pcb *pcb, err_t err = 0);
// Offers refused data again, as lwIP's fast timer does.  ERR_OK once it is taken (or if
// there was none), ERR_INPROGRESS if it is refused again.
err_t retry_refused(tcp_pcb *pcb);

err_t fire_sent(tcp_pcb *pcb, uint16_t len);
err_t fire_poll(tcp_pcb *pcb);

// Builds a fresh ESTABLISHED pcb and offers it to the listening pcb's
// tcp_accept_fn. Returns the new pcb (which may already have been freed by the
// library, so check is_live() before dereferencing).  As in lwIP, a return other than
// ERR_OK or ERR_ABRT aborts the new pcb.  The peer is 10.0.0.2:40000 unless given.  The
// local address is the listener's; on a listener bound to any address, only its family
// follows the peer's.
tcp_pcb *fire_accept(tcp_pcb *listen_pcb, err_t err = 0);
tcp_pcb *fire_accept(tcp_pcb *listen_pcb, const ip_addr_t &peer, uint16_t port, err_t err = 0);
// A SYN lwIP could not allocate a pcb for: tcp_accept_fn with a NULL pcb and <err>, whose
// return lwIP ignores.
void fire_accept_failure(tcp_pcb *listen_pcb, err_t err = ERR_MEM);
// Builds a fresh ESTABLISHED pcb from 10.0.0.2:40000 and offers it to <accept> on the LwIP
// thread, as to an accept callback the application registered with lwIP itself.  Returns
// the new pcb, as fire_accept() does, and treats the return the same way.
tcp_pcb *fire_raw_accept(const std::function<err_t(tcp_pcb *)> &accept);

// Convenience: build a pbuf holding <len> bytes of <data>.
pbuf *make_pbuf(const void *data, size_t len);

// Non-zero if the library made an api call while standing on the LwIP thread, which on a
// real target would deadlock.
unsigned reentrant_api_calls();

// Calls into tcp_* or dns_* made neither on the LwIP thread nor under the TCPIP core
// lock, which on a real target race the LwIP thread.  The first one's name.
unsigned unlocked_calls();
const char *first_unlocked_call();

// Callbacks handed a pcb that returned ERR_ABRT without aborting it, or anything else
// after aborting it; lwIP would then leak the pcb or use it after free.  The first one.
unsigned callback_return_violations();
const char *first_callback_return_violation();

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
// True while a dns_gethostbyname() that returned ERR_INPROGRESS is outstanding.
bool dns_pending();
// How many are outstanding.  LwIP cannot cancel a lookup, so they accumulate.
size_t dns_pending_count();
// The hostname of the oldest outstanding lookup.
std::string dns_pending_host();
// Fire the deferred callback with a resolved address.
void fire_dns(uint32_t addr);
void fire_dns(const ip_addr_t &addr);
// Fire the deferred callback with NULL (failure / timeout).
void fire_dns_failure();

}  // namespace mocklwip

#endif
