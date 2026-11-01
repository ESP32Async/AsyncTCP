// Host-native mock of lwip/tcp.h.
//
// Only the parts AsyncTCP touches are modeled. The behavioral contract of the
// mocked functions is documented in test/test_native/mocks/mock_lwip.h.
#ifndef MOCK_LWIP_TCP_H
#define MOCK_LWIP_TCP_H

#include "lwip/arch.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/opt.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_pcb;

typedef err_t (*tcp_accept_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
typedef err_t (*tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb, u16_t len);
typedef err_t (*tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);
typedef void (*tcp_err_fn)(void *arg, err_t err);
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, err_t err);

enum tcp_state {
  CLOSED = 0,
  LISTEN = 1,
  SYN_SENT = 2,
  SYN_RCVD = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1 = 5,
  FIN_WAIT_2 = 6,
  CLOSE_WAIT = 7,
  CLOSING = 8,
  LAST_ACK = 9,
  TIME_WAIT = 10
};

typedef u8_t tcpflags_t;

#if LWIP_WND_SCALE
typedef u32_t tcpwnd_size_t;
#define TCPWND16(x) ((u16_t)((x) < 0xFFFF ? (x) : 0xFFFF))
#else
typedef u16_t tcpwnd_size_t;
#define TCPWND16(x) (x)
#endif
#define TF_NODELAY 0x40U

// SOF_* socket options, as used by AsyncClient::setKeepAlive()
#define SOF_REUSEADDR 0x04U
#define SOF_KEEPALIVE 0x08U

struct tcp_pcb {
  ip_addr_t local_ip;
  ip_addr_t remote_ip;
  u8_t so_options;

  enum tcp_state state;
  void *callback_arg;

  u16_t local_port;
  u16_t remote_port;

  tcpflags_t flags;
  u16_t mss;
  tcpwnd_size_t snd_buf;
  u16_t snd_queuelen;

  u32_t keep_idle;
  u32_t keep_intvl;
  u32_t keep_cnt;

  tcp_sent_fn sent;
  tcp_recv_fn recv;
  tcp_connected_fn connected;
  tcp_poll_fn poll;
  tcp_err_fn errf;
  tcp_accept_fn accept;

  struct pbuf *refused_data;  // what the recv callback last refused
};

struct tcp_pcb *tcp_new_ip_type(u8_t type);

void tcp_arg(struct tcp_pcb *pcb, void *arg);
void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv);
void tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent);
void tcp_err(struct tcp_pcb *pcb, tcp_err_fn err);
void tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept);
void tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval);

err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port);
struct tcp_pcb *tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog);

err_t tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port, tcp_connected_fn connected);
err_t tcp_close(struct tcp_pcb *pcb);
void tcp_abort(struct tcp_pcb *pcb);

err_t tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len, u8_t apiflags);
err_t tcp_output(struct tcp_pcb *pcb);
void tcp_recved(struct tcp_pcb *pcb, u16_t len);

#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

// Real lwIP implements these as macros over pcb fields; keep that shape so tests
// can assert on the pcb directly.
#define tcp_sndbuf(pcb)         (TCPWND16((pcb)->snd_buf))
#define tcp_sndqueuelen(pcb)    ((pcb)->snd_queuelen)
#define tcp_mss(pcb)            ((pcb)->mss)
#define tcp_nagle_disable(pcb)  ((pcb)->flags = (tcpflags_t)((pcb)->flags | TF_NODELAY))
#define tcp_nagle_enable(pcb)   ((pcb)->flags = (tcpflags_t)((pcb)->flags & (tcpflags_t)(~TF_NODELAY)))
#define tcp_nagle_disabled(pcb) (((pcb)->flags & TF_NODELAY) != 0)

#ifdef __cplusplus
}
#endif

#endif
