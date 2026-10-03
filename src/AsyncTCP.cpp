// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#include "AsyncTCP.h"
#include "AsyncTCPLogging.h"
#include "AsyncTCPSimpleIntrusiveList.h"

#include <algorithm>
#include <cassert>
#include <memory>
#include <type_traits>

/**
 * Assertion macros
 * ESP-IDF leaves assertions on by default; we prefer the opposite as performance in this layer is critical.
 */
#ifdef CONFIG_ASYNC_TCP_ASSERTIONS
#define ASYNCTCP_ASSERT(x) assert(x)
#else
#define ASYNCTCP_ASSERT(x) ((void)0)
#endif

/**
 * Utility macro
 *
 * Most API functions are delegated to the impl class.  Ensure the wrapped functions are always inlined
 * to avoid the extra function call overhead.
*/
#define ASYNCTCP_ALWAYS_INLINE __attribute__((always_inline)) inline

/**
 * LibreTiny specific configurations
 */
#if defined(LIBRETINY)
#include <Arduino.h>
// LibreTiny does not support IDF - disable code that expects it to be available
#define ESP_IDF_VERSION_MAJOR (0)
// xTaskCreatePinnedToCore is not available, force single-core operation
#define CONFIG_FREERTOS_UNICORE 1
// ESP watchdog is not available
#undef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 0
#endif  // LIBRETINY

/**
 * Arduino specific configurations
 */
#if defined(ARDUINO) && !defined(LIBRETINY)
#include <Arduino.h>
#include <esp_idf_version.h>
#if (ESP_IDF_VERSION_MAJOR >= 5)
#include <NetworkInterface.h>
#endif  // ESP_IDF_VERSION_MAJOR
#endif  // ARDUINO

/**
 * ESP-IDF specific configurations
 */
#if !defined(LIBRETINY) && !defined(ARDUINO)
#include "esp_timer.h"
static unsigned long millis() {
  return (unsigned long)(esp_timer_get_time() / 1000ULL);
}
static unsigned long micros() {
  return static_cast<unsigned long>(esp_timer_get_time());
}
#endif  // !LIBRETINY && !ARDUINO

extern "C" {
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/inet.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"
}

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#endif

// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

/**
 * async_tcp_log_elapsed
 * Log the time elapsed in a given statement (typically the user callbacks).  Useful for performance monitoring and debugging.
 * The complex gate is because micros() is opaque to the compiler and cannot be optimized away when unused, so we
 * only enable this feature if verbose logging is enabled.
 */
#if defined(CONFIG_ASYNC_TCP_DEBUG) || defined(CONFIG_ASYNC_TCP_LOG_CUSTOM) || (defined(CORE_DEBUG_LEVEL) && (CORE_DEBUG_LEVEL >= 5)) \
  || (defined(LOG_LOCAL_LEVEL) && (LOG_LOCAL_LEVEL >= 5))
#define async_tcp_log_elapsed(tag, statement)                                                 \
  {                                                                                           \
    const uint32_t s_time = micros();                                                         \
    statement;                                                                                \
    async_tcp_log_v("%s took %" PRIu32 " us", tag, static_cast<uint32_t>(micros()) - s_time); \
  }
#else
#define async_tcp_log_elapsed(tag, statement) \
  { statement; }
#endif

/**
 * LwIP locking
 *
 * Utilities for managing LwIP TCP core mutexing.  Includes two features
 * - tcp_core_guard: a guard class usable when LWIP_TCPIP_CORE_LOCKING exposes the mutex for direct usage
 * - with_tcp_core_lock: a metafunction that runs a function inside the LwIP TCP core lock context, using the most efficient method available on the current build.
 *
 * https://github.com/espressif/arduino-esp32/issues/10526
 */
namespace {
#if LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  inline tcp_core_guard() {
    LOCK_TCPIP_CORE();
  }
  inline ~tcp_core_guard() {
    UNLOCK_TCPIP_CORE();
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // LWIP_TCPIP_CORE_LOCKING

/*
  Locking metafunction for TCP core operations.

  Runs a function inside the LwIP context by whichever route is cheapest on this build.
  Where the core lock exists we take it and call straight through, which avoids marshaling
  the arguments through a message.  Where direct locking is not available, we wrap the function
  call with tcpip_api_call.
*/
template<typename T> err_t with_tcp_core_lock(T &&func) {
#if LWIP_TCPIP_CORE_LOCKING || NO_SYS
  tcp_core_guard guard;
  return func();
#else
  // The functor is reached by pointer: a reference member would leave the struct without
  // a default constructor, and it only has to outlive the call.
  struct call_data {
    struct tcpip_api_call_data call;  // must be first member
    typename std::remove_reference<T>::type *f;
  } data;
  data.f = &func;
  return tcpip_api_call(
    // The lambda here constructs a C function which perfectly forwards the call to the functor.
    +[](struct tcpip_api_call_data *c) -> err_t {
      return (*reinterpret_cast<call_data *>(c)->f)();
    },
    &data.call
  );
#endif
}

}  // anonymous namespace

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#define CONFIG_ASYNC_TCP_POLL_TIMER 1

// Depth of the pending-connection queue handed to tcp_listen_with_backlog()
#define ASYNCTCP_LISTEN_BACKLOG 5

/*
 * TCP/IP Event Task
 * */

typedef enum {
  LWIP_TCP_SENT,
  LWIP_TCP_RECV,
  LWIP_TCP_FIN,
  LWIP_TCP_ERROR,
  LWIP_TCP_POLL,
  LWIP_TCP_ACCEPT,
  LWIP_TCP_CONNECTED
} lwip_tcp_event_t;

struct lwip_tcp_event_packet_t {
  lwip_tcp_event_packet_t *next;
  lwip_tcp_event_t event;
  std::shared_ptr<AsyncClientImpl> impl;  // keeps it alive for the life of the event
  // Only an accept carries one.  It keeps the server's implementation alive too, so a
  // connection still in flight can always find out whether it still has somewhere to go.
  std::shared_ptr<AsyncServerImpl> server;
  union {
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } connected;
    struct {
      int8_t err;
    } error;
    struct {
      tcp_pcb *pcb;
      uint16_t len;
    } sent;
    struct {
      tcp_pcb *pcb;
      pbuf *pb;
      int8_t err;
    } recv;
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } fin;
    struct {
      tcp_pcb *pcb;
    } poll;
    struct {
      uint32_t epoch;  // the listening session this connection was accepted on
    } accept;
  };

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, std::shared_ptr<AsyncClientImpl> _impl) : next(nullptr), event(_event), impl(std::move(_impl)){};
};

// Detail class for interacting with AsyncClient internals, but without exposing the API
class AsyncTCP_detail {
public:
  // Helper functions
  static void __attribute__((visibility("internal"))) handle_async_event(lwip_tcp_event_packet_t *event);

  // LwIP TCP event callbacks that (will) require privileged access
  static int8_t __attribute__((visibility("internal"))) tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len);
  static void __attribute__((visibility("internal"))) tcp_error(void *arg, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_poll(void *arg, struct tcp_pcb *pcb);
  static int8_t __attribute__((visibility("internal"))) tcp_accept(void *arg, tcp_pcb *pcb, int8_t err);
  static void __attribute__((visibility("internal"))) tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg);
};

namespace {
// Global queue mutex
static SemaphoreHandle_t _async_queue_mutex = nullptr;

// Created by _start_async_task(), which every path that can queue an event passes first.
// Unsynchronized, as _start_async_task() always has been.
static bool _init_queue_mutex() {
  if (!_async_queue_mutex) {
    _async_queue_mutex = xSemaphoreCreateMutex();
    if (!_async_queue_mutex) {
      async_tcp_log_e("Failed to create the queue mutex");
    }
  }
  return _async_queue_mutex != nullptr;
}

// Guard class for the global queue
class queue_mutex_guard {
  bool holds_mutex;

public:
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  inline ~queue_mutex_guard() {
    if (holds_mutex) {
      xSemaphoreGive(_async_queue_mutex);
    }
  };
  inline explicit operator bool() const {
    return holds_mutex;
  };
};
}  // anonymous namespace

static SimpleIntrusiveList<lwip_tcp_event_packet_t> _async_queue;
static TaskHandle_t _async_service_task_handle = NULL;

/*
  Client implementation, held by shared_ptr.

  The AsyncClient facade is created and destroyed by the application, but LwIP and the
  event queue both hold pointers that outlive it.  Putting the state here and sharing
  ownership of it means neither has to care: the facade and each queued event own the
  implementation, and it lives until the last of them lets go.

  Because the callbacks live here rather than on the facade, they stay in scope while
  being called, ensuring that any captures remain alive until the callback completes,
  even if the AsyncClient object is destroyed.

  The context passed to LwIP callbacks are deliberately not owners -- instead this class
  owns them and ensures that all are released before destruction.

  _facade is nulled when the application's object is destroyed.  Callback dispatch is
  always gated on it, so a detached implementation runs no user code and any leftover
  events simply drain.
*/
class AsyncClientImpl : public std::enable_shared_from_this<AsyncClientImpl> {
public:
  explicit AsyncClientImpl(AsyncClient *facade);
  ~AsyncClientImpl();

  AsyncClientImpl(const AsyncClientImpl &) = delete;
  AsyncClientImpl &operator=(const AsyncClientImpl &) = delete;

  /*
    Members held under LwIP context
  */
  tcp_pcb *_pcb;
  uint16_t _connect_port;
  std::weak_ptr<AsyncClientImpl> *_dns_token;  // non-owning pointer to the most recent DNS lookup token
  bool _dispose_owed;                          // a terminal notification is owed to the application

  /*
    Not synchronized.  The handlers are installed by the application before it connects
    and read by the async task when it dispatches; the rest is connection state that the
    async task owns in practice, touched from the calling task only through calls the
    application is expected not to make from two tasks at once against one client.
  */
  AsyncClient *_facade;  // nulled once the application's object is destroyed

  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;
  AcConnectHandler _discard_cb;
  void *_discard_cb_arg;
  AcAckHandler _sent_cb;
  void *_sent_cb_arg;
  AcErrorHandler _error_cb;
  void *_error_cb_arg;
  AcDataHandler _recv_cb;
  void *_recv_cb_arg;
  AcPacketHandler _pb_cb;
  void *_pb_cb_arg;
  AcTimeoutHandler _timeout_cb;
  void *_timeout_cb_arg;
  AcConnectHandler _poll_cb;
  void *_poll_cb_arg;

  bool _ack_pcb;
  uint32_t _tx_last_packet;
  uint32_t _rx_ack_len;
  uint32_t _rx_last_packet;
  uint32_t _rx_timeout;
  uint32_t _rx_last_ack;
  uint32_t _ack_timeout;
  uint32_t _in_callback_ack_len;  // bytes handed to onData but not yet acked

  ASYNCTCP_ALWAYS_INLINE bool connect(ip_addr_t addr, uint16_t port);
  ASYNCTCP_ALWAYS_INLINE bool connect(const char *host, uint16_t port);
#ifdef ARDUINO
  ASYNCTCP_ALWAYS_INLINE bool connect(const IPAddress &ip, uint16_t port);
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
  ASYNCTCP_ALWAYS_INLINE bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  ASYNCTCP_ALWAYS_INLINE void close();
  ASYNCTCP_ALWAYS_INLINE int8_t abort();
  ASYNCTCP_ALWAYS_INLINE bool free();

  ASYNCTCP_ALWAYS_INLINE bool canSend() const;
  ASYNCTCP_ALWAYS_INLINE size_t space() const;
  ASYNCTCP_ALWAYS_INLINE size_t add(const char *data, size_t size, uint8_t apiflags);
  ASYNCTCP_ALWAYS_INLINE bool send();
  ASYNCTCP_ALWAYS_INLINE size_t write(const char *data, size_t size, uint8_t apiflags);

  ASYNCTCP_ALWAYS_INLINE uint8_t state() const;
  ASYNCTCP_ALWAYS_INLINE bool connecting() const;
  ASYNCTCP_ALWAYS_INLINE bool connected() const;
  ASYNCTCP_ALWAYS_INLINE bool disconnecting() const;
  ASYNCTCP_ALWAYS_INLINE bool disconnected() const;
  ASYNCTCP_ALWAYS_INLINE bool freeable() const;

  ASYNCTCP_ALWAYS_INLINE uint16_t getMss() const;
  ASYNCTCP_ALWAYS_INLINE uint32_t getRxTimeout() const;
  ASYNCTCP_ALWAYS_INLINE void setRxTimeout(uint32_t timeout);
  ASYNCTCP_ALWAYS_INLINE uint32_t getAckTimeout() const;
  ASYNCTCP_ALWAYS_INLINE void setAckTimeout(uint32_t timeout);
  ASYNCTCP_ALWAYS_INLINE void setNoDelay(bool nodelay) const;
  ASYNCTCP_ALWAYS_INLINE bool getNoDelay();
  ASYNCTCP_ALWAYS_INLINE void setKeepAlive(uint32_t ms, uint8_t cnt);

  ASYNCTCP_ALWAYS_INLINE uint32_t getRemoteAddress() const;
  ASYNCTCP_ALWAYS_INLINE uint16_t getRemotePort() const;
  ASYNCTCP_ALWAYS_INLINE uint32_t getLocalAddress() const;
  ASYNCTCP_ALWAYS_INLINE uint16_t getLocalPort() const;
  ASYNCTCP_ALWAYS_INLINE ip4_addr_t getRemoteAddress4() const;
  ASYNCTCP_ALWAYS_INLINE ip4_addr_t getLocalAddress4() const;
#if LWIP_IPV6
  ASYNCTCP_ALWAYS_INLINE ip6_addr_t getRemoteAddress6() const;
  ASYNCTCP_ALWAYS_INLINE ip6_addr_t getLocalAddress6() const;
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
  ASYNCTCP_ALWAYS_INLINE IPv6Address remoteIP6() const;
  ASYNCTCP_ALWAYS_INLINE IPv6Address localIP6() const;
#else
  ASYNCTCP_ALWAYS_INLINE IPAddress remoteIP6() const;
  ASYNCTCP_ALWAYS_INLINE IPAddress localIP6() const;
#endif
#endif
#endif
#ifdef ARDUINO
  ASYNCTCP_ALWAYS_INLINE IPAddress remoteIP() const;
  ASYNCTCP_ALWAYS_INLINE IPAddress localIP() const;
#endif

  ASYNCTCP_ALWAYS_INLINE void ackPacket(struct pbuf *pb);
  ASYNCTCP_ALWAYS_INLINE size_t ack(size_t len);
  ASYNCTCP_ALWAYS_INLINE void ackLater();
  ASYNCTCP_ALWAYS_INLINE const char *stateToString() const;

  void _adopt(tcp_pcb *pcb);
  int8_t _connected(tcp_pcb *pcb, int8_t err);
  void _error(int8_t err);
  int8_t _poll(tcp_pcb *pcb);
  int8_t _sent(tcp_pcb *pcb, uint16_t len);
  int8_t _fin(tcp_pcb *pcb, int8_t err);
  int8_t _recv(tcp_pcb *pcb, pbuf *pb, int8_t err);
};

/*
  Server implementation class

  This has the same basic pattern as AsyncClient: an underlying shared_ptr allows the
  event dispatcher to hold the implementation in scope if it is destroyed by the application
  while a connection is being constructed.

  _facade is the orphan indicator.  ~AsyncServer() clears it, and a queued connection that
  finds it null is dropped as though it never arrived.  A connection accepted before end()
  is dropped too, on the epoch rather than on _pcb - see below.

  One consequence of outliving the facade: the last reference can be dropped by a purge on
  the LwIP thread, so this object's destructor - and with it the application's onClient
  std::function - can run there.  That is the same exposure AsyncClientImpl's callbacks
  have, and the same caution applies: nothing captured by a handler may re-enter the
  library from its own destructor.
*/
class AsyncServerImpl : public std::enable_shared_from_this<AsyncServerImpl> {
public:
  AsyncServerImpl(AsyncServer *facade, ip_addr_t addr, uint16_t port)
    : _pcb(nullptr), _epoch(0), _facade(facade), _addr(addr), _port(port), _noDelay(false), _connect_cb(nullptr), _connect_cb_arg(nullptr) {}
  ~AsyncServerImpl() {
    // end() here would be wrong for the same reason ~AsyncClientImpl does not close: the
    // last reference can be dropped by a purge on the LwIP thread, and end() is a
    // transaction, which from there would wait for itself.  Every path that releases the
    // implementation has already stopped it listening.
    ASYNCTCP_ASSERT(!_pcb);
  }

  AsyncServerImpl(const AsyncServerImpl &) = delete;
  AsyncServerImpl &operator=(const AsyncServerImpl &) = delete;

  // Written only inside the LwIP context; null once we have stopped listening.
  tcp_pcb *_pcb;

  /*
    Which listening session we are on.  Bumped in LwIP context in end() to ensure any pending
    connections do not get mishandled if a client should call end() then begin() before LwIP
    can dispatch them.
  */
  uint32_t _epoch;

  // Cleared by ~AsyncServer().  Read without a lock on the async task, on the same terms
  // as AsyncClientImpl::_facade - see the note there.
  AsyncServer *_facade;

  // Not synchronized: set up before begin() and read afterwards.
  ip_addr_t _addr;
  uint16_t _port;
  bool _noDelay;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;

  ASYNCTCP_ALWAYS_INLINE void onClient(AcConnectHandler cb, void *arg);
  ASYNCTCP_ALWAYS_INLINE void begin();
  ASYNCTCP_ALWAYS_INLINE void end();
  ASYNCTCP_ALWAYS_INLINE void setNoDelay(bool nodelay);
  ASYNCTCP_ALWAYS_INLINE bool getNoDelay() const;
  ASYNCTCP_ALWAYS_INLINE uint8_t status() const;
  int8_t _accepted(AsyncClient *client);
};

static uint32_t _xor_shift_state = 31;  // any nonzero seed will do
static uint32_t _xor_shift_next() {
  uint32_t x = _xor_shift_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return _xor_shift_state = x;
}

static void _free_event(lwip_tcp_event_packet_t *evpkt) {
  if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
    pbuf_free(evpkt->recv.pb);
  }
  delete evpkt;  // releases the event's reference to the implementation
}

static inline void _send_async_event(lwip_tcp_event_packet_t *e) {
  ASYNCTCP_ASSERT(e != nullptr);
  ASYNCTCP_ASSERT(e->impl != nullptr);
  _async_queue.push_back(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline void _prepend_async_event(lwip_tcp_event_packet_t *e) {
  ASYNCTCP_ASSERT(e != nullptr);
  ASYNCTCP_ASSERT(e->impl != nullptr);
  _async_queue.push_front(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline lwip_tcp_event_packet_t *_get_async_event() {
  lwip_tcp_event_packet_t *result = nullptr;
  // Discarded events are freed once the mutex is released, to keep pbuf_free() out of
  // the critical section.
  lwip_tcp_event_packet_t *discarded = nullptr;

  {
    queue_mutex_guard guard;
    while (1) {
      lwip_tcp_event_packet_t *e = _async_queue.pop_front();

      if ((!e) || (e->event != LWIP_TCP_POLL)) {
        result = e;
        break;
      }

      /*
      Let's try to coalesce two (or more) consecutive poll events into one
      this usually happens with poor implemented user-callbacks that are runs too long and makes poll events to stack in the queue
      if consecutive user callback for a same connection runs longer that poll time then it will fill the queue with events until it deadlocks.
      This is a workaround to mitigate such poor designs and won't let other events/connections to starve the task time.
      It won't be effective if user would run multiple simultaneous long running callbacks due to message interleaving.
      todo: implement some kind of fair dequeuing or (better) simply punish user for a bad designed callbacks by resetting hog connections
    */
      for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->impl == e->impl) && (next_pkt->event == LWIP_TCP_POLL);
           next_pkt = _async_queue.begin()) {
        // if the next event that will come is a poll event for the same connection, we can discard it and continue
        auto dup = _async_queue.pop_front();
        dup->next = discarded;
        discarded = dup;
        async_tcp_log_d("coalescing polls, network congestion or async callbacks might be too slow!");
      }

      /*
      now we have to decide if to proceed with poll callback handler or discard it?
      poor designed apps using asynctcp without proper dataflow control could flood the queue with interleaved pool/ack events.
      I.e. on each poll app would try to generate more data to send, which in turn results in additional ack event triggering chain effect
      for long connections. Or poll callback could take long time starving other connections. Anyway our goal is to keep the queue length
      grows under control (if possible) and poll events are the safest to discard.
      Let's discard poll events processing using linear-increasing probability curve when queue size grows over 3/4
      Poll events are periodic and connection could get another chance next time
    */
      if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 4 + CONFIG_ASYNC_TCP_QUEUE_SIZE * 3 / 4)) {
        e->next = discarded;
        discarded = e;
        async_tcp_log_d("discarding poll due to queue congestion");
        continue;
      }

      result = e;
      break;
    }
  }

  while (discarded) {
    auto t = discarded;
    discarded = t->next;
    _free_event(t);
  }
  return result;
}

static size_t _remove_events_for_client(AsyncClientImpl *client, lwip_tcp_event_packet_t *terminal_event = nullptr) {
  if (!_async_queue_mutex) {
    // Never started, so nothing can have been queued.  A terminal event comes from an
    // LwIP callback, and a bound pcb implies a started task.
    ASYNCTCP_ASSERT(!terminal_event);
    return 0;
  }
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return pkt.impl.get() == client;
    });
    if (terminal_event) {
      _send_async_event(terminal_event);
    }
  }

  size_t count = 0;
  while (removed_event_chain) {
    ++count;
    auto t = removed_event_chain;
    removed_event_chain = t->next;
    _free_event(t);
  }
  return count;
};

void AsyncTCP_detail::handle_async_event(lwip_tcp_event_packet_t *e) {
  ASYNCTCP_ASSERT(e->impl);

  if (e->event == LWIP_TCP_ACCEPT) {
    // Accept is checked first because we need to handle it before the client facade check,
    // since we haven't constructed a facade for it yet.
    AsyncServerImpl *server = e->server.get();
    const bool wanted = server && server->_facade               // the application still has this server
                        && (server->_epoch == e->accept.epoch)  // ...and has not stopped listening since
                        && e->impl->_pcb;                       // ...and the connection is still up
    AsyncClient *c = wanted ? new (std::nothrow) AsyncClient(e->impl) : nullptr;
    if (c) {
      server->_accepted(c);
    } else {
      e->impl->close();  // Not wanted or failed to create a client facade
    }
  } else if ((e->impl->_facade == NULL)) {
    // A detached implementation has no facade to hand to the user's callbacks, so its
    // events simply drain.  The reference the event holds keeps it alive until then.
    // ets_printf("event arg == NULL: 0x%08x\n", e->recv.pcb);
  } else if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    e->impl->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    e->recv.pb = nullptr;  // given to client
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->impl->_fin(e->fin.pcb, e->fin.err);
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    e->impl->_sent(e->sent.pcb, e->sent.len);
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    e->impl->_poll(e->poll.pcb);
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->impl, e->error.err);
    e->impl->_error(e->error.err);
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->impl, e->connected.pcb, e->connected.err);
    e->impl->_connected(e->connected.pcb, e->connected.err);
  }
  _free_event(e);
}

static void _async_service_task(void *pvParameters) {
  async_tcp_log_d("Task 'async_tcp' started on core %d", static_cast<int>(xPortGetCoreID()));
#if CONFIG_ASYNC_TCP_USE_WDT
  if (esp_task_wdt_add(NULL) != ESP_OK) {
    async_tcp_log_w("Failed to add async task to WDT");
  }
#endif
  for (;;) {
    while (auto packet = _get_async_event()) {
      async_tcp_log_elapsed("handle_async_event", AsyncTCP_detail::handle_async_event(packet));
#if CONFIG_ASYNC_TCP_USE_WDT
      esp_task_wdt_reset();
#endif
    }
    // queue is empty
    // DEBUG_PRINTF("Async task waiting 0x%08",(intptr_t)_async_queue_head);
    ulTaskNotifyTake(pdTRUE, ASYNC_TCP_MAX_TASK_SLEEP);
    // DEBUG_PRINTF("Async task woke = %d 0x%08x",q, (intptr_t)_async_queue_head);
#if CONFIG_ASYNC_TCP_USE_WDT
    esp_task_wdt_reset();
#endif
  }
#if CONFIG_ASYNC_TCP_USE_WDT
  esp_task_wdt_delete(NULL);
#endif
  vTaskDelete(NULL);
  _async_service_task_handle = NULL;
}

/*
static void _stop_async_task(){
    if(_async_service_task_handle){
        vTaskDelete(_async_service_task_handle);
        _async_service_task_handle = NULL;
    }
}
*/

static bool customTaskCreateUniversal(
  TaskFunction_t pxTaskCode, const char *const pcName, const uint32_t usStackDepth, void *const pvParameters, UBaseType_t uxPriority,
  TaskHandle_t *const pxCreatedTask, const BaseType_t xCoreID
) {
#ifndef CONFIG_FREERTOS_UNICORE
  if (xCoreID >= 0 && xCoreID < 2) {
    return xTaskCreatePinnedToCore(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask, xCoreID);
  } else {
#endif
    return xTaskCreate(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask);
#ifndef CONFIG_FREERTOS_UNICORE
  }
#endif
}

static bool _start_async_task() {
  if (!_init_queue_mutex()) {
    return false;
  }

  if (!_async_service_task_handle) {
    customTaskCreateUniversal(
      _async_service_task, "async_tcp", CONFIG_ASYNC_TCP_STACK_SIZE, NULL, CONFIG_ASYNC_TCP_PRIORITY, &_async_service_task_handle, CONFIG_ASYNC_TCP_RUNNING_CORE
    );
    if (!_async_service_task_handle) {
      return false;
    }
  }
  return true;
}

/*
 * LwIP Callbacks
 * */

// Defined with the other api calls below; tcp_dns_found() dials through it directly.
static err_t _tcp_connect_in_context(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port);

// Attach an AsyncClient to a TCP PCB by setting the appropriate LwIP callbacks and argument.
static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  if (client) {
    _remove_events_for_client(client);
  }
}

//  Stand down any outstanding name lookup.  Run in LwIP context to ensure atomicity with the tcp_dns_found() callback.
static void _abandon_resolve(AsyncClientImpl *client) {
  if (client) {
    client->_dns_token = nullptr;
  }
}

// Callback when a connection is established.  pcb is already bound to the client.
static int8_t _tcp_connected(void *arg, tcp_pcb *pcb, int8_t err) {
  // ets_printf("+C: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->connected.pcb = pcb;
  e->connected.err = err;
  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_poll(void *arg, struct tcp_pcb *pcb) {
  // throttle polling events queueing when event queue is getting filled up, let it handle _onack's
  {
    queue_mutex_guard guard;
    // async_tcp_log_d("qs:%u", _async_queue.size());
    if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 2 + CONFIG_ASYNC_TCP_QUEUE_SIZE / 4)) {
      async_tcp_log_d("throttling");
      return ERR_OK;
    }
  }

  // ets_printf("+P: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->poll.pcb = pcb;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err) {
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  if (pb) {
    // ets_printf("+R: 0x%08x\n", pcb);
    e->recv.pcb = pcb;
    e->recv.pb = pb;
    e->recv.err = err;
  } else {
    // ets_printf("+F: 0x%08x\n", pcb);
    e->event = LWIP_TCP_FIN;
    e->fin.pcb = pcb;
    e->fin.err = err;
  }

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len) {
  // ets_printf("+S: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->sent.pcb = pcb;
  e->sent.len = len;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

void AsyncTCP_detail::tcp_error(void *arg, int8_t err) {
  // ets_printf("+E: 0x%08x\n", arg);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  if ((client == nullptr) || (client->_pcb == nullptr)) {
    // Not the client that owns this pcb: there is nothing to report, and LwIP's
    // reference was already released when we forgot the pcb.
    async_tcp_log_e("error callback for a client with no pcb");
    return;
  }

  // LwIP has already freed the pcb; do not attempt to clear the callbacks.  Clear the
  // saved value in the client object to avoid future use.
  client->_pcb = nullptr;

  // Construct event packet first.  This will hold the client in scope in case we have yet to
  // process its ACCEPT event (ie. it has no facade yet, and so the ACCEPT event is the only reference).
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client->shared_from_this()};
  if (e) {
    e->error.err = err;
  } else {
    async_tcp_log_e("Failed to allocate event packet");
  }

  // Remove all pending events for this client, and send the terminal error event if we could allocate it.
  _remove_events_for_client(client, e);
}

void AsyncTCP_detail::tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg) {
  // ets_printf("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  // 'name' points into LwIP's DNS table, which the next lookup recycles; don't keep it.
  (void)name;
  // Adopt ownership of the callback state from the argument passed by LwIP.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(reinterpret_cast<std::weak_ptr<AsyncClientImpl> *>(arg));
  // Validate that our client still exists.
  auto client = callback_state->lock();
  if (!client) {
    return;  // the implementation was destroyed while the lookup was in flight
  }

  // Validate that we're the most recent DNS lookup for this client.
  if (client->_dns_token != callback_state.get()) {
    return;  // close(), abort() or a newer lookup superseded this query
  }
  const uint16_t port = client->_connect_port;
  client->_dns_token = nullptr;  // lookup complete

  // Check that client isn't already open?
  if (client->_pcb) {
    return;  // connected by some other route while we were resolving
  }

  // Treat any-address or blocklist responses as failed lookups.
  const bool resolved = (ipaddr != nullptr) && !ip_addr_isany_val(*ipaddr);

  // Start the connection right away; we're already in LwIP context
  if (resolved && _tcp_connect_in_context(client.get(), ipaddr, port) == ERR_OK) {
    return;
  }

  // The original DNS-based connect() reported "success" to the caller, so we must notify
  // them of the failure.  Queue an error event packet.
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return;
  }
  e->error.err = resolved ? ERR_CONN : -55;
  queue_mutex_guard guard;
  _send_async_event(e);
}

/*
 * TCP/IP API Calls
 * */

/*
  Context structure for `tcpip_api_call`, ie. code running in LwIP context.
  The pcb is always reached through `client`.
*/
typedef struct {
  struct tcpip_api_call_data call;
  AsyncClientImpl *client;
  int8_t err;
  union {
    size_t close_ack;  // bytes to tcp_recved() before closing, in the same pass
    size_t received;
    struct {
      const ip_addr_t *addr;
      uint16_t port;
    } connect;
    struct {
      const char *host;
      ip_addr_t *addr;
      std::weak_ptr<AsyncClientImpl> *token;
      uint16_t port;
    } dns;
  };
} tcp_api_call_t;

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (msg->client->_pcb) {
    msg->err = tcp_output(msg->client->_pcb);
  }
  return msg->err;
}

static esp_err_t _tcp_output(AsyncClientImpl *client) {
  if (!client->_pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.client = client;
  tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (msg->client->_pcb) {
    msg->err = 0;
    tcp_recved(msg->client->_pcb, msg->received);
  }
  return msg->err;
}

static esp_err_t _tcp_recved(AsyncClientImpl *client, size_t len) {
  if (!client->_pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.client = client;
  msg.received = len;
  tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg) {
  // Unlike the other calls, this is not a direct wrapper of the LwIP function; we perform
  // the AsyncClient teardown interlocked safely with the LwIP task.

  // As a postcondition, the queue must not have any events referencing this client.  This
  // is because it is possible for an error event to have been queued, clearing the pcb*,
  // but after the async thread has committed to closing/destructing the AsyncClient.

  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;
  msg->err = ERR_CONN;
  _abandon_resolve(client);
  if (client->_pcb) {
    tcp_pcb *pcb = client->_pcb;
    // Ack anything the application withheld, in this same pass.  Done as a separate call
    // the LwIP thread could run in between, and the peer would get an RST rather than a
    // FIN for data that was in fact processed.
    if (msg->close_ack) {
      tcp_recved(pcb, msg->close_ack);
    }
    _reset_tcp_callbacks(pcb, client);
    if (tcp_close(pcb) != ERR_OK) {
      // We do not permit failure here: abandon the pcb anyways.
      tcp_abort(pcb);
    }
    msg->err = ERR_OK;
    client->_pcb = nullptr;  // PCB is now the property of LwIP
  } else {
    // Ensure there is not an error event queued for this client
    if (_remove_events_for_client(client)) {
      msg->err = ERR_OK;  // dispose needs to be run
    }
  }
  return msg->err;
}

static esp_err_t _tcp_close(AsyncClientImpl *client, size_t ack) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.close_ack = ack;
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg) {
  // Like close(), we must ensure that the queue is cleared of any events referencing the
  // AsyncClient.
  // ERR_ABRT: the pcb was aborted.
  // ERR_OK:   the pcb was already gone, but a queued error event was purged, so the
  //           caller must still run the discard callback (dispose needs to run).
  // ERR_CONN: nothing to do (pcb already null and no queued events).
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;
  _abandon_resolve(client);
  if (client->_pcb) {
    _reset_tcp_callbacks(client->_pcb, client);
    tcp_abort(client->_pcb);
    client->_pcb = nullptr;  // PCB is now the property of LwIP
    msg->err = ERR_ABRT;
  } else {
    msg->err = _remove_events_for_client(client) ? ERR_OK : ERR_CONN;
  }
  return msg->err;
}

static esp_err_t _tcp_abort(AsyncClientImpl *client) {
  // No early return on a null pcb.  An outstanding lookup is a second thing LwIP is
  // holding, and standing it down has to happen inside the interlock.
  tcp_api_call_t msg;
  msg.client = client;
  tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_connect_in_context(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port) {
#if LWIP_IPV4 && LWIP_IPV6
  tcp_pcb *pcb = tcp_new_ip_type(addr->type);
#else
  tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
#endif
  if (!pcb) {
    async_tcp_log_e("pcb == NULL");
    return ERR_MEM;
  }

  // Take ownership of the pcb
  client->_adopt(pcb);

  err_t err = tcp_connect(pcb, addr, port, (tcp_connected_fn)&_tcp_connected);
  if (err != ERR_OK) {
    // Failure - clean up
    _reset_tcp_callbacks(pcb, nullptr);
    // Work around LwIP bug
    // tcp_connect() may have taken a local port without adding the pcb to
    // tcp_bound_pcbs.  Clear it, or tcp_close() will try to remove the pcb from a list
    // it was never on.
    pcb->local_port = 0;
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    client->_pcb = nullptr;
    // Note that _adopt() armed _dispose_owed; the caller will need to clear it if it is no longer needed.
  }

  return err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = _tcp_connect_in_context(msg->client, msg->connect.addr, msg->connect.port);
  // On a failure, release _dispose_owed while we still hold the LwIP lock.
  if (msg->err != ERR_OK) {
    msg->client->_dispose_owed = false;
  }
  return msg->err;
}

static esp_err_t _tcp_connect(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.connect.addr = addr;
  msg.connect.port = port;
  tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

/*
  Start a name lookup and publish its token as one transaction.

  These cannot be separate steps.  LwIP answers on its own thread, so a token published
  after dns_gethostbyname() returns can arrive too late: the callback finds no token,
  concludes it has been superseded, and drops an answer the caller is still waiting for -
  leaving connect() having reported success that never resolves either way.

  Taking the LwIP core lock around just the lookup would not fix it, and not only because
  the window would remain: that lock does not exist without CONFIG_LWIP_TCPIP_CORE_LOCKING,
  where the interlock is the api call itself and nothing else.
*/
static err_t _tcp_dns_start_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;

  // Supersedes any lookup already outstanding; that one will find the token moved on.
  if (client->_dns_token) {
    // The displaced lookup will never report, so its obligation dies with it rather than
    // passing to this attempt - which may answer from cache and never arm one of its own,
    // and would then refuse itself on a notice nobody can ever deliver.
    client->_dispose_owed = false;
  }
  client->_connect_port = msg->dns.port;
  client->_dns_token = msg->dns.token;

  msg->err = dns_gethostbyname(msg->dns.host, msg->dns.addr, (dns_found_callback)&AsyncTCP_detail::tcp_dns_found, msg->dns.token);
  if (msg->err == ERR_INPROGRESS) {
    // Reporting success promises onConnect or onError, and a dispose with it, even though no
    // pcb exists yet (and may never).  Armed here rather than on return: the answer can land
    // the instant this transaction ends, and an error reported before the caller had armed it
    // would consume a notification that was not yet owed - and then rearm it forever.
    client->_dispose_owed = true;
  } else {
    client->_dns_token = nullptr;  // no callback is coming
  }
  return msg->err;
}

static err_t _tcp_dns_start(AsyncClientImpl *client, const char *host, ip_addr_t *addr, uint16_t port, std::weak_ptr<AsyncClientImpl> *token) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.dns.host = host;
  msg.dns.addr = addr;
  msg.dns.port = port;
  msg.dns.token = token;
  tcpip_api_call(_tcp_dns_start_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

/*
  Async TCP Client
 */

AsyncClientImpl::AsyncClientImpl(AsyncClient *facade)
  : _pcb(nullptr), _connect_port(0), _dns_token(nullptr), _dispose_owed(false), _facade(facade), _connect_cb(0), _connect_cb_arg(0), _discard_cb(0),
    _discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0), _recv_cb(0), _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0),
    _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true), _tx_last_packet(0), _rx_ack_len(0), _rx_last_packet(0), _rx_timeout(0), _rx_last_ack(0),
    _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _in_callback_ack_len(0) {}

AsyncClientImpl::~AsyncClientImpl() {
  // Every path that drops the last reference must ensure the binding was cleared first.
  // This can be called from the LwIP thread, so any cleanup must have been performed already.
  ASYNCTCP_ASSERT(!_pcb);
}

AsyncClient::AsyncClient(tcp_pcb *pcb) : _impl(std::make_shared<AsyncClientImpl>(this)) {
  if (pcb) {
    // The pcb's callbacks queue events, so the task must be there to take them.
    if (_start_async_task()) {
      _impl->_adopt(pcb);
    } else {
      // The pcb is ours, and nothing could deliver its events.  Close rather than abort:
      // in an accept callback, only the callback's return value can report ERR_ABRT.
      async_tcp_log_e("failed to start task");
      if (tcp_close(pcb) != ERR_OK) {
        async_tcp_log_e("failed to close pcb");
      }
    }
  }
}

AsyncClient::AsyncClient(std::shared_ptr<AsyncClientImpl> impl) : _impl(std::move(impl)) {
  _impl->_facade = this;
}

AsyncClient::~AsyncClient() {
  // Unconditional, because whether there is anything to close is not knowable from here -
  // _pcb and the lookup token are both written by the LwIP thread, and a name lookup can
  // still turn into a bound pcb after we have looked.
  _impl->close();
  // Detach: queued events and LwIP callbacks may still reach the implementation, but
  // must not run user code against a facade that no longer exists.
  _impl->_facade = nullptr;
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) const {
  return _impl->_pcb == other._impl->_pcb;
}

/*
 * Callback Setters
 * */

/*
 * Main Public Methods
 * */

bool AsyncClientImpl::connect(ip_addr_t addr, uint16_t port) {
  if (_pcb) {
    async_tcp_log_d("already connected, state %d", _pcb->state);
    return false;
  }
  if (_dns_token) {
    async_tcp_log_d("name resolution in progress");
    return false;
  }
  if (_dispose_owed) {
    // A previous failed connection has not reported yet - the error event
    // is still queued (otherwise we'd have _pcb).  Treat this as "not ready
    // for a new connection".
    async_tcp_log_d("previous connection not yet reported");
    return false;
  }
  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  // One pass through the LwIP context for the whole sequence; see
  // _tcp_connect_in_context().  On failure it has already disposed of the pcb and cleared
  // _pcb, and no callbacks were raised.
  if (_tcp_connect(this, &addr, port) == ERR_OK) {
    return true;
  }
  async_tcp_log_d("connect failed");
  return false;
}
#ifdef ARDUINO
bool AsyncClientImpl::connect(const IPAddress &ip, uint16_t port) {
  ip_addr_t addr;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  // if both IPv4 and IPv6 are enabled, ip_addr_t has a union field and the address type
  addr.u_addr.ip4.addr = ip;
  addr.type = IPADDR_TYPE_V4;
#else
  addr.addr = ip;
#endif
#else
  ip.to_ip_addr_t(&addr);
#endif

  return connect(addr, port);
}
#endif

#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClientImpl::connect(const IPv6Address &ip, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port);
}
#endif

bool AsyncClientImpl::connect(const char *host, uint16_t port) {
  ip_addr_t addr;

  if (_pcb) {
    async_tcp_log_d("already connected, state %d", _pcb->state);
    return false;
  }
  // For compatibility, calling `connect()` with a lookup outstanding supersedes
  // the previous lookup.
  if (_dispose_owed && !_dns_token) {
    // The previous connection has errored out but its async event hasn't run.
    // We can't cancel it -- it may already be pending on the async task.
    // So we treat this as "not ready for a new connection".
    async_tcp_log_d("previous connection not yet reported");
    return false;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  // A lookup already in flight is superseded rather than refused.  Ignoring the new
  // call would silently dial the *previous* host and port and report success for it;
  // refusing would be the better API, but previous versions would (brokenly) accept
  // this (and then leak).  The classic case is a client retrying a "wedged" lookup --
  // it's not really wedged, LwIP guarantees a return, but the timeouts might be longer
  // than a client might expect.
  // To avoid this leak, we allocate a unique "lookup context" for each request, and
  // validate it when the request completes.  Ownership of the context lives in the
  // LwIP DNS callback once triggered.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(new (std::nothrow) std::weak_ptr<AsyncClientImpl>(shared_from_this()));
  if (!callback_state) {
    async_tcp_log_e("Failed to allocate the lookup context");
    return false;
  }

  // Initiate DNS transaction
  const err_t err = _tcp_dns_start(this, host, &addr, port, callback_state.get());

  if (err == ERR_INPROGRESS) {
    // DNS lookup in progress; _tcp_dns_start_api armed _dispose_owed inside the transaction
    callback_state.release();  // now tcp_dns_found's to destroy
    return true;
  }

  if (err == ERR_OK) {
    // Answered from the cache, or the name was a literal address
    // Validate the resolved address (same rules as tcp_dns_found)
    if (ip_addr_isany_val(addr)) {
      async_tcp_log_d("lookup returned the any-address");
      return false;
    }
    // We can delegate to the direct connection function here.
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV6
    if (addr.type == IPADDR_TYPE_V6) {
      return connect(IPv6Address(addr.u_addr.ip6.addr), port);
    }
    return connect(IPAddress(addr.u_addr.ip4.addr), port);
#else
    return connect(IPAddress(addr.addr), port);
#endif
#else
    return connect(addr, port);
#endif
  }
  async_tcp_log_d("error: %d", err);
  return false;
}

void AsyncClientImpl::close() {
  // Ack anything withheld by ackLater(), plus the packet onData is holding right now if
  // we are being called from inside it.  Without this the peer gets an RST rather than a
  // FIN for data the application did in fact process.
  const size_t pending = _rx_ack_len + _in_callback_ack_len;
  _rx_ack_len = 0;
  _in_callback_ack_len = 0;
  _tcp_close(this, pending);
  // _pcb is now NULL, all queued events are cleared, and any outstanding lookup has been
  // stood down.  Call the dispose callback if owed.
  if (_facade && _dispose_owed) {
    _dispose_owed = false;
    if (_discard_cb) {
      auto self = shared_from_this();  // ensure our object stays in scope during the callback
      async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
    }
  }
}

int8_t AsyncClientImpl::abort() {
  int8_t err = _tcp_abort(this);
  // _pcb is now NULL
  // LwIP invokes the error callback when abort is issued; preserve this semantic.
  // This will also trigger the dispose callback if otherwise owed (ie. error is already pending or canceling a DNS lookup).
  // If the pcb was previously invalidated by some other queued error, we've discarded that value; so we always send ERR_ABRT.
  if (err != ERR_CONN || _dispose_owed) {
    _error(ERR_ABRT);
  }
  return err;
}

size_t AsyncClientImpl::space() const {
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED)) {
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

size_t AsyncClientImpl::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
  // Early check outside of lock
  if (space() == 0) {
    return 0;
  }
  auto err = with_tcp_core_lock([&]() -> err_t {
    if (!_pcb) {
      return ERR_CONN;
    }
    size = std::min(size, space());
    return tcp_write(_pcb, data, size, apiflags);
  });
  if (err != ERR_OK) {
    return 0;
  }
  return size;
}

bool AsyncClientImpl::send() {
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(this) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClientImpl::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(this, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClientImpl::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(this, pb->len);
  pbuf_free(pb);
}

void AsyncClientImpl::ackLater() {
  _ack_pcb = false;
}

/*
 * Main Private Methods
 * */

/*
 * Private Callbacks
 * */

// Adopt a pcb and reset all per-connection state.  Callers must already be
// serialized against the LwIP core - called from inside a transaction, or from a callback.
void AsyncClientImpl::_adopt(tcp_pcb *pcb) {
  _dispose_owed = true;  // a bound pcb owes the application a terminal notification
  _pcb = pcb;
  _rx_ack_len = 0;
  _tx_last_packet = 0;
  _rx_last_ack = 0;
  _rx_last_packet = millis();
  _bind_tcp_callbacks(pcb, this);
}

int8_t AsyncClientImpl::_connected(tcp_pcb *pcb, int8_t err) {
  if (pcb != _pcb) {
    // Stale event for a pcb we no longer own
    async_tcp_log_d("%p != %p", (const void *)pcb, (const void *)_pcb);
    return ERR_OK;
  }
  _rx_last_packet = millis();
  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, _facade));
  }
  return ERR_OK;
}

void AsyncClientImpl::_error(int8_t err) {
  // Hold a reference to self to ensure this remains valid throughout the user callbacks.
  auto self = shared_from_this();
  // Claim the notification before running anything: onError may destroy the AsyncClient,
  // and ~AsyncClient() closes, which would otherwise report this same connection again.
  const bool owed = _dispose_owed;
  _dispose_owed = false;
  // Run error callback
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, _facade, err));
  }
  // Things could have been changed under that callback:
  // - User might have deleted the AsyncClient (_facade is now nullptr)
  // - User might have reconnected the object (re-armed _dispose_owed)
  // In either case, we skip the dispose.
  if (owed && _facade && !_dispose_owed && _discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
}

int8_t AsyncClientImpl::_fin(tcp_pcb *pcb, int8_t err) {
  close();
  return ERR_OK;
}

int8_t AsyncClientImpl::_sent(tcp_pcb *pcb, uint16_t len) {
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, _facade, len, (_rx_last_packet - _tx_last_packet)));
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  while (pb != NULL) {
    _rx_last_packet = millis();
    // we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    if (_pb_cb) {
      // The callback owns b now, and must ackPacket() or free it
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, _facade, b));
    } else {
      // Visible to close(), so closing from inside onData still acks this packet
      _in_callback_ack_len = b->len;
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, _facade, b->payload, b->len));
      }
      pbuf_free(b);
      if (_pcb != pcb) {
        // Bizarre as it might sound, it's actually possible for the user callback to reconnect.
        _in_callback_ack_len = 0;
        break;
      }
      if (_in_callback_ack_len) {
        if (!_ack_pcb) {
          _rx_ack_len += _in_callback_ack_len;
        } else {
          _tcp_recved(this, _in_callback_ack_len);
        }
        _in_callback_ack_len = 0;
      }
    }
    // Stop if the callback closed the connection, destroyed the client, or replaced the
    // connection outright - a callback that reconnects leaves _pcb non-null but pointing
    // at a different peer, and the rest of this chain belongs to the old one.  Comparing
    // against the pcb the data arrived on covers all three.
    if (_pcb != pcb || !_facade) {
      break;
    }
  }
  if (pb) {
    pbuf_free(pb);  // release whatever we did not get to
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_poll(tcp_pcb *pcb) {
  if (!_pcb) {
    // async_tcp_log_d("pcb is NULL");
    return ERR_OK;
  }
  if (pcb != _pcb) {
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }

  if (_pcb->state < ESTABLISHED) {
    // Still connecting; LwIP handles the SYN timeout itself
    return ERR_OK;
  }

  uint32_t now = millis();

  // ACK Timeout
  if (_ack_timeout) {
    const uint32_t one_day = 86400000;
    bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
    if (last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
      async_tcp_log_d("ack timeout %d", pcb->state);
      if (_timeout_cb) {
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, _facade, (now - _tx_last_packet)));
      }
      return ERR_OK;
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", pcb->state);
    close();
    return ERR_OK;
  }
  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, _facade));
  }
  return ERR_OK;
}

/*
 * Public Helper Methods
 * */

bool AsyncClientImpl::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClientImpl::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClientImpl::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClientImpl::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClientImpl::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClientImpl::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClientImpl::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClientImpl::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClientImpl::setKeepAlive(uint32_t ms, uint8_t cnt) {
  if (!_pcb) {
    return;
  }
  if (ms != 0) {
    _pcb->so_options |= SOF_KEEPALIVE;  // Turn on TCP Keepalive for the given pcb
    // Set the time between keepalive messages in milli-seconds
    _pcb->keep_idle = ms;
    _pcb->keep_intvl = ms;
    _pcb->keep_cnt = cnt;  // The number of unanswered probes required to force closure of the socket
  } else {
    _pcb->so_options &= ~SOF_KEEPALIVE;  // Turn off TCP Keepalive for the given pcb
  }
}

uint16_t AsyncClientImpl::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClientImpl::getRemoteAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->remote_ip.u_addr.ip4.addr;
#else
  return _pcb->remote_ip.addr;
#endif
}

#if LWIP_IPV6
ip6_addr_t AsyncClientImpl::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClientImpl::getLocalAddress6() const {
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V6) {
    return _pcb->local_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClientImpl::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClientImpl::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClientImpl::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClientImpl::localIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
}
#endif
#endif
#endif

uint16_t AsyncClientImpl::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClientImpl::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClientImpl::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClientImpl::getRemoteAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V4) {
    return _pcb->remote_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->remote_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip4_addr_t AsyncClientImpl::getLocalAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V4) {
    return _pcb->local_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->local_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

#ifdef ARDUINO
IPAddress AsyncClientImpl::remoteIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getRemoteAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
#endif
}

IPAddress AsyncClientImpl::localIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getLocalAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
#endif
}
#endif

uint8_t AsyncClientImpl::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClientImpl::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClientImpl::connecting() const {
  if (_dns_token) {
    return true;  // resolving the hostname
  }
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClientImpl::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClientImpl::disconnected() const {
  if (_dns_token) {
    return false;  // resolving the hostname
  }
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClientImpl::freeable() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClientImpl::canSend() const {
  return space() > 0;
}

const char *AsyncClient::errorToString(int8_t error) {
  switch (error) {
    case ERR_OK:         return "OK";
    case ERR_MEM:        return "Out of memory error";
    case ERR_BUF:        return "Buffer error";
    case ERR_TIMEOUT:    return "Timeout";
    case ERR_RTE:        return "Routing problem";
    case ERR_INPROGRESS: return "Operation in progress";
    case ERR_VAL:        return "Illegal value";
    case ERR_WOULDBLOCK: return "Operation would block";
    case ERR_USE:        return "Address in use";
    case ERR_ALREADY:    return "Already connected";
    case ERR_CONN:       return "Not connected";
    case ERR_IF:         return "Low-level netif error";
    case ERR_ABRT:       return "Connection aborted";
    case ERR_RST:        return "Connection reset";
    case ERR_CLSD:       return "Connection closed";
    case ERR_ARG:        return "Illegal argument";
    case -55:            return "DNS failed";
    default:             return "UNKNOWN";
  }
}

const char *AsyncClientImpl::stateToString() const {
  switch (state()) {
    case 0:  return "Closed";
    case 1:  return "Listen";
    case 2:  return "SYN Sent";
    case 3:  return "SYN Received";
    case 4:  return "Established";
    case 5:  return "FIN Wait 1";
    case 6:  return "FIN Wait 2";
    case 7:  return "Close Wait";
    case 8:  return "Closing";
    case 9:  return "Last ACK";
    case 10: return "Time Wait";
    default: return "UNKNOWN";
  }
}

/*
 * AsyncClient - the application-facing facade.
 *
 * Every method below forwards to the reference-counted implementation.  _impl is never
 * null for a live AsyncClient: it is created in the constructor and only released in
 * the destructor.
 */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
  return _impl->connect(addr, port);
}

bool AsyncClient::connect(const char *host, uint16_t port) {
  return _impl->connect(host, port);
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
  return _impl->connect(ip, port);
}
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  return _impl->connect(ip, port);
}
#endif
#endif

void AsyncClient::close() {
  _impl->close();
}

int8_t AsyncClient::abort() {
  return _impl->abort();
}

bool AsyncClient::free() {
  return _impl->free();
}

bool AsyncClient::canSend() const {
  return _impl->canSend();
}

size_t AsyncClient::space() const {
  return _impl->space();
}

size_t AsyncClient::add(const char *data, size_t size, uint8_t apiflags) {
  return _impl->add(data, size, apiflags);
}

bool AsyncClient::send() {
  return _impl->send();
}

size_t AsyncClient::write(const char *data, size_t size, uint8_t apiflags) {
  return _impl->write(data, size, apiflags);
}

uint8_t AsyncClient::state() const {
  return _impl->state();
}

bool AsyncClient::connecting() const {
  return _impl->connecting();
}

bool AsyncClient::connected() const {
  return _impl->connected();
}

bool AsyncClient::disconnecting() const {
  return _impl->disconnecting();
}

bool AsyncClient::disconnected() const {
  return _impl->disconnected();
}

bool AsyncClient::freeable() const {
  return _impl->freeable();
}

uint16_t AsyncClient::getMss() const {
  return _impl->getMss();
}

uint32_t AsyncClient::getRxTimeout() const {
  return _impl->getRxTimeout();
}

void AsyncClient::setRxTimeout(uint32_t timeout) {
  _impl->setRxTimeout(timeout);
}

uint32_t AsyncClient::getAckTimeout() const {
  return _impl->getAckTimeout();
}

void AsyncClient::setAckTimeout(uint32_t timeout) {
  _impl->setAckTimeout(timeout);
}

void AsyncClient::setNoDelay(bool nodelay) const {
  _impl->setNoDelay(nodelay);
}

bool AsyncClient::getNoDelay() {
  return _impl->getNoDelay();
}

void AsyncClient::setKeepAlive(uint32_t ms, uint8_t cnt) {
  _impl->setKeepAlive(ms, cnt);
}

uint32_t AsyncClient::getRemoteAddress() const {
  return _impl->getRemoteAddress();
}

uint16_t AsyncClient::getRemotePort() const {
  return _impl->getRemotePort();
}

uint32_t AsyncClient::getLocalAddress() const {
  return _impl->getLocalAddress();
}

uint16_t AsyncClient::getLocalPort() const {
  return _impl->getLocalPort();
}

ip4_addr_t AsyncClient::getRemoteAddress4() const {
  return _impl->getRemoteAddress4();
}

ip4_addr_t AsyncClient::getLocalAddress4() const {
  return _impl->getLocalAddress4();
}

#if LWIP_IPV6
ip6_addr_t AsyncClient::getRemoteAddress6() const {
  return _impl->getRemoteAddress6();
}

ip6_addr_t AsyncClient::getLocalAddress6() const {
  return _impl->getLocalAddress6();
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClient::remoteIP6() const {
  return _impl->remoteIP6();
}

IPv6Address AsyncClient::localIP6() const {
  return _impl->localIP6();
}
#else
IPAddress AsyncClient::remoteIP6() const {
  return _impl->remoteIP6();
}

IPAddress AsyncClient::localIP6() const {
  return _impl->localIP6();
}
#endif
#endif
#endif

#ifdef ARDUINO
IPAddress AsyncClient::remoteIP() const {
  return _impl->remoteIP();
}

IPAddress AsyncClient::localIP() const {
  return _impl->localIP();
}
#endif

void AsyncClient::ackPacket(struct pbuf *pb) {
  _impl->ackPacket(pb);
}

size_t AsyncClient::ack(size_t len) {
  return _impl->ack(len);
}

void AsyncClient::ackLater() {
  _impl->ackLater();
}

const char *AsyncClient::stateToString() const {
  return _impl->stateToString();
}

int8_t AsyncClient::_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  return _impl->_recv(pcb, pb, err);
}

tcp_pcb *AsyncClient::pcb() {
  return _impl->_pcb;
}

void AsyncClient::onConnect(AcConnectHandler cb, void *arg) {
  _impl->_connect_cb = cb;
  _impl->_connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  _impl->_discard_cb = cb;
  _impl->_discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  _impl->_sent_cb = cb;
  _impl->_sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  _impl->_error_cb = cb;
  _impl->_error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  _impl->_recv_cb = cb;
  _impl->_recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  _impl->_pb_cb = cb;
  _impl->_pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  _impl->_timeout_cb = cb;
  _impl->_timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  _impl->_poll_cb = cb;
  _impl->_poll_cb_arg = arg;
}

/*
  Async TCP Server
 */

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port) : _impl(std::make_shared<AsyncServerImpl>(this, addr, port)) {}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) {
  ip_addr_t a;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_V4;
  a.u_addr.ip4.addr = addr;
#else
  a.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&a);
#endif
  _impl = std::make_shared<AsyncServerImpl>(this, a, port);
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(addr);
  ip_addr_t a = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_V6;
#endif
  _impl = std::make_shared<AsyncServerImpl>(this, a, port);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) {
  ip_addr_t a;
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_ANY;
  a.u_addr.ip4.addr = INADDR_ANY;
#else
  a.addr = INADDR_ANY;
#endif
  _impl = std::make_shared<AsyncServerImpl>(this, a, port);
}

AsyncServer::~AsyncServer() {
  _impl->end();
  // Detach: a connection accepted but not yet delivered still points at the implementation,
  // and this is how it learns there is no longer a server to hand it to.
  _impl->_facade = nullptr;
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  _impl->onClient(cb, arg);
}
void AsyncServer::begin() {
  _impl->begin();
}
void AsyncServer::end() {
  _impl->end();
}
void AsyncServer::setNoDelay(bool nodelay) {
  _impl->setNoDelay(nodelay);
}
bool AsyncServer::getNoDelay() const {
  return _impl->getNoDelay();
}
uint8_t AsyncServer::status() const {
  return _impl->status();
}

void AsyncServerImpl::begin() {
  if (_pcb) {
    return;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return;
  }

  /*
    Allocate, bind, listen and hook up the accept callback as one transaction.  This used
    to be five separate entries into the LwIP context, three of them taking only the core
    lock - which does not exist without CONFIG_LWIP_TCPIP_CORE_LOCKING - so the LwIP thread
    could see a pcb bound but not listening, or listening with no accept callback and no
    argument, and _pcb itself was published in stages.
  */
  auto err = with_tcp_core_lock([&]() -> err_t {
#if LWIP_IPV4 && LWIP_IPV6
    tcp_pcb *pcb = tcp_new_ip_type(_addr.type);
#else
    tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
#endif
    if (!pcb) {
      return ERR_MEM;
    }

    auto err = tcp_bind(pcb, &_addr, _port);
    if (err != ERR_OK) {
      // Never registered, so nothing can reach it; dispose of it here.
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return err;
    }

    tcp_pcb *listen_pcb = tcp_listen_with_backlog(pcb, ASYNCTCP_LISTEN_BACKLOG);
    if (!listen_pcb) {
      // LwIP frees the original only on success; ours is still bound, and holds the
      // port reserved until we release it.
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return ERR_MEM;
    }

    // Published last, and with its callbacks already attached: an accept cannot arrive
    // against a server that is not ready for it.
    tcp_arg(listen_pcb, this);
    tcp_accept(listen_pcb, &AsyncTCP_detail::tcp_accept);
    _pcb = listen_pcb;
    return ERR_OK;
  });  // end LwIP scope

  if (err != ERR_OK) {
    async_tcp_log_e("begin failed: %d", (int)err);
  }
}

void AsyncServerImpl::end() {
  // The mirror of begin(): stop listening, and disown anything accepted but not fully constructed
  // on the session we are closing.  Those connections are not torn down here to avoid racing with
  // the async thread; the async task drops them when it reaches them.
  with_tcp_core_lock([&]() -> err_t {
    if (_pcb) {
      tcp_arg(_pcb, NULL);
      tcp_accept(_pcb, NULL);
      if (tcp_close(_pcb) != ERR_OK) {
        tcp_abort(_pcb);
      }
      _pcb = NULL;  // PCB is now the property of LwIP
    }
    // Disown anything already accepted on the session we just closed.  Bumped inside the
    // transaction, so it is ordered against tcp_accept() rather than racing it.
    ++_epoch;
    return ERR_OK;
  });
}

// runs on LwIP thread
int8_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, int8_t err) {
  // Note LwIP return value semantics:
  //  - ERR_OK: delivery successful
  //  - ERR_ABRT: the connection was aborted, discard your reference
  //  - Anything else: abort the connection

  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }

  auto server = reinterpret_cast<AsyncServerImpl *>(arg);
  if (!server->_connect_cb) {
    async_tcp_log_e("_accept failed: no onConnect callback");
    tcp_abort(pcb);
    return ERR_ABRT;
  }

  // Queue the accept event for processing by the async task.
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, nullptr};
  if (!e) {
    async_tcp_log_e("_accept failed: couldn't allocate event");
    tcp_abort(pcb);
    return ERR_ABRT;
  }

  // Allocate and initialize the AsyncClient implementation for this accepted connection.
  // The facade will be constructed by the async task when it processes this event -- if the connection
  // errors out prior to accept running, the event will be discarded and the implementation destroyed
  // as there's no API to inform the server of the error.
  e->impl = std::make_shared<AsyncClientImpl>(nullptr);
  e->impl->_adopt(pcb);
  e->impl->setNoDelay(server->_noDelay);
  e->server = server->shared_from_this();  // Lock server impl in scope
  e->accept.epoch = server->_epoch;        // And remember in case it's end()ed

  queue_mutex_guard guard;
  _prepend_async_event(e);
  return ERR_OK;
}

int8_t AsyncServerImpl::_accepted(AsyncClient *client) {
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  } else {
    delete client;  // nowhere to go
  }
  return ERR_OK;
}

void AsyncServerImpl::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServerImpl::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServerImpl::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServerImpl::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
