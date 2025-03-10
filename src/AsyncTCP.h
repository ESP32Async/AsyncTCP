// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2025 Hristo Gochkov, Mathieu Carbou, Emil Muratov

#ifndef ASYNCTCP_H_
#define ASYNCTCP_H_

#include "AsyncTCPVersion.h"
#define ASYNCTCP_FORK_ESP32Async

#include "IPAddress.h"
#if ESP_IDF_VERSION_MAJOR < 5
#include "IPv6Address.h"
#endif
#include "lwip/ip6_addr.h"
#include "lwip/ip_addr.h"
#include <functional>

#ifndef LIBRETINY
#include "sdkconfig.h"
extern "C" {
#include "freertos/semphr.h"
#include "lwip/pbuf.h"
}
#else
extern "C" {
#include <lwip/pbuf.h>
#include <semphr.h>
}
#define CONFIG_ASYNC_TCP_RUNNING_CORE -1  // any available core
#endif

// If core is not defined, then we are running in Arduino or PIO
#ifndef CONFIG_ASYNC_TCP_RUNNING_CORE
#define CONFIG_ASYNC_TCP_RUNNING_CORE -1  // any available core
#endif

// guard AsyncTCP task with watchdog
#ifndef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 1
#endif

#ifndef CONFIG_ASYNC_TCP_STACK_SIZE
#define CONFIG_ASYNC_TCP_STACK_SIZE 8192 * 2
#endif

#ifndef CONFIG_ASYNC_TCP_PRIORITY
#define CONFIG_ASYNC_TCP_PRIORITY 10
#endif

#ifndef CONFIG_ASYNC_TCP_MAX_ACK_TIME
#define CONFIG_ASYNC_TCP_MAX_ACK_TIME 5000
#endif

class AsyncClient;

#define ASYNC_WRITE_FLAG_COPY 0x01  // will allocate new buffer to hold the data while sending (else will hold reference to the data given)
#define ASYNC_WRITE_FLAG_MORE 0x02  // will not send PSH flag, meaning that there should be more data to be sent before the application should react.

typedef std::function<void(void *, AsyncClient *)> AcConnectHandler;
typedef std::function<void(void *, AsyncClient *, size_t len, uint32_t time)> AcAckHandler;
typedef std::function<void(void *, AsyncClient *, int8_t error)> AcErrorHandler;
typedef std::function<void(void *, AsyncClient *, void *data, size_t len)> AcDataHandler;
typedef std::function<void(void *, AsyncClient *, struct pbuf *pb)> AcPacketHandler;
typedef std::function<void(void *, AsyncClient *, uint32_t time)> AcTimeoutHandler;

struct tcp_pcb;
struct ip_addr;
class AsyncClient_detail;
struct lwip_tcp_event_packet_t;

class AsyncClient {
public:
  AsyncClient(tcp_pcb *pcb = 0);
  ~AsyncClient();

  // Noncopyable
  AsyncClient(const AsyncClient &) = delete;
  AsyncClient &operator=(const AsyncClient &) = delete;

  // Nonmovable
  AsyncClient(AsyncClient &&) = delete;
  AsyncClient &operator=(AsyncClient &&) = delete;

  inline bool operator==(const AsyncClient &other) {
    return _pcb == other._pcb;
  }
  inline bool operator!=(const AsyncClient &other) {
    return !(*this == other);
  }

  bool connect(const IPAddress &ip, uint16_t port);
#if ESP_IDF_VERSION_MAJOR < 5
  bool connect(const IPv6Address &ip, uint16_t port);
#endif
  bool connect(const char *host, uint16_t port);
  /**
     * @brief close connection
     * @note will call onDisconnect callback
     *
     * @param now - ignored
     */
  void close(bool now = false);
  // same as close()
  void stop() {
    close(false);
  };

  /**
     * @brief abort connection
     * @note does NOT call onDisconnect callback!
     *
     * @return always returns ERR_ABRT
     */
  int8_t abort();
  bool free();

  // ack is not pending
  bool canSend();
  // TCP buffer space available
  size_t space();

  /**
     * @brief add data to be send (but do not send yet)
     * @note add() would call lwip's tcp_write()
        By default apiflags=ASYNC_WRITE_FLAG_COPY
        You could try to use apiflags with this flag unset to pass data by reference and avoid copy to socket buffer,
        but looks like it does not work for Arduino's lwip in ESP32/IDF at least
        it is enforced in https://github.com/espressif/esp-lwip/blob/0606eed9d8b98a797514fdf6eabb4daf1c8c8cd9/src/core/tcp_out.c#L422C5-L422C30
        if LWIP_NETIF_TX_SINGLE_PBUF is set, and it is set indeed in IDF
        https://github.com/espressif/esp-idf/blob/a0f798cfc4bbd624aab52b2c194d219e242d80c1/components/lwip/port/include/lwipopts.h#L744
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t amount of data that has been copied
     */
  size_t add(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief send data previously add()'ed
     *
     * @return true on success
     * @return false on error
     */
  bool send();

  /**
     * @brief add and enqueue data for sending
     * @note it is same as add() + send()
     * @note only make sense when canSend() == true
     *
     * @param data
     * @param size
     * @param apiflags
     * @return size_t
     */
  size_t write(const char *data, size_t size, uint8_t apiflags = ASYNC_WRITE_FLAG_COPY);

  /**
     * @brief add and enqueue data for sending
     * @note treats data as null-terminated string
     *
     * @param data
     * @return size_t
     */
  size_t write(const char *data) {
    return data == NULL ? 0 : write(data, strlen(data));
  };

  uint8_t state();
  bool connecting();
  bool connected();
  bool disconnecting();
  bool disconnected();

  // disconnected or disconnecting
  bool freeable();

  uint16_t getMss();

  uint32_t getRxTimeout();
  // no RX data timeout for the connection in seconds
  void setRxTimeout(uint32_t timeout);

  uint32_t getAckTimeout();
  // no ACK timeout for the last sent packet in milliseconds
  void setAckTimeout(uint32_t timeout);

  void setNoDelay(bool nodelay);
  bool getNoDelay();

  void setKeepAlive(uint32_t ms, uint8_t cnt);

  uint32_t getRemoteAddress();
  uint16_t getRemotePort();
  uint32_t getLocalAddress();
  uint16_t getLocalPort();
#if LWIP_IPV6
  ip6_addr_t getRemoteAddress6();
  ip6_addr_t getLocalAddress6();
#if ESP_IDF_VERSION_MAJOR < 5
  IPv6Address remoteIP6();
  IPv6Address localIP6();
#else
  IPAddress remoteIP6();
  IPAddress localIP6();
#endif
#endif

  // compatibility
  IPAddress remoteIP();
  uint16_t remotePort();
  IPAddress localIP();
  uint16_t localPort();

  // set callback - on successful connect
  void onConnect(AcConnectHandler cb, void *arg = 0);
  // set callback - disconnected
  void onDisconnect(AcConnectHandler cb, void *arg = 0);
  // set callback - ack received
  void onAck(AcAckHandler cb, void *arg = 0);
  // set callback - unsuccessful connect or error
  void onError(AcErrorHandler cb, void *arg = 0);
  // set callback - data received (called if onPacket is not used)
  void onData(AcDataHandler cb, void *arg = 0);
  // set callback - data received
  void onPacket(AcPacketHandler cb, void *arg = 0);
  // set callback - ack timeout
  void onTimeout(AcTimeoutHandler cb, void *arg = 0);
  // set callback - every 125ms when connected
  void onPoll(AcConnectHandler cb, void *arg = 0);

  // ack pbuf from onPacket
  void ackPacket(struct pbuf *pb);
  // ack data that you have not acked using the method below
  size_t ack(size_t len);
  // will not ack the current packet. Call from onData
  void ackLater() {
    _ack_pcb = false;
  }

  static const char *errorToString(int8_t error);
  const char *stateToString();

  tcp_pcb *pcb() {
    return _pcb;
  }

protected:
  tcp_pcb *_pcb;
  lwip_tcp_event_packet_t *_end_event;
  bool _needs_discard;
  unsigned _polls_pending;
  uint16_t _sent_pending;
#ifdef CONFIG_ASYNC_TCP_COALESCE_RECV
  struct lwip_tcp_event_packet_t *_recv_pending;
#endif

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
  uint16_t _connect_port;

  friend class AsyncClient_detail;
  bool _connect(const ip_addr_t &addr, uint16_t port);
  int8_t _close();
  int8_t _connected(int8_t err);
  void _error(int8_t err);
  int8_t _poll();
  int8_t _sent(uint16_t len);
  int8_t _fin(int8_t err);
  int8_t _lwip_fin(tcp_pcb *pcb, int8_t err);
  int8_t _recv(pbuf *pb, int8_t err);
  void _dns_found(struct ip_addr *ipaddr);
  int8_t _recved(size_t len);
};

class AsyncServer {
public:
  AsyncServer(IPAddress addr, uint16_t port);
#if ESP_IDF_VERSION_MAJOR < 5
  AsyncServer(IPv6Address addr, uint16_t port);
#endif
  AsyncServer(uint16_t port);
  ~AsyncServer();

  // Noncopyable
  AsyncServer(const AsyncServer &) = delete;
  AsyncServer &operator=(const AsyncServer &) = delete;

  // Nonmovable
  AsyncServer(AsyncServer &&) = delete;
  AsyncServer &operator=(AsyncServer &&) = delete;

  void onClient(AcConnectHandler cb, void *arg);
  void begin();
  void end();
  void setNoDelay(bool nodelay);
  bool getNoDelay();
  uint8_t status();

  // Do not use any of the functions below!
  static int8_t _s_accept(void *arg, tcp_pcb *newpcb, int8_t err);
  static int8_t _s_accepted(void *arg, AsyncClient *client);

protected:
  uint16_t _port;
  bool _bind4 = false;
  bool _bind6 = false;
  IPAddress _addr;
#if ESP_IDF_VERSION_MAJOR < 5
  IPv6Address _addr6;
#endif
  bool _noDelay;
  tcp_pcb *_pcb;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;

  friend class AsyncClient_detail;
  int8_t _accept(tcp_pcb *newpcb, int8_t err);
  int8_t _accepted(AsyncClient *client);
};

#endif /* ASYNCTCP_H_ */
