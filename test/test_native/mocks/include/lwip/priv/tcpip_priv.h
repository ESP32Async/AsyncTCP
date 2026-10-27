// Host-native mock of lwip/priv/tcpip_priv.h.
//
// tcpip_api_call() invokes the callback on the calling thread in either flavor,
// which keeps the library deterministic and single-threaded under test.
#ifndef MOCK_LWIP_TCPIP_PRIV_H
#define MOCK_LWIP_TCPIP_PRIV_H

#include "lwip/err.h"
#include "lwip/tcpip.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcpip_api_call_data {
#if LWIP_TCPIP_CORE_LOCKING
  u8_t dummy;
#else
  err_t err;  // no sem: ESP-IDF sets LWIP_NETCONN_SEM_PER_THREAD
#endif
};

typedef err_t (*tcpip_api_call_fn)(struct tcpip_api_call_data *call);

err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *call);

#ifdef __cplusplus
}
#endif

#endif
