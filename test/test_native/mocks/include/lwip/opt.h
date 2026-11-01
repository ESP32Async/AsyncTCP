// Host-native mock of lwip/opt.h
#ifndef MOCK_LWIP_OPT_H
#define MOCK_LWIP_OPT_H

#include "lwip/arch.h"

#define LWIP_IPV4 1
#ifndef LWIP_IPV6
#define LWIP_IPV6 1
#endif
#define TCP_MSS          1436
#define TCP_SND_BUF      (4 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))

// Window scaling, which ESP-IDF offers as CONFIG_LWIP_WND_SCALE, widens the send buffer
// past 16 bits.
#ifndef LWIP_WND_SCALE
#define LWIP_WND_SCALE 1
#endif

// As ESP-IDF's lwipopts.h derives it.
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
#define LWIP_TCPIP_CORE_LOCKING 1
#else
#define LWIP_TCPIP_CORE_LOCKING 0
#endif

#endif
