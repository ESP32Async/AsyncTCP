// Host-native mock of lwip/inet.h
#ifndef MOCK_LWIP_INET_H
#define MOCK_LWIP_INET_H

#include "lwip/ip_addr.h"

#ifndef INADDR_ANY
#define INADDR_ANY IPADDR_ANY
#endif

#endif
