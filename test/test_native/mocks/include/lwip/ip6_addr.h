// Host-native mock of lwip/ip6_addr.h
#ifndef MOCK_LWIP_IP6_ADDR_H
#define MOCK_LWIP_IP6_ADDR_H

#include "lwip/arch.h"
#include "lwip/opt.h"

#if LWIP_IPV6

#ifdef __cplusplus
extern "C" {
#endif

struct ip6_addr {
  u32_t addr[4];
};
typedef struct ip6_addr ip6_addr_t;

#define ip6_addr_set_zero(ip6addr)                                                         \
  do {                                                                                     \
    (ip6addr)->addr[0] = (ip6addr)->addr[1] = (ip6addr)->addr[2] = (ip6addr)->addr[3] = 0; \
  } while (0)
#define ip6_addr_isany_val(ip6addr) (((ip6addr).addr[0] == 0) && ((ip6addr).addr[1] == 0) && ((ip6addr).addr[2] == 0) && ((ip6addr).addr[3] == 0))

#ifdef __cplusplus
}
#endif

#endif  // LWIP_IPV6

#endif
