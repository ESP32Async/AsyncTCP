// Host-native mock of lwip/ip4_addr.h
#ifndef MOCK_LWIP_IP4_ADDR_H
#define MOCK_LWIP_IP4_ADDR_H

#include "lwip/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ip4_addr {
  u32_t addr;  // network byte order on target; host order here (see README)
};
typedef struct ip4_addr ip4_addr_t;

#define IPADDR_ANY ((u32_t)0x00000000UL)

#define ip4_addr_set_zero(ipaddr)              ((ipaddr)->addr = 0)
#define ip4_addr_get_u32(src_ipaddr)           ((src_ipaddr)->addr)
#define ip4_addr_set_u32(dest_ipaddr, src_u32) ((dest_ipaddr)->addr = (src_u32))
#define ip4_addr_isany_val(addr1)              ((addr1).addr == IPADDR_ANY)

#ifdef __cplusplus
}
#endif

#endif
