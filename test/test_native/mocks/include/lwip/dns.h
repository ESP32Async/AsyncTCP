// Host-native mock of lwip/dns.h
#ifndef MOCK_LWIP_DNS_H
#define MOCK_LWIP_DNS_H

#include "lwip/arch.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dns_found_callback)(const char *name, const ip_addr_t *ipaddr, void *callback_arg);

err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg);

#ifdef __cplusplus
}
#endif

#endif
