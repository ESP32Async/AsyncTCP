// Host-native mock of the arduino-esp32 IPv6Address class (pre-IDF5 API).
#ifndef MOCK_IPV6ADDRESS_H
#define MOCK_IPV6ADDRESS_H

#include <stdint.h>
#include <string.h>

class IPv6Address {
public:
  IPv6Address() {
    memset(_addr, 0, sizeof(_addr));
  }
  IPv6Address(const uint32_t *address) {
    memcpy(_addr, address, sizeof(_addr));
  }

  operator const uint32_t *() const {
    return (const uint32_t *)_addr;
  }
  bool operator==(const IPv6Address &other) const {
    return memcmp(_addr, other._addr, sizeof(_addr)) == 0;
  }

private:
  uint8_t _addr[16];
};

#endif
