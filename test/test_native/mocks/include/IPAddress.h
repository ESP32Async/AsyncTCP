// Host-native mock of the Arduino/ESP32 IPAddress class.
// Header-only; only the surface AsyncTCP uses is provided.
#ifndef MOCK_IPADDRESS_H
#define MOCK_IPADDRESS_H

#include <stdint.h>

class IPAddress {
public:
  IPAddress() : _addr(0) {}
  IPAddress(uint32_t address) : _addr(address) {}
  IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : _addr(((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d) {}

  operator uint32_t() const {
    return _addr;
  }

  bool operator==(const IPAddress &other) const {
    return _addr == other._addr;
  }

private:
  uint32_t _addr;
};

#endif
