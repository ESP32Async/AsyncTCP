// Replaces the nothrow operator new so tests can make it fail.
//
// A successful allocation goes through the ordinary operator new, so the sanitizers see
// it as one and a later delete matches it.

#include "mock_alloc.h"

#include <new>

namespace {
unsigned g_attempts = 0;
unsigned g_failures = 0;
unsigned g_fail_from = 0;  // attempt number of the first failure; 0 when disarmed
unsigned g_fail_count = 0;

bool should_fail() {
  const unsigned n = ++g_attempts;
  if (g_fail_from && n >= g_fail_from && n < g_fail_from + g_fail_count) {
    g_failures++;
    return true;
  }
  return false;
}

void *allocate(std::size_t size) noexcept {
  if (should_fail()) {
    return nullptr;
  }
  try {
    return ::operator new(size);
  } catch (...) {
    return nullptr;
  }
}

void *allocate_array(std::size_t size) noexcept {
  if (should_fail()) {
    return nullptr;
  }
  try {
    return ::operator new[](size);
  } catch (...) {
    return nullptr;
  }
}
}  // namespace

void *operator new(std::size_t size, const std::nothrow_t &) noexcept {
  return allocate(size);
}

void *operator new[](std::size_t size, const std::nothrow_t &) noexcept {
  return allocate_array(size);
}

namespace mockalloc {

void reset() {
  g_attempts = 0;
  g_failures = 0;
  g_fail_from = 0;
  g_fail_count = 0;
}

void fail_nth(unsigned nth, unsigned count) {
  g_fail_from = nth ? g_attempts + nth : 0;
  g_fail_count = count;
}

unsigned failures() {
  return g_failures;
}

}  // namespace mockalloc
