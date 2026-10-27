// Test-facing control surface for failing nothrow allocations.
//
// The library allocates with new (std::nothrow) and copes with nullptr; the harness and
// the mocks allocate with plain new.  So only the library's allocations are counted and
// failed.
//
// This header is for tests only -- the library never sees it.
#ifndef ASYNCTCP_MOCK_ALLOC_H
#define ASYNCTCP_MOCK_ALLOC_H

namespace mockalloc {

// Forgets any armed failure and zeroes the counts.  Call between tests.
void reset();

// Fails the <nth> nothrow allocation from now (1 is the next one), and the <count> - 1
// after it.
void fail_nth(unsigned nth, unsigned count = 1);
inline void fail_next(unsigned count = 1) {
  fail_nth(1, count);
}

// Nothrow allocations failed since reset().
unsigned failures();

}  // namespace mockalloc

#endif
