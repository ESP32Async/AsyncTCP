// Test invocation for the host-native suite.
//
// The tests themselves are ordinary Unity. This only changes how they are called:
// each one runs in a forked child, so a crash costs one test rather than the rest of
// the run, and the sanitizers' leak check reports against the test that leaked. Unity leaves RUN_TEST overridable for exactly this.
//
// Include this instead of <unity.h>.
#ifndef ASYNCTCP_TEST_RUNNER_H
#define ASYNCTCP_TEST_RUNNER_H

#include <unity.h>

void asynctcp_run_test(void (*fn)(void), const char *name, int line);

#undef RUN_TEST
#define RUN_TEST(func) asynctcp_run_test(func, #func, __LINE__)

#endif
