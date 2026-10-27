// Unity configuration for the host-native suite. Its presence here stops PlatformIO
// generating its own.
#ifndef UNITY_CONFIG_H
#define UNITY_CONFIG_H

#define UNITY_USE_FLUSH_STDOUT

// -f, -x and the rest, applied by the forking runner (see test_main.cpp).
#define UNITY_USE_COMMAND_LINE_ARGS

// A failed assertion ends the test by throwing (see test_main.cpp), so the test's
// destructors run.  Unity's default is a longjmp, which skips them.
#define UNITY_EXCLUDE_SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif
void asynctcp_test_abort(void);
#ifdef __cplusplus
}
#endif

#define UNITY_TEST_ABORT() asynctcp_test_abort()

#endif
