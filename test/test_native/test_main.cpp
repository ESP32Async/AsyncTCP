// Host-native AsyncTCP tests.
//
//   pio test -e native                  run everything
//   pio test -e native-asan             ... under ASan/UBSan
//   pio test -e native-no-ipv6          ... against IPv4-only lwIP
//   pio test -e native-no-core-locking  ... without the TCPIP core lock
//   ASYNCTCP_TEST_VERBOSE=1             also print the library's log_* output
//   ASYNCTCP_TEST_NOFORK=1              run in-process, for a debugger
//
// Each tests/*.cpp file exposes one run_*_tests() listing what it contains.

#include "runner.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#if defined(__unix__) || defined(__APPLE__)
#define ASYNCTCP_TEST_CAN_FORK 1
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "mocks/mock_alloc.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

#if defined(__SANITIZE_ADDRESS__)
#define ASYNCTCP_TEST_LSAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ASYNCTCP_TEST_LSAN 1
#endif
#endif

#ifdef ASYNCTCP_TEST_LSAN
#include <sanitizer/lsan_interface.h>
#endif

#ifdef __GLIBC__
#include <malloc.h>
#endif

void run_client_tests(void);
void run_write_tests(void);
void run_recv_tests(void);
void run_timeout_tests(void);
void run_dns_tests(void);
void run_server_listen_tests(void);
void run_server_accept_tests(void);
void run_server_config_tests(void);
void run_state_tests(void);
void run_error_tests(void);
void run_dispose_tests(void);
void run_lifetime_tests(void);
void run_callback_tests(void);
void run_context_tests(void);
void run_alloc_tests(void);
void run_congestion_tests(void);
void run_start_tests(void);

namespace {

// Thrown by TEST_ABORT() -- see unity_config.h.  Unity calls it after it has printed a
// failure, from inside the failed assertion.
struct TestAbort {};

// Set where there is nothing left to unwind to.  TEST_ABORT() then just returns.
bool g_abort_returns = false;

bool g_in_child = false;

// -l: print each test's name rather than run it.
bool g_list_only = false;

// Runs one stage of a test.  A failed assertion ends the stage; Unity has already
// recorded it.
void guarded(void (*fn)(void)) {
  try {
    fn();
  } catch (const TestAbort &) {}
}

void reset_mocks(void) {
  mocklwip::reset();
  mockrtos::reset();
  mockclock::reset();
  mockalloc::reset();
  // As on a target that has been up a while.  A test about millis() == 0 sets it itself.
  mockclock::set_millis(1000);
}

void check_invariants(void) {
  // Whole-library invariants, checked after every test rather than restated in each one,
  // and reported against the test's own line.
  const UNITY_LINE_TYPE line = Unity.CurrentTestLineNumber;
  UNITY_TEST_ASSERT(!mockrtos::null_semaphores(), line, "semaphore used before it was created");
  UNITY_TEST_ASSERT(!mockrtos::deadlocks(), line, "non-recursive mutex taken while held (would deadlock)");
  UNITY_TEST_ASSERT(!mocklwip::reentrant_api_calls(), line, "tcpip_api_call from the LwIP thread (would deadlock)");
  UNITY_TEST_ASSERT_EQUAL_INT(0, mocklwip::core_lock_depth(), line, "TCPIP core lock still held");
  if (mocklwip::unlocked_calls()) {
    const std::string msg = std::string(mocklwip::first_unlocked_call()) + "() called off the LwIP thread without the TCPIP core lock";
    UNITY_TEST_FAIL(line, msg.c_str());
  }
  if (mocklwip::callback_return_violations()) {
    UNITY_TEST_FAIL(line, mocklwip::first_callback_return_violation());
  }
}

// Only in a forked child: in one process, a leak would be reported again by every later
// test.  A test that has already failed is not reported twice.
void check_leaks(void) {
#ifdef ASYNCTCP_TEST_LSAN
  if (!g_in_child || Unity.CurrentTestFailed) {
    return;
  }
  if (__lsan_do_recoverable_leak_check()) {
    UnityFail("leaked memory (see the LeakSanitizer report)", Unity.CurrentTestLineNumber);
  }
#endif
}

// The test UnityDefaultTestRun() is running, called through run_current_test().
void (*g_current_test)(void) = nullptr;

void run_current_test(void) {
  if (!Unity.CurrentTestFailed && !Unity.CurrentTestIgnored) {
    guarded(g_current_test);
  }
}

void run_test(void (*fn)(void), const char *name, int line) {
  g_current_test = fn;
  UnityDefaultTestRun(&run_current_test, name, line);
}

}  // namespace

void setUp(void) {
  guarded(reset_mocks);
}

void tearDown(void) {
  guarded(check_invariants);

  // Drop anything the test left behind so the next one starts clean.
  mocklwip::reset();

  guarded(check_leaks);
}

namespace {

// How a child process reports back, as an exit status.  Anything else -- 1 from a
// sanitizer, say -- means it died without concluding the test.
enum ChildResult {
  CHILD_PASSED = 80,
  CHILD_FAILED = 81,
  CHILD_IGNORED = 82
};

// A stand-in for a test whose real body ran in a child that printed nothing. Unity
// runs this in the parent, so it prints and counts exactly as any other test does.
const char *g_verdict = nullptr;
int g_verdict_line = 0;

void report_verdict(void) {
  // Report against the test's own line, not this file's.
  UNITY_TEST_FAIL((UNITY_LINE_TYPE)g_verdict_line, g_verdict);
}

void run_verdict(const char *name, int line, const char *message) {
  g_verdict = message;
  g_verdict_line = line;
  run_test(&report_verdict, name, line);
}

// Count a test whose line the child already printed.
void tally(int result) {
  Unity.NumberOfTests++;
  if (result == CHILD_FAILED) {
    Unity.TestFailures++;
  } else if (result == CHILD_IGNORED) {
    Unity.TestIgnores++;
  }
}

// UnityDefaultTestRun() ends in UnityConcludeTest(), which folds CurrentTestFailed
// and CurrentTestIgnored into these totals and then clears them -- so the verdict has
// to be read as a delta across the run, not from the per-test flags afterwards.
struct UnityTally {
  UNITY_COUNTER_TYPE failures;
  UNITY_COUNTER_TYPE ignores;
};

UnityTally tally_now(void) {
  return UnityTally{Unity.TestFailures, Unity.TestIgnores};
}

int result_since(const UnityTally &before) {
  if (Unity.TestFailures != before.failures) {
    return CHILD_FAILED;
  }
  return Unity.TestIgnores != before.ignores ? CHILD_IGNORED : CHILD_PASSED;
}

#ifdef ASYNCTCP_TEST_CAN_FORK
// Shared with the parent: the verdict the child has printed so far, if any.  A child
// that dies after printing a failure must not then be reported a second time.
const int NOTHING_PRINTED = -1;
volatile int *g_printed = nullptr;

UnityTally g_child_before;

// _exit(), so the sanitizers' exit-time leak check cannot report the test again.
[[noreturn]]
void end_child(void) {
  fflush(stdout);
  _exit(result_since(g_child_before));
}

// A throw from a noexcept context -- a failed assertion in a callback run from a
// destructor, say -- lands here, with nothing left to unwind.  Conclude the test as
// failed, once.
[[noreturn]]
void on_terminate(void) {
  g_abort_returns = true;
  if (!Unity.CurrentTestFailed && !Unity.CurrentTestIgnored) {
    UnityFail("std::terminate() called", Unity.CurrentTestLineNumber);
  }
  UnityConcludeTest();
  end_child();
}
#endif

}  // namespace

extern "C" void asynctcp_test_abort(void) {
#ifdef ASYNCTCP_TEST_CAN_FORK
  if (g_printed) {
    *g_printed = Unity.CurrentTestIgnored ? CHILD_IGNORED : CHILD_FAILED;
  }
#endif
  if (!g_abort_returns) {
    throw TestAbort{};
  }
}

void asynctcp_run_test(void (*fn)(void), const char *name, int line) {
  Unity.CurrentTestName = name;
  if (!UnityTestMatches()) {
    return;
  }
  if (g_list_only) {
    printf("%s:%s\n", Unity.TestFile, name);
    return;
  }

#ifdef ASYNCTCP_TEST_CAN_FORK
  if (getenv("ASYNCTCP_TEST_NOFORK") == nullptr) {
    if (!g_printed) {
      void *shared = mmap(nullptr, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
      if (shared == MAP_FAILED) {
        run_verdict(name, line, "mmap() failed");
        return;
      }
      g_printed = (volatile int *)shared;
    }
    *g_printed = NOTHING_PRINTED;

    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
      run_verdict(name, line, "fork() failed");
      return;
    }

    if (pid == 0) {
      g_in_child = true;
      g_child_before = tally_now();
      std::set_terminate(on_terminate);
      run_test(fn, name, line);
      end_child();
    }

    int status = 0;
    waitpid(pid, &status, 0);

    const int result = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (result == CHILD_PASSED || result == CHILD_FAILED || result == CHILD_IGNORED) {
      tally(result);
      return;
    }

    static char msg[128];
    if (WIFSIGNALED(status)) {
      snprintf(msg, sizeof(msg), "killed by signal %d (%s)", WTERMSIG(status), strsignal(WTERMSIG(status)));
    } else {
      snprintf(msg, sizeof(msg), "exited with status %d", result);
    }
    if (*g_printed != NOTHING_PRINTED) {
      // The child died after printing its verdict: finish that line.
      printf(" -- then %s\n", msg);
      tally(*g_printed);
      return;
    }
    // The child died partway through, so it never printed a verdict of its own.
    if (!WIFSIGNALED(status)) {
      strncat(msg, " without a verdict", sizeof(msg) - strlen(msg) - 1);
    }
    run_verdict(name, line, msg);
    return;
  }
#endif

  // In-process, for a debugger.
  run_test(fn, name, line);
}

// Fresh allocations are filled with 0xfe, as locals are (see platformio.ini), so a value
// read before it was written is the same on every run.
#ifdef ASYNCTCP_TEST_LSAN
extern "C" const char *__asan_default_options(void) {
  return "malloc_fill_byte=254:max_malloc_fill_size=1048576";
}
#endif

int main(int argc, char **argv) {
#ifdef __GLIBC__
  mallopt(M_PERTURB, 0x01);  // glibc fills with the complement
#endif

  // Unity's own options; see README.md.
  const int options = UnityParseOptions(argc, argv);
  if (options > 0) {
    return options;
  }
  g_list_only = options < 0;

  UNITY_BEGIN();

  run_client_tests();
  run_write_tests();
  run_recv_tests();
  run_timeout_tests();
  run_dns_tests();
  run_server_listen_tests();
  run_server_accept_tests();
  run_server_config_tests();
  run_state_tests();
  run_error_tests();
  run_dispose_tests();
  run_lifetime_tests();
  run_callback_tests();
  run_context_tests();
  run_alloc_tests();
  run_congestion_tests();
  run_start_tests();

  if (g_list_only) {
    return 0;
  }
  UNITY_END();

  // PlatformIO's native runner reads the verdict out of the Unity output above, and
  // passes any non-zero exit code to signal.Signals(), which renames a plain test
  // failure to "received signal SIGHUP".
  return 0;
}
