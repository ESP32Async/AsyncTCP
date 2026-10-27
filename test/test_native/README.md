# Host-native test harness

The harness compiles `src/AsyncTCP.cpp` for the host against mock lwIP, FreeRTOS
and Arduino headers, so the library's logic can be exercised on a desktop with no
ESP32 and no network.

It needs no changes to anything under `src/`.

## Running

```
pio test -e native                  # the suite
pio test -e native-asan             # ... under ASan/UBSan, with leak detection
pio test -e native-no-ipv6          # ... against lwIP built for IPv4 only
pio test -e native-no-core-locking  # ... against lwIP without core locking
```

Each environment reports every test separately, and `pio test` exits non-zero if
any test fails. The two lwIP configurations change address layout and locking,
not who owns what, so they run without the sanitizers.

To work under a debugger, run the built program directly;
`ASYNCTCP_TEST_NOFORK=1` keeps every test in one process:

```
ASYNCTCP_TEST_NOFORK=1 gdb .pio/build/native/program
```

`ASYNCTCP_TEST_VERBOSE=1` additionally prints the library's `log_*` output.

Unity's own options select which tests run; `-h` lists them. To pass one through
`pio test`, give it as a single `-a` argument, with any value joined by `=`:

```
pio test -e native -a -f=test_dns_     # only tests whose name contains test_dns_
pio test -e native -a -x=congestion    # all but those
.pio/build/native/program -f=dns_ -l   # list the matches instead of running them
```

## Reading the results

A failing test is a defect in the library, not in the test. Tests documenting
known library failures begin with a `TEST_IGNORE_MESSAGE()` describing the
defect, so a run is green. Fixing the defect includes deleting that line. A
change must not make any test fail.

To list what is still ignored:

```
pio test -e native -v | grep ':IGNORE:'
```

## Why each test is forked

`test_main.cpp` runs every test in a child process, so a test that segfaults
costs one red result instead of the rest of the run -- which matters, because the
bugs this suite is aimed at tend to crash rather than to fail an assertion.
Forking also lets `tearDown()` run LeakSanitizer's check on one test at a time, so a
leak fails the test that caused it.

## How a failed assertion ends a test

`unity_config.h` makes Unity's `TEST_ABORT()` throw, and `test_main.cpp` catches
that around the test, `setUp()` and `tearDown()`. So a failed assertion ends the
test on the spot, as it would with Unity's default `longjmp`, but the test's
destructors still run, and so does `tearDown()`. The same is true of a failed
assertion in a callback that a pump runs.

Where nothing can be unwound -- a failed assertion in a callback run from a
destructor, which is `noexcept` -- the throw ends in `std::terminate()`. In a
forked child, the runner's terminate handler then records the test as failed;
under `ASYNCTCP_TEST_NOFORK=1`, the whole run ends.

## How the async task is pumped

`AsyncTCP` does its application-callback work on a FreeRTOS task
(`_async_service_task`), started once via `xTaskCreate`. Running that
as a real thread would make every test a race, so the harness does not.

Instead:

* the FreeRTOS mock's `xTaskCreate()` **records** the task function
  and its parameter and returns a fake handle, without starting anything;
* `asynctcp_test_pump()` calls that recorded function **on the calling
  thread**. The task's `for (;;)` body drains the library's event queue exactly
  as it would on target;
* when the queue is empty the task calls `ulTaskNotifyTake(pdTRUE,
  portMAX_DELAY)` to sleep. The mock notices it is inside a pump and throws a
  private `PumpExit` exception, which `asynctcp_test_pump()` catches.

So `asynctcp_test_pump()` means "run the async task until its queue is empty,
then return".

This needs no hook in `src/`. It relies on two properties of the task loop, both
true today:

* no live objects span the `ulTaskNotifyTake()` call (the queue mutex guard
  lives and dies inside `_get_async_event()`), so the unwind is safe. It is a
  real C++ unwind, so destructors run — unlike a `longjmp`;
* the loop keeps no state across iterations, so re-entering it from the top on
  each pump is equivalent to letting it spin.

The build therefore **must** keep `-fexceptions`, which failed assertions need
too.

`_async_service_task_handle` is a file-static inside `src/AsyncTCP.cpp` that the
harness cannot reach, so once the library has started its task it stays started
for the life of the process. That is fine (the task is stateless) and is why
`mockrtos::reset()` deliberately does not forget the recorded task function.
Forking sidesteps it anyway: the parent runs no test bodies, so each child starts
from a process in which the library has not yet started anything.

## Layout

```
test/test_native/
  runner.h              RUN_TEST, overridden to fork
  unity_config.h        makes TEST_ABORT() throw
  test_main.cpp         the runner: per-test reset, forking, Unity reporting
  asynctcp.cpp          the library under test, compiled into the test program
  fixtures.h            what most tests share: the peer and ports, establish(),
                        listen_pcb(), AppCall, Recorder, Accepted
  tests/                one file per topic; new files here are picked up automatically
    test_client.cpp         end-to-end smoke tests, one per main path
    test_state.cpp          the connection state machine and the accessors
    test_write.cpp          the outbound path
    test_recv.cpp           the inbound path
    test_timeout.cpp        the rx and ack timeouts, onPoll, keepalive
    test_error.cpp          how failures are reported
    test_dispose.cpp        one connection, one terminal notification
    test_dns.cpp            name resolution, and lookups that are abandoned
    test_lifetime.cpp       destroying a client at awkward moments
    test_callback.cpp       what each handler is handed
    test_context.cpp        callbacks run on the async task, not inside calls
    test_server_listen.cpp  begin(), end(), status(), restarts
    test_server_accept.cpp  delivering accepted connections
    test_server_config.cpp  setNoDelay()
    test_alloc.cpp          each lwIP callback when the library cannot allocate
    test_congestion.cpp     far more events queued than the queue is sized for
    test_start.cpp          when FreeRTOS cannot create the queue mutex or the task
  mocks/
    include/            fake system headers -- on the include path FIRST, so
                        #include "lwip/tcp.h" etc. resolve here
      Arduino.h  IPAddress.h  IPv6Address.h  sdkconfig.h  esp_*.h
      freertos/{FreeRTOS,task,semphr}.h
      lwip/{arch,opt,err,pbuf,ip_addr,ip4_addr,ip6_addr,inet,tcp,dns,tcpip}.h
      lwip/priv/tcpip_priv.h
    mock_lwip.h/.cpp    mock lwIP stack + its test-facing control API
    mock_rtos.h/.cpp    FreeRTOS, mock clock, logging, the pump
    mock_alloc.h/.cpp   nothrow operator new, which tests can make fail
```

`mock_lwip.h`, `mock_rtos.h` and `mock_alloc.h` are for tests only; the library never sees them.

## What the mock lwIP models

The mock behaves as real lwIP does wherever AsyncTCP's lifetime handling depends
on it:

* `tcp_abort()` frees the pcb and **then** invokes the error callback with
  `ERR_ABRT` (except on `LISTEN` pcbs).
* A fatal error (`fire_error`) frees the pcb **before** the error callback runs,
  so the pointer the library sees is already dangling.
* `tcp_close()` frees the pcb only when it returns `ERR_OK`.
* `tcp_listen_with_backlog()` on success allocates a **new** listen pcb and
  frees the one passed in; on failure it returns `NULL` and leaves the caller's
  pcb alone, so the caller still owns it. (That asymmetry is what
  `test_server_listen_begin_frees_the_bound_pcb_when_listen_fails` is
  about.)
* `tcp_connect()` failure does **not** free the pcb.
* `tcp_write()` checks what `tcp_write_checks()` does: `ERR_CONN` outside
  `ESTABLISHED`, `CLOSE_WAIT`, `SYN_SENT` and `SYN_RCVD`; `ERR_MEM` for more than
  `tcp_sndbuf()`, or for more segments than `TCP_SND_QUEUELEN`. Segments are cut as
  ESP-IDF's lwIP cuts them (one pbuf each, topped up to the MSS until `tcp_output()`),
  and leave the queue as `fire_sent()` acks them.
* lwIP is built with window scaling, so the send buffer is 32 bits wide and
  `tcp_sndbuf()` saturates at 65535, as it does in lwIP. `set_send_buffer(pcb, n)`
  resizes a pcb's.
* Data the recv callback refuses (anything but `ERR_OK` or `ERR_ABRT`) stays on the
  pcb and is offered again by `retry_refused()`, or before the next segment; until it
  is taken, later segments are dropped. A FIN is reported once, whatever the callback
  returns.
* A callback handed a pcb must return `ERR_ABRT` if and only if it aborted that pcb,
  as `tcp_abort()` in lwIP's `tcp.c` requires. An accept callback returning any
  other error has the new pcb aborted, as `tcp_process()` does.
* Ports are tracked, so a second bind to a live port returns `ERR_USE` and a
  leaked listen pcb shows up as a leaked port.

`tcpip_api_call(fn, msg)` calls `fn(msg)` directly on the calling thread. With
`CONFIG_LWIP_TCPIP_CORE_LOCKING` that is what lwIP does, under the core lock;
without it, lwIP runs `fn` on its own thread, and there is no core lock at all,
so `LOCK_TCPIP_CORE()` is empty and the raw API is safe only on the lwIP thread.

The mock treats code running inside `tcpip_api_call()` or a `fire_*` helper as
running on the lwIP thread. After every test, the runner fails that test if the
library:

* called `tcpip_api_call()` from the lwIP thread, which would deadlock;
* left the TCPIP core lock held;
* called any `tcp_*` or `dns_*` function neither on the lwIP thread nor under
  the core lock, which would race the lwIP thread;
* returned `ERR_ABRT` from a callback for a pcb it had not aborted, or anything
  else for one it had, which would leave lwIP using a freed pcb or dropping a live
  one.

Addresses are kept in **host** byte order throughout, which keeps
`IPAddress(10,0,0,1)` and `remote_ip4(pcb)` directly comparable.

`LWIP_IPV6` defaults to 1; with it 0, as LibreTiny builds lwIP, `ip_addr_t` is
plain `ip4_addr_t` with no `type` or `u_addr`.

## Adding a test

Add a new test to the file for its topic, or put it in a new `.cpp` file in
`tests/`; PlatformIO compiles everything under this directory. The tests are
plain Unity, and each file registers its tests in a single `run_*_tests()`
function:

```cpp
#include "fixtures.h"

using namespace mocklwip;

static void test_topic_data_reaches_onData(void) {
  AsyncClient c;
  Recorder t;
  t.attach(c, "CEDR");          // onConnect, onError, onDisconnect, onData
  tcp_pcb *pcb = establish(c);  // connected to kPeer:kPort, onConnect delivered

  fire_recv(pcb, "hi", 2);
  asynctcp_test_pump();
  TEST_ASSERT_EQUAL_STRING("CR", t.seq.c_str());
  TEST_ASSERT_EQUAL_STRING("hi", t.data.c_str());
  c.close();
}

void run_topic_tests(void) {
  UnitySetTestFile(__FILE__);
  RUN_TEST(test_topic_data_reaches_onData);
}
```

Include `fixtures.h`, or at least `runner.h`, rather than `<unity.h>`: `runner.h`
is what redirects `RUN_TEST` into the forking runner. A new file's
`run_*_tests()` has to be declared and called in `test_main.cpp`.

Every configuration builds every test, so tests about IPv6 should go inside
`#if LWIP_IPV6`, and tests should read addresses through `remote_ip4(pcb)`
rather than the fields of `ip_addr_t`, whose layout depends on `LWIP_IPV6`.

`fixtures.h` holds what most tests start with:

* `kPeer`, `kPort`, `kServerPort`, `kResolved`: where clients dial, where
  servers listen, what a lookup answers;
* `establish(c)`: connects `c` and delivers the handshake, returning its pcb;
* `listen_pcb(port)`: the listening pcb, on `port` or on any port;
* `Recorder`: records a client's callbacks as a string, one letter each, so
  order, count and exactly-once are one assertion;
* `AppCall`, `app()`, `app_close()`, `app_abort()`, `app_delete()`: mark the span
  of an application call into the library. A `Recorder` adds to `violations`
  any callback that runs during that span but that the call may not run;
* `Accepted`: takes delivery of a server's clients and deletes whatever is left
  of them at scope exit.

`python3 test/check_registration.py` (run by pre-commit and CI) fails if a test
is never registered, or is not named for its file: tests in `test_topic.cpp`
must be named `test_topic_*`.

`test_main.cpp` calls `mocklwip::reset()`, `mockrtos::reset()`, `mockclock::reset()`
and `mockalloc::reset()` before every test, and `mocklwip::reset()` again after, so
each test starts from zero pcbs, zero pbufs, no faults and `millis() == 1000`. A
test that needs `millis() == 0` should set it with `mockclock::set_millis(0)`.

**Destroy your `AsyncClient`/`AsyncServer` before the test returns** if you want
leak assertions to mean anything — `reset()` reclaims whatever is left, but a
client that outlives the reset would hold a dangling pcb pointer.

### Driving a new lwIP callback

The `mocklwip::fire_*` functions play the part of the lwIP thread: they call
straight into the callback the library registered on the pcb. Nothing reaches
the application until you then call `asynctcp_test_pump()`. That two-step is the
whole point — it is where the queue-handling bugs live.

```cpp
fire_connected(pcb, ERR_OK);   // tcp_connected_fn; moves pcb to ESTABLISHED
fire_recv(pcb, "data", 4);     // tcp_recv_fn with a pbuf the mock allocates
fire_recv_pbuf(pcb, chain);    // ... or with a chain you built via make_pbuf()
fire_fin(pcb);                 // tcp_recv_fn with a NULL pbuf
retry_refused(pcb);            // offers refused data again
fire_sent(pcb, 4);             // tcp_sent_fn
fire_poll(pcb);                // tcp_poll_fn
fire_error(pcb, ERR_RST);      // frees pcb, then tcp_err_fn -- pcb is dead after
fire_accept(listen_pcb);       // builds a new ESTABLISHED pcb, offers it
fire_accept(listen_pcb, peer, 41234);  // ... from the peer at that ip_addr_t and port
fire_accept_failure(listen_pcb);       // ... or NULL with ERR_MEM, as when no pcb is free
fire_raw_accept(fn);           // a new ESTABLISHED pcb, offered to fn on the lwIP thread
fire_dns(0x0A000005);          // deferred dns_found_callback with an address
fire_dns(addr);                // ... or with any ip_addr_t, IPv6 included
fire_dns_failure();            // ... or with NULL
asynctcp_test_pump();          // now the application callbacks run
```

To add a callback the mock does not fire yet: store the callback pointer on
`struct tcp_pcb` in `mocks/include/lwip/tcp.h`, set it in the corresponding
`tcp_*` setter in `mock_lwip.cpp`, and add a `fire_*` that checks `is_live(pcb)`
and then calls it with `pcb->callback_arg`.

### Injecting failures

`mocklwip::faults()` returns a mutable struct, reset before each test:

```cpp
faults().fail_tcp_new = 1;          // next tcp_new_ip_type() returns NULL
faults().connect_result = ERR_RTE;  // tcp_connect() fails
faults().bind_result = ERR_USE;
faults().listen_returns_null = true;
faults().close_result = ERR_MEM;    // tcp_close() fails, pcb stays allocated
faults().write_result = ERR_MEM;
faults().dns_result = ERR_INPROGRESS;  // or ERR_OK / an error
faults().dns_addr = 0x0A000005;        // used when dns_result == ERR_OK
faults().dns_fails_inside_the_call = true;  // with ERR_INPROGRESS: answers NULL, runs the task, then returns
```

`mockrtos::faults()` does the same for FreeRTOS:

```cpp
mockrtos::faults().fail_mutex_create = true;  // xSemaphoreCreateMutex() returns NULL
mockrtos::faults().fail_task_create = true;   // xTaskCreate() fails
```

The library allocates with `new (std::nothrow)`; nothing else in the program does, so
`mockalloc` fails only the library's allocations:

```cpp
mockalloc::fail_next();       // the next one returns nullptr
mockalloc::fail_nth(2);       // ... or the one after
mockalloc::fail_nth(3, 2);    // ... or the third and fourth
mockalloc::failures()         // how many have failed
```

### Asserting

```cpp
live_pcbs()               // outstanding pcbs -- the leak check
live_pbufs()
port_is_bound(8080)
is_live(pcb)
count("tcp_close")        // number of calls
count("tcp_close", pcb)
recved(pcb)               // total bytes handed to tcp_recved(): the window reopened
saw("tcp_recved", pcb, 42)   // called on this pcb with first arg 42
written(pcb)              // everything handed to tcp_write(), concatenated
remote_ip4(pcb)           // the pcb's remote IPv4 address, with or without IPv6
mockrtos::deadlocks()     // non-recursive mutex re-taken -- a deadlock on target
mockclock::advance(1500)  // move millis() forward
```

## Caveats

* The harness is single-threaded by construction, so it cannot find races. It
  finds lifetime, ordering and leak bugs.
* `reset()` cannot un-start the library's async task or free its queue mutex;
  those are process-lifetime singletons in `src/AsyncTCP.cpp`. Under the default
  fork-per-test that costs nothing; under `ASYNCTCP_TEST_NOFORK=1` they persist
  from one test to the next, so the tests in `test_start.cpp` that make creating
  them fail are meaningful only when they are the first to start the library.
* The mocks cover the API surface `src/AsyncTCP.cpp` actually uses. A change that
  reaches for more of lwIP will need them extended to match.
* Forking is POSIX-only; elsewhere the tests run in one process and a crash ends
  the run.
* The harness fills new stack and heap memory with 0xfe bytes, so if the library
  reads memory before writing it, the test gets the same result on every run.
  The heap fill needs glibc or ASan.
