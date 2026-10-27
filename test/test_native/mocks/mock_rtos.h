// Test-facing control surface for the FreeRTOS / clock / logging mocks.
//
// This header is for tests only -- the library never sees it.
#ifndef ASYNCTCP_MOCK_RTOS_H
#define ASYNCTCP_MOCK_RTOS_H

#include <cstdint>

// ---------------------------------------------------------------------------
// The async-task pump
// ---------------------------------------------------------------------------
//
// AsyncTCP starts its event-service task with xTaskCreateUniversal(). The mock
// records the task function and parameter but never runs it. Calling
// asynctcp_test_pump() invokes that recorded function on the *calling* thread;
// it drains the library's event queue exactly as the real task would, and when
// it reaches its ulTaskNotifyTake() "sleep" the mock unwinds out of it with a
// private C++ exception which asynctcp_test_pump() catches.
//
// Net effect: pump() == "run the async task until its queue is empty, then
// return". Everything stays on one thread, so tests are fully deterministic.
//
// Safe because the library's task loop holds no live objects across the
// ulTaskNotifyTake() call -- the queue mutex guard lives and dies inside
// _get_async_event(). If a future rewrite changes that, the unwinding is still
// a proper C++ unwind (destructors run), unlike a longjmp.
//
void asynctcp_test_pump();

// True once the library has created its async service task.
bool asynctcp_test_task_started();

namespace mockrtos {

// Clears task and semaphore state. Call between tests.
void reset();

// Number of times a non-recursive mutex was taken while already held. On the
// real target that is a deadlock; here it is recorded and allowed to proceed.
unsigned deadlocks();

// Takes or gives against a null handle.  FreeRTOS faults on those; the runner treats
// any occurrence as a test failure.
unsigned null_semaphores();

// Failure injection. Reset by reset().
struct Faults {
  bool fail_mutex_create = false;  // xSemaphoreCreateMutex() returns NULL
  bool fail_task_create = false;   // xTaskCreate() fails and starts nothing
};
Faults &faults();

}  // namespace mockrtos

namespace mockclock {

void reset();  // back to t=0
void set_millis(uint32_t ms);
void advance(uint32_t ms);

}  // namespace mockclock

#endif
