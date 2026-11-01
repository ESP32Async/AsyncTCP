// Implementation of the FreeRTOS / clock / logging mocks.

#include "mock_rtos.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

extern "C" {
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------
namespace {
uint64_t g_micros = 0;
}

namespace mockclock {
void reset() {
  g_micros = 0;
}
void set_millis(uint32_t ms) {
  g_micros = (uint64_t)ms * 1000ULL;
}
void advance(uint32_t ms) {
  g_micros += (uint64_t)ms * 1000ULL;
}
}  // namespace mockclock

extern "C" unsigned long millis(void) {
  return (unsigned long)(g_micros / 1000ULL);
}

extern "C" unsigned long micros(void) {
  return (unsigned long)g_micros;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
namespace {
int g_log_enabled = -1;  // -1 = not yet resolved from the environment

bool log_enabled() {
  if (g_log_enabled < 0) {
    const char *v = getenv("ASYNCTCP_TEST_VERBOSE");
    g_log_enabled = (v && *v && *v != '0') ? 1 : 0;
  }
  return g_log_enabled != 0;
}
}  // namespace

extern "C" void asynctcp_mock_log(char level, const char *file, int line, const char *fmt, ...) {
  if (!log_enabled()) {
    return;
  }
  const char *base = strrchr(file, '/');
  fprintf(stderr, "[%c][%s:%d] ", level, base ? base + 1 : file, line);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

// ---------------------------------------------------------------------------
// Semaphores
// ---------------------------------------------------------------------------
namespace {

struct MockSemaphore {
  bool recursive;
  int depth;
};

std::set<MockSemaphore *> g_semaphores;
unsigned g_deadlocks = 0;
unsigned g_null_semaphores = 0;
mockrtos::Faults g_faults;

}  // namespace

extern "C" SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  if (g_faults.fail_mutex_create) {
    return nullptr;
  }
  MockSemaphore *s = new MockSemaphore{false, 0};
  g_semaphores.insert(s);
  return (SemaphoreHandle_t)s;
}

extern "C" BaseType_t xSemaphoreTake(SemaphoreHandle_t xSemaphore, TickType_t) {
  MockSemaphore *s = (MockSemaphore *)xSemaphore;
  if (!s) {
    // FreeRTOS faults on a null handle - configASSERT, or a null dereference.
    // Record it rather than returning a quiet pdFALSE that hides the bug.
    g_null_semaphores++;
    return pdFALSE;
  }
  // Single-threaded, so we can never actually block; a re-take of a
  // non-recursive mutex would deadlock on the target, so record it.
  if (!s->recursive && s->depth > 0) {
    g_deadlocks++;
  }
  s->depth++;
  return pdTRUE;
}

extern "C" BaseType_t xSemaphoreGive(SemaphoreHandle_t xSemaphore) {
  MockSemaphore *s = (MockSemaphore *)xSemaphore;
  if (!s) {
    g_null_semaphores++;
    return pdFALSE;
  }
  if (s->depth > 0) {
    s->depth--;
  }
  return pdTRUE;
}

// ---------------------------------------------------------------------------
// Tasks and the pump
// ---------------------------------------------------------------------------
namespace {

struct PumpExit {};  // thrown by ulTaskNotifyTake to unwind out of the task loop

TaskFunction_t g_task_fn = nullptr;
void *g_task_param = nullptr;
int g_task_handle_storage = 0;  // address used as the fake TaskHandle_t
bool g_in_pump = false;

BaseType_t create_task(TaskFunction_t fn, void *param, TaskHandle_t *handle) {
  if (g_faults.fail_task_create) {
    return errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY;  // and *handle is left alone
  }
  g_task_fn = fn;
  g_task_param = param;
  if (handle) {
    *handle = (TaskHandle_t)&g_task_handle_storage;
  }
  return pdPASS;
}

}  // namespace

extern "C" BaseType_t xTaskCreate(TaskFunction_t fn, const char *, const configSTACK_DEPTH_TYPE, void *param, UBaseType_t, TaskHandle_t *handle) {
  return create_task(fn, param, handle);
}

extern "C" void vTaskDelete(TaskHandle_t) {
  // The task loop only reaches this after its infinite for(;;), which the pump
  // unwinds out of, so this is unreachable in practice.
}

extern "C" BaseType_t xPortGetCoreID(void) {
  return 0;
}

extern "C" BaseType_t xTaskNotifyGive(TaskHandle_t) {
  return pdPASS;
}

extern "C" uint32_t ulTaskNotifyTake(BaseType_t, TickType_t) {
  if (g_in_pump) {
    // The task has drained its queue and is about to sleep. Unwind back out to
    // asynctcp_test_pump() rather than blocking forever.
    throw PumpExit{};
  }
  return 0;
}

extern "C" esp_err_t esp_task_wdt_add(TaskHandle_t) {
  return ESP_OK;
}

extern "C" esp_err_t esp_task_wdt_delete(TaskHandle_t) {
  return ESP_OK;
}

extern "C" esp_err_t esp_task_wdt_reset(void) {
  return ESP_OK;
}

void asynctcp_test_pump() {
  if (!g_task_fn) {
    return;  // library never started its task
  }
  g_in_pump = true;
  try {
    g_task_fn(g_task_param);
  } catch (const PumpExit &) {
    // Expected: the task reached its idle wait.
  } catch (...) {
    // A failed assertion in a callback, ending the test.
    g_in_pump = false;
    throw;
  }
  g_in_pump = false;
}

bool asynctcp_test_task_started() {
  return g_task_fn != nullptr;
}

namespace mockrtos {

void reset() {
  // NOTE: g_task_fn is deliberately *not* cleared. The library caches its task
  // handle in a file-static that we cannot reach, so once started it stays
  // started for the life of the process -- which is fine, the task is
  // stateless.
  g_deadlocks = 0;
  g_null_semaphores = 0;
  g_faults = Faults{};
  for (MockSemaphore *s : g_semaphores) {
    s->depth = 0;
  }
}

Faults &faults() {
  return g_faults;
}

unsigned null_semaphores() {
  return g_null_semaphores;
}

unsigned deadlocks() {
  return g_deadlocks;
}

}  // namespace mockrtos
