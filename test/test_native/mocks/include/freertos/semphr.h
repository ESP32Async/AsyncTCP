// Host-native mock of freertos/semphr.h. Stays C-compatible.
#ifndef MOCK_FREERTOS_SEMPHR_H
#define MOCK_FREERTOS_SEMPHR_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *SemaphoreHandle_t;

// Single-threaded, so these never block. Taking a non-recursive mutex that is
// already held is recorded as a would-be deadlock: see mockrtos::deadlocks().
SemaphoreHandle_t xSemaphoreCreateMutex(void);

BaseType_t xSemaphoreTake(SemaphoreHandle_t xSemaphore, TickType_t xTicksToWait);
BaseType_t xSemaphoreGive(SemaphoreHandle_t xSemaphore);

#ifdef __cplusplus
}
#endif

#endif
