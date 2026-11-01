// Host-native mock of freertos/task.h. Stays C-compatible.
#ifndef MOCK_FREERTOS_TASK_H
#define MOCK_FREERTOS_TASK_H

#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);

// The mock records the task function instead of running it; see
// mock_rtos.h / asynctcp_test_pump().
BaseType_t xTaskCreate(
  TaskFunction_t pxTaskCode, const char *pcName, const configSTACK_DEPTH_TYPE usStackDepth, void *pvParameters, UBaseType_t uxPriority,
  TaskHandle_t *pxCreatedTask
);

void vTaskDelete(TaskHandle_t xTaskToDelete);

BaseType_t xTaskNotifyGive(TaskHandle_t xTaskToNotify);
uint32_t ulTaskNotifyTake(BaseType_t xClearCountOnExit, TickType_t xTicksToWait);

BaseType_t xPortGetCoreID(void);

#ifdef __cplusplus
}
#endif

#endif
