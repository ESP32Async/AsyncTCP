// Host-native mock of esp_task_wdt.h. Always succeeds.
#ifndef MOCK_ESP_TASK_WDT_H
#define MOCK_ESP_TASK_WDT_H

#include "esp_err.h"
#include "freertos/task.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t esp_task_wdt_add(TaskHandle_t handle);
esp_err_t esp_task_wdt_delete(TaskHandle_t handle);
esp_err_t esp_task_wdt_reset(void);

#ifdef __cplusplus
}
#endif

#endif
