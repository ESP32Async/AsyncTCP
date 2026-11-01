// Host-native mock of Arduino.h.
//
// Provides just enough of the Arduino/ESP32 core for AsyncTCP: the mock clock
// (millis/micros), the arduino-esp32 log_* macros, and the usual pull-ins.
#ifndef MOCK_ARDUINO_H
#define MOCK_ARDUINO_H

#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <cassert>

#include "IPAddress.h"
#include "esp_err.h"
#include "esp_idf_version.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

// Mock clock. Advance it from tests via mockclock::advance().
unsigned long millis(void);
unsigned long micros(void);

// arduino-esp32 logging. Output is off by default; enable with
// ASYNCTCP_TEST_VERBOSE=1 in the environment.
void asynctcp_mock_log(char level, const char *file, int line, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#define log_e(fmt, ...) asynctcp_mock_log('E', __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_w(fmt, ...) asynctcp_mock_log('W', __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_d(fmt, ...) asynctcp_mock_log('D', __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define log_v(fmt, ...) asynctcp_mock_log('V', __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif
