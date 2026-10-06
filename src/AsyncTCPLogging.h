// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#pragma once

#ifdef CONFIG_ASYNC_TCP_LOG_CUSTOM
// The user must provide the following macros in AsyncTCPLoggingCustom.h:
//   async_tcp_log_e, async_tcp_log_w, async_tcp_log_i, async_tcp_log_d, async_tcp_log_v
#include <AsyncTCPLoggingCustom.h>

#elif defined(CONFIG_ASYNC_TCP_DEBUG)
// Local Debug logging
#include <HardwareSerial.h>
#define async_tcp_log_e(format, ...) Serial.printf("E async_tcp %s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define async_tcp_log_w(format, ...) Serial.printf("W async_tcp %s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define async_tcp_log_i(format, ...) Serial.printf("I async_tcp %s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define async_tcp_log_d(format, ...) Serial.printf("D async_tcp %s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define async_tcp_log_v(format, ...) Serial.printf("V async_tcp %s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__);

#else
// Framework-based logging

/**
 * LibreTiny specific configurations
 */
#if defined(LIBRETINY)
#include <Arduino.h>
#define async_tcp_log_e(format, ...) log_e(format, ##__VA_ARGS__)
#define async_tcp_log_w(format, ...) log_w(format, ##__VA_ARGS__)
#define async_tcp_log_i(format, ...) log_i(format, ##__VA_ARGS__)
#define async_tcp_log_d(format, ...) log_d(format, ##__VA_ARGS__)
#define async_tcp_log_v(format, ...) log_v(format, ##__VA_ARGS__)


/**
 * ESP8266 specific configurations
 * Uses ets_printf to avoid dependency on global Serial object.
 * Format strings are stored in PROGMEM and copied to a stack buffer.
 */
#elif defined(ESP8266)
#include <ets_sys.h>
#include <pgmspace.h>
// define log levels
#define ASYNC_TCP_LOG_NONE    0 /*!< No log output */
#define ASYNC_TCP_LOG_ERROR   1 /*!< Critical errors, software module can not recover on its own */
#define ASYNC_TCP_LOG_WARN    2 /*!< Error conditions from which recovery measures have been taken */
#define ASYNC_TCP_LOG_INFO    3 /*!< Information messages which describe normal flow of events */
#define ASYNC_TCP_LOG_DEBUG   4 /*!< Extra information which is not necessary for normal use (values, pointers, sizes, etc). */
#define ASYNC_TCP_LOG_VERBOSE 5 /*!< Verbose information for debugging purposes */
#define ASYNC_TCP_LOG_MAX     6 /*!< Number of levels supported */
// set default log level
#ifndef ASYNCTCP_LOG_LEVEL
#define ASYNCTCP_LOG_LEVEL ASYNC_TCP_LOG_INFO
#endif
// helper macro to copy PROGMEM format string to stack and call ets_printf
// level is a char literal ('E', 'W', etc.) to avoid RAM usage from string literals
#define _ASYNC_TCP_LOG(level, format, ...)                               \
  do {                                                                  \
    static const char __fmt[] PROGMEM = "%c async_ws %d: " format "\n"; \
    char __buf[sizeof(__fmt)];                                          \
    strcpy_P(__buf, __fmt);                                             \
    ets_printf(__buf, level, __LINE__, ##__VA_ARGS__);                  \
  } while (0)
// error
#if ASYNCTCP_LOG_LEVEL >= ASYNC_TCP_LOG_ERROR
#define async_tcp_log_e(format, ...) _ASYNC_TCP_LOG('E', format, ##__VA_ARGS__)
#else
#define async_tcp_log_e(format, ...)
#endif
// warn
#if ASYNCTCP_LOG_LEVEL >= ASYNC_TCP_LOG_WARN
#define async_tcp_log_w(format, ...) _ASYNC_TCP_LOG('W', format, ##__VA_ARGS__)
#else
#define async_tcp_log_w(format, ...)
#endif
// info
#if ASYNCTCP_LOG_LEVEL >= ASYNC_TCP_LOG_INFO
#define async_tcp_log_i(format, ...) _ASYNC_TCP_LOG('I', format, ##__VA_ARGS__)
#else
#define async_tcp_log_i(format, ...)
#endif
// debug
#if ASYNCTCP_LOG_LEVEL >= ASYNC_TCP_LOG_DEBUG
#define async_tcp_log_d(format, ...) _ASYNC_TCP_LOG('D', format, ##__VA_ARGS__)
#else
#define async_tcp_log_d(format, ...)
#endif
// verbose
#if ASYNCTCP_LOG_LEVEL >= ASYNC_TCP_LOG_VERBOSE
#define async_tcp_log_v(format, ...) _ASYNC_TCP_LOG('V', format, ##__VA_ARGS__)
#else
#define async_tcp_log_v(format, ...)
#endif

/**
 * Arduino specific configurations
 */
#elif defined(ARDUINO)
#if defined(USE_ESP_IDF_LOG)
#include <esp_log.h>
#define async_tcp_log_e(format, ...) ESP_LOGE("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_w(format, ...) ESP_LOGW("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_i(format, ...) ESP_LOGI("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_d(format, ...) ESP_LOGD("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_v(format, ...) ESP_LOGV("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#include <esp32-hal-log.h>
#define async_tcp_log_e(format, ...) log_e(format, ##__VA_ARGS__)
#define async_tcp_log_w(format, ...) log_w(format, ##__VA_ARGS__)
#define async_tcp_log_i(format, ...) log_i(format, ##__VA_ARGS__)
#define async_tcp_log_d(format, ...) log_d(format, ##__VA_ARGS__)
#define async_tcp_log_v(format, ...) log_v(format, ##__VA_ARGS__)
#endif  // USE_ESP_IDF_LOG

/**
 * ESP-IDF specific configurations
 */
#else
#include <esp_log.h>
#define async_tcp_log_e(format, ...) ESP_LOGE("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_w(format, ...) ESP_LOGW("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_i(format, ...) ESP_LOGI("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_d(format, ...) ESP_LOGD("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define async_tcp_log_v(format, ...) ESP_LOGV("async_tcp", "%s() %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif  // !LIBRETINY && !ARDUINO

#endif  // CONFIG_ASYNC_TCP_LOG_CUSTOM
