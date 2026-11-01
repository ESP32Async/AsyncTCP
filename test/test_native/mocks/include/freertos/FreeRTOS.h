// Host-native mock of freertos/FreeRTOS.h
//
// Must stay C-compatible: AsyncTCP.h pulls freertos/semphr.h in from inside an
// extern "C" block.
#ifndef MOCK_FREERTOS_H
#define MOCK_FREERTOS_H

#include <stddef.h>
#include <stdint.h>

typedef long BaseType_t;
typedef unsigned long UBaseType_t;
typedef uint32_t TickType_t;
typedef size_t configSTACK_DEPTH_TYPE;

#define pdFALSE ((BaseType_t)0)
#define pdTRUE  ((BaseType_t)1)
#define pdPASS  pdTRUE

#define errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY ((BaseType_t)(-1))

#define portMAX_DELAY ((TickType_t)0xffffffffUL)

#define pdMS_TO_TICKS(xTimeInMs) ((TickType_t)(xTimeInMs))

#endif
