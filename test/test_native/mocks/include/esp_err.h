// Host-native mock of esp_err.h
#ifndef MOCK_ESP_ERR_H
#define MOCK_ESP_ERR_H

#include <stdint.h>

typedef int esp_err_t;

#define ESP_OK   0
#define ESP_FAIL -1

#endif
