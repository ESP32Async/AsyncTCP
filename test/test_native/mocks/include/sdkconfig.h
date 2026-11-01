// Host-native mock of sdkconfig.h.
#ifndef MOCK_SDKCONFIG_H
#define MOCK_SDKCONFIG_H

// CONFIG_LWIP_TCPIP_CORE_LOCKING comes from the build flags, so an environment can
// leave it out.

#define CONFIG_FREERTOS_UNICORE       1
#define CONFIG_ESP_TASK_WDT_TIMEOUT_S 5

#endif
