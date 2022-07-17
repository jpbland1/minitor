#ifndef MINITOR_PORT_TYPES
#define MINITOR_PORT_TYPES

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/timers.h"

// DEFINE TYPES
typedef SemaphoreHandle_t MinitorMutex;
typedef TimerHandle_t MinitorTimer;
typedef QueueHandle_t MinitorQueue;
typedef TaskHandle_t MinitorTask;

#endif
