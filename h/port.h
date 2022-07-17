#ifndef MINITOR_PORT
#define MINITOR_PORT

#include "../include/config.h"

// INCLUDE LIBRARIES
#include "stdlib.h"
#include "esp_log.h"

#include "lwip/sockets.h"

#include "./port_types.h"

// DEFINE FUNCTIONS
//#define MINITOR_MALLOC( size ) malloc( size )
//#define MINITOR_FREE( pointer ) free( pointer )

#define MINITOR_MUTEX_CREATE() xSemaphoreCreateMutex()
#define MINITOR_MUTEX_TAKE_MS( mutex, ms ) xSemaphoreTake( mutex, ms / portTICK_PERIOD_MS )
#define MINITOR_MUTEX_TAKE_BLOCKING( mutex ) xSemaphoreTake( mutex, portMAX_DELAY )
#define MINITOR_MUTEX_GIVE( mutex ) xSemaphoreGive( mutex )

#define MINITOR_TIMER_CREATE_MS( name, ms, repeat, timer_p, function ) xTimerCreate( name, ms / portTICK_PERIOD_MS, repeat, timer_p, function )
#define MINITOR_TIMER_SET_MS_BLOCKING( timer, ms ) xTimerChangePeriod( timer, ms / portTICK_PERIOD_MS, portMAX_DELAY )
#define MINITOR_TIMER_RESET_BLOCKING( timer ) xTimerReset( timer, portMAX_DELAY )
#define MINITOR_TIMER_STOP_BLOCKING( timer ) xTimerStop( timer, portMAX_DELAY )

#define MINITOR_QUEUE_CREATE( length, size ) xQueueCreate( length, size )
#define MINITOR_ENQUEUE_MS( queue, pointer, ms ) xQueueSendToBack( queue, pointer, ms / portTICK_PERIOD_MS )
#define MINITOR_ENQUEUE_BLOCKING( queue, pointer ) xQueueSendToBack( queue, pointer, portMAX_DELAY )
#define MINITOR_DEQUEUE_MS( queue, pointer, ms ) xQueueReceive( queue, pointer, ms / portTICK_PERIOD_MS )
#define MINITOR_DEQUEUE_BLOCKING( queue, pointer ) xQueueReceive( queue, pointer, portMAX_DELAY )
#define MINITOR_QUEUE_MESSAGES_WAITING( queue ) uxQueueMessagesWaiting( queue )

#define MINITOR_TASK_DELETE( task ) vTaskDelete( task )

#define MINITOR_RANDOM() esp_random()
#define MINITOR_FILL_RANDOM( dest, length ) esp_fill_random( dest, length )

#define MINITOR_GET_TIME() esp_timer_get_time()

#ifdef DEBUG_MINITOR

#define MINITOR_LOG ESP_LOGE

#else

#define MINITOR_LOG( tag, format, ... ) do {} while(0)

#endif

bool b_create_core_task( MinitorTask* handle );
bool b_create_connections_task( MinitorTask* handle );
bool b_create_fetch_task( MinitorTask* handle, void* consensus );
bool b_create_insert_task( MinitorTask* handle, void* consensus );

#endif
