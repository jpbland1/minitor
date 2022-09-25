#ifndef MINITOR_PORT
#define MINITOR_PORT

#include "user_settings.h"

#include "../include/config.h"

// INCLUDE LIBRARIES
#include "stdlib.h"
#include "esp_log.h"

#include "lwip/sockets.h"

#include "./port_types.h"

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

// DEFINE FUNCTIONS
bool b_create_core_task( MinitorTask* handle );
bool b_create_connections_task( MinitorTask* handle );
bool b_create_poll_task( MinitorTask* handle );
bool b_create_local_connection_handler( MinitorTask* handle, void* local_connection );
bool b_create_fetch_task( MinitorTask* handle, void* consensus );
bool b_create_insert_task( MinitorTask* handle, void* consensus );

#define MINITOR_MUTEX_CREATE() xSemaphoreCreateMutex()
#define MINITOR_MUTEX_TAKE_MS( mutex, ms ) xSemaphoreTake( mutex, ms / portTICK_PERIOD_MS )
#define MINITOR_MUTEX_TAKE_BLOCKING( mutex ) xSemaphoreTake( mutex, portMAX_DELAY )
#define MINITOR_MUTEX_GIVE( mutex ) xSemaphoreGive( mutex )

#define MINITOR_TIMER_CREATE_MS( name, ms, repeat, timer_p, function ) xTimerCreate( name, ms / portTICK_PERIOD_MS, repeat, timer_p, function )
#define MINITOR_TIMER_SET_MS_BLOCKING( timer, ms ) xTimerChangePeriod( timer, ms / portTICK_PERIOD_MS, portMAX_DELAY )
#define MINITOR_TIMER_RESET_BLOCKING( timer ) xTimerReset( timer, portMAX_DELAY )
#define MINITOR_TIMER_STOP_BLOCKING( timer ) xTimerStop( timer, portMAX_DELAY )
#define MINITOR_TIMER_GET_DATA( timer ) pvTimerGetTimerID( x_timer )

#define MINITOR_QUEUE_CREATE( length, size ) xQueueCreate( length, size )
#define MINITOR_ENQUEUE_MS( queue, pointer, ms ) xQueueSendToBack( queue, pointer, ms / portTICK_PERIOD_MS )
#define MINITOR_ENQUEUE_BLOCKING( queue, pointer ) xQueueSendToBack( queue, pointer, portMAX_DELAY )
#define MINITOR_DEQUEUE_MS( queue, pointer, ms ) xQueueReceive( queue, pointer, ms / portTICK_PERIOD_MS )
#define MINITOR_DEQUEUE_BLOCKING( queue, pointer ) xQueueReceive( queue, pointer, portMAX_DELAY )
#define MINITOR_DEQUEUE_NONBLOCKING( queue, pointer ) xQueueReceive( queue, pointer, 1 )
#define MINITOR_QUEUE_MESSAGES_WAITING( queue ) uxQueueMessagesWaiting( queue )
#define MINITOR_QUEUE_DELETE( queue ) vQueueDelete( queue )

#define MINITOR_TASK_DELETE( task ) vTaskDelete( task )

#define MINITOR_RANDOM() esp_random()
#define MINITOR_FILL_RANDOM( dest, length ) esp_fill_random( dest, length )

#define MINITOR_GET_TIME() esp_timer_get_time()

#define MINITOR_GET_READABLE( sockfd, readable ) ioctl( sockfd, FIONREAD, readable )

#define MINITOR_POLL( pollfds, len ) poll( pollfds, len, 100 )

#define MINITOR_RESTART_POLL() do {} while(0)

#define MINITOR_FE_SUB( a, b, c ) lm_sub( a, b, c );
#define MINITOR_FE_ADD( a, b, c ) lm_add( a, b, c );
#define MINITOR_FE_INVERT( a, b ) lm_invert( a, b );
#define MINITOR_FE_MUL( a, b, c ) lm_mul( a, b, c );

#define MINITOR_TIMEGM( tm ) mktime( tm )

#ifdef DEBUG_MINITOR

#define MINITOR_LOG ESP_LOGE

#else

#define MINITOR_LOG( tag, format, ... ) do {} while(0)

#endif

#endif
