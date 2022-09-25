#ifndef MINITOR_PORT_TYPES
#define MINITOR_PORT_TYPES

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/timers.h"

// DEFINE TYPES
/*
typedef pthread_mutex_t* MinitorMutex;

typedef struct port_timer_t
{
  pthread_t thread;
  int ms;
  bool repeat;
  void* data;
  void ( *function )( struct port_timer_t* );
} port_timer_t;

typedef port_timer_t* MinitorTimer;

typedef struct port_queue_t
{
  void** buffer;
  int capacity;
  int size;
  int in;
  int out;
	pthread_mutex_t mutex;
	pthread_cond_t cond_full;
	pthread_cond_t cond_empty;
} port_queue_t;

typedef port_queue_t* MinitorQueue;
typedef pthread_t MinitorTask;
*/

typedef SemaphoreHandle_t MinitorMutex;
typedef TimerHandle_t MinitorTimer;
typedef QueueHandle_t MinitorQueue;
typedef TaskHandle_t MinitorTask;

#endif
