#ifndef MINITOR_PORT_TYPES
#define MINITOR_PORT_TYPES

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

// DEFINE TYPES
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

#endif
