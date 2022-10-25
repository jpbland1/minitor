#ifndef MINITOR_PORT
#define MINITOR_PORT

#include "../include/config.h"

// INCLUDE LIBRARIES
#include "pthread.h"
#include "stdbool.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "fcntl.h"
#include "unistd.h"
#include "sys/socket.h"
#include "sys/ioctl.h"
#include "sys/stat.h"
#include "netinet/in.h"
#include "netinet/ip.h"
#include "arpa/inet.h"
#include "errno.h"

#include "time.h"
#include "poll.h"

#include "./port_types.h"

// DEFINE FUNCTIONS
bool b_create_core_task( MinitorTask* handle );
bool b_create_connections_task( MinitorTask* handle );
bool b_create_poll_task( MinitorTask* handle );
bool b_create_local_connection_handler( MinitorTask* handle, void* local_connection );
bool b_create_fetch_task( MinitorTask* handle, void* consensus );
bool b_create_insert_task( MinitorTask* handle, void* consensus );
void port_task_delete( MinitorTask task );

MinitorMutex port_mutex_create();

MinitorTimer port_timer_create( int ms, bool repeat, void* timer_p, void* function );
void port_timer_set_ms( MinitorTimer timer, int ms );
void port_timer_stop( MinitorTimer timer );

MinitorQueue port_queue_create( int length, int size );
bool port_queue_enqueue( MinitorQueue queue, void** pointer );
bool port_queue_dequeue( MinitorQueue queue, void** pointer );
bool port_queue_dequeue_nonblocking( MinitorQueue queue, void** pointer );
int port_messages_waiting( MinitorQueue queue );
void port_queue_delete( MinitorQueue queue );

int port_random();
void port_fill_random( uint8_t* dest, int length );

#define MINITOR_MUTEX_CREATE() port_mutex_create()
#define MINITOR_MUTEX_TAKE_MS( mutex, ms ) pthread_mutex_lock( mutex ) == 0
#define MINITOR_MUTEX_TAKE_BLOCKING( mutex ) pthread_mutex_lock( mutex ) == 0
#define MINITOR_MUTEX_GIVE( mutex ) pthread_mutex_unlock( mutex ) == 0

#define MINITOR_TIMER_CREATE_MS( name, ms, repeat, timer_p, function ) port_timer_create( ms, repeat, timer_p, function )
#define MINITOR_TIMER_SET_MS_BLOCKING( timer, ms ) port_timer_set_ms( timer, ms )
#define MINITOR_TIMER_RESET_BLOCKING( timer ) port_timer_set_ms( timer, timer->ms )
#define MINITOR_TIMER_STOP_BLOCKING( timer ) port_timer_stop( timer )
#define MINITOR_TIMER_GET_DATA( timer ) timer->data

#define MINITOR_QUEUE_CREATE( length, size ) port_queue_create( length, size )
#define MINITOR_ENQUEUE_MS( queue, pointer, ms ) port_queue_enqueue( queue, pointer )
#define MINITOR_ENQUEUE_BLOCKING( queue, pointer ) port_queue_enqueue( queue, pointer )
#define MINITOR_DEQUEUE_MS( queue, pointer, ms ) port_queue_dequeue( queue, pointer )
#define MINITOR_DEQUEUE_BLOCKING( queue, pointer ) port_queue_dequeue( queue, pointer )
#define MINITOR_DEQUEUE_NONBLOCKING( queue, pointer ) port_queue_dequeue_nonblocking( queue, pointer )
#define MINITOR_QUEUE_MESSAGES_WAITING( queue ) port_messages_waiting( queue )
#define MINITOR_QUEUE_DELETE( queue ) port_queue_delete( queue )

#define MINITOR_TASK_DELETE( task ) port_task_delete( task )

#define MINITOR_RANDOM() port_random()
#define MINITOR_FILL_RANDOM( dest, length ) port_fill_random( dest, length )

#define MINITOR_GET_TIME() time( NULL )

#define MINITOR_GET_READABLE( sockfd, readable ) ioctl( sockfd, FIONREAD, readable )

#define MINITOR_TIMEGM( tm ) timegm( tm )

#ifdef DEBUG_MINITOR

#define MINITOR_LOG( tag, format, ... ) { printf( "%s: ", tag ); printf( format, ##__VA_ARGS__ ); printf( "\n" ); }

#else

#define MINITOR_LOG( tag, format, ... ) do {} while(0)

#endif

#endif
