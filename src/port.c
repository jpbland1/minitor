#include "../h/port.h"

#include "../h/core.h"
#include "../h/connections.h"
#include "../h/consensus.h"

const char* PORT_TAG = "PORT";

MinitorMutex port_mutex_create()
{
  int ret;
  MinitorMutex mutex = malloc( sizeof( pthread_mutex_t ) );

  ret = pthread_mutex_init( mutex, NULL );

  if ( ret != 0 )
  {
    MINITOR_LOG( PORT_TAG, "pthread_mutex err: %d", ret );

    free( mutex );
  }

  return mutex;
}

static void port_timer_task( MinitorTimer timer )
{
  while ( 1 )
  {
    sleep( timer->ms );

    timer->function( timer );

    if ( !timer->repeat )
    {
      break;
    }
  }

  // return will auto kill pthread
}

MinitorTimer port_timer_create( int ms, bool repeat, void* timer_p, void* function )
{
  int ret;
  MinitorTimer timer = malloc( sizeof( port_timer_t ) );

  timer->ms = ms;
  timer->repeat = repeat;
  timer->function = function;
  timer->data = timer_p;

  ret = pthread_create(
    &timer->thread,
    NULL,
    port_timer_task,
    timer
  );

  if ( ret != 0 )
  {
    free( timer );
    timer = NULL;
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }

  return timer;
}

void port_timer_set_ms( MinitorTimer timer, int ms )
{
  int ret;

  pthread_cancel( timer->thread );

  timer->ms = ms;

  ret = pthread_create(
    &timer->thread,
    NULL,
    port_timer_task,
    timer
  );

  if ( ret != 0 )
  {
    free( timer );
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }
}

void port_timer_stop( MinitorTimer timer )
{
  pthread_cancel( timer->thread );
}

MinitorQueue port_queue_create( int length, int size )
{
  int ret;
  MinitorQueue queue = malloc( sizeof( port_queue_t ) );

  queue->buffer = malloc( size * length );
  queue->capacity = length;
  queue->size = 0;
  queue->in = 0;
  queue->out = 0;

  ret = pthread_mutex_init( &( queue->mutex ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  ret = pthread_cond_init( &( queue->cond_full ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  ret = pthread_cond_init( &( queue->cond_empty ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  return queue;
}

bool port_queue_enqueue( MinitorQueue queue, void** pointer )
{
  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  while ( queue->size == queue->capacity )
  {
    pthread_cond_wait( &( queue->cond_full ), &( queue->mutex ) );
  }

  memcpy( &( queue->buffer[queue->in] ), pointer, sizeof( void* ) );

  queue->size++;
  queue->in++;

  queue->in %= queue->capacity;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  pthread_cond_broadcast( &( queue->cond_empty ) );

  return true;
}

bool port_queue_dequeue( MinitorQueue queue, void** pointer )
{
  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  while ( queue->size == 0 )
  {
    pthread_cond_wait( &( queue->cond_empty ), &( queue->mutex ) );
  }

  memcpy( pointer, &( queue->buffer[queue->out] ), sizeof( void* ) );

  queue->size--;
  queue->out++;

  queue->out %= queue->capacity;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  pthread_cond_broadcast( &( queue->cond_full ) );

  return true;
}

int port_messages_waiting( MinitorQueue queue )
{
  int ret;

  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  ret = queue->size;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  return ret;
}

void port_queue_delete( MinitorQueue queue )
{
  pthread_mutex_destroy( &( queue->mutex ) );
  pthread_cond_destroy( &( queue->cond_empty ) );
  pthread_cond_destroy( &( queue->cond_full ) );
  free( queue->buffer );
  free( queue );
}

bool b_create_core_task( MinitorTask* handle )
{
  int ret;

  ret = pthread_create(
    handle,
    NULL,
    v_minitor_daemon,
    NULL
  );

  if ( ret == 0 )
  {
    return true;
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }
}

bool b_create_connections_task( MinitorTask* handle )
{
  int ret;

  ret = pthread_create(
    handle,
    NULL,
    v_connections_daemon,
    NULL
  );

  if ( ret == 0 )
  {
    return true;
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }
}

bool b_create_fetch_task( MinitorTask* handle, void* consensus )
{
  int ret;

  ret = pthread_create(
    handle,
    NULL,
    v_handle_relay_fetch,
    consensus
  );

  if ( ret == 0 )
  {
    return true;
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }
}

bool b_create_insert_task( MinitorTask* handle, void* consensus )
{
  int ret;

  ret = pthread_create(
    handle,
    NULL,
    v_handle_crypto_and_insert,
    consensus
  );

  if ( ret == 0 )
  {
    return true;
  }
  else
  {
    MINITOR_LOG( PORT_TAG, "pthread err: %d", ret );
  }
}

void port_task_delete( MinitorTask task )
{
  if ( task == NULL )
  {
    pthread_cancel( pthread_self() );
  }
  else
  {
    pthread_cancel( task );
  }
}

int port_random()
{
  int r;

  srand( time( NULL ) );

  r = rand();

  return r;
}

void port_fill_random( uint8_t* dest, int length )
{
  int i;

  srand( time( NULL ) );

  for ( i = 0; i < length; i++ )
  {
    dest[i] = rand();
  }
}
