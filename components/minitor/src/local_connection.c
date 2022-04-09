#include <stddef.h>
#include <stdlib.h>

#include "esp_log.h"
#include "user_settings.h"
#include "wolfssl/internal.h"

#include "../include/config.h"
#include "../h/minitor.h"
#include "../h/circuit.h"
#include "../h/cell.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/structures/onion_service.h"
#include "../h/models/relay.h"
#include "../h/local_connection.h"
#include "../h/consensus.h"

TaskHandle_t handle_local_connections_task_handle = NULL;
DoublyLinkedLocalConnection* local_connections = NULL;
struct pollfd local_connections_poll[16];

static void v_cleanup_local_connection( DoublyLinkedLocalConnection* db_local_connection )
{
  v_pop_local_connection_from_list( db_local_connection, &local_connections );

  shutdown( db_local_connection->connection->sock_fd, 0 );
  close( db_local_connection->connection->sock_fd );

  local_connections_poll[db_local_connection->connection->poll_index].fd = -1;

  free( db_local_connection->connection );
  free( db_local_connection );
}

static void v_handle_local_connections( void* pv_parameters )
{
  int succ;
  uint8_t rx_buffer[RELAY_PAYLOAD_LEN];
  DoublyLinkedLocalConnection* db_local_connection;
  DoublyLinkedLocalConnection* tmp_local_connection;
  OnionMessage* onion_message;

  while ( 1 )
  {
    // wait 1.5 seconds for a poll event
    succ = poll( local_connections_poll, 16, 1500 );

    if ( succ <= 0 )
    {
#ifdef DEBUG_MINITOR
      if ( succ < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Failed to poll local connections" );
      }
#endif

      continue;
    }

    // MUTEX TAKE
    xSemaphoreTake( local_connections_mutex, portMAX_DELAY );

    db_local_connection = local_connections;

    while ( db_local_connection != NULL )
    {
      if ( ( local_connections_poll[db_local_connection->connection->poll_index].revents & local_connections_poll[db_local_connection->connection->poll_index].events ) != 0 )
      {
        // MUTEX TAKE
        xSemaphoreTake( db_local_connection->connection->access_mutex, portMAX_DELAY );

        succ = recv( db_local_connection->connection->sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

        xSemaphoreGive( db_local_connection->connection->access_mutex );
        // MUTEX GIVE

        onion_message = malloc( sizeof( OnionMessage ) );

        onion_message->type = SERVICE_TCP_DATA;
        onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );

        ( (ServiceTcpTraffic*)onion_message->data )->circ_id = db_local_connection->connection->circ_id;
        ( (ServiceTcpTraffic*)onion_message->data )->stream_id = db_local_connection->connection->stream_id;

        if ( succ <= 0 )
        {
          ( (ServiceTcpTraffic*)onion_message->data )->length = 0;
        }
        else
        {
          ( (ServiceTcpTraffic*)onion_message->data )->length = succ;
          ( (ServiceTcpTraffic*)onion_message->data )->data = malloc( sizeof( uint8_t ) * succ );
          memcpy( ( (ServiceTcpTraffic*)onion_message->data )->data, rx_buffer, succ );
        }

        xQueueSendToBack( db_local_connection->connection->forward_queue, (void*)(&onion_message), portMAX_DELAY );

        if ( succ <= 0 )
        {
          tmp_local_connection = db_local_connection->next;
          v_cleanup_local_connection( db_local_connection );
          db_local_connection = tmp_local_connection;
          continue;
        }
      }

      db_local_connection = db_local_connection->next;
    }

    xSemaphoreGive( local_connections_mutex );
    // MUTEX GIVE
  }
}

int d_create_local_connection( OnionService* onion_service, uint32_t circ_id, uint16_t stream_id )
{
  int i;
  int succ;
  struct sockaddr_in dest_addr;
  LocalConnection* local_connection;
  DoublyLinkedLocalConnection* db_local_connection;

  // MUTEX TAKE
  xSemaphoreTake( local_connections_mutex, portMAX_DELAY );

  if ( handle_local_connections_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      local_connections_poll[i].fd = -1;
    }
  }

  local_connection = malloc( sizeof( LocalConnection ) );

  local_connection->circ_id = circ_id;
  local_connection->stream_id = stream_id;
  local_connection->forward_queue = onion_service->rx_queue;
  local_connection->access_mutex = xSemaphoreCreateMutex();

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( onion_service->local_port );

  local_connection->sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( local_connection->sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to the local port, err: %d, errno: %d", local_connection->sock_fd, errno );
#endif

    goto fail;
  }

  succ = connect( local_connection->sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to the local port" );
#endif

    close( local_connection->sock_fd );
    goto fail;
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( local_connections_poll[i].fd == -1 )
    {
      local_connection->poll_index = i;
      local_connections_poll[i].fd = local_connection->sock_fd;
      local_connections_poll[i].events = POLLIN;
      break;
    }
  }

  if ( i >= 16 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't find an open poll spot" );
#endif

    close( local_connection->sock_fd );
    goto fail;
  }

  // add connection to list of connections
  db_local_connection = malloc( sizeof( DoublyLinkedLocalConnection ) );
  db_local_connection->connection = local_connection;

  v_add_local_connection_to_list( db_local_connection, &local_connections );

  // add connection to list of connections this service's connections
  db_local_connection = malloc( sizeof( DoublyLinkedLocalConnection ) );
  db_local_connection->connection = local_connection;

  v_add_local_connection_to_list( db_local_connection, &onion_service->local_connections );

  if ( handle_local_connections_task_handle == NULL )
  {
    xTaskCreatePinnedToCore(
      v_handle_local_connections,
      "H_LOCAL_CONNECTIONS",
      3072,
      NULL,
      10,
      &handle_local_connections_task_handle,
      tskNO_AFFINITY
    );
  }

  xSemaphoreGive( local_connections_mutex );
  // MUTEX GIVE

  return 0;

fail:
  free( local_connection );
  xSemaphoreGive( local_connections_mutex );
  // MUTEX GIVE

  return -1;
}
