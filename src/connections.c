#include <stdlib.h>

#include "esp_log.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "freertos/queue.h"

#include "../include/config.h"
#include "../h/minitor.h"
#include "../h/circuit.h"
#include "../h/cell.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/models/relay.h"
#include "../h/connections.h"
#include "../h/consensus.h"
#include "../h/core.h"

static const char* CONN_TAG = "CONNECTIONS DAEMON";

TaskHandle_t connections_daemon_task_handle;
struct pollfd connections_poll[16];
DlConnection* connections;
SemaphoreHandle_t connections_mutex;

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store ) {
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( CONN_TAG, "SSL callback error %d", store->error );
#endif

  return 0;
}

static void v_cleanup_connection( DlConnection* dl_connection )
{
  OnionMessage* onion_message;

  // we only need to inform the core daemon if an or connection
  // closed, local connections closing already triggered a
  // RELAY_END and don't need aditonal work
  if ( dl_connection->is_or == 1 )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = CONN_CLOSE;
    onion_message->data = dl_connection;
    wolfSSL_shutdown( dl_connection->ssl );
    wolfSSL_free( dl_connection->ssl );

    xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
  }

  connections_poll[dl_connection->poll_index].fd = -1;

  shutdown( dl_connection->sock_fd, 0 );
  close( dl_connection->sock_fd );

  v_remove_connection_from_list( dl_connection, &connections );

  vSemaphoreDelete( dl_connection->access_mutex );

  free( dl_connection );
}

static int d_recv_on_or_connection( DlConnection* or_connection )
{
  int succ;
  uint8_t* packed_cell;
  OnionMessage* onion_message;

  if ( or_connection->status == CONNECTION_WANT_VERSIONS )
  {
    // MUTEX TAKE
    xSemaphoreTake( or_connection->access_mutex, portMAX_DELAY );

    succ = d_recv_packed_cell( or_connection->ssl, &packed_cell, LEGACY_CIRCID_LEN );

    xSemaphoreGive( or_connection->access_mutex );
    // MUTEX GIVE

    if ( succ <= 0 || packed_cell[2] != VERSIONS )
    {
      succ = -1;
      goto finish;
    }

    v_process_versions( or_connection, packed_cell, succ );

    or_connection->status = CONNECTION_WANT_CERTS;
  }
  else
  {
    // MUTEX TAKE
    xSemaphoreTake( or_connection->access_mutex, portMAX_DELAY );

    succ = d_recv_packed_cell( or_connection->ssl, &packed_cell, CIRCID_LEN );

    xSemaphoreGive( or_connection->access_mutex );
    // MUTEX GIVE

    if ( succ <= 0 )
    {
      goto finish;
    }

    switch ( or_connection->status )
    {
      case CONNECTION_WANT_CERTS:
        if 
        (
          packed_cell[4] != CERTS ||
          d_process_certs( or_connection, packed_cell, succ ) < 0
        )
        {
          succ = -1;
          goto finish;
        }

        or_connection->status = CONNECTION_WANT_CHALLENGE;

        break;
      case CONNECTION_WANT_CHALLENGE:
        if
        (
          packed_cell[4] != AUTH_CHALLENGE ||
          d_process_challenge( or_connection, packed_cell, succ ) < 0
        )
        {
          succ = -1;
          goto finish;
        }

        or_connection->status = CONNECTION_WANT_NETINFO;

        break;
      case CONNECTION_WANT_NETINFO:
        if
        (
          packed_cell[4] != NETINFO ||
          d_process_netinfo( or_connection, packed_cell ) < 0
        )
        {
          succ = -1;
          goto finish;
        }

        or_connection->status = CONNECTION_LIVE;

        onion_message = malloc( sizeof( OnionMessage ) );

        onion_message->type = CONN_READY;
        onion_message->data = or_connection;

        xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

        break;
      case CONNECTION_LIVE:
        onion_message = malloc( sizeof( OnionMessage ) );

        onion_message->type = PACKED_CELL;
        onion_message->data = packed_cell;

        xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

        break;
      case CONNECTION_WANT_VERSIONS:
      default:
        ESP_LOGE( CONN_TAG, "Unhandled connection status: %d", or_connection->status );
        succ = -1;

        break;
    }
  }

finish:
  return succ;
}

static int d_recv_on_local_connection( DlConnection* local_connection )
{
  int succ;
  OnionMessage* onion_message;

  onion_message = malloc( sizeof( OnionMessage ) );

  onion_message->type = SERVICE_TCP_DATA;
  onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );
  ( (ServiceTcpTraffic*)onion_message->data )->circ_id = local_connection->circ_id;
  ( (ServiceTcpTraffic*)onion_message->data )->stream_id = local_connection->stream_id;
  ( (ServiceTcpTraffic*)onion_message->data )->data = malloc( sizeof( uint8_t ) * RELAY_PAYLOAD_LEN );

  // MUTEX TAKE
  xSemaphoreTake( local_connection->access_mutex, portMAX_DELAY );

  succ = recv( local_connection->sock_fd, ( (ServiceTcpTraffic*)onion_message->data )->data, sizeof( uint8_t ) * RELAY_PAYLOAD_LEN, 0 );

  xSemaphoreGive( local_connection->access_mutex );
  // MUTEX GIVE

  if ( succ <= 0 )
  {
    ( (ServiceTcpTraffic*)onion_message->data )->length = 0;
    free( ( (ServiceTcpTraffic*)onion_message->data )->data );
  }
  else
  {
    ( (ServiceTcpTraffic*)onion_message->data )->length = succ;
  }

  xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

  return succ;
}

static int d_recv_on_connection( DlConnection* dl_connection )
{
  int succ;

  if ( dl_connection->is_or == 1 )
  {
    succ = d_recv_on_or_connection( dl_connection );
  }
  else
  {
    succ = d_recv_on_local_connection( dl_connection );
  }

  return succ;
}

static void v_connections_daemon( void* pv_parameters )
{
  int i;
  time_t now;
  int want_next;
  int succ;
  int readable_bytes;
  uint8_t* rx_buffer;
  OnionMessage* onion_message;
  DlConnection* dl_connection;
  DlConnection* tmp_connection;
  DlConnection* ready_connections[16];

  while ( 1 )
  {
    succ = poll( connections_poll, 16, 1000 * 3 );

    if ( succ <= 0 || uxQueueMessagesWaiting( core_task_queue ) >= 15 )
    {
#ifdef DEBUG_MINITOR
      if ( succ < 0 )
      {
        ESP_LOGE( CONN_TAG, "Failed to poll local connections" );
      }
#endif
    }

    // MUTEX TAKE
    xSemaphoreTake( connections_mutex, portMAX_DELAY );

    i = 0;
    time( &now );

    dl_connection = connections;

    while ( dl_connection != NULL )
    {
      if ( ( connections_poll[dl_connection->poll_index].revents & connections_poll[dl_connection->poll_index].events ) != 0 )
      {
        ready_connections[i] = dl_connection;
        i++;
      }

      // need to send local connection timeout to the core task
      // as a 0 length tcp event
      else if ( dl_connection->is_or == 0 && now > dl_connection->last_action && now - dl_connection->last_action >= 5 )
      {
        onion_message = malloc( sizeof( OnionMessage ) );

        onion_message->type = SERVICE_TCP_DATA;
        onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );
        ( (ServiceTcpTraffic*)onion_message->data )->length = 0;
        ( (ServiceTcpTraffic*)onion_message->data )->circ_id = dl_connection->circ_id;
        ( (ServiceTcpTraffic*)onion_message->data )->stream_id = dl_connection->stream_id;

        xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

        tmp_connection = dl_connection->next;
        v_cleanup_connection( dl_connection );
        dl_connection = tmp_connection;

        continue;
      }

      dl_connection = dl_connection->next;
    }

    if ( i == 0 )
    {
      xSemaphoreGive( connections_mutex );
      // MUTEX GIVE

      continue;
    }

    for ( i = i - 1; i >= 0; i-- )
    {
      // because of how file descriptors in ssl are handled, we must read all the
      // current contents in 1 go, otherwise the ssl connection will pull the data
      // out of the file descriptor and the next poll will report no read ready
      if ( lwip_ioctl( ready_connections[i]->sock_fd, FIONREAD, &readable_bytes ) < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( CONN_TAG, "Failed to ioctl on connection fd, errno: %d", errno );
#endif
        continue;
      }

      do
      {
        if ( uxQueueMessagesWaiting( core_task_queue ) >= 15 )
        {
          break;
        }

        succ = d_recv_on_connection( ready_connections[i] );

        if ( succ <= 0 )
        {
          v_cleanup_connection( ready_connections[i] );
          ready_connections[i] = NULL;

          break;
        }

        /*
        if ( ready_connections[i]->is_or == 0 )
        {
          if ( lwip_ioctl( ready_connections[i]->sock_fd, FIONREAD, &readable_bytes ) < 0 )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( CONN_TAG, "Failed to ioctl on connection fd, errno: %d", errno );
#endif
            break;
          }
        }
        else
        {
          readable_bytes -= succ;
        }
        */

        readable_bytes -= succ;

      } while (
        ( ready_connections[i]->is_or == 0 && readable_bytes > 0 ) ||
        ( ready_connections[i]->is_or == 1 && ( readable_bytes >= CELL_LEN || ( ready_connections[i]->status == CONNECTION_WANT_CERTS && readable_bytes >= 0 ) ) )
      );

      if ( ready_connections[i] != NULL && ready_connections[i]->is_or == 0 )
      {
        time( &now );
        ready_connections[i]->last_action = now;
      }
    }

    xSemaphoreGive( connections_mutex );
    // MUTEX GIVE
  }
}

static DlConnection* px_create_or_connection( uint32_t address, uint16_t port )
{
  int i;
  int sock_fd;
  struct sockaddr_in dest_addr;
  WOLFSSL* ssl;
  DlConnection* or_connection;

  // connect to the relay over ssl
  dest_addr.sin_addr.s_addr = address;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to create socket" );
#endif

    return NULL;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to connect socket, errno: %d", errno );
#endif

    close( sock_fd );

    return NULL;
  }

  ESP_LOGE( CONN_TAG, "xMinitorWolfSSL_Context: %p", xMinitorWolfSSL_Context );

  ssl = wolfSSL_new( xMinitorWolfSSL_Context );

  if ( ssl == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    return NULL;
  }

  wolfSSL_set_verify( ssl, SSL_VERIFY_PEER, d_ignore_ca_callback );
  wolfSSL_KeepArrays( ssl );

  if ( wolfSSL_set_fd( ssl, sock_fd ) != SSL_SUCCESS )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to set ssl fd" );
#endif

    goto clean_ssl;
  }

  if ( wolfSSL_connect( ssl ) != SSL_SUCCESS )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to wolfssl_connect" );
#endif

    goto clean_ssl;
  }

  ESP_LOGE( CONN_TAG, "Starting handshake" );

  or_connection = malloc( sizeof( DlConnection ) );

  memset( or_connection, 0, sizeof( DlConnection ) );

  or_connection->address = address;
  or_connection->port = port;
  or_connection->ssl = ssl;
  or_connection->access_mutex = xSemaphoreCreateMutex();
  or_connection->sock_fd = sock_fd;
  or_connection->is_or = 1;

  if ( d_start_v3_handshake( or_connection ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "Failed to handshake with first relay" );
#endif

    goto clean_connection;
  }

  or_connection->status = CONNECTION_WANT_VERSIONS;

  v_add_connection_to_list( or_connection, &connections );

  if ( connections_daemon_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      connections_poll[i].fd = -1;
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( connections_poll[i].fd == -1 )
    {
      or_connection->poll_index = i;
      connections_poll[i].fd = sock_fd;
      connections_poll[i].events = POLLIN;

      break;
    }
  }

  if ( i >= 16 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "couldn't find an open poll spot" );
#endif

    goto clean_connection;
  }

  if ( connections_daemon_task_handle == NULL )
  {
    xTaskCreatePinnedToCore(
      v_connections_daemon,
      "CONNECTIONS_DAEMON",
      4096,
      NULL,
      6,
      &connections_daemon_task_handle,
      tskNO_AFFINITY
    );
  }

  return or_connection;

clean_connection:
  free( or_connection );
clean_ssl:
  wolfSSL_shutdown( ssl );
  wolfSSL_free( ssl );
  shutdown( sock_fd, 0 );
  close( sock_fd );

  return NULL;
}

int d_attach_or_connection( uint32_t address, uint16_t port, OnionCircuit* circuit )
{
  int i;
  DlConnection* dl_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->is_or == 1 && dl_connection->address == address && dl_connection->port == port )
    {
      break;
    }

    dl_connection = dl_connection->next;
  }

  if ( dl_connection == NULL )
  {
    dl_connection = px_create_or_connection( address, port );

    if ( dl_connection == NULL )
    {
      xSemaphoreGive( connections_mutex );
      // MUTEX GIVE

      return -1;
    }
  }

  circuit->or_connection = dl_connection;

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  if ( dl_connection->status == CONNECTION_LIVE )
  {
    return 1;
  }

  return 0;
}

int d_create_local_connection( uint32_t circ_id, uint16_t stream_id, uint16_t port )
{
  int i;
  int succ;
  int sock_fd;
  struct sockaddr_in dest_addr;
  DlConnection* local_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "couldn't create a socket to the local port, err: %d, errno: %d", sock_fd, errno );
#endif

    goto fail;
  }

  succ = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "couldn't connect to the local port" );
#endif

    goto clean_socket;
  }

  local_connection = malloc( sizeof( DlConnection ) );

  memset( local_connection, 0, sizeof( DlConnection ) );

  local_connection->circ_id = circ_id;
  local_connection->stream_id = stream_id;
  local_connection->access_mutex = xSemaphoreCreateMutex();
  local_connection->sock_fd = sock_fd;
  local_connection->is_or = 0;
  // set last action to uint max so it isn't killed before it can read (no one should be killed before they can read)
  local_connection->last_action = INT_MAX;

  if ( connections_daemon_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      connections_poll[i].fd = -1;
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( connections_poll[i].fd == -1 )
    {
      local_connection->poll_index = i;
      connections_poll[i].fd = sock_fd;
      connections_poll[i].events = POLLIN;

      break;
    }
  }

  if ( i >= 16 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CONN_TAG, "couldn't find an open poll spot" );
#endif

    free( local_connection );
    goto clean_socket;
  }

  v_add_connection_to_list( local_connection, &connections );

  if ( connections_daemon_task_handle == NULL )
  {
    xTaskCreatePinnedToCore(
      v_connections_daemon,
      "CONNECTIONS_DAEMON",
      4096,
      NULL,
      6,
      &connections_daemon_task_handle,
      tskNO_AFFINITY
    );
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  return 0;

clean_socket:
  shutdown( sock_fd, 0 );
  close( sock_fd );
fail:
  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  return -1;
}

int d_forward_to_local_connection( uint32_t circ_id, uint32_t stream_id, uint8_t* data, uint32_t length )
{
  int ret = 0;
  DlConnection* local_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id && local_connection->stream_id == stream_id )
    {
      // MUTEX TAKE
      xSemaphoreTake( local_connection->access_mutex, portMAX_DELAY );

      ret = send( local_connection->sock_fd, data, length, 0 );

      xSemaphoreGive( local_connection->access_mutex );
      // MUTEX GIVE

      break;
    }

    local_connection = local_connection->next;
  }

  if ( local_connection == NULL )
  {
    ret = -1;
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  return ret;
}

void v_cleanup_local_connection( uint32_t circ_id, uint32_t stream_id )
{
  DlConnection* local_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id && local_connection->stream_id == stream_id )
    {
      v_cleanup_connection( local_connection );
      break;
    }

    local_connection = local_connection->next;
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE
}

void v_cleanup_local_connections_by_circ_id( uint32_t circ_id )
{
  DlConnection* local_connection;
  DlConnection* tmp_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id )
    {
      tmp_connection = local_connection->next;
      v_cleanup_connection( local_connection );
      local_connection = tmp_connection;
    }
    else
    {
      local_connection = local_connection->next;
    }
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE
}

bool b_verify_or_connection( DlConnection* or_connection )
{
  uint8_t ret = false;
  DlConnection* in_list;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  in_list = connections;

  while ( in_list != NULL )
  {
    if ( in_list->is_or == 1 && in_list == or_connection )
    {
      ret = 1;
      break;
    }

    in_list = in_list->next;
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  return ret;
}

void v_dettach_connection( DlConnection* or_connection )
{
  OnionCircuit* check_circuit;
  DlConnection* dl_connection;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  check_circuit = onion_circuits;

  while ( check_circuit != NULL )
  {
    if ( check_circuit->or_connection == or_connection )
    {
      break;
    }

    check_circuit = check_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  if ( check_circuit == NULL )
  {
    // MUTEX TAKE
    xSemaphoreTake( connections_mutex, portMAX_DELAY );

    dl_connection = connections;

    while ( dl_connection != NULL )
    {
      if ( dl_connection == or_connection )
      {
        break;
      }

      dl_connection = dl_connection->next;
    }

    if ( dl_connection != NULL )
    {
      v_cleanup_connection( or_connection );
    }

    xSemaphoreGive( connections_mutex );
    // MUTEX GIVE
  }
}
