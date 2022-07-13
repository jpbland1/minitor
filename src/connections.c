/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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

uint32_t conn_id = 0;
TaskHandle_t connections_daemon_task_handle;
struct pollfd connections_poll[16];
DlConnection* connections;
SemaphoreHandle_t connections_mutex;
SemaphoreHandle_t connection_access_mutex[16];

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store )
{
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( CONN_TAG, "SSL callback error %d", store->error );
#endif

  return 0;
}

static void v_cleanup_connection_in_lock( DlConnection* dl_connection )
{
  int i;
  OnionMessage* onion_message;

  // we only need to inform the core daemon if an or connection
  // closed, local connections closing already triggered a
  // RELAY_END and don't need aditonal work
  if ( dl_connection->is_or == 1 )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = CONN_CLOSE;
    onion_message->data = dl_connection->conn_id;

    wolfSSL_shutdown( dl_connection->ssl );
    wolfSSL_free( dl_connection->ssl );

    for ( i = 0; i < 20; i++ )
    {
      if ( dl_connection->cell_ring_buf[i] != NULL )
      {
        free( dl_connection->cell_ring_buf[i] );
      }
    }

    if (
      dl_connection->status == CONNECTION_WANT_VERSIONS ||
      dl_connection->status == CONNECTION_WANT_CERTS ||
      dl_connection->status == CONNECTION_WANT_CHALLENGE
    )
    {
      wc_FreeRsaKey( &dl_connection->initiator_rsa_auth_key );

      free( dl_connection->responder_rsa_identity_key_der );
      free( dl_connection->initiator_rsa_identity_key_der );

      wc_Sha256Free( &dl_connection->responder_sha );
      wc_Sha256Free( &dl_connection->initiator_sha );
    }

    xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
  }

  connections_poll[dl_connection->poll_index].fd = -1;

  shutdown( dl_connection->sock_fd, 0 );
  close( dl_connection->sock_fd );

  v_remove_connection_from_list( dl_connection, &connections );

  free( dl_connection );
}

void v_cleanup_connection( DlConnection* dl_connection )
{
  SemaphoreHandle_t access_mutex;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  if ( b_verify_or_connection( dl_connection->conn_id ) == false )
  {
    xSemaphoreGive( connections_mutex );
    // MUTEX GIVE

    return;
  }

  access_mutex = connection_access_mutex[dl_connection->mutex_index];

  // MUTEX TAKE
  xSemaphoreTake( access_mutex, portMAX_DELAY );

  v_cleanup_connection_in_lock( dl_connection );

  xSemaphoreGive( access_mutex );
  // MUTEX TAKE

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE
}

static int d_recv_on_or_connection( DlConnection* or_connection )
{
  int succ;
  uint8_t* cell;
  OnionMessage* onion_message;

  if ( ( or_connection->cell_ring_end + 1 ) % 20 == or_connection->cell_ring_start )
  {
    succ = -1;
    goto finish;
  }

  if ( or_connection->has_versions == false )
  {
    succ = d_recv_cell( or_connection->ssl, &cell, LEGACY_CIRCID_LEN );

    or_connection->has_versions = true;
  }
  else
  {
    succ = d_recv_cell( or_connection->ssl, &cell, CIRCID_LEN );
  }

  if ( succ <= 0 )
  {
    succ = -1;
    goto finish;
  }

  or_connection->cell_ring_buf[or_connection->cell_ring_end] = cell;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->data = or_connection->conn_id;
  onion_message->length = succ;

  if ( or_connection->status == CONNECTION_LIVE )
  {
    onion_message->type = TOR_CELL;
  }
  else
  {
    onion_message->type = CONN_HANDSHAKE;
  }

  or_connection->cell_ring_end = ( or_connection->cell_ring_end + 1 ) % 20;

  xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

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

  succ = recv( local_connection->sock_fd, ( (ServiceTcpTraffic*)onion_message->data )->data, sizeof( uint8_t ) * RELAY_PAYLOAD_LEN, 0 );

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
  SemaphoreHandle_t access_mutex;
  OnionMessage* onion_message;
  DlConnection* dl_connection;
  DlConnection* tmp_connection;
  DlConnection* ready_connections[16];

  while ( 1 )
  {
    succ = poll( connections_poll, 16, 500 );

    if ( succ <= 0 )
    {
#ifdef DEBUG_MINITOR
      if ( succ < 0 )
      {
        ESP_LOGE( CONN_TAG, "Failed to poll local connections" );
      }
#endif
    }

    if ( uxQueueMessagesWaiting( core_task_queue ) >= 15 )
    {
      continue;
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

        access_mutex = connection_access_mutex[dl_connection->mutex_index];

        // MUTEX TAKE
        xSemaphoreTake( access_mutex, portMAX_DELAY );

        v_cleanup_connection_in_lock( dl_connection );

        xSemaphoreGive( access_mutex );
        // MUTEX GIVE

        access_mutex = NULL;

        dl_connection = tmp_connection;

        continue;
      }

      dl_connection = dl_connection->next;
    }

    for ( i = i - 1; i >= 0; i-- )
    {
      access_mutex = connection_access_mutex[ready_connections[i]->mutex_index];

      // MUTEX TAKE
      xSemaphoreTake( access_mutex, portMAX_DELAY );

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
          v_cleanup_connection_in_lock( ready_connections[i] );
          ready_connections[i] = NULL;

          break;
        }

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

      xSemaphoreGive( access_mutex );
      // MUTEX GIVE
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

  wolfSSL_set_verify( ssl, SSL_VERIFY_NONE, NULL );
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
  or_connection->sock_fd = sock_fd;
  or_connection->is_or = 1;
  or_connection->conn_id = conn_id++;

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
      connection_access_mutex[i] = xSemaphoreCreateMutex();
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( connections_poll[i].fd == -1 )
    {
      or_connection->poll_index = i;
      or_connection->mutex_index = i;
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
      //2048,
      3072,
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

  circuit->conn_id = dl_connection->conn_id;

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
  local_connection->sock_fd = sock_fd;
  local_connection->is_or = 0;
  // set last action to uint max so it isn't killed before it can read (no one should be killed before they can read)
  local_connection->last_action = INT_MAX;
  local_connection->conn_id = conn_id++;

  if ( connections_daemon_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      connections_poll[i].fd = -1;
      connection_access_mutex[i] = xSemaphoreCreateMutex();
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( connections_poll[i].fd == -1 )
    {
      local_connection->poll_index = i;
      local_connection->mutex_index = i;
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
      //2048,
      3072,
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

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id && local_connection->stream_id == stream_id )
    {
      ret = send( local_connection->sock_fd, data, length, 0 );

      break;
    }

    local_connection = local_connection->next;
  }

  if ( local_connection == NULL )
  {
    ret = -1;
  }

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
      v_cleanup_connection_in_lock( local_connection );
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

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id )
    {
      tmp_connection = local_connection->next;
      v_cleanup_connection_in_lock( local_connection );
      local_connection = tmp_connection;
    }
    else
    {
      local_connection = local_connection->next;
    }
  }
}

bool b_verify_or_connection( uint32_t id )
{
  bool ret = false;
  DlConnection* in_list;

  in_list = connections;

  while ( in_list != NULL )
  {
    if ( in_list->is_or == 1 && in_list->conn_id == id )
    {
      ret = true;
      break;
    }

    in_list = in_list->next;
  }

  return ret;
}

void v_dettach_connection( DlConnection* dl_connection )
{
  OnionCircuit* check_circuit;
  SemaphoreHandle_t access_mutex;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  check_circuit = onion_circuits;

  while ( check_circuit != NULL )
  {
    if ( check_circuit->conn_id == dl_connection->conn_id )
    {
      break;
    }

    check_circuit = check_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  if ( check_circuit == NULL )
  {
    v_cleanup_connection( dl_connection );
  }
}

// caller must give the access semaphore
DlConnection* px_get_conn_by_id_and_lock( uint32_t id )
{
  DlConnection* dl_connection;

  // MUTEX TAKE
  xSemaphoreTake( connections_mutex, portMAX_DELAY );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->conn_id == id )
    {
      // MUTEX TAKE
      xSemaphoreTake( connection_access_mutex[dl_connection->mutex_index], portMAX_DELAY );

      break;
    }

    dl_connection = dl_connection->next;
  }

  xSemaphoreGive( connections_mutex );
  // MUTEX GIVE

  return dl_connection;
}
