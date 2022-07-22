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

#include "wolfssl/options.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "../h/wolfssl_internal.h"

#include "../include/config.h"
#include "../h/port.h"

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
MinitorTask connections_daemon_task_handle = NULL;
struct pollfd connections_poll[16];
DlConnection* connections;
MinitorMutex connections_mutex;
MinitorMutex connection_access_mutex[16];

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store )
{
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

  MINITOR_LOG( CONN_TAG, "SSL callback error %d", store->error );

  return 0;
}

static int conn_secrects_cb( WOLFSSL* ssl, void* secret, int* secretSz, void* ctx )
{
  DlConnection* or_connection = ctx;

  MINITOR_LOG( CONN_TAG, "SETTING master_secret memcmp: %d %d", memcmp( secret, ssl->arrays->masterSecret, 48 ), *secretSz );

  {
    int i;

    printf( "\nsecret " );

    for ( i = 0; i < 48; i++ )
    {
      printf( "%.2x", ((uint8_t*)secret)[i] );
    }

    printf( "\n" );
  }

  memcpy( or_connection->master_secret, secret, 48 );

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

    MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );
  }

  connections_poll[dl_connection->poll_index].fd = -1;

  shutdown( dl_connection->sock_fd, 0 );
  close( dl_connection->sock_fd );

  v_remove_connection_from_list( dl_connection, &connections );

  free( dl_connection );
}

void v_cleanup_connection( DlConnection* dl_connection )
{
  MinitorMutex access_mutex;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  if ( b_verify_or_connection( dl_connection->conn_id ) == false )
  {
    MINITOR_MUTEX_GIVE( connections_mutex );
    // MUTEX GIVE

    return;
  }

  access_mutex = connection_access_mutex[dl_connection->mutex_index];

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( access_mutex );

  v_cleanup_connection_in_lock( dl_connection );

  MINITOR_MUTEX_GIVE( access_mutex );
  // MUTEX TAKE

  MINITOR_MUTEX_GIVE( connections_mutex );
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

  MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

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

  MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

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

void v_connections_daemon( void* pv_parameters )
{
  int i;
  time_t now;
  int want_next;
  int succ;
  int readable_bytes;
  uint8_t* rx_buffer;
  MinitorMutex access_mutex;
  OnionMessage* onion_message;
  DlConnection* dl_connection;
  DlConnection* tmp_connection;
  DlConnection* ready_connections[16];

  while ( 1 )
  {
    succ = poll( connections_poll, 16, 500 );

    if ( succ <= 0 )
    {
      if ( succ < 0 )
      {
        MINITOR_LOG( CONN_TAG, "Failed to poll local connections" );
      }
    }

    if ( MINITOR_QUEUE_MESSAGES_WAITING( core_task_queue ) >= 15 )
    {
      continue;
    }

    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

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

        MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

        tmp_connection = dl_connection->next;

        access_mutex = connection_access_mutex[dl_connection->mutex_index];

        // MUTEX TAKE
        MINITOR_MUTEX_TAKE_BLOCKING( access_mutex );

        v_cleanup_connection_in_lock( dl_connection );

        MINITOR_MUTEX_GIVE( access_mutex );
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
      MINITOR_MUTEX_TAKE_BLOCKING( access_mutex );

      // because of how file descriptors in ssl are handled, we must read all the
      // current contents in 1 go, otherwise the ssl connection will pull the data
      // out of the file descriptor and the next poll will report no read ready
      if ( MINITOR_GET_READABLE( ready_connections[i]->sock_fd, &readable_bytes ) < 0 )
      {
        MINITOR_LOG( CONN_TAG, "Failed to ioctl on connection fd, errno: %d", errno );

        continue;
      }

      do
      {
        if ( MINITOR_QUEUE_MESSAGES_WAITING( core_task_queue ) >= 15 )
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

      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE
    }

    MINITOR_MUTEX_GIVE( connections_mutex );
    // MUTEX GIVE
  }
}

static DlConnection* px_create_or_connection( uint32_t address, uint16_t port )
{
  int i;
  int succ;
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
    MINITOR_LOG( CONN_TAG, "Failed to create socket" );

    return NULL;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 )
  {
    MINITOR_LOG( CONN_TAG, "Failed to connect socket, errno: %d", errno );

    close( sock_fd );

    return NULL;
  }

  ssl = wolfSSL_new( xMinitorWolfSSL_Context );

  if ( ssl == NULL )
  {
    MINITOR_LOG( CONN_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );

    shutdown( sock_fd, 0 );
    close( sock_fd );

    return NULL;
  }

  or_connection = malloc( sizeof( DlConnection ) );

  memset( or_connection, 0, sizeof( DlConnection ) );

  wolfSSL_set_verify( ssl, SSL_VERIFY_NONE, NULL );
  wolfSSL_KeepArrays( ssl );
  wolfSSL_set_session_secret_cb( ssl, conn_secrects_cb, or_connection );

  succ = wolfSSL_set_fd( ssl, sock_fd );

  if ( succ != SSL_SUCCESS )
  {
    MINITOR_LOG( CONN_TAG, "Failed to set ssl fd %d", succ );

    free( or_connection );
    goto clean_ssl;
  }

  succ = wolfSSL_connect( ssl );

  if ( succ != SSL_SUCCESS )
  {
    MINITOR_LOG( CONN_TAG, "Failed to wolfSSL_connect %d", wolfSSL_get_error( ssl, succ ) );

    free( or_connection );
    goto clean_ssl;
  }

  MINITOR_LOG( CONN_TAG, "Starting handshake" );

  or_connection->address = address;
  or_connection->port = port;
  or_connection->ssl = ssl;
  or_connection->sock_fd = sock_fd;
  or_connection->is_or = 1;
  or_connection->conn_id = conn_id++;

  if ( d_start_v3_handshake( or_connection ) < 0 )
  {
    MINITOR_LOG( CONN_TAG, "Failed to handshake with first relay" );

    goto clean_connection;
  }

  or_connection->status = CONNECTION_WANT_VERSIONS;

  v_add_connection_to_list( or_connection, &connections );

  if ( connections_daemon_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      connections_poll[i].fd = -1;
      connection_access_mutex[i] = MINITOR_MUTEX_CREATE();
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
    MINITOR_LOG( CONN_TAG, "couldn't find an open poll spot" );

    goto clean_connection;
  }

  if ( connections_daemon_task_handle == NULL )
  {
    b_create_connections_task( &connections_daemon_task_handle );
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
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

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
      MINITOR_MUTEX_GIVE( connections_mutex );
      // MUTEX GIVE

      return -1;
    }
  }

  circuit->conn_id = dl_connection->conn_id;

  MINITOR_MUTEX_GIVE( connections_mutex );
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
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
    MINITOR_LOG( CONN_TAG, "couldn't create a socket to the local port, err: %d, errno: %d", sock_fd, errno );

    goto fail;
  }

  succ = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( succ != 0 )
  {
    MINITOR_LOG( CONN_TAG, "couldn't connect to the local port" );

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
      connection_access_mutex[i] = MINITOR_MUTEX_CREATE();
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
    MINITOR_LOG( CONN_TAG, "couldn't find an open poll spot" );

    free( local_connection );
    goto clean_socket;
  }

  v_add_connection_to_list( local_connection, &connections );

  if ( connections_daemon_task_handle == NULL )
  {
    b_create_connections_task( &connections_daemon_task_handle );
  }

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  return 0;

clean_socket:
  shutdown( sock_fd, 0 );
  close( sock_fd );
fail:
  MINITOR_MUTEX_GIVE( connections_mutex );
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
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

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

  MINITOR_MUTEX_GIVE( connections_mutex );
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
  MinitorMutex access_mutex;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  check_circuit = onion_circuits;

  while ( check_circuit != NULL )
  {
    if ( check_circuit->conn_id == dl_connection->conn_id )
    {
      break;
    }

    check_circuit = check_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
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
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->conn_id == id )
    {
      // MUTEX TAKE
      MINITOR_MUTEX_TAKE_BLOCKING( connection_access_mutex[dl_connection->mutex_index] );

      break;
    }

    dl_connection = dl_connection->next;
  }

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  return dl_connection;
}
