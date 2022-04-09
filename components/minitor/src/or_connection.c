#include <stdlib.h>

#include "esp_log.h"
#include "user_settings.h"
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
#include "../h/or_connection.h"
#include "../h/consensus.h"

TaskHandle_t handle_or_connections_task_handle;

struct pollfd or_connections_poll[16];
int free_poll_indices[16];

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store ) {
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "SSL callback error %d", store->error );
#endif

  return 0;
}

void v_cleanup_or_connection( OrConnection* or_connection )
{
  int i;
  uint8_t* packed_cell;
  DoublyLinkedOnionCircuit* db_circuit;

  vSemaphoreDelete( or_connection->access_mutex );
  or_connection->access_mutex = NULL;

  v_remove_or_connection_from_list( or_connection, &or_connections );

  if ( or_connections.length == 0 )
  {
    vTaskDelete( handle_or_connections_task_handle );
    handle_or_connections_task_handle = NULL;
  }

  db_circuit = or_connection->circuits.head;

  packed_cell = NULL;

  for ( i = 0; i < or_connection->circuits.length; i++ )
  {
    xQueueSendToFront( db_circuit->circuit->rx_queue, (void*)(&packed_cell), portMAX_DELAY );

    if ( i == or_connection->circuits.length - 1 )
    {
      free( db_circuit );
    }
    else
    {
      db_circuit = db_circuit->next;
      free( db_circuit->previous );
    }
  }

  wolfSSL_shutdown( or_connection->ssl );
  shutdown( wolfSSL_get_fd( or_connection->ssl ), 0 );
  close( wolfSSL_get_fd( or_connection->ssl ) );
  wolfSSL_free( or_connection->ssl );

  or_connections_poll[or_connection->poll_index].fd = -1;
  free_poll_indices[or_connection->poll_index] = 0;

  free( or_connection );
}

void v_handle_or_connections( void* pv_parameters )
{
  int succ;
  uint32_t circ_id;
  uint8_t* packed_cell;
  OrConnection* or_connection;
  OrConnection* tmp_or_connection;
  DoublyLinkedOnionCircuit* db_circuit;
  OnionMessage* onion_message;

  while ( 1 )
  {
    // at most we will have to wait 1.5 seconds for a connection to become readable
    // hopefully execution time to the continue statement is neglegable
    succ = poll( or_connections_poll, 16, 1500 );

    if ( succ <= 0 )
    {
#ifdef DEBUG_MINITOR
      if ( succ < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Failed to poll or connections" );
      }
#endif

      continue;
    }

    // MUTEX TAKE
    xSemaphoreTake( or_connections_mutex, portMAX_DELAY );

    or_connection = or_connections.head;

    while ( or_connection != NULL )
    {
      if ( ( or_connections_poll[or_connection->poll_index].revents & or_connections_poll[or_connection->poll_index].events ) != 0 )
      {
        // MUTEX TAKE
        xSemaphoreTake( or_connection->access_mutex, portMAX_DELAY );

        succ = d_recv_packed_cell( or_connection->ssl, &packed_cell, CIRCID_LEN );

        xSemaphoreGive( or_connection->access_mutex );
        // MUTEX GIVE

        if ( succ < 0 )
        {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to recv cell on connection" );
#endif

          // next could be null so we can't just call cleanup with previous
          tmp_or_connection = or_connection->next;
          v_cleanup_or_connection( or_connection );
          or_connection = tmp_or_connection;
          continue;
        }
        else
        {
          db_circuit = or_connection->circuits.head;

          circ_id = ((uint32_t)packed_cell[0]) << 24;
          circ_id |= ((uint32_t)packed_cell[1]) << 16;
          circ_id |= ((uint32_t)packed_cell[2]) << 8;
          circ_id |= (packed_cell[3]);

          while ( db_circuit != NULL )
          {
            if ( db_circuit->circuit->circ_id == circ_id )
            {
              break;
            }

            db_circuit = db_circuit->next;
          }

          if ( db_circuit != NULL )
          {
            onion_message = malloc( sizeof( OnionMessage ) );
            onion_message->type = PACKED_CELL;
            onion_message->data = packed_cell;
            onion_message->length = succ;

            xQueueSendToBack( db_circuit->circuit->rx_queue, (void*)(&onion_message), portMAX_DELAY );
          }
          else
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Ignoring circuit-less cell: %d", circ_id );
#endif
            free( packed_cell );
          }
        }
      }

      or_connection = or_connection->next;
    }

    xSemaphoreGive( or_connections_mutex );
    // MUTEX GIVE
  }
}

void v_dettach_connection( OnionCircuit* circuit )
{
  int i;
  DoublyLinkedOnionCircuit* db_circuit;

  db_circuit = circuit->or_connection->circuits.head;

  for ( i = 0; i < circuit->or_connection->circuits.length; i++ )
  {
    if ( db_circuit->circuit->circ_id == circuit->circ_id )
    {
      if ( db_circuit == circuit->or_connection->circuits.head )
      {
        circuit->or_connection->circuits.head = db_circuit->next;
      }

      if ( db_circuit == circuit->or_connection->circuits.tail )
      {
        circuit->or_connection->circuits.tail = db_circuit->previous;
      }

      if ( db_circuit->next != NULL )
      {
        db_circuit->next->previous = db_circuit->previous;
      }

      if ( db_circuit->previous != NULL )
      {
        db_circuit->previous->next = db_circuit->next;
      }

      circuit->or_connection->circuits.length--;

      if ( circuit->or_connection->circuits.length == 0 )
      {
        v_cleanup_or_connection( circuit->or_connection );
      }

      free( db_circuit );

      break;
    }

    db_circuit = db_circuit->next;
  }
}

int d_attach_connection( uint32_t address, uint16_t port, OnionCircuit* circuit )
{
  int i;
  OrConnection* working_or_connection;
  DoublyLinkedOnionCircuit* db_circuit;

  // MUTEX TAKE
  xSemaphoreTake( or_connections_mutex, portMAX_DELAY );

  working_or_connection = or_connections.head;

  for ( i = 0; i < or_connections.length; i++ )
  {
    if ( working_or_connection->address == address && working_or_connection->port == port )
    {
      break;
    }

    working_or_connection = working_or_connection->next;
  }

  if ( working_or_connection == NULL )
  {
    working_or_connection = px_create_connection( address, port );

    if ( working_or_connection == NULL )
    {
      xSemaphoreGive( or_connections_mutex );
      // MUTEX GIVE

      return -1;
    }
  }

  db_circuit = malloc( sizeof( DoublyLinkedOnionCircuit ) );
  db_circuit->circuit = circuit;

  v_add_circuit_to_list( db_circuit, &working_or_connection->circuits );
  db_circuit->circuit->or_connection = working_or_connection;

  xSemaphoreGive( or_connections_mutex );
  // MUTEX GIVE

  return 0;
}

OrConnection* px_create_connection( uint32_t address, uint16_t port )
{
  int i;
  int sock_fd;
  struct sockaddr_in dest_addr;
  WOLFSSL* ssl;
  OrConnection* or_connection;

  // connect to the relay over ssl
  dest_addr.sin_addr.s_addr = address;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create socket" );
#endif

    return NULL;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to connect socket, errno: %d", errno );
#endif

    close( sock_fd );

    return NULL;
  }

  ESP_LOGE( MINITOR_TAG, "xMinitorWolfSSL_Context: %p", xMinitorWolfSSL_Context );

  ssl = wolfSSL_new( xMinitorWolfSSL_Context );

  if ( ssl == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );
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
    ESP_LOGE( MINITOR_TAG, "Failed to set ssl fd" );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    goto clean_ssl;
  }

  if ( wolfSSL_connect( ssl ) != SSL_SUCCESS )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to wolfssl_connect" );
#endif

    goto clean_ssl;
  }

  ESP_LOGE( MINITOR_TAG, "Starting handshake" );

  if ( d_router_handshake( ssl ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to handshake with first relay" );
#endif

    goto clean_ssl;
  }

  ESP_LOGE( MINITOR_TAG, "Finish handshake" );

  or_connection = malloc( sizeof( OrConnection ) );

  memset( or_connection, 0, sizeof( OrConnection ) );

  or_connection->address = address;
  or_connection->port = port;
  or_connection->ssl = ssl;
  or_connection->access_mutex = xSemaphoreCreateMutex();

  v_add_or_connection_to_list( or_connection, &or_connections );

  if ( handle_or_connections_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      or_connections_poll[i].fd = -1;
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( free_poll_indices[i] == 0 )
    {
      free_poll_indices[i] = 1;
      or_connection->poll_index = i;
      or_connections_poll[i].fd = wolfSSL_get_fd( or_connection->ssl );
      or_connections_poll[i].events = POLLIN;
      break;
    }
  }

  if ( handle_or_connections_task_handle == NULL )
  {
    xTaskCreatePinnedToCore(
      v_handle_or_connections,
      "H_OR_CONNECTIONS",
      4096,
      NULL,
      4,
      &handle_or_connections_task_handle,
      tskNO_AFFINITY
    );
  }

  return or_connection;

clean_ssl:
  wolfSSL_shutdown( ssl );
  shutdown( wolfSSL_get_fd( ssl ), 0 );
  close( wolfSSL_get_fd( ssl ) );
  wolfSSL_free( ssl );

  return NULL;
}
