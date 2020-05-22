#include <stdlib.h>

#include "esp_log.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "../include/config.h"
#include "../h/circuit.h"
#include "../h/cell.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/models/relay.h"

extern WOLFSSL_CTX* xMinitorWolfSSL_Context;

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store ) {
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "SSL callback error %d", store->error );
#endif

  return 0;
}

static unsigned int ud_get_cert_date( unsigned char* date_buffer, int date_size ) {
  int i = 0;
  struct tm temp_time;
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;

  for ( i = 0; i < date_size; i++ ) {
    if ( i < 2 ) {
      year *= 10;
      year += date_buffer[i] & 0x0f;
    } else if ( i < 4 ) {
      month *= 10;
      month += date_buffer[i] & 0x0f;
    } else if ( i < 6 ) {
      day *= 10;
      day += date_buffer[i] & 0x0f;
    } else if ( i < 8 ) {
      hour *= 10;
      hour += date_buffer[i] & 0x0f;
    } else if ( i < 10 ) {
      minute *= 10;
      minute += date_buffer[i] & 0x0f;
    } else if ( i < 12 ) {
      second *= 10;
      second += date_buffer[i] & 0x0f;
    } else {
      temp_time.tm_year = ( year + 100 );
      temp_time.tm_mon = month - 1;
      temp_time.tm_mday = day;
      temp_time.tm_hour = hour;
      temp_time.tm_min = minute;
      temp_time.tm_sec = second;

      return mktime( &temp_time );
    }
  }

  return 0;
}

// create three hop circuits that can quickly be turned into introduction points
int d_setup_init_circuits( int circuit_count ) {
  int res = 0;

  int i;
  DoublyLinkedOnionCircuit* node;

  for ( i = 0; i < circuit_count; i++ ) {
    node = malloc( sizeof( DoublyLinkedOnionCircuit ) );
    node->circuit.task_handle = NULL;

    switch ( d_build_random_onion_circuit( &node->circuit, 3 ) ) {
      case -1:
        i--;
        free( node );
        break;
      case -2:
        i = circuit_count;
        free( node );
        break;
      case 0:
        node->circuit.status = CIRCUIT_STANDBY;

        // spawn a task to block on the tls buffer and put the data into the rx_queue
        xTaskCreatePinnedToCore(
          v_handle_circuit,
          "HANDLE_CIRCUIT",
          4096,
          (void*)(&node->circuit),
          6,
          &node->circuit.task_handle,
          tskNO_AFFINITY
        );

        // BEGIN mutex for standby circuits
        xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

        v_add_circuit_to_list( node, &standby_circuits );

        xSemaphoreGive( standby_circuits_mutex );
        // END mutex for standby circuits

        res++;
        break;
      default:
        break;
    }
  }

  return res;
}

// create a tor circuit
int d_build_random_onion_circuit( OnionCircuit* circuit, int circuit_length ) {
  int succ;

  succ = d_prepare_random_onion_circuit( circuit, circuit_length, NULL );

  if ( succ < 0 ) {
    while ( circuit->relay_list.length ) {
      v_pop_relay_from_list_back( &circuit->relay_list );
    }

    return succ;
  }

  return d_build_onion_circuit( circuit );
}

int d_build_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay ) {
  int succ;
  DoublyLinkedOnionRelay* node;

  succ = d_prepare_random_onion_circuit( circuit, circuit_length - 1, destination_relay->identity );

  if ( succ < 0 ) {
    while ( circuit->relay_list.length ) {
      v_pop_relay_from_list_back( &circuit->relay_list );
    }

    return succ;
  }

  node = malloc( sizeof( DoublyLinkedOnionRelay ) );
  node->previous = NULL;
  node->next = NULL;
  node->relay = destination_relay;

  v_add_relay_to_list( node, &circuit->relay_list );

  return d_build_onion_circuit( circuit );
}

int d_extend_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay ) {
  int i;
  DoublyLinkedOnionRelay* node;

  if ( d_get_suitable_onion_relays( &circuit->relay_list, circuit_length - 1, destination_relay->identity ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get suitable relays to extend to" );
#endif
  }

  node = malloc( sizeof( DoublyLinkedOnionRelay ) );
  node->previous = NULL;
  node->next = NULL;
  node->relay = destination_relay;

  v_add_relay_to_list( node, &circuit->relay_list );

  if ( d_fetch_descriptor_info( circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to fetch descriptors" );
#endif

    return -1;
  }

  node = circuit->relay_list.head;

  // TODO possibly better to make d_build_onion_circuit capable of doing this instead of doing it here
  for ( i = circuit->relay_list.built_length; i < circuit->relay_list.length; i++ ) {
    // make an extend cell and send it to the hop
    if ( d_router_extend2( circuit, i ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to EXTEND2 with relay %d", i + 1 );
#endif

      return -1;
    }

    circuit->relay_list.built_length++;
  }

  return 0;
}

int d_prepare_random_onion_circuit( OnionCircuit* circuit, int circuit_length, unsigned char* exclude ) {
  // find 3 suitable relays from our directory information
  circuit->status = CIRCUIT_BUILDING;
  circuit->rx_queue = NULL;

  // BEGIN mutex for circ_id
  xSemaphoreTake( circ_id_mutex, portMAX_DELAY );

  circuit->circ_id = ++circ_id_counter;

  xSemaphoreGive( circ_id_mutex );
  // END mutex for circ_id

  circuit->relay_list.length = 0;
  circuit->relay_list.built_length = 0;

  return d_get_suitable_onion_relays( &circuit->relay_list, circuit_length, exclude );
}

int d_get_suitable_onion_relays( DoublyLinkedOnionRelayList* relay_list, int desired_length, unsigned char* exclude ) {
  int i;
  DoublyLinkedOnionRelay* tmp_node;

  for ( i = relay_list->length; i < desired_length; i++ ) {
    tmp_node = malloc( sizeof( DoublyLinkedOnionRelay ) );

    tmp_node->next = NULL;
    tmp_node->previous = NULL;

    if ( i == 0 ) {
      if ( ( tmp_node->relay = px_get_random_relay_non_guard( exclude ) ) == NULL ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to get guard relay" );
#endif

        free( tmp_node );

        return -1;
      }

      if ( d_mark_relay_as_guard( tmp_node->relay->identity ) < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to mark guard relay" );
#endif

        free( tmp_node->relay );
        free( tmp_node );

        return -1;
      }
    } else {
      if ( ( tmp_node->relay = px_get_random_relay( relay_list, exclude ) ) == NULL ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to get mid relay" );
#endif

        free( tmp_node );

        return -1;
      }
    }

    v_add_relay_to_list( tmp_node, relay_list );
  }

  return 0;
}

int d_build_onion_circuit( OnionCircuit* circuit ) {
  int i;
  int sock_fd;
  struct sockaddr_in dest_addr;
  WOLFSSL* ssl;

  // get the relay's ntor onion keys
  if ( d_fetch_descriptor_info( circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to fetch descriptors" );
#endif

    goto clean_circuit;
  }

  // connect to the relay over ssl
  dest_addr.sin_addr.s_addr = circuit->relay_list.head->relay->address;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( circuit->relay_list.head->relay->or_port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create socket" );
#endif

    goto clean_circuit;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to connect socket" );
#endif

    close( sock_fd );

    goto clean_circuit;
  }

  if ( ( ssl = wolfSSL_new( xMinitorWolfSSL_Context ) ) == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    goto clean_circuit;
  }

  wolfSSL_set_verify( ssl, SSL_VERIFY_PEER, d_ignore_ca_callback );
  wolfSSL_KeepArrays( ssl );

  if ( wolfSSL_set_fd( ssl, sock_fd ) != SSL_SUCCESS ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to set ssl fd" );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    goto clean_ssl;
  }

  if ( wolfSSL_connect( ssl ) != SSL_SUCCESS ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to wolfssl_connect" );
#endif

    goto clean_ssl;
  }

  // attach the ssl object to the circuit
  circuit->ssl = ssl;

  if ( d_router_handshake( circuit->ssl ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to handshake with first relay" );
#endif

    goto clean_ssl;
  }

  if ( d_router_create2( circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to CREATE2 with first relay" );
#endif

    goto clean_ssl;
  }

  circuit->relay_list.built_length++;

  for ( i = 1; i < circuit->relay_list.length; i++ ) {
    // make an extend cell and send it to the hop
    if ( d_router_extend2( circuit, i ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to EXTEND2 with relay %d", i + 1 );
#endif

      d_destroy_onion_circuit( circuit );

      return -1;
    }

    circuit->relay_list.built_length++;
  }

  return 0;

clean_ssl:
  wolfSSL_shutdown( ssl );
  shutdown( wolfSSL_get_fd( ssl ), 0 );
  close( wolfSSL_get_fd( ssl ) );
  wolfSSL_free( ssl );
clean_circuit:
  d_unmark_relay_as_guard( circuit->relay_list.head->relay->identity );

  while ( circuit->relay_list.length ) {
    v_pop_relay_from_list_back( &circuit->relay_list );
  }

  return -1;
}

// destroy a tor circuit
int d_destroy_onion_circuit( OnionCircuit* circuit ) {
  int i;
  Cell unpacked_cell = {
    .circ_id = circuit->circ_id,
    .command = DESTROY,
    .payload = malloc( sizeof( PayloadDestroy ) ),
  };
  unsigned char* packed_cell;
  DoublyLinkedOnionRelay* tmp_relay_node;

  ( (PayloadDestroy*)unpacked_cell.payload )->destroy_code = NO_DESTROY_CODE;

  packed_cell = pack_and_free( &unpacked_cell );

  // send a destroy cell to the first hop
  if ( wolfSSL_send( circuit->ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send DESTROY cell" );
#endif

    return -1;
  }

  free( packed_cell );

  tmp_relay_node = circuit->relay_list.head;

  for ( i = 0; i < circuit->relay_list.length; i++ ) {
    if ( i == 0 ) {
      if ( d_unmark_relay_as_guard( tmp_relay_node->relay->identity ) < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to unmark guard" );
#endif
      }
    }

    if ( i < circuit->relay_list.built_length ) {
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_forward );
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_backward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_forward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_backward );
      free( tmp_relay_node->relay_crypto );
    }

    free( tmp_relay_node->relay );

    if ( i == circuit->relay_list.length - 1 ) {
      free( tmp_relay_node );
    } else {
      tmp_relay_node = tmp_relay_node->next;
      free( tmp_relay_node->previous );
    }
  }

  circuit->relay_list.length = 0;
  circuit->relay_list.built_length = 0;
  circuit->relay_list.head = NULL;
  circuit->relay_list.tail = NULL;

  if ( circuit->status == CIRCUIT_INTRO_POINT ) {
    wc_ed25519_free( &circuit->intro_crypto->auth_key );
    wc_curve25519_free( &circuit->intro_crypto->encrypt_key );
    free( circuit->intro_crypto );
  } else if ( circuit->status == CIRCUIT_RENDEZVOUS ) {
    wc_Sha3_256_Free( &circuit->hs_crypto->hs_running_sha_forward );
    wc_Sha3_256_Free( &circuit->hs_crypto->hs_running_sha_backward );
    free( circuit->hs_crypto );
  }

  // free the ssl object
  wolfSSL_shutdown( circuit->ssl );
  shutdown( wolfSSL_get_fd( circuit->ssl ), 0 );
  close( wolfSSL_get_fd( circuit->ssl ) );
  wolfSSL_free( circuit->ssl );

  // TODO may need to make a mutex for the handle, not sure if it could be set
  // to NULL by another thread after this NULL check, causing the current task to
  // rip in sauce
  if ( circuit->task_handle != NULL ) {
    vTaskDelete( circuit->task_handle );
  }

  return 0;
}

int d_truncate_onion_circuit( OnionCircuit* circuit, int new_length ) {
  int i;
  Cell unpacked_cell = {
    .circ_id = circuit->circ_id,
    .command = RELAY,
    .payload = malloc( sizeof( PayloadRelay ) ),
  };
  unsigned char* packed_cell;
  DoublyLinkedOnionRelay* tmp_relay_node;

  if ( circuit->relay_list.length == new_length ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Circuit is already at length" );
#endif

    free_cell( &unpacked_cell );

    return -1;
  }

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_TRUNCATE;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 0;

  packed_cell = pack_and_free( &unpacked_cell );

  tmp_relay_node = circuit->relay_list.tail;

  for ( i = circuit->relay_list.length - 1; i >= new_length; i-- ) {
    if ( i < circuit->relay_list.built_length ) {
      ESP_LOGE( MINITOR_TAG, "freeing crypto" );
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_forward );
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_backward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_forward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_backward );
      free( tmp_relay_node->relay_crypto );
    }

    ESP_LOGE( MINITOR_TAG, "freeing node" );
    free( tmp_relay_node->relay );

    tmp_relay_node = tmp_relay_node->previous;
    free( tmp_relay_node->next );
    tmp_relay_node->next = NULL;
  }

  circuit->relay_list.tail = tmp_relay_node;
  circuit->relay_list.length = new_length;
  circuit->relay_list.built_length = new_length;

  // send a destroy cell to the first hop
  if ( d_send_packed_relay_cell_and_free( circuit->ssl, packed_cell, &circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_TRUNCATE cell" );
#endif

    return -1;
  }

  if ( d_recv_cell( circuit->ssl, &unpacked_cell, CIRCID_LEN, &circuit->relay_list, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_TRUNCATED cell" );
#endif

    return -1;
  }

  if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_TRUNCATED ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Didn't get a relay RELAY_TRUNCATED cell back" );
#endif

    free_cell( &unpacked_cell );

    return -1;
  }

  free_cell( &unpacked_cell );

  return 0;
}

void v_handle_circuit( void* pv_parameters ) {
  int succ;
  OnionCircuit* onion_circuit = (OnionCircuit*)pv_parameters;
  Cell* unpacked_cell;
  OnionMessage* onion_message;

  while ( 1 ) {
    unpacked_cell = malloc( sizeof( Cell ) );

    if ( onion_circuit->status == CIRCUIT_RENDEZVOUS ) {
      succ = d_recv_cell( onion_circuit->ssl, unpacked_cell, CIRCID_LEN, &onion_circuit->relay_list, NULL, onion_circuit );
    } else {
      succ = d_recv_cell( onion_circuit->ssl, unpacked_cell, CIRCID_LEN, &onion_circuit->relay_list, NULL, NULL );
    }

    if ( succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Circuit %.8x received error code: %d waiting for a cell", onion_circuit->circ_id, succ );
#endif

      free( unpacked_cell );
      continue;
    }

    // TODO should determine if we need to destroy the circuit on a NULL queue
    if ( unpacked_cell->command == PADDING || onion_circuit->rx_queue == NULL ) {
      free_cell( unpacked_cell );
      free( unpacked_cell );
    } else {
      onion_message = malloc( sizeof( OnionMessage ) );
      onion_message->type = ONION_CELL;
      onion_message->data = unpacked_cell;

      xQueueSendToBack( onion_circuit->rx_queue, (void*)(&onion_message), portMAX_DELAY );
    }
  }
}

int d_router_extend2( OnionCircuit* onion_circuit, int node_index ) {
  int ret = 0;
  int i;
  int wolf_succ;
  WC_RNG rng;
  DoublyLinkedOnionRelay* relay;
  DoublyLinkedOnionRelay* target_relay;
  Cell unpacked_cell;
  unsigned char* packed_cell;
  curve25519_key extend2_handshake_key;
  curve25519_key extended2_handshake_public_key;
  curve25519_key ntor_onion_key;

  wc_curve25519_init( &extend2_handshake_key );
  wc_curve25519_init( &extended2_handshake_public_key );
  wc_curve25519_init( &ntor_onion_key );
  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &extend2_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make extend2_handshake_key, error code %d", wolf_succ );
#endif

    ret = -1;
    goto finish;
  }

  relay = onion_circuit->relay_list.head;

  for ( i = 0; i < node_index; i++ ) {
    relay = relay->next;
  }

  target_relay = relay;

  // construct link specifiers
  unpacked_cell.circ_id = onion_circuit->circ_id;
  unpacked_cell.command = RELAY_EARLY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_EXTEND2;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 35 + ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadExtend2 ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->specifier_count = 2;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers = malloc( sizeof( LinkSpecifier* ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->specifier_count );

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0] = malloc( sizeof( LinkSpecifier ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->type = IPv4Link;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->length = 6;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->length );

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[3] = (unsigned char)( target_relay->relay->address >> 24 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[2] = (unsigned char)( target_relay->relay->address >> 16 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[1] = (unsigned char)( target_relay->relay->address >> 8 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[0] = (unsigned char)target_relay->relay->address;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[4] = (unsigned char)target_relay->relay->or_port >> 8;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[5] = (unsigned char)target_relay->relay->or_port;

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1] = malloc( sizeof( LinkSpecifier ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->type = LEGACYLink;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->length = ID_LENGTH;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->specifier = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->length );

  memcpy( ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->specifier, target_relay->relay->identity, ID_LENGTH );

  // construct our side of the handshake
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_type = NTOR;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_length );

  if ( d_ntor_handshake_start( ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data, target_relay->relay, &extend2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    free_cell( &unpacked_cell );

    ret = -1;
    goto finish;
  }

  packed_cell = pack_and_free( &unpacked_cell );

  // send the EXTEND2 cell
  if ( d_send_packed_relay_cell_and_free( onion_circuit->ssl, packed_cell, &onion_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_EXTEND2 cell" );
#endif
  }

  // recv EXTENDED2 cell and perform the second half of the handshake
  if ( d_recv_cell( onion_circuit->ssl, &unpacked_cell, CIRCID_LEN, &onion_circuit->relay_list, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_EXTENDED2 cell" );
#endif

    ret = -1;
    goto finish;
  }

  if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_EXTENDED2 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Got something other than RELAY_EXTENDED2: %d", unpacked_cell.command );
#endif

#ifdef DEBUG_MINITOR
    if ( unpacked_cell.command == DESTROY ) {
      ESP_LOGE( MINITOR_TAG, "DESTROY: %d", ( (PayloadDestroy*)unpacked_cell.payload )->destroy_code );
    } else if ( ( (PayloadRelay*)unpacked_cell.payload )->command == RELAY_TRUNCATED ) {
      ESP_LOGE( MINITOR_TAG, "RELAY_TRUNCATED: %d", ( (PayloadDestroy*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->destroy_code );
    }
#endif

    free_cell( &unpacked_cell );

    ret = -1;
    goto finish;
  }

  if ( d_ntor_handshake_finish( ( (PayloadCreated2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data, target_relay, &extend2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    ret = -1;
  }

  free_cell( &unpacked_cell );

finish:
  wc_curve25519_free( &extend2_handshake_key );
  wc_curve25519_free( &extended2_handshake_public_key );
  wc_curve25519_free( &ntor_onion_key );

  return ret;
}

int d_router_create2( OnionCircuit* onion_circuit ) {
  int wolf_succ;
  WC_RNG rng;
  Cell unpacked_cell;
  unsigned char* packed_cell;
  curve25519_key create2_handshake_key;

  wc_curve25519_init( &create2_handshake_key );
  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &create2_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make create2_handshake_key, error code %d", wolf_succ );
#endif

    goto cleanup;
  }

  // make a create2 cell
  unpacked_cell.circ_id = onion_circuit->circ_id;
  unpacked_cell.command = CREATE2;
  unpacked_cell.payload = malloc( sizeof( PayloadCreate2 ) );

  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_type = NTOR;
  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_data = malloc( sizeof( unsigned char ) * ( (PayloadCreate2*)unpacked_cell.payload )->handshake_length );

  if ( d_ntor_handshake_start( ( (PayloadCreate2*)unpacked_cell.payload )->handshake_data, onion_circuit->relay_list.head->relay, &create2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export create2_handshake_key into unpacked_cell" );
#endif

    free_cell( &unpacked_cell );

    goto cleanup;
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( wolfSSL_send( onion_circuit->ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send CREATE2 cell" );
#endif

    free( packed_cell );

    goto cleanup;
  }

  free( packed_cell );

  if ( d_recv_cell( onion_circuit->ssl, &unpacked_cell, CIRCID_LEN, NULL, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv CREATED2 cell" );
#endif

    goto cleanup;
  }

  if ( d_ntor_handshake_finish( ( (PayloadCreated2*)unpacked_cell.payload )->handshake_data, onion_circuit->relay_list.head, &create2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to finish CREATED2 handshake" );
#endif

    free_cell( &unpacked_cell );

    goto cleanup;
  }

  wc_curve25519_free( &create2_handshake_key );
  free_cell( &unpacked_cell );

  return 0;

cleanup:
  wc_curve25519_free( &create2_handshake_key );
  return -1;
}

int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key ) {
  int wolf_succ;
  unsigned int idx;

  memcpy( handshake_data, relay->identity, ID_LENGTH );
  memcpy( handshake_data + ID_LENGTH, relay->ntor_onion_key, H_LENGTH );

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, handshake_data + ID_LENGTH + H_LENGTH, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export curve25519_key into handshake_data, error code: %d", wolf_succ );
#endif

    return -1;
  }

  return 0;
}

int d_ntor_handshake_finish( unsigned char* handshake_data, DoublyLinkedOnionRelay* db_relay, curve25519_key* key ) {
  int ret = 0;
  int wolf_succ;
  unsigned int idx;
  curve25519_key responder_handshake_public_key;
  curve25519_key ntor_onion_key;
  unsigned char* secret_input = malloc( sizeof( unsigned char ) * SECRET_INPUT_LENGTH );
  unsigned char* working_secret_input = secret_input;
  unsigned char* auth_input = malloc( sizeof( unsigned char ) * AUTH_INPUT_LENGTH );
  unsigned char* working_auth_input = auth_input;
  Hmac reusable_hmac;
  unsigned char reusable_hmac_digest[WC_SHA256_DIGEST_SIZE];
  unsigned char reusable_aes_key[KEY_LEN];
  unsigned char aes_iv[16] = { 0 };
  unsigned char key_seed[WC_SHA256_DIGEST_SIZE];
  unsigned char expand_i;
  int bytes_written;
  int bytes_remaining;

  wc_curve25519_init( &responder_handshake_public_key );
  wc_curve25519_init( &ntor_onion_key );

  db_relay->relay_crypto = malloc( sizeof( RelayCrypto ) );

  wc_InitSha( &db_relay->relay_crypto->running_sha_forward );
  wc_InitSha( &db_relay->relay_crypto->running_sha_backward );
  wc_AesInit( &db_relay->relay_crypto->aes_forward, NULL, INVALID_DEVID );
  wc_AesInit( &db_relay->relay_crypto->aes_backward, NULL, INVALID_DEVID );

  wolf_succ = wc_curve25519_import_public_ex( handshake_data, G_LENGTH, &responder_handshake_public_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import responder public key, error code %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  wolf_succ = wc_curve25519_import_public_ex( db_relay->relay->ntor_onion_key, H_LENGTH, &ntor_onion_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import ntor onion public key, error code %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  // create secret_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &responder_handshake_public_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(Y,x), error code %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  working_secret_input += 32;

  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &ntor_onion_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(B,x), error code %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  working_secret_input += 32;

  memcpy( working_secret_input, db_relay->relay->identity, ID_LENGTH );
  working_secret_input += ID_LENGTH;

  memcpy( working_secret_input, db_relay->relay->ntor_onion_key, H_LENGTH );
  working_secret_input += H_LENGTH;

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_secret_input, error code: %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  working_secret_input += 32;

  memcpy( working_secret_input, handshake_data, G_LENGTH );
  working_secret_input += G_LENGTH;

  memcpy( working_secret_input, PROTOID, PROTOID_LENGTH );

  // create auth_input
  wc_HmacSetKey( &reusable_hmac, WC_SHA256, (unsigned char*)PROTOID_VERIFY, PROTOID_VERIFY_LENGTH );
  wc_HmacUpdate( &reusable_hmac, secret_input, SECRET_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, working_auth_input );
  wc_HmacFree( &reusable_hmac );
  working_auth_input += WC_SHA256_DIGEST_SIZE;

  memcpy( working_auth_input, db_relay->relay->identity, ID_LENGTH );
  working_auth_input += ID_LENGTH;

  memcpy( working_auth_input, db_relay->relay->ntor_onion_key, H_LENGTH );
  working_auth_input += H_LENGTH;

  memcpy( working_auth_input, handshake_data, G_LENGTH );
  working_auth_input += G_LENGTH;

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, working_auth_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_auth_input, error code: %d", wolf_succ );
#endif

    ret = -1;
    goto fail;
  }

  working_auth_input += 32;

  memcpy( working_auth_input, PROTOID, PROTOID_LENGTH );
  working_auth_input += PROTOID_LENGTH;

  memcpy( working_auth_input, SERVER_STR, SERVER_STR_LENGTH );

  wc_HmacSetKey( &reusable_hmac, WC_SHA256, (unsigned char*)PROTOID_MAC, PROTOID_MAC_LENGTH );
  wc_HmacUpdate( &reusable_hmac, auth_input, AUTH_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );
  wc_HmacFree( &reusable_hmac );

  if ( memcmp( reusable_hmac_digest, handshake_data + G_LENGTH, WC_SHA256_DIGEST_SIZE ) != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to match AUTH with our own digest" );
#endif

    ret = -1;
    goto fail;
  }

  // create the key seed
  wc_HmacSetKey( &reusable_hmac, WC_SHA256, (unsigned char*)PROTOID_KEY, PROTOID_KEY_LENGTH );
  wc_HmacUpdate( &reusable_hmac, secret_input, SECRET_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, key_seed );
  wc_HmacFree( &reusable_hmac );

  // generate the first 32 bytes
  wc_HmacSetKey( &reusable_hmac, WC_SHA256, key_seed, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 1;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );
  wc_HmacFree( &reusable_hmac );

  // seed the forward sha
  wc_ShaUpdate( &db_relay->relay_crypto->running_sha_forward, reusable_hmac_digest, HASH_LEN );
  // seed the first 16 bytes of backwards sha
  wc_ShaUpdate( &db_relay->relay_crypto->running_sha_backward, reusable_hmac_digest + HASH_LEN, WC_SHA256_DIGEST_SIZE - HASH_LEN );
  // mark how many bytes we've written to the backwards sha and how many remain
  bytes_written = WC_SHA256_DIGEST_SIZE - HASH_LEN;
  bytes_remaining = HASH_LEN - bytes_written;

  // generate the second 32 bytes
  wc_HmacUpdate( &reusable_hmac, reusable_hmac_digest, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 2;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );
  wc_HmacFree( &reusable_hmac );

  // seed the last 8 bytes of backward sha
  wc_ShaUpdate( &db_relay->relay_crypto->running_sha_backward, reusable_hmac_digest, bytes_remaining );
  // set the forward aes key
  memcpy( reusable_aes_key, reusable_hmac_digest + bytes_remaining, KEY_LEN );
  wc_AesSetKeyDirect( &db_relay->relay_crypto->aes_forward, reusable_aes_key, KEY_LEN, aes_iv, AES_ENCRYPTION );
  // copy the first part of the backward key into the buffer
  memcpy( reusable_aes_key, reusable_hmac_digest + bytes_remaining + KEY_LEN, WC_SHA256_DIGEST_SIZE - bytes_remaining - KEY_LEN );
  // mark how many bytes we've written to the backwards key and how many remain
  bytes_written = WC_SHA256_DIGEST_SIZE - bytes_remaining - KEY_LEN;
  bytes_remaining = KEY_LEN - bytes_written;

  // generate the third 32 bytes
  wc_HmacUpdate( &reusable_hmac, reusable_hmac_digest, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 3;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );
  wc_HmacFree( &reusable_hmac );

  // copy the last part of the key into the buffer and initialize the key
  memcpy( reusable_aes_key + bytes_written, reusable_hmac_digest, bytes_remaining );
  wc_AesSetKeyDirect( &db_relay->relay_crypto->aes_backward, reusable_aes_key, KEY_LEN, aes_iv, AES_ENCRYPTION );

  // copy the nonce
  memcpy( db_relay->relay_crypto->nonce, reusable_hmac_digest + bytes_remaining, DIGEST_LEN );

finish:
  // free all the heap resources
  wc_curve25519_free( &responder_handshake_public_key );
  wc_curve25519_free( &ntor_onion_key );

  free( secret_input );
  free( auth_input );

  return ret;

fail:
  wc_ShaFree( &db_relay->relay_crypto->running_sha_forward );
  wc_ShaFree( &db_relay->relay_crypto->running_sha_backward );
  wc_AesFree( &db_relay->relay_crypto->aes_forward );
  wc_AesFree( &db_relay->relay_crypto->aes_backward );
  free( db_relay->relay_crypto );
  goto finish;
}

int d_router_handshake( WOLFSSL* ssl ) {
  int i;
  int wolf_succ;
  WOLFSSL_X509* peer_cert;
  Sha256 reusable_sha;
  unsigned char reusable_sha_sum[WC_SHA256_DIGEST_SIZE];
  Hmac tls_secrets_hmac;
  unsigned char tls_secrets_digest[WC_SHA256_DIGEST_SIZE];
  Cell unpacked_cell;
  unsigned char* packed_cell;
  Sha256 initiator_sha;
  unsigned char initiator_sha_sum[WC_SHA256_DIGEST_SIZE];
  Sha256 responder_sha;
  unsigned char responder_sha_sum[WC_SHA256_DIGEST_SIZE];
  unsigned char* responder_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );
  int responder_rsa_identity_key_der_size;
  unsigned char* initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_identity_key_der_size;
  unsigned char* initiator_rsa_identity_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_identity_cert_der_size;
  RsaKey initiator_rsa_auth_key;
  unsigned char* initiator_rsa_auth_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_auth_cert_der_size;
  WC_RNG rng;
  unsigned char my_address_length;
  unsigned char* my_address;
  unsigned char other_address_length;
  unsigned char* other_address;

  wc_InitSha256( &reusable_sha );
  wc_InitSha256( &initiator_sha );
  wc_InitSha256( &responder_sha );

  wc_InitRng( &rng );

  // get the peer cert
  peer_cert = wolfSSL_get_peer_certificate( ssl );

  if ( peer_cert == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed get peer cert" );
#endif

    return -1;
  }

  // set the hmac key to the master secret that was negotiated
  wc_HmacSetKey( &tls_secrets_hmac, WC_SHA256, ssl->arrays->masterSecret, SECRET_LEN );
  // update the hmac
  wc_HmacUpdate( &tls_secrets_hmac, ssl->arrays->clientRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, ssl->arrays->serverRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, (unsigned char*)"Tor V3 handshake TLS cross-certification", strlen( "Tor V3 handshake TLS cross-certification" ) + 1 );
  // finalize the hmac
  wc_HmacFinal( &tls_secrets_hmac, tls_secrets_digest );
  wc_HmacFree( &tls_secrets_hmac );
  // free the temporary arrays
  wolfSSL_FreeArrays( ssl );

  // make a versions cell
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = VERSIONS;
  unpacked_cell.length = 4;
  unpacked_cell.payload = malloc( sizeof( PayloadVersions ) );

  ( (PayloadVersions*)unpacked_cell.payload )->versions = malloc( sizeof( unsigned short ) * 2 );
  ( (PayloadVersions*)unpacked_cell.payload )->versions[0] = 3;
  ( (PayloadVersions*)unpacked_cell.payload )->versions[1] = 4;

  packed_cell = pack_and_free( &unpacked_cell );

  wc_Sha256Update( &initiator_sha, packed_cell, LEGACY_CIRCID_LEN + 3 + unpacked_cell.length );

  // send the versions cell
  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, LEGACY_CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send versions cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  // reset the packed cell
  free( packed_cell );

  // recv and unpack the versions cell
  if ( d_recv_cell( ssl, &unpacked_cell, LEGACY_CIRCID_LEN, NULL, &responder_sha, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv versions cell" );
#endif

    return -1;
  }

  // free the unpacked cell
  free_cell( &unpacked_cell );

  // recv and unpack the certs cell
  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, &responder_sha, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv certs cell" );
#endif

    return -1;
  }

  // verify certs
  if ( d_verify_certs( &unpacked_cell, peer_cert, &responder_rsa_identity_key_der_size, responder_rsa_identity_key_der ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to verify certs" );
#endif

    return -1;
  }

  free_cell( &unpacked_cell );

  // recv and unpack the auth challenge cell
  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, &responder_sha, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv auth challenge cell" );
#endif

    return -1;
  }

  // free the unpacked cell
  free_cell( &unpacked_cell );

  // generate certs for certs cell
  if ( d_generate_certs( &initiator_rsa_identity_key_der_size, initiator_rsa_identity_key_der, initiator_rsa_identity_cert_der, &initiator_rsa_identity_cert_der_size, initiator_rsa_auth_cert_der, &initiator_rsa_auth_cert_der_size, &initiator_rsa_auth_key, &rng ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate rsa certificates" );
#endif

    return -1;
  }

  // generate a certs cell of our own
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = CERTS;
  unpacked_cell.length = 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size;
  unpacked_cell.payload = malloc( sizeof( PayloadCerts ) );

  ( (PayloadCerts*)unpacked_cell.payload )->cert_count = 2;
  ( (PayloadCerts*)unpacked_cell.payload )->certs = malloc( sizeof( MinitorCert* ) * 2 );

  for ( i = 0; i < ( (PayloadCerts*)unpacked_cell.payload )->cert_count; i++ ) {
    ( (PayloadCerts*)unpacked_cell.payload )->certs[i] = malloc( sizeof( MinitorCert ) );
  }

  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_type = IDENTITY_CERT;
  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_length = initiator_rsa_identity_cert_der_size;

  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert = malloc( sizeof( unsigned char ) * initiator_rsa_identity_cert_der_size );

  memcpy( ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert, initiator_rsa_identity_cert_der, ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_length );

  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_type = RSA_AUTH_CERT;
  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_length = initiator_rsa_auth_cert_der_size;

  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert = malloc( sizeof( unsigned char ) * initiator_rsa_auth_cert_der_size );

  memcpy( ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert, initiator_rsa_auth_cert_der, ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_length );

  free( initiator_rsa_identity_cert_der );
  free( initiator_rsa_auth_cert_der );

  packed_cell = pack_and_free( &unpacked_cell );
  wc_Sha256Update( &initiator_sha, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send certs cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  free( packed_cell );

  // generate answer for auth challenge
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = AUTHENTICATE;
  unpacked_cell.length = 4 + 352;
  unpacked_cell.payload = malloc( sizeof( PayloadAuthenticate ) );

  ( (PayloadAuthenticate*)unpacked_cell.payload )->auth_type = AUTH_ONE;
  ( (PayloadAuthenticate*)unpacked_cell.payload )->auth_length = 352;
  ( (PayloadAuthenticate*)unpacked_cell.payload )->authentication = malloc( sizeof( AuthenticationOne ) );

  // fill in type
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->type, "AUTH0001", 8 );
  // create the hash of the clients identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, initiator_rsa_identity_key_der, initiator_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_id, reusable_sha_sum, 32 );
  // create the hash of the server's identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, responder_rsa_identity_key_der, responder_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_id, reusable_sha_sum, 32 );
  // create the hash of all server cells so far and fill the authenticate cell with it
  wc_Sha256Final( &responder_sha, responder_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_log, responder_sha_sum, 32 );
  // create the hash of all cilent cells so far and fill the authenticate cell with it
  wc_Sha256Final( &initiator_sha, initiator_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_log, initiator_sha_sum, 32 );
  // create a sha hash of the tls cert and copy it in
  wc_Sha256Update( &reusable_sha, peer_cert->derCert->buffer, peer_cert->derCert->length );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_cert, reusable_sha_sum, 32 );
  // copy the tls secrets digest in
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->tls_secrets, tls_secrets_digest, 32 );
  // fill the rand array
  wc_RNG_GenerateBlock( &rng, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->rand, 24 );
  // create the signature
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->type, 8 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_id, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_id, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_log, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_log, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_cert, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->tls_secrets, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->rand, 24 );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );

  wolf_succ = wc_RsaSSL_Sign( reusable_sha_sum, 32, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->signature, 128, &initiator_rsa_auth_key, &rng );

  free( responder_rsa_identity_key_der );
  free( initiator_rsa_identity_key_der );
  wc_FreeRsaKey( &initiator_rsa_auth_key );
  wc_Sha256Free( &reusable_sha );
  wc_Sha256Free( &initiator_sha );
  wc_Sha256Free( &responder_sha );
  wc_FreeRng( &rng );

  if (wolf_succ  < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign authenticate cell, error code: %d", wolf_succ );
#endif
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send authenticate cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  free( packed_cell );

  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv netinfo cell" );
#endif

    return -1;
  }

  my_address_length = ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->length;
  my_address = malloc( sizeof( unsigned char ) * my_address_length );
  memcpy( my_address, ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address, my_address_length );

  other_address_length = ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->length;
  other_address = malloc( sizeof( unsigned char ) * other_address_length );
  memcpy( other_address, ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address, other_address_length );

  free_cell( &unpacked_cell );

  unpacked_cell.circ_id = 0;
  unpacked_cell.command = NETINFO;
  unpacked_cell.payload = malloc( sizeof( PayloadNetInfo ) );

  time( &( (PayloadNetInfo*)unpacked_cell.payload )->time );
  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address = malloc( sizeof( Address ) );

  if ( other_address_length == 4 ) {
    ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address_type = IPv4;
  } else {
    ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address_type = IPv6;
  }

  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->length = other_address_length;
  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address = other_address;

  ( (PayloadNetInfo*)unpacked_cell.payload )->address_count = 1;
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses = malloc( sizeof( Address* ) );
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0] = malloc( sizeof( Address ) );

  if ( my_address_length == 4 ) {
    ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address_type = IPv4;
  } else {
    ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address_type = IPv6;
  }

  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->length = my_address_length;
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address = my_address;

  // this will also free my_address and other_address
  packed_cell = pack_and_free( &unpacked_cell );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CELL_LEN, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send NETINFO cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  free( packed_cell );

  return 0;
}

int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der ) {
  int i;
  time_t now;
  WOLFSSL_X509* certificate = NULL;
  WOLFSSL_X509* link_key_certificate = NULL;
  unsigned int cert_date;
  int link_key_count = 0;
  int identity_count = 0;
  unsigned int idx;
  int wolf_succ;
  RsaKey responder_rsa_identity_key;
  unsigned char* temp_array;

  wc_InitRsaKey( &responder_rsa_identity_key, NULL );

  // verify the certs
  time( &now );

  for ( i = 0; i < ( (PayloadCerts*)certs_cell->payload )->cert_count; i++ ) {
    if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type > IDENTITY_CERT ) {
      break;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert,
      ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_length,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid certificate" );
#endif

      return -1;
    }

    cert_date = ud_get_cert_date( certificate->notBefore.data, certificate->notBefore.length );

    if ( cert_date == 0 || cert_date > now ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not before time" );
#endif

      return -1;
    }

    cert_date = ud_get_cert_date( certificate->notAfter.data, certificate->notAfter.length );

    if ( cert_date == 0 || cert_date < now ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not after time" );
#endif

      return -1;
    }

    if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type == LINK_KEY ) {
      link_key_certificate = certificate;
      link_key_count++;

      if ( link_key_count > 1 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many LINK_KEYs" );
#endif

        return -1;
      }

      if ( memcmp( certificate->pubKey.buffer, peer_cert->pubKey.buffer, certificate->pubKey.length ) != 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to match LINK_KEY with tls key" );
#endif

        return -1;
      }
    } else if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type == IDENTITY_CERT ) {
      identity_count++;

      if ( identity_count > 1 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many IDENTITY_CERTs" );
#endif

        return -1;
      }

      idx = 0;
      wolf_succ = wc_RsaPublicKeyDecode( certificate->pubKey.buffer, &idx, &responder_rsa_identity_key, certificate->pubKey.length );
      if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to parse IDENTITY_CERT, error code: %d", wolf_succ );
#endif

        return -1;
      }

      memcpy( responder_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
      *responder_rsa_identity_key_der_size = certificate->pubKey.length;

      temp_array = malloc( sizeof( unsigned char ) * 128 );

      // verify the signatures on the keys
      wolf_succ = wc_RsaSSL_Verify(
        link_key_certificate->sig.buffer,
        link_key_certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify LINK_KEY signature, error code: %d", wolf_succ );
#endif

          return -1;
      }

      wolf_succ = wc_RsaSSL_Verify(
        certificate->sig.buffer,
        certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      free( temp_array );

      if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify IDENTITY_CERT signature, error code: %d", wolf_succ );
#endif

          return -1;
      }
    }

  }

  if ( link_key_count == 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No LINK_KEYs" );
#endif

    return -1;
  }

  if ( identity_count == 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No IDENTITY_CERTs" );
#endif

    return -1;
  }

  wc_FreeRsaKey( &responder_rsa_identity_key );
  wolfSSL_X509_free( certificate );
  wolfSSL_X509_free( link_key_certificate );

  return 0;
}

int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng ) {
  struct stat st;
  int fd;
  int wolf_succ;
  unsigned int idx;
  RsaKey initiator_rsa_identity_key;
  unsigned char* tmp_initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 1024 );
  Cert initiator_rsa_identity_cert;
  Cert initiator_rsa_auth_cert;
  WOLFSSL_X509* certificate = NULL;

  // init the rsa keys
  wc_InitRsaKey( &initiator_rsa_identity_key, NULL );
  wc_InitRsaKey( initiator_rsa_auth_key, NULL );

  // rsa identity key doesn't exist, create it and save it
  if ( stat( "/sdcard/identity_rsa_key", &st ) == -1 ) {
    // make and save the identity key to the file system
    wolf_succ = wc_MakeRsaKey( &initiator_rsa_identity_key, 1024, 65537, rng );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key, error code: %d", wolf_succ );
#endif

      return -1;
    }

    wolf_succ = wc_RsaKeyToDer( &initiator_rsa_identity_key, tmp_initiator_rsa_identity_key_der, 1024 );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key der, error code: %d", wolf_succ );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_key", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }
  // rsa identity key exists, load it from the file system
  } else {
    if ( ( fd = open( "/sdcard/identity_rsa_key", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( read( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    idx = 0;
    wolf_succ = wc_RsaPrivateKeyDecode( tmp_initiator_rsa_identity_key_der, &idx, &initiator_rsa_identity_key, 1024 );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to load rsa identity private key der, error code: %d", wolf_succ );
#endif

      return -1;
    }
  }

  free( tmp_initiator_rsa_identity_key_der );

  // make and export the auth key
  wolf_succ = wc_MakeRsaKey( initiator_rsa_auth_key, 1024, 65537, rng );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wc_InitCert( &initiator_rsa_identity_cert );

  // rsa identity cert doesn't exist, create it and save it
  if ( stat( "/sdcard/identity_rsa_cert_der", &st ) == -1 ) {
    // TODO randomize these
    strncpy( initiator_rsa_identity_cert.subject.country, "US", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.state, "OR", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.locality, "Portland", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.org, "yaSSL", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.unit, "Development", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE );

    *initiator_rsa_identity_cert_der_size = wc_MakeSelfCert( &initiator_rsa_identity_cert, initiator_rsa_identity_cert_der, 2048, &initiator_rsa_identity_key, rng );

    if ( *initiator_rsa_identity_cert_der_size <= 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity cert der, error code: %d", *initiator_rsa_identity_cert_der_size );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_cert_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_cert_der_size ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      initiator_rsa_identity_cert_der,
      *initiator_rsa_identity_cert_der_size,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid identity certificate" );
#endif

      return -1;
    }

    memcpy( initiator_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
    *initiator_rsa_identity_key_der_size = certificate->pubKey.length;

    wolfSSL_X509_free( certificate );

    if ( ( fd = open( "/sdcard/identity_rsa_key_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_key_der_size ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }
  // rsa identity cert exists, load it from the file system
  } else {
    if ( ( fd = open( "/sdcard/identity_rsa_cert_der", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( *initiator_rsa_identity_cert_der_size = read( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * 2048 ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_key_der", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( *initiator_rsa_identity_key_der_size = read( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * 2048 ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }
  }

  // TODO figure out if we can just use one of these and save it to the file system
  wc_InitCert( &initiator_rsa_auth_cert );

  // TODO randomize these
  strncpy( initiator_rsa_auth_cert.subject.country, "US", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.state, "OR", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.locality, "Portland", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.org, "yaSSL", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.unit, "Development", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE );

  wc_SetIssuerBuffer( &initiator_rsa_auth_cert, initiator_rsa_identity_cert_der, *initiator_rsa_identity_cert_der_size );

  *initiator_rsa_auth_cert_der_size = wc_MakeCert( &initiator_rsa_auth_cert, initiator_rsa_auth_cert_der, 2048, initiator_rsa_auth_key, NULL, rng );

  if ( *initiator_rsa_auth_cert_der_size <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth cert der, error code: %d", *initiator_rsa_auth_cert_der_size );
#endif

    return -1;
  }

  wolf_succ = wc_SignCert( *initiator_rsa_auth_cert_der_size, initiator_rsa_auth_cert.sigType, initiator_rsa_auth_cert_der, 2048, &initiator_rsa_identity_key, NULL, rng );

  if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign rsa auth cert der, error code: %d", wolf_succ );
#endif

    return -1;
  }

  *initiator_rsa_auth_cert_der_size = wolf_succ;

  wc_FreeRsaKey( &initiator_rsa_identity_key );

  return 0;
}

// fetch the descriptor info for the list of relays
int d_fetch_descriptor_info( OnionCircuit* circuit ) {
  const char* REQUEST_CONST = "GET /tor/server/d/**************************************** HTTP/1.0\r\n"
#ifdef MINITOR_CHUTNEY
      "Host: "MINITOR_CHUTNEY_ADDRESS_STR"\r\n"
#else
      "Host: "MINITOR_DIR_ADDR_STR"\r\n"
#endif
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[127];

  const char* ntor_onion_key = "\nntor-onion-key ";
  int ntor_onion_key_found = 0;
  char ntor_onion_key_64[43] = { 0 };
  int ntor_onion_key_64_length = 0;

  int i;
  int retries;
  int rx_length;
  int sock_fd;
  int err;
  char end_header = 0;
  // buffer thath holds data returned from the socket
  char rx_buffer[512];
  struct sockaddr_in dest_addr;

  // copy the string into editable memory
  strcpy( REQUEST, REQUEST_CONST );

  // set the address of the directory server
#ifdef MINITOR_CHUTNEY
  dest_addr.sin_addr.s_addr = MINITOR_CHUTNEY_ADDRESS;
  dest_addr.sin_port = htons( MINITOR_CHUTNEY_PORT );
#else
  dest_addr.sin_addr.s_addr = MINITOR_DIR_ADDR;
  dest_addr.sin_port = htons( MINITOR_DIR_PORT );
#endif

  dest_addr.sin_family = AF_INET;

  DoublyLinkedOnionRelay* node = circuit->relay_list.head;

  while ( node != NULL ) {
    retries = 0;
    end_header = 0;
    ntor_onion_key_found = 0;
    ntor_onion_key_64_length = 0;

    while ( retries < 3 ) {
      // create a socket to access the descriptor
      sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

      if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server" );
#endif

        return -1;
      }

      // connect the socket to the dir server address
      err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

      if ( err != 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

        shutdown( sock_fd, 0 );
        close( sock_fd );

        if ( retries >= 2 ) {
          return -1;
        } else {
          retries++;
        }
      } else {
        retries = 3;
      }
    }

#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "connected to http socket" );
#endif

    for ( i = 0; i < 20; i++ ) {
      if ( node->relay->digest[i] >> 4 < 10 ) {
        REQUEST[18 + 2 * i] = 48 + ( node->relay->digest[i] >> 4 );
      } else {
        REQUEST[18 + 2 * i] = 65 + ( ( node->relay->digest[i] >> 4 ) - 10 );
      }

      if ( ( node->relay->digest[i] & 0x0f ) < 10  ) {
        REQUEST[18 + 2 * i + 1] = 48 + ( node->relay->digest[i] & 0x0f );
      } else {
        REQUEST[18 + 2 * i + 1] = 65 + ( ( node->relay->digest[i] & 0x0f ) - 10 );
      }
    }

    // send the http request to the dir server
    err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

    if ( err < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

      return -1;
    }

#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "sent to http socket" );
#endif

    // keep reading forever, we will break inside when the transfer is over
    while ( 1 ) {
      // recv data from the destination and fill the rx_buffer with the data
      rx_length = recv( sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

      // if we got less than 0 we encoutered an error
      if ( rx_length < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

        return -1;
      // we got 0 bytes back then the connection closed and we're done getting
      // consensus data
      } else if ( rx_length == 0 ) {
        break;
      }

#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "recved from http socket" );
#endif

      // iterate over each byte we got back from the socket recv
      // NOTE that we can't rely on all the data being there, we
      // have to treat each byte as though we only have that byte
      for ( i = 0; i < rx_length; i++ ) {
        // skip over the http header, when we get two \r\n s in a row we
        // know we're at the end
        if ( end_header < 4 ) {
          // increment end_header whenever we get part of a carrage retrun
          if ( rx_buffer[i] == '\r' || rx_buffer[i] == '\n' ) {
            end_header++;
          // otherwise reset the count
          } else {
            end_header = 0;
          }
        // if we have 4 end_header we're onto the actual data
        } else {
          if ( ntor_onion_key_found != -1 ) {
            if ( ntor_onion_key_found == strlen( ntor_onion_key ) ) {
              ntor_onion_key_64[ntor_onion_key_64_length] = rx_buffer[i];
              ntor_onion_key_64_length++;

              if ( ntor_onion_key_64_length == 43 ) {
                v_base_64_decode( node->relay->ntor_onion_key, ntor_onion_key_64, 43 );
                ntor_onion_key_found = -1;
              }
            } else if ( rx_buffer[i] == ntor_onion_key[ntor_onion_key_found] ) {
              ntor_onion_key_found++;
            } else {
              ntor_onion_key_found = 0;
            }
          }
        }
      }
    }

    node = node->next;
    shutdown( sock_fd, 0 );
    close( sock_fd );
  }

  return 0;
}
