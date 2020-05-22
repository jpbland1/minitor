#include "esp_log.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "../include/config.h"
#include "../h/onion_service.h"
#include "../h/constants.h"
#include "../h/encoding.h"
#include "../h/cell.h"
#include "../h/circuit.h"
#include "../h/models/relay.h"

void v_handle_onion_service( void* pv_parameters ) {
  OnionService* onion_service = (OnionService*)pv_parameters;
  OnionMessage* onion_message;

  while ( 1 ) {
    // TODO block on rx_queue
    xQueueReceive( onion_service->rx_queue, &onion_message, portMAX_DELAY );

    switch ( onion_message->type ) {
      case ONION_CELL:
        if ( d_onion_service_handle_cell( onion_service, (Cell*)onion_message->data ) < 0 ) {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to handle a cell on circuit: %.8x", ( (Cell*)onion_message->data )->circ_id );
#endif
        }

        free_cell( (Cell*)onion_message->data );

        break;
      case SERVICE_TCP_DATA:
        if ( d_onion_service_handle_local_tcp_data( onion_service, (ServiceTcpTraffic*)onion_message->data ) < 0 ) {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to handle local tcp traffic on circuit %.8x and stream %d", ( (ServiceTcpTraffic*)onion_message->data )->circ_id, ( (ServiceTcpTraffic*)onion_message->data )->stream_id );
#endif
        }

        if ( ( (ServiceTcpTraffic*)onion_message->data )->length > 0 ) {
          free( ( (ServiceTcpTraffic*)onion_message->data )->data );
        }

        break;
      case SERVICE_COMMAND:
        break;
    }

    free( onion_message->data );
    free( onion_message );
  }
}

int d_onion_service_handle_local_tcp_data( OnionService* onion_service, ServiceTcpTraffic* tcp_traffic ) {
  int i;
  Cell unpacked_cell;
  unsigned char* packed_cell;
  DoublyLinkedOnionCircuit* db_rend_circuit;

  db_rend_circuit = onion_service->rend_circuits.head;

  for ( i = 0; i < onion_service->rend_circuits.length; i++ ) {
    if ( db_rend_circuit->circuit.circ_id == tcp_traffic->circ_id ) {
      break;
    }

    db_rend_circuit = db_rend_circuit->next;
  }

  if ( db_rend_circuit == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't find the associated rend circuit" );
#endif

    return -1;
  }

  unpacked_cell.circ_id = tcp_traffic->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = tcp_traffic->stream_id;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;

  if ( tcp_traffic->length == 0 ) {
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_END;
    ( (PayloadRelay*)unpacked_cell.payload )->length = 1;
    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadEnd ) );

    ( (RelayPayloadEnd*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->reason = REASON_DONE;
  } else {
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_DATA;
    ( (PayloadRelay*)unpacked_cell.payload )->length = (unsigned short)tcp_traffic->length;
    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadData ) );

    ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload = malloc( sizeof( unsigned char ) * tcp_traffic->length );

    memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, tcp_traffic->data, tcp_traffic->length );
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( d_send_packed_relay_cell_and_free( db_rend_circuit->circuit.ssl, packed_cell, &db_rend_circuit->circuit.relay_list, db_rend_circuit->circuit.hs_crypto ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA" );
#endif

    return -1;
  }

  return 0;
}

int d_onion_service_handle_cell( OnionService* onion_service, Cell* unpacked_cell ) {
  switch( unpacked_cell->command ) {
    case RELAY:
      switch( ( (PayloadRelay*)unpacked_cell->payload )->command ) {
        // TODO when a relay_begin comes in, create a task to block on the local tcp stream
        case RELAY_BEGIN:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_BEGIN!" );

          if ( d_onion_service_handle_relay_begin( onion_service, unpacked_cell ) < 0 ) {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_BEGIN cell" );
#endif

            return -1;
          }

          break;
        // TODO when a relay_data comes in, send the data to the local tcp stream
        case RELAY_DATA:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_DATA!" );

          if ( d_onion_service_handle_relay_data( onion_service, unpacked_cell ) < 0 ) {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_DATA cell" );
#endif

            return -1;
          }
          break;
        case RELAY_END:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_END!" );
          break;
        case RELAY_DROP:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_DROP!" );
          break;
        // when an intro request comes in, respond to it
        case RELAY_COMMAND_INTRODUCE2:
          if ( d_onion_service_handle_introduce_2( onion_service, unpacked_cell ) < 0 ) {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_COMMAND_INTRODUCE2 cell" );
#endif

            return -1;
          }

          break;
        default:
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Unequiped to handle relay command %d", ( (PayloadRelay*)unpacked_cell->payload )->command );
#endif
          return -1;
      }

      break;
    // TODO when a destroy comes in close and clean the circuit and local tcp stream
    default:
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Unequiped to handle cell command %d", unpacked_cell->command );
#endif
      return -1;
  }

  return 0;
}

int d_onion_service_handle_relay_data( OnionService* onion_service, Cell* unpacked_cell ) {
  int i;
  int err;
  DoublyLinkedLocalStream* db_local_stream;

  db_local_stream = onion_service->local_streams.head;

  for ( i = 0; i < onion_service->local_streams.length; i++ ) {
    if ( db_local_stream->circ_id == unpacked_cell->circ_id && db_local_stream->stream_id == ( (PayloadRelay*)unpacked_cell->payload )->stream_id ) {
      break;
    }

    db_local_stream = db_local_stream->next;
  }

  if ( db_local_stream == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't find the associated local_stream" );
#endif

    return -1;
  }

  err = send( db_local_stream->sock_fd, ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->payload, ( (PayloadRelay*)unpacked_cell->payload )->length, 0 );

  if ( err < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to local stream" );
#endif

    return -1;
  }

  return 0;
}

int d_onion_service_handle_relay_begin( OnionService* onion_service, Cell* unpacked_cell ) {
  int i;
  int err;
  struct sockaddr_in dest_addr;
  DoublyLinkedLocalStream* db_local_stream;
  Cell unpacked_connected_cell;
  unsigned char* packed_cell;
  DoublyLinkedOnionCircuit* db_rend_circuit;

  db_rend_circuit = onion_service->rend_circuits.head;

  for ( i = 0; i < onion_service->rend_circuits.length; i++ ) {
    if ( db_rend_circuit->circuit.circ_id == unpacked_cell->circ_id ) {
      break;
    }

    db_rend_circuit = db_rend_circuit->next;
  }

  if ( db_rend_circuit == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't find the associated rend circuit" );
#endif

    return -1;
  }

  if ( ( (RelayPayloadBegin*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->port != onion_service->exit_port ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "request was for the wrong port" );
#endif

    return -1;
  }

  db_local_stream = malloc( sizeof( DoublyLinkedLocalStream ) );

  db_local_stream->circ_id = unpacked_cell->circ_id;
  db_local_stream->stream_id = ( (PayloadRelay*)unpacked_cell->payload )->stream_id;
  db_local_stream->rx_queue = onion_service->rx_queue;

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( onion_service->local_port );

  ESP_LOGE( MINITOR_TAG, "errno: %d", errno );

  db_local_stream->sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( db_local_stream->sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to the local port, err: %d, errno: %d", db_local_stream->sock_fd, errno );
#endif

    return -1;
  }

  err = connect( db_local_stream->sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( err != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to the local port" );
#endif

    return -1;
  }

  xTaskCreatePinnedToCore(
    v_handle_local,
    "HANDLE_LOCAL",
    4096,
    (void*)(db_local_stream),
    6,
    db_rend_circuit->circuit.task_handle,
    tskNO_AFFINITY
  );

  v_add_local_stream_to_list( db_local_stream, &onion_service->local_streams );

  unpacked_connected_cell.circ_id = unpacked_cell->circ_id;
  unpacked_connected_cell.command = RELAY;
  unpacked_connected_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_connected_cell.payload )->command = RELAY_CONNECTED;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->stream_id = ( (PayloadRelay*)unpacked_cell->payload )->stream_id;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->length = 8;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadConnected ) );

  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->address = malloc( sizeof( unsigned char ) * 4 );

  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->address[0] = 0x7f;
  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->address[1] = 0x00;
  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->address[2] = 0x00;
  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->address[3] = 0x01;
  ( (RelayPayloadConnected*)( (PayloadRelay*)unpacked_connected_cell.payload )->relay_payload )->time_to_live = 120;

  packed_cell = pack_and_free( &unpacked_connected_cell );

  if ( d_send_packed_relay_cell_and_free( db_rend_circuit->circuit.ssl, packed_cell, &db_rend_circuit->circuit.relay_list, db_rend_circuit->circuit.hs_crypto ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_CONNECTED" );
#endif

    return -1;
  }

  return 0;
}

void v_handle_local( void* pv_parameters ) {
  int rx_length;
  unsigned char rx_buffer[RELAY_PAYLOAD_LEN];
  DoublyLinkedLocalStream* db_local_stream = (DoublyLinkedLocalStream*)pv_parameters;
  OnionMessage* onion_message;

  while ( 1 ) {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( db_local_stream->sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't recv local socket" );
#endif

      vTaskDelete( NULL );
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    }

    onion_message = malloc( sizeof( OnionMessage ) );

    onion_message->type = SERVICE_TCP_DATA;
    onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );

    ( (ServiceTcpTraffic*)onion_message->data )->circ_id = db_local_stream->circ_id;
    ( (ServiceTcpTraffic*)onion_message->data )->stream_id = db_local_stream->stream_id;
    ( (ServiceTcpTraffic*)onion_message->data )->length = rx_length;

    if ( rx_length == 0 ) {
      xQueueSendToBack( db_local_stream->rx_queue, (void*)(&onion_message), portMAX_DELAY );
      vTaskDelete( NULL );
    } else {
      ( (ServiceTcpTraffic*)onion_message->data )->data = malloc( sizeof( unsigned char ) * rx_length );
      memcpy( ( (ServiceTcpTraffic*)onion_message->data )->data, rx_buffer, rx_length );
      xQueueSendToBack( db_local_stream->rx_queue, (void*)(&onion_message), portMAX_DELAY );
    }
  }
}

int d_onion_service_handle_introduce_2( OnionService* onion_service, Cell* unpacked_cell ) {
  int i;
  int wolf_succ;
  DoublyLinkedOnionCircuit* db_intro_circuit;
  WC_RNG rng;
  curve25519_key hs_handshake_key;
  curve25519_key client_handshake_key;
  DecryptedIntroduce2 unpacked_introduce_data;
  DoublyLinkedRendezvousCookie* db_rendezvous_cookie;
  DoublyLinkedOnionCircuit* db_rend_circuit;
  OnionRelay* rend_relay;
  unsigned char auth_input_mac[MAC_LEN];

  if ( onion_service->rendezvous_cookies.length > 0 ) {
    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "circ_id: %.8x", unpacked_cell->circ_id );

  db_intro_circuit = onion_service->intro_circuits.head;

  for ( i = 0; i < onion_service->intro_circuits.length; i++ ) {
    if ( db_intro_circuit->circuit.circ_id == unpacked_cell->circ_id ) {
      break;
    }

    db_intro_circuit = db_intro_circuit->next;
  }

  if ( db_intro_circuit == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to find the circuit for this RELAY_COMMAND_INTRODUCE2" );
#endif

    return -1;
  }

  if ( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_type != EDSHA3 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key type for RELAY_COMMAND_INTRODUCE2 was not EDSHA3" );
#endif

    return -1;
  }

  if ( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key length for RELAY_COMMAND_INTRODUCE2 was not 32" );
#endif

    return -1;
  }

  if ( memcmp( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, db_intro_circuit->circuit.intro_crypto->auth_key.p, 32 ) != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key for RELAY_COMMAND_INTRODUCE2 does not match" );
#endif

    return -1;
  }

  wc_curve25519_init( &client_handshake_key );

  wolf_succ = wc_curve25519_import_public_ex( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, PK_PUBKEY_LEN, &client_handshake_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import client public key, error code %d", wolf_succ );
#endif

    return -1;
  }

  // verify and decrypt
  if ( d_verify_and_decrypt_introduce_2( onion_service, unpacked_cell, &db_intro_circuit->circuit, &client_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to verify and decrypt RELAY_COMMAND_INTRODUCE2" );
#endif

    return -1;
  }

  // unpack the decrypted secction
  if ( d_unpack_introduce_2_data( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, &unpacked_introduce_data ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to unpack RELAY_COMMAND_INTRODUCE2 decrypted data" );
#endif

    return -1;
  }

  db_rendezvous_cookie = onion_service->rendezvous_cookies.head;

  ESP_LOGE( MINITOR_TAG, "cookie count %d", onion_service->rendezvous_cookies.length );

  for ( i = 0; i < onion_service->rendezvous_cookies.length; i++ ) {
    if ( memcmp( db_rendezvous_cookie->rendezvous_cookie, unpacked_introduce_data.rendezvous_cookie, 20 ) == 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Got a replay, silently dropping" );
#endif

      return 0;
    }

    db_rendezvous_cookie = db_rendezvous_cookie->next;
  }

  db_rendezvous_cookie = malloc( sizeof( DoublyLinkedRendezvousCookie ) );

  memcpy( db_rendezvous_cookie->rendezvous_cookie, unpacked_introduce_data.rendezvous_cookie, 20 );

  v_add_rendezvous_cookie_to_list( db_rendezvous_cookie, &onion_service->rendezvous_cookies );

  wc_curve25519_init( &hs_handshake_key );

  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &hs_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make hs_handshake_key, error code %d", wolf_succ );
#endif

    return -1;
  }

  db_rend_circuit = malloc( sizeof( DoublyLinkedOnionCircuit ) );
  db_rend_circuit->next = NULL;
  db_rend_circuit->previous = NULL;

  if ( d_hs_ntor_handshake_finish( unpacked_cell, &db_intro_circuit->circuit, &hs_handshake_key, &client_handshake_key, &db_rend_circuit->circuit, auth_input_mac ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to finish the RELAY_COMMAND_INTRODUCE2 ntor handshake" );
#endif

    return -1;
  }

  // extend to the specified relay and send the handshake reply
  rend_relay = malloc( sizeof( OnionRelay ) );
  rend_relay->address = 0;
  rend_relay->or_port = 0;

  memcpy( rend_relay->ntor_onion_key, unpacked_introduce_data.onion_key, 32 );

  for ( i = 0; i < unpacked_introduce_data.specifier_count; i++ ) {
    if ( unpacked_introduce_data.link_specifiers[i]->type == IPv4Link ) {
      // comes in big endian, lwip wants it little endian
      rend_relay->address |= (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[0];
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[1] ) << 8;
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[2] ) << 16;
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[3] ) << 24;

      rend_relay->or_port |= ( (unsigned short)unpacked_introduce_data.link_specifiers[i]->specifier[4] ) << 8;
      rend_relay->or_port |= (unsigned short)unpacked_introduce_data.link_specifiers[i]->specifier[5];
    } else if ( unpacked_introduce_data.link_specifiers[i]->type == LEGACYLink ) {
      memcpy( rend_relay->identity, unpacked_introduce_data.link_specifiers[i]->specifier, ID_LENGTH );
    }
  }

  if ( d_build_onion_circuit_to( &db_rend_circuit->circuit, 3, rend_relay ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to build the rendezvous circuit" );
#endif

    return -1;
  }

  db_rend_circuit->circuit.status = CIRCUIT_RENDEZVOUS;
  db_rend_circuit->circuit.rx_queue = onion_service->rx_queue;

  if ( d_router_join_rendezvous( &db_rend_circuit->circuit, unpacked_introduce_data.rendezvous_cookie, hs_handshake_key.p.point, auth_input_mac ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to join the rendezvous relay" );
#endif

    return -1;
  }

  v_add_circuit_to_list( db_rend_circuit, &onion_service->rend_circuits );

  wc_curve25519_free( &client_handshake_key );
  wc_curve25519_free( &hs_handshake_key );


  v_free_introduce_2_data( &unpacked_introduce_data );

  return 0;
}

int d_router_join_rendezvous( OnionCircuit* rend_circuit, unsigned char* rendezvous_cookie, unsigned char* hs_pub_key, unsigned char* auth_input_mac ) {
  Cell unpacked_cell;
  unsigned char* packed_cell;

  unpacked_cell.circ_id = rend_circuit->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_COMMAND_RENDEZVOUS1;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 20 + PK_PUBKEY_LEN + MAC_LEN;
  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadCommandRendezvous1 ) );

  memcpy( ( (RelayPayloadCommandRendezvous1*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->rendezvous_cookie, rendezvous_cookie, 20 );
  memcpy( ( (RelayPayloadCommandRendezvous1*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_info.public_key, hs_pub_key, PK_PUBKEY_LEN );
  memcpy( ( (RelayPayloadCommandRendezvous1*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_info.auth, auth_input_mac, MAC_LEN );

  packed_cell = pack_and_free( &unpacked_cell );

  if ( d_send_packed_relay_cell_and_free( rend_circuit->ssl, packed_cell, &rend_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send the RELAY_COMMAND_RENDEZVOUS1 cell" );
#endif

    return -1;
  }

  // spawn a task to block on the tls buffer and put the data into the rx_queue
  xTaskCreatePinnedToCore(
    v_handle_circuit,
    "HANDLE_REND_CIRCUIT",
    4096,
    (void*)(rend_circuit),
    6,
    rend_circuit->task_handle,
    tskNO_AFFINITY
  );

  return 0;
}

int d_verify_and_decrypt_introduce_2( OnionService* onion_service, Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* client_handshake_key ) {
  int i;
  unsigned int idx;
  int wolf_succ;
  Aes aes_key;
  unsigned char aes_iv[16] = { 0 };
  wc_Shake reusable_shake;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char* intro_secret_hs_input = malloc( sizeof( unsigned char ) * ( CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH ) );
  unsigned char* working_intro_secret_hs_input = intro_secret_hs_input;
  unsigned char* info = malloc( sizeof( unsigned char ) * ( HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE ) );
  unsigned char* hs_keys = malloc( sizeof( unsigned char ) * ( AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE ) );
  int64_t reusable_length;
  unsigned char reusable_length_buffer[8];

  wc_AesInit( &aes_key, NULL, INVALID_DEVID );
  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  // compute intro_secret_hs_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( &intro_circuit->intro_crypto->encrypt_key, client_handshake_key, working_intro_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute shared secret, error code: %d", wolf_succ );
#endif

    return -1;
  }

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length );

  working_intro_secret_hs_input += ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length;

  memcpy( working_intro_secret_hs_input, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, 32 );

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, intro_circuit->intro_crypto->encrypt_key.p.point, 32 );

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, HS_PROTOID, HS_PROTOID_LENGTH );

  // TODO compute info
  memcpy( info, HS_PROTOID_EXPAND, HS_PROTOID_EXPAND_LENGTH );

  for ( i = 0; i < 2; i++ ) {
    if ( i == 0 ) {
      memcpy( info + HS_PROTOID_EXPAND_LENGTH, onion_service->current_sub_credential, WC_SHA3_256_DIGEST_SIZE );
    } else {
      memcpy( info + HS_PROTOID_EXPAND_LENGTH, onion_service->previous_sub_credential, WC_SHA3_256_DIGEST_SIZE );
    }

    // compute hs_keys
    wc_Shake256_Update( &reusable_shake, intro_secret_hs_input,  CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH );
    wc_Shake256_Update( &reusable_shake, (unsigned char*)HS_PROTOID_KEY, HS_PROTOID_KEY_LENGTH );
    wc_Shake256_Update( &reusable_shake, info, HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE );
    wc_Shake256_Final( &reusable_shake, hs_keys, AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE );

    // verify the mac
    /* ESP_LOGE( MINITOR_TAG, "Introduce Keys" ); */

    /* for ( j = 0; j < AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE; j++ ) { */
      /* ESP_LOGE( MINITOR_TAG, "%.2x", hs_keys[j] ); */
    /* } */

    reusable_length = WC_SHA256_DIGEST_SIZE;
    reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
    reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
    reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
    reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
    reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
    reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
    reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
    reusable_length_buffer[7] = (unsigned char)reusable_length;

    wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 8 );
    wc_Sha3_256_Update( &reusable_sha3, hs_keys + AES_256_KEY_SIZE, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->legacy_key_id, 20 );

    reusable_length_buffer[0] = (unsigned char)( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_type );

    wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 1 );

    reusable_length_buffer[0] = (unsigned char)( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length >> 8 );
    reusable_length_buffer[1] = (unsigned char)( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length;

    wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 2 );
    wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length );
    wc_Sha3_256_Update( &reusable_sha3, &( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->extension_count, 1 );

    ESP_LOGE( MINITOR_TAG, "extension_count: %d", ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->extension_count );

    wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, PK_PUBKEY_LEN );
    wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_length );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    if ( memcmp( reusable_sha3_sum, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->mac, WC_SHA3_256_DIGEST_SIZE ) == 0 ) {
      ESP_LOGE( MINITOR_TAG, "Got a match" );
      i = 0;
      break;
    }
  }

  if ( i >= 2 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "The mac of the RELAY_COMMAND_INTRODUCE2 cell does not match our calculations" );
#endif

    return -1;
  }

  // decrypt the encrypted section
  wc_AesSetKeyDirect( &aes_key, hs_keys, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wolf_succ = wc_AesCtrEncrypt( &aes_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_length );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY_COMMAND_INTRODUCE2 encrypted data, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wc_Shake256_Free( &reusable_shake );
  wc_Sha3_256_Free( &reusable_sha3 );

  free( intro_secret_hs_input );
  free( info );
  free( hs_keys );

  return 0;
}

int d_hs_ntor_handshake_finish( Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* hs_handshake_key, curve25519_key* client_handshake_key, OnionCircuit* rend_circuit, unsigned char* auth_input_mac ) {
  int i;
  unsigned int idx;
  int wolf_succ;
  unsigned char* rend_secret_hs_input = malloc( sizeof( unsigned char ) * ( CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH ) );
  unsigned char* working_rend_secret_hs_input = rend_secret_hs_input;
  unsigned char aes_iv[16] = { 0 };
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  wc_Shake reusable_shake;
  unsigned char* expanded_keys = malloc( sizeof( unsigned char ) * ( WC_SHA3_256_DIGEST_SIZE * 2 + AES_256_KEY_SIZE * 2 ) );
  unsigned char* hs_key_seed = malloc( sizeof(  unsigned char ) * WC_SHA256_DIGEST_SIZE );
  int64_t reusable_length;
  unsigned char reusable_length_buffer[8];

  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  // compute rend_secret_hs_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( hs_handshake_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );
#endif

    return -1;
  }

  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( &intro_circuit->intro_crypto->encrypt_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );
#endif

    return -1;
  }

  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  memcpy( working_rend_secret_hs_input, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length );
  working_rend_secret_hs_input += ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length;

  memcpy( working_rend_secret_hs_input, intro_circuit->intro_crypto->encrypt_key.p.point, CURVE25519_KEYSIZE );
  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  memcpy( working_rend_secret_hs_input, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, PK_PUBKEY_LEN );
  working_rend_secret_hs_input += PK_PUBKEY_LEN;

  memcpy( working_rend_secret_hs_input, hs_handshake_key->p.point, CURVE25519_KEYSIZE );
  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  memcpy( working_rend_secret_hs_input, HS_PROTOID, HS_PROTOID_LENGTH );

  // compute NTOR_KEY_SEED
  reusable_length = CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH;
  reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
  reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
  reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
  reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
  reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
  reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
  reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
  reusable_length_buffer[7] = (unsigned char)reusable_length;

  wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 8 );
  wc_Sha3_256_Update( &reusable_sha3, rend_secret_hs_input, CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_PROTOID_KEY, HS_PROTOID_KEY_LENGTH );
  wc_Sha3_256_Final( &reusable_sha3, hs_key_seed );

  // compute verify
  wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 8 );
  wc_Sha3_256_Update( &reusable_sha3, rend_secret_hs_input, CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_PROTOID_VERIFY, HS_PROTOID_VERIFY_LENGTH );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  // compute AUTH_INPUT_MAC
  reusable_length = WC_SHA3_256_DIGEST_SIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH + strlen( "Server" );
  reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
  reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
  reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
  reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
  reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
  reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
  reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
  reusable_length_buffer[7] = (unsigned char)reusable_length;

  wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 8 );
  wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length );
  wc_Sha3_256_Update( &reusable_sha3, intro_circuit->intro_crypto->encrypt_key.p.point, CURVE25519_KEYSIZE );
  wc_Sha3_256_Update( &reusable_sha3, hs_handshake_key->p.point, CURVE25519_KEYSIZE );
  wc_Sha3_256_Update( &reusable_sha3, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, CURVE25519_KEYSIZE );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_PROTOID, HS_PROTOID_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"Server", strlen( "Server" ) );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_PROTOID_MAC, HS_PROTOID_MAC_LENGTH );
  wc_Sha3_256_Final( &reusable_sha3, auth_input_mac );

  // derive the encryption and digest seeds
  wc_Shake256_Update( &reusable_shake, hs_key_seed, WC_SHA3_256_DIGEST_SIZE );
  wc_Shake256_Update( &reusable_shake, (unsigned char*)HS_PROTOID_EXPAND, HS_PROTOID_EXPAND_LENGTH );
  wc_Shake256_Final( &reusable_shake, expanded_keys,  WC_SHA3_256_DIGEST_SIZE * 2 + AES_256_KEY_SIZE * 2  );

  ESP_LOGE( MINITOR_TAG, "expanded keys" );

  for ( i = 0; i < WC_SHA3_256_DIGEST_SIZE * 2 + AES_256_KEY_SIZE * 2; i++ ) {
    ESP_LOGE( MINITOR_TAG, "%.2x", expanded_keys[i] );
  }

  rend_circuit->hs_crypto = malloc( sizeof( HsCrypto ) );

  wc_InitSha3_256( &rend_circuit->hs_crypto->hs_running_sha_forward, NULL, INVALID_DEVID );
  wc_InitSha3_256( &rend_circuit->hs_crypto->hs_running_sha_backward, NULL, INVALID_DEVID );
  wc_AesInit( &rend_circuit->hs_crypto->hs_aes_forward, NULL, INVALID_DEVID );
  wc_AesInit( &rend_circuit->hs_crypto->hs_aes_backward, NULL, INVALID_DEVID );

  wc_Sha3_256_Update( &rend_circuit->hs_crypto->hs_running_sha_forward, expanded_keys, WC_SHA3_256_DIGEST_SIZE );

  wc_Sha3_256_Update( &rend_circuit->hs_crypto->hs_running_sha_backward, expanded_keys + WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_DIGEST_SIZE );

  wc_AesSetKeyDirect( &rend_circuit->hs_crypto->hs_aes_forward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ), AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wc_AesSetKeyDirect( &rend_circuit->hs_crypto->hs_aes_backward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ) + AES_256_KEY_SIZE, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );

  free( rend_secret_hs_input );
  free( hs_key_seed );
  free( expanded_keys );

  return 0;
}

int d_binary_search_hsdir_index( unsigned char* hash, HsDirIndexNode** index_array, int index_length ) {
  int left = 0;
  int mid = 0;
  int right = index_length - 1;
  int res;

  while ( left <= right ) {
    mid = left + ( right - left ) / 2;

    res = memcmp( hash, index_array[mid]->hash, 32 );

    mid++;

    if ( res == 0 ) {
      break;
    } else if ( res > 0 ) {
      left = mid;
    } else {
      mid--;
      right = mid - 1;
    }
  }

  return mid;
}

static DoublyLinkedOnionRelayList* px_get_relays_by_hash( unsigned char* hash, int desired_count, DoublyLinkedOnionRelayList* used_relays, int previous ) {
  int i;
  int j;
  int left = 0;
  int mid = 0;
  int right;
  int res;
  int hsdir_relay_count = d_get_hsdir_count();
  unsigned char* tmp_hash;
  OnionRelay* tmp_relay;
  DoublyLinkedOnionRelay* db_tmp_relay;
  DoublyLinkedOnionRelayList* relay_list = malloc( sizeof( DoublyLinkedOnionRelayList ) );
  relay_list->length = 0;
  relay_list->head = NULL;
  relay_list->tail = NULL;

  if ( hsdir_relay_count < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get the number of hsdir relays" );
#endif

    goto cleanup;
  }

  right = hsdir_relay_count;

  while ( left <= right ) {
    mid = left + ( right - left ) / 2;

    ESP_LOGE( MINITOR_TAG, "mid: %d", mid );
    if ( mid == hsdir_relay_count ) {
      mid = 0;
      break;
    } 

    if ( ( tmp_hash = puc_get_hash_by_index( mid, previous ) ) == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to get the hash of the mid relay" );
#endif

      goto cleanup;
    }

    res = memcmp( hash, tmp_hash, H_LENGTH );
    free( tmp_hash );

    if ( res == 0 ) {
      break;
    } else if ( res > 0 ) {
      left = mid + 1;
    } else {
      right = mid - 1;
    }
  }

  for ( i = mid; relay_list->length < desired_count; i = ( i + 1 ) % hsdir_relay_count ) {
    if ( ( tmp_relay = px_get_relay_by_hash_index( i, previous ) ) == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to get the relay identity by its hash" );
#endif

      goto cleanup;
    }

    db_tmp_relay = used_relays->head;

    for ( j = 0; j < used_relays->length; j++ ) {
      if ( memcmp( tmp_relay->identity, db_tmp_relay->relay->identity, ID_LENGTH ) == 0 ) {
        break;
      }

      db_tmp_relay = db_tmp_relay->next;
    }

    if ( j < used_relays->length ) {
      free( tmp_relay );
      continue;
    }

    db_tmp_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    db_tmp_relay->next = NULL;
    db_tmp_relay->previous = NULL;
    db_tmp_relay->relay = tmp_relay;

    v_add_relay_to_list( db_tmp_relay, relay_list );
  }

  return relay_list;

cleanup:
  db_tmp_relay = relay_list->head;

  for ( i = 0; i < relay_list->length; i++ ) {
    free( db_tmp_relay->relay );

    if ( i == relay_list->length - 1 ) {
      free( db_tmp_relay );
    } else {
      db_tmp_relay = db_tmp_relay->next;
      free( db_tmp_relay->previous );
    }
  }

  free( relay_list );

  return NULL;
}

static int d_test_db() {
  unsigned char* tmp_hash = puc_get_hash_by_index( 5, 0 );

  if ( tmp_hash == NULL ) {
    return -1;
  }

  free( tmp_hash );

  return 0;
}

int d_send_descriptors( unsigned char* descriptor_text, int descriptor_length, unsigned int hsdir_n_replicas, unsigned char* blinded_pub_key, int time_period, unsigned int hsdir_interval, unsigned char* shared_rand, unsigned int hsdir_spread_store, int previous ) {
  int i;
  int j;
  int k;
  int to_store;
  unsigned char tmp_64_buffer[8];
  Sha3 reusable_sha3;
  unsigned char** hs_index = malloc( sizeof( unsigned char* ) * hsdir_n_replicas );
  OnionRelay* target_relay;
  DoublyLinkedOnionRelayList* hsdir_index_list;
  DoublyLinkedOnionRelayList used_relays = {
    .head = NULL,
    .tail = NULL,
    .length = 0,
  };
  DoublyLinkedOnionRelay* hsdir_relay_node;
  DoublyLinkedOnionRelay* tmp_relay_node;
  OnionCircuit publish_circuit = {
    .ssl = NULL
  };

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  for ( i = 0; i < hsdir_n_replicas; i++ ) {
    hs_index[i] = malloc( sizeof( unsigned char ) * WC_SHA3_256_DIGEST_SIZE );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"store-at-idx", strlen( "store-at-idx" ) );
    wc_Sha3_256_Update( &reusable_sha3, blinded_pub_key, ED25519_PUB_KEY_SIZE );

    tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 56 );
    tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 48 );
    tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 40 );
    tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 32 );
    tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 24 );
    tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 16 );
    tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( i + 1 ) ) >> 8 );
    tmp_64_buffer[7] = (unsigned char)( (int64_t)( i + 1 ) );

    wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

    tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 56 );
    tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 48 );
    tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 40 );
    tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 32 );
    tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 24 );
    tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 16 );
    tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( hsdir_interval ) ) >> 8 );
    tmp_64_buffer[7] = (unsigned char)( (int64_t)( hsdir_interval ) );

    wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

    tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( time_period ) ) >> 56 );
    tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( time_period ) ) >> 48 );
    tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( time_period ) ) >> 40 );
    tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( time_period ) ) >> 32 );
    tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( time_period ) ) >> 24 );
    tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( time_period ) ) >> 16 );
    tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( time_period ) ) >> 8 );
    tmp_64_buffer[7] = (unsigned char)( (int64_t)( time_period ) );

    wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

    wc_Sha3_256_Final( &reusable_sha3, hs_index[i] );
  }

  for ( i = 0; i < hsdir_n_replicas; i++ ) {
    to_store = hsdir_spread_store;

    if ( ( hsdir_index_list = px_get_relays_by_hash( hs_index[i], hsdir_spread_store, &used_relays, previous ) ) == NULL ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to get the list of relays to send to for the time period" );
#endif

        return -1;
    }

    hsdir_relay_node = hsdir_index_list->head;

    ESP_LOGE( MINITOR_TAG, "hsdir_index_list->length: %d", hsdir_index_list->length );
    for ( j = 0; j < hsdir_index_list->length && to_store > 0; j++ ) {
      if ( d_test_db() < 0 ) {
        ESP_LOGE( MINITOR_TAG, "db test failed on geff" );
        return -1;
      }

      if ( ( target_relay = px_get_relay( hsdir_relay_node->relay->identity ) ) == NULL ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to get the target relay from its identity" );
#endif

        return -1;
      }

      if ( d_test_db() < 0 ) {
        ESP_LOGE( MINITOR_TAG, "db test failed on feff" );
        return -1;
      }

      if ( publish_circuit.ssl != NULL ) {
        tmp_relay_node = publish_circuit.relay_list.head;

        for ( k = 0; k < publish_circuit.relay_list.length; k++ ) {
          if ( memcmp( tmp_relay_node->relay->identity, target_relay->identity, ID_LENGTH ) == 0 || k == publish_circuit.relay_list.length - 1 ) {
            if ( k == 0 ) {
              ESP_LOGE( MINITOR_TAG, "First matches, destroying circuit" );

              if ( d_destroy_onion_circuit( &publish_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif

                return -1;
              }

              ESP_LOGE( MINITOR_TAG, "Finished destroying" );

              publish_circuit.ssl = NULL;
            } else {
              ESP_LOGE( MINITOR_TAG, "Truncating to length %d", k );

              if ( d_truncate_onion_circuit( &publish_circuit, k ) < 0 ) {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to truncate publish circuit" );
#endif

                return -1;
              }

              ESP_LOGE( MINITOR_TAG, "Trying to extend to %d", target_relay->or_port );

              if ( d_extend_onion_circuit_to( &publish_circuit, 3, target_relay ) < 0 ) {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to extend publish circuit" );
#endif

                if ( d_destroy_onion_circuit( &publish_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
                  ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif

                  return -1;
                }

                publish_circuit.ssl = NULL;
              }
            }

            break;
          }

          tmp_relay_node = tmp_relay_node->next;
        }
      }

      if ( d_test_db() < 0 ) {
        ESP_LOGE( MINITOR_TAG, "db test failed on eeff" );
        return -1;
      }

      while ( publish_circuit.ssl == NULL ) {
        ESP_LOGE( MINITOR_TAG, "Inside the create circuit" );

        if ( d_build_onion_circuit_to( &publish_circuit, 3, target_relay ) < 0 ) {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to build publish circuit" );
#endif

          if ( d_destroy_onion_circuit( &publish_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif

            return -1;
          }

          publish_circuit.ssl = NULL;
        }

        ESP_LOGE( MINITOR_TAG, "Finished building circuit" );
      }

      if ( d_test_db() < 0 ) {
        ESP_LOGE( MINITOR_TAG, "db test failed on deff" );
        return -1;
      }

      if ( d_post_descriptor( descriptor_text, descriptor_length, &publish_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to post descriptor" );
#endif

        return -1;
      }

      to_store--;

      tmp_relay_node = malloc( sizeof( DoublyLinkedOnionRelay ) );
      tmp_relay_node->next = NULL;
      tmp_relay_node->previous = NULL;
      tmp_relay_node->relay = malloc( sizeof( OnionRelay ) );

      memcpy( tmp_relay_node->relay->identity, hsdir_relay_node->relay->identity, ID_LENGTH );

      v_add_relay_to_list( tmp_relay_node, &used_relays );

      hsdir_relay_node = hsdir_relay_node->next;

      if ( d_test_db() < 0 ) {
        ESP_LOGE( MINITOR_TAG, "db test failed on ceff" );
        return -1;
      }
    }

    if ( d_test_db() < 0 ) {
      ESP_LOGE( MINITOR_TAG, "db test failed on beff" );
      return -1;
    }

    hsdir_relay_node = hsdir_index_list->head;

    for ( j = 0; j < hsdir_index_list->length; j++ ) {
      free( hsdir_relay_node->relay );

      if ( j != hsdir_index_list->length - 1 ) {
        hsdir_relay_node = hsdir_relay_node->next;

        free( hsdir_relay_node->previous );
      } else {
        free( hsdir_relay_node );
      }
    }

    free( hsdir_index_list );

    if ( d_test_db() < 0 ) {
      ESP_LOGE( MINITOR_TAG, "db test failed on aeff" );
      return -1;
    }
  }

  tmp_relay_node = used_relays.head;

  for ( i = 0; i < used_relays.length; i++ ) {
    free( tmp_relay_node->relay );

    if ( i != used_relays.length - 1 ) {
      tmp_relay_node = tmp_relay_node->next;

      free( tmp_relay_node->previous );
    } else {
      free( tmp_relay_node );
    }
  }

  if ( d_destroy_onion_circuit( &publish_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif

    return -1;
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  for ( i = 0; i < hsdir_n_replicas; i++ ) {
    free( hs_index[i] );
  }

  free( hs_index );

  ESP_LOGE( MINITOR_TAG, "Done sending descriptors" );

  return 0;
}

static char* pc_ipv4_to_string( unsigned int address ) {
  int i;
  int length = 0;
  char* result = malloc( sizeof( char ) * 16 );
  int tmp_length = 0;
  unsigned char tmp_byte;

  for ( i = 0; i < 4; i++ ) {
    tmp_byte = ( address >> ( 8 * i ) ) & 0xff;

    if ( tmp_byte < 10 ) {
      tmp_length = 1;
    } else if ( tmp_byte < 100 ) {
      tmp_length = 2;
    } else {
      tmp_length = 3;
    }

    sprintf( result + length, "%d", tmp_byte );
    length += tmp_length;

    if ( i != 3 ) {
      result[length] = '.';
      length++;
    }
  }

  result[length] = 0;

  return result;
}

int d_post_descriptor( unsigned char* descriptor_text, int descriptor_length, OnionCircuit* publish_circuit ) {
  char* REQUEST;
  char* ipv4_string;
  const char* REQUEST_CONST = "POST /tor/hs/3/publish HTTP/1.0\r\n"
    "Host: \r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: "
    ;
  const char* header_end = "\r\n\r\n";

  int i;
  int total_tx_length = 0;
  int http_header_length;
  int tx_limit;
  // buffer thath holds data returned from the socket
  char content_length[10] = { 0 };
  Cell unpacked_cell;
  unsigned char* packed_cell;

  ipv4_string = pc_ipv4_to_string( publish_circuit->relay_list.head->relay->address );
  REQUEST = malloc( sizeof( char ) * ( strlen( REQUEST_CONST ) + strlen( ipv4_string ) ) );

  memcpy( REQUEST, REQUEST_CONST, 39 );
  strcpy( REQUEST + 39, ipv4_string );
  strcpy( REQUEST + 39 + strlen( ipv4_string ), REQUEST_CONST + 39 );

  free( ipv4_string );

  ESP_LOGE( MINITOR_TAG, "%s", REQUEST );
  ESP_LOGE( MINITOR_TAG, "descriptor has length %d", descriptor_length );

  unpacked_cell.circ_id = publish_circuit->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_BEGIN_DIR;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 0;

  packed_cell = pack_and_free( &unpacked_cell );

  if ( d_send_packed_relay_cell_and_free( publish_circuit->ssl, packed_cell, &publish_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_BEGIN_DIR cell" );
#endif

    return -1;
  }

  if ( d_recv_cell( publish_circuit->ssl, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_CONNECTED cell" );
#endif

    return -1;
  }

  if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_CONNECTED ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Didn't get RELAY_CONNECTED back" );
#endif

    return -1;
  }

  free_cell( &unpacked_cell );

  sprintf( content_length, "%d", descriptor_length );

  http_header_length = strlen( REQUEST ) + strlen( content_length ) + strlen( header_end );
  tx_limit = http_header_length + descriptor_length;

  unpacked_cell.command = RELAY;

  while ( total_tx_length < tx_limit ) {
    unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_DATA;
    ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
    // TODO possibly need to set the stream_id, wasn't clear in torspec
    ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
    ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;

    if ( tx_limit - total_tx_length < RELAY_PAYLOAD_LEN ) {
      ( (PayloadRelay*)unpacked_cell.payload )->length = tx_limit - total_tx_length;
    } else {
      ( (PayloadRelay*)unpacked_cell.payload )->length = RELAY_PAYLOAD_LEN;
    }

    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadData ) );

    ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload = malloc( sizeof( unsigned char ) * ( (PayloadRelay*)unpacked_cell.payload )->length );

    if ( total_tx_length == 0 ) {
      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, REQUEST, strlen( REQUEST ) );
      total_tx_length += strlen( REQUEST );

      free( REQUEST );

      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + total_tx_length, content_length, strlen( content_length ) );
      total_tx_length += strlen( content_length );

      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + total_tx_length, header_end, strlen( header_end ) );
      total_tx_length += strlen( header_end );

      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + total_tx_length, descriptor_text, ( (PayloadRelay*)unpacked_cell.payload )->length - total_tx_length );
      total_tx_length += ( (PayloadRelay*)unpacked_cell.payload )->length - total_tx_length;
    } else {
      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, descriptor_text + total_tx_length - http_header_length, ( (PayloadRelay*)unpacked_cell.payload )->length );
      total_tx_length += ( (PayloadRelay*)unpacked_cell.payload )->length;
    }

    for ( i = 0; i < ( (PayloadRelay*)unpacked_cell.payload )->length; i++ ) {
      putchar( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload[i] );
    }

    putchar( '\n' );

    packed_cell = pack_and_free( &unpacked_cell );

    if ( d_send_packed_relay_cell_and_free( publish_circuit->ssl, packed_cell, &publish_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA cell" );
#endif

      return -1;
    }
  }

  if ( d_recv_cell( publish_circuit->ssl, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_DATA cell" );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "cell command %d", unpacked_cell.command );
  ESP_LOGE( MINITOR_TAG, "relay command %d", ( (PayloadRelay*)unpacked_cell.payload )->command );

  ESP_LOGE( MINITOR_TAG, "%.*s\n", ( (PayloadRelay*)unpacked_cell.payload )->length, ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload );

  free_cell( &unpacked_cell );

  if ( d_recv_cell( publish_circuit->ssl, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_END cell" );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "cell command %d", unpacked_cell.command );
  ESP_LOGE( MINITOR_TAG, "relay command %d", ( (PayloadRelay*)unpacked_cell.payload )->command );

  free_cell( &unpacked_cell );

  return 0;
}

// depricated
void v_binary_insert_hsdir_index( HsDirIndexNode* node, HsDirIndexNode** index_array, int index_length ) {
  int i;
  int mid = d_binary_search_hsdir_index( node->hash, index_array, index_length );

  for ( i = index_length - 1; i >= mid; i-- ) {
    index_array[i + 1] = index_array[i];

    if ( i != 0 ) {
      index_array[i] = index_array[i - 1];
    }
  }

  index_array[mid] = node;
}

int d_generate_outer_descriptor( unsigned char** outer_layer, unsigned char* ciphertext, int ciphertext_length, ed25519_key* descriptor_signing_key, long int valid_after, ed25519_key* blinded_key, int revision_counter ) {
  unsigned int idx;
  int wolf_succ;
  int layer_length;
  char revision_counter_str[32];
  unsigned char* working_outer_layer;
  unsigned char tmp_signature[64];

  const char* outer_layer_template_0 =
    "hs-descriptor 3\n"
    "descriptor-lifetime 180\n"
    "descriptor-signing-key-cert\n"
    "-----BEGIN ED25519 CERT-----\n"
    "*******************************************************************************************************************************************************************************************"
    "-----END ED25519 CERT-----\n"
    "revision-counter ";
  const char* outer_layer_template_1 =
    "\nsuperencrypted\n"
    "-----BEGIN MESSAGE-----\n"
    ;
  const char* outer_layer_template_2 =
    "-----END MESSAGE-----\n"
    "signature **************************************************************************************"
    ;

  sprintf( revision_counter_str, "%d", revision_counter );

  layer_length = HS_DESC_SIG_PREFIX_LENGTH + strlen( outer_layer_template_0 ) + strlen( revision_counter_str ) + strlen( outer_layer_template_1 ) + ciphertext_length * 4 / 3 + strlen( outer_layer_template_2 );

  if ( ciphertext_length % 6 != 0 ) {
    layer_length ++;
  }

  *outer_layer = malloc( sizeof( unsigned char ) * layer_length );
  working_outer_layer = *outer_layer;

  memcpy( working_outer_layer, HS_DESC_SIG_PREFIX, HS_DESC_SIG_PREFIX_LENGTH );

  // skip past the prefix
  working_outer_layer += HS_DESC_SIG_PREFIX_LENGTH;

  memcpy( working_outer_layer, outer_layer_template_0, strlen( outer_layer_template_0 ) );

  // skip past all the headers to the cert body
  working_outer_layer += 97;

  if ( d_generate_packed_crosscert( working_outer_layer, descriptor_signing_key->p, blinded_key, 0x08, valid_after ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate the auth_key cross cert" );
#endif

    return -1;
  }

  // skip past cert body and next header
  working_outer_layer += 187 + 44;

  // copy revision counter
  memcpy( working_outer_layer, revision_counter_str, strlen( revision_counter_str ) );

  working_outer_layer += strlen( revision_counter_str );

  // copy the next part of the template
  memcpy( working_outer_layer, outer_layer_template_1, strlen( outer_layer_template_1 ) );

  // skip over the template headers
  working_outer_layer += strlen( outer_layer_template_1 );

  v_base_64_encode( (char*)working_outer_layer, ciphertext, ciphertext_length );

  // skip past message body
  working_outer_layer += ciphertext_length * 4 / 3;

  if ( ciphertext_length % 6 != 0 ) {
    working_outer_layer++;
  }

  memcpy( working_outer_layer, outer_layer_template_2, strlen( outer_layer_template_2 ) );

  // skip past the header
  working_outer_layer += 32;

  idx = ED25519_SIG_SIZE;
  wolf_succ = wc_ed25519_sign_msg( *outer_layer, working_outer_layer - *outer_layer - 10, tmp_signature, &idx, descriptor_signing_key );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign the outer descriptor, error code: %d", wolf_succ );
#endif

    return -1;
  }

  v_base_64_encode( (char*)working_outer_layer, tmp_signature, 64 );

  return layer_length - HS_DESC_SIG_PREFIX_LENGTH;
}

int d_generate_first_plaintext( unsigned char** first_layer, unsigned char* ciphertext, int ciphertext_length ) {
  int i;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char* working_first_layer;
  const char* first_layer_template =
    "desc-auth-type x25519\n"
    "desc-auth-ephemeral-key *******************************************\n"
    ;
  const char* auth_client_template =
    "auth-client *********** ********************** **********************\n"
    ;
  const char* begin_encrypted =
    "encrypted\n"
    "-----BEGIN MESSAGE-----\n"
    ;
  const char* end_encrypted =
    "-----END MESSAGE-----"
    ;

  int layer_length = strlen( first_layer_template ) + strlen( auth_client_template ) * 16 + strlen( begin_encrypted ) + ciphertext_length * 4 / 3 + strlen( end_encrypted );

  if ( ciphertext_length % 6 != 0 ) {
    layer_length++;
  }

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  *first_layer = malloc( sizeof( unsigned char ) * layer_length );
  working_first_layer = *first_layer;

  memcpy( working_first_layer, first_layer_template, strlen( first_layer_template ) );

  // skip over the desc-auth-type and next header
  working_first_layer += 46;

  esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
  v_base_64_encode( (char*)working_first_layer, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );

  // skip over the ephemeral key and the newline
  working_first_layer += 44;

  for ( i = 0; i < 16; i++ ) {
    memcpy( working_first_layer, auth_client_template, strlen( auth_client_template ) );

    // skip over the header
    working_first_layer += 12;

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( (char*)working_first_layer, reusable_sha3_sum, 8 );

    // skip over the client-id
    working_first_layer += 12;

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( (char*)working_first_layer, reusable_sha3_sum, 16 );

    // skip over the iv
    working_first_layer += 23;

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( (char*)working_first_layer, reusable_sha3_sum, 16 );

    // skip over the encrypted-cookie
    working_first_layer += 23;
  }

  memcpy( working_first_layer, begin_encrypted, strlen( begin_encrypted ) );

  // skip over the header
  working_first_layer += strlen( begin_encrypted );

  v_base_64_encode( (char*)working_first_layer, ciphertext, ciphertext_length );

  // skip over the blob
  working_first_layer += ciphertext_length * 4 / 3;

  if ( ciphertext_length % 6 != 0 ) {
    working_first_layer++;
  }

  memcpy( working_first_layer, end_encrypted, strlen( end_encrypted ) );

  wc_Sha3_256_Free( &reusable_sha3 );

  return layer_length;
}

int d_encrypt_descriptor_plaintext( unsigned char** ciphertext, unsigned char* plaintext, int plaintext_length, unsigned char* secret_data, int secret_data_length, const char* string_constant, int string_constant_length, unsigned char* sub_credential, int64_t revision_counter ) {
  int wolf_succ;
  int64_t reusable_length;
  unsigned char reusable_length_buffer[8];
  unsigned char salt[16];
  unsigned char* secret_input = malloc( sizeof( unsigned char ) * ( secret_data_length + WC_SHA3_256_DIGEST_SIZE + sizeof( int64_t ) ) );
  Sha3 reusable_sha3;
  wc_Shake reusable_shake;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char keys[AES_256_KEY_SIZE + AES_IV_SIZE + WC_SHA3_256_DIGEST_SIZE];
  Aes reusable_aes_key;

  *ciphertext = malloc( sizeof( unsigned char ) * ( plaintext_length + 16 + WC_SHA3_256_DIGEST_SIZE ) );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );
  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_AesInit( &reusable_aes_key, NULL, INVALID_DEVID );

  esp_fill_random( salt, 16 );
  wc_Sha3_256_Update( &reusable_sha3, salt, 16 );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
  memcpy( salt, reusable_sha3_sum, 16 );

  memcpy( secret_input, secret_data, secret_data_length );
  memcpy( secret_input + secret_data_length, sub_credential, WC_SHA3_256_DIGEST_SIZE );

  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[0] = (unsigned char)( revision_counter >> 56 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[1] = (unsigned char)( revision_counter >> 48 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[2] = (unsigned char)( revision_counter >> 40 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[3] = (unsigned char)( revision_counter >> 32 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[4] = (unsigned char)( revision_counter >> 24 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[5] = (unsigned char)( revision_counter >> 16 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[6] = (unsigned char)( revision_counter >> 8 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[7] = (unsigned char)revision_counter;

  wc_Shake256_Update( &reusable_shake, secret_input, secret_data_length + WC_SHA3_256_DIGEST_SIZE + sizeof( int64_t ) );
  wc_Shake256_Update( &reusable_shake, salt, 16 );
  wc_Shake256_Update( &reusable_shake, (unsigned char*)string_constant, string_constant_length );
  wc_Shake256_Final( &reusable_shake, keys, sizeof( keys ) );

  memcpy( *ciphertext, salt, 16 );

  wc_AesSetKeyDirect( &reusable_aes_key, keys, AES_256_KEY_SIZE, keys + AES_256_KEY_SIZE, AES_ENCRYPTION );

  wolf_succ = wc_AesCtrEncrypt( &reusable_aes_key, *ciphertext + 16, plaintext, plaintext_length );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to encrypt descriptor plaintext, error code: %d", wolf_succ );
#endif

    return -1;
  }

  reusable_length = WC_SHA256_DIGEST_SIZE;
  reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
  reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
  reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
  reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
  reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
  reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
  reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
  reusable_length_buffer[7] = (unsigned char)reusable_length;

  wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, sizeof( reusable_length_buffer ) );
  wc_Sha3_256_Update( &reusable_sha3, keys + AES_256_KEY_SIZE + AES_IV_SIZE, WC_SHA256_DIGEST_SIZE );

  reusable_length = 16;
  reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
  reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
  reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
  reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
  reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
  reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
  reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
  reusable_length_buffer[7] = (unsigned char)reusable_length;

  wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, sizeof( reusable_length_buffer ) );
  wc_Sha3_256_Update( &reusable_sha3, salt, 16 );

  wc_Sha3_256_Update( &reusable_sha3, *ciphertext + 16, plaintext_length );

  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  memcpy( *ciphertext + 16 + plaintext_length, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );

  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );

  free( secret_input );

  return plaintext_length + 16 + WC_SHA3_256_DIGEST_SIZE;
}

int d_generate_second_plaintext( unsigned char** second_layer, DoublyLinkedOnionCircuitList* intro_circuits, long int valid_after, ed25519_key* descriptor_signing_key ) {
  int i;
  unsigned int idx;
  int wolf_succ;
  unsigned char packed_link_specifiers[1 + 4 + 6 + ID_LENGTH];
  unsigned char tmp_pub_key[CURVE25519_KEYSIZE];
  DoublyLinkedOnionCircuit* node;
  unsigned char* working_second_layer;

  const char* second_layer_template =
    "create2-formats 2\n"
    ;
  const char* introduction_point_template =
    "introduction-point ******************************************\n"
    "onion-key ntor *******************************************\n"
    "auth-key\n"
    // TODO this is a crosscert with the descriptor signing key as the main key and the intoduction point authentication key as the mandatory extension
    "-----BEGIN ED25519 CERT-----\n"
    "*******************************************************************************************************************************************************************************************"
    "-----END ED25519 CERT-----\n"
    // TODO this is the public cruve25519 key used to encrypt the introduction request
    "enc-key ntor *******************************************\n"
    "enc-key-cert\n"
    // TODO this is a crosscert with the descriptor signing key as the main key and the the ed25519 equivilent of the above key used as the mandatory extension
    "-----BEGIN ED25519 CERT-----\n"
    "*******************************************************************************************************************************************************************************************"
    "-----END ED25519 CERT-----\n"
    ;

  *second_layer = malloc( sizeof( unsigned char ) * ( strlen( second_layer_template ) + strlen( introduction_point_template ) * intro_circuits->length ) );

  working_second_layer = *second_layer;

  memcpy( working_second_layer, second_layer_template, strlen( second_layer_template ) );
  working_second_layer += strlen( second_layer_template );

  node = intro_circuits->head;

  for ( i = 0; i < intro_circuits->length; i++ ) {
    memcpy( working_second_layer, introduction_point_template, strlen( introduction_point_template ) );
    // skip past the intordouction-point header
    working_second_layer += 19;
    v_generate_packed_link_specifiers( node->circuit.relay_list.tail->relay, packed_link_specifiers );
    v_base_64_encode( (char*)working_second_layer, packed_link_specifiers, sizeof( packed_link_specifiers ) );
    // skip past the link specifiers and \nonion-key ntor
    working_second_layer += 42 + 16;
    v_base_64_encode( (char*)working_second_layer, node->circuit.relay_list.tail->relay->ntor_onion_key, H_LENGTH );
    // skip past the onion key and next header
    working_second_layer += 43 + 39;

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &node->circuit.intro_crypto->auth_key, tmp_pub_key, &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export intro circuit auth key, error code: %d", wolf_succ );
#endif
    }

    if ( d_generate_packed_crosscert( working_second_layer, tmp_pub_key, descriptor_signing_key, 0x09, valid_after ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate the auth_key cross cert" );
#endif
    }

    // skip past the cert and next header
    working_second_layer += 187 + 40;

    idx = CURVE25519_KEYSIZE;
    wolf_succ = wc_curve25519_export_public_ex( &node->circuit.intro_crypto->encrypt_key, tmp_pub_key, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ );
#endif

      return -1;
    }

    v_base_64_encode( (char*)working_second_layer, tmp_pub_key, CURVE25519_KEYSIZE );

    // skip past the enc key and next header
    working_second_layer += 43 + 43;

    // TODO create the derived key by converting our intro_encrypt_key into an ed25519 key and verify that this method works
    v_ed_pubkey_from_curve_pubkey( tmp_pub_key, node->circuit.intro_crypto->encrypt_key.p.point, 0 );

    if ( d_generate_packed_crosscert( working_second_layer, tmp_pub_key, descriptor_signing_key, 0x0B, valid_after ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate the enc-key cross cert" );
#endif
    }

    // skip past the cert and next header
    working_second_layer += 187 + 27;

    node = node->next;
  }

  return strlen( second_layer_template ) + strlen( introduction_point_template ) * intro_circuits->length;
}

void v_generate_packed_link_specifiers( OnionRelay* relay, unsigned char* packed_link_specifiers ) {
  // set the specifier count
  packed_link_specifiers[0] = 2;

  // IPv4 specifier
  // set the type
  packed_link_specifiers[1] = IPv4Link;
  // set the length
  packed_link_specifiers[2] = 6;
  // set the address and port
  packed_link_specifiers[6] = (unsigned char)( relay->address >> 24 );
  packed_link_specifiers[5] = (unsigned char)( relay->address >> 16 );
  packed_link_specifiers[4] = (unsigned char)( relay->address >> 8 );
  packed_link_specifiers[3] = (unsigned char)relay->address;
  packed_link_specifiers[7] = (unsigned char)relay->or_port >> 8;
  packed_link_specifiers[8] = (unsigned char)relay->or_port;

  // LEGACYLink specifier
  // set the type
  packed_link_specifiers[9] = LEGACYLink;
  // set the length
  packed_link_specifiers[10] = ID_LENGTH;
  // copy the identity in
  memcpy( packed_link_specifiers + 11, relay->identity, ID_LENGTH );
}

int d_generate_packed_crosscert( unsigned char* destination, unsigned char* certified_key, ed25519_key* signing_key, unsigned char cert_type, long int valid_after ) {
  int res = 0;

  unsigned int idx;
  int wolf_succ;
  // set epoch hours to current epoch hours plus three hours later
  int epoch_hours = valid_after / 3600 + 3;
  unsigned char* tmp_body = malloc( sizeof( unsigned char ) * 140 );

  // set the version
  tmp_body[0] = 0x01;
  // set the cert type
  tmp_body[1] = cert_type;
  // set the expiration date, four bytes
  tmp_body[2] = (unsigned char)( epoch_hours >> 24 );
  tmp_body[3] = (unsigned char)( epoch_hours >> 16 );
  tmp_body[4] = (unsigned char)( epoch_hours >> 8 );
  tmp_body[5] = (unsigned char)epoch_hours;
  // set the cert key type, same a cert type
  tmp_body[6] = cert_type;
  // copy the certified key
  memcpy( tmp_body + 7, certified_key, 32 );
  // set n extensions to 1
  tmp_body[39] = 1;
  // set the ext length to key size
  tmp_body[40] = 0;
  tmp_body[41] = ED25519_PUB_KEY_SIZE;
  // set the ext type to 0x04
  tmp_body[42] = 0x04;
  // set ext flag to 1
  tmp_body[43] = 0x01;
  // copy the signing key
  idx = ED25519_PUB_KEY_SIZE;
  wolf_succ = wc_ed25519_export_public( signing_key, tmp_body + 44, &idx );

  if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );
#endif

    res = -1;
    goto cleanup;
  }

  idx = ED25519_SIG_SIZE;
  wolf_succ = wc_ed25519_sign_msg( tmp_body, 76, tmp_body + 76, &idx, signing_key );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign the ed crosscert, error code: %d", wolf_succ );
#endif

    res = -1;
    goto cleanup;
  }

  v_base_64_encode( (char*)destination, tmp_body, 140 );

cleanup:
  free( tmp_body );
  return res;
}

void v_ed_pubkey_from_curve_pubkey( unsigned char* output, const unsigned char* input, int sign_bit ) {
  unsigned char one[F25519_SIZE] = { 1 };
  unsigned char input_minus_1[F25519_SIZE];
  unsigned char input_plus_1[F25519_SIZE];
  unsigned char inverse_input_plus_1[F25519_SIZE];

  lm_sub( input_minus_1, input, one );
  lm_add( input_plus_1, input, one );
  lm_invert( inverse_input_plus_1, input_plus_1 );
  lm_mul( output, input_minus_1, inverse_input_plus_1 );
  output[31] = (!!sign_bit) << 7;
}

int d_router_establish_intro( OnionCircuit* circuit ) {
  int wolf_succ;
  unsigned int idx;
  int64_t ordered_digest_length = (int64_t)DIGEST_LEN;
  unsigned char ordered_digest_length_buffer[8];
  WC_RNG rng;
  Sha3 reusable_sha3;
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  Cell unpacked_cell;
  OnionMessage* onion_message;
  unsigned char* packed_cell;
  unsigned char* prefixed_cell;
  const char* prefix_str = "Tor establish-intro cell v1";

  circuit->intro_crypto = malloc( sizeof( IntroCrypto ) );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  wc_InitRng( &rng );
  wc_ed25519_init( &circuit->intro_crypto->auth_key );
  wc_curve25519_init( &circuit->intro_crypto->encrypt_key );

  wc_ed25519_make_key( &rng, 32, &circuit->intro_crypto->auth_key );
  wc_curve25519_make_key( &rng, 32, &circuit->intro_crypto->encrypt_key );

  wc_FreeRng( &rng );

  idx = ED25519_PUB_KEY_SIZE;
  wolf_succ = wc_ed25519_export_public( &circuit->intro_crypto->auth_key, tmp_pub_key, &idx );

  if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  unpacked_cell.circ_id = circuit->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_COMMAND_ESTABLISH_INTRO;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN + 2 + ED25519_SIG_SIZE;
  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadEstablishIntro ) );

  ( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->type = ESTABLISH_INTRO_CURRENT;
  ( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro = malloc( sizeof( EstablishIntroCurrent ) );

  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key_type = EDSHA3;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key_length = ED25519_PUB_KEY_SIZE;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key = malloc( sizeof( unsigned char ) * ED25519_PUB_KEY_SIZE );
  memcpy( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key, tmp_pub_key, ED25519_PUB_KEY_SIZE );
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->extension_count = 0;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->signature_length = ED25519_SIG_SIZE;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->signature = NULL;

  packed_cell = pack_and_free( &unpacked_cell );

  ESP_LOGE( MINITOR_TAG, "%lld", ordered_digest_length );
  ESP_LOGE( MINITOR_TAG, "%lld", (int64_t)DIGEST_LEN );

  ordered_digest_length_buffer[0] = (unsigned char)( ordered_digest_length >> 56 );
  ordered_digest_length_buffer[1] = (unsigned char)( ordered_digest_length >> 48 );
  ordered_digest_length_buffer[2] = (unsigned char)( ordered_digest_length >> 40 );
  ordered_digest_length_buffer[3] = (unsigned char)( ordered_digest_length >> 32 );
  ordered_digest_length_buffer[4] = (unsigned char)( ordered_digest_length >> 24 );
  ordered_digest_length_buffer[5] = (unsigned char)( ordered_digest_length >> 16 );
  ordered_digest_length_buffer[6] = (unsigned char)( ordered_digest_length >> 8 );
  ordered_digest_length_buffer[7] = (unsigned char)ordered_digest_length;

  /* wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)&ordered_digest_length, 8 ); */
  wc_Sha3_256_Update( &reusable_sha3, ordered_digest_length_buffer, sizeof( ordered_digest_length_buffer ) );
  wc_Sha3_256_Update( &reusable_sha3, circuit->relay_list.tail->relay_crypto->nonce, DIGEST_LEN );
  wc_Sha3_256_Update( &reusable_sha3, packed_cell + 5 + 11, 3 + ED25519_PUB_KEY_SIZE + 1 );
  wc_Sha3_256_Final( &reusable_sha3, packed_cell + 5 + 11 + 3 + ED25519_PUB_KEY_SIZE + 1 );

  prefixed_cell = malloc( sizeof( unsigned char ) * ( strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN ) );
  memcpy( prefixed_cell, prefix_str, strlen( prefix_str ) );
  memcpy( prefixed_cell + strlen( prefix_str ), packed_cell + 5 + 11, 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN );

  idx = ED25519_SIG_SIZE;
  wolf_succ = wc_ed25519_sign_msg(
    prefixed_cell,
    strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN,
    packed_cell + 5 + 11 + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN + 2,
    &idx,
    &circuit->intro_crypto->auth_key
  );

  free( prefixed_cell );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate establish intro signature, error code: %d", wolf_succ );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "Sending establish intro to %d", circuit->relay_list.tail->relay->or_port );

  if ( d_send_packed_relay_cell_and_free( circuit->ssl, packed_cell, &circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_COMMAND_ESTABLISH_INTRO cell" );
#endif
  }

  while ( 1 ) {
    ESP_LOGE( MINITOR_TAG, "Waiting for intro response" );
    xQueueReceive( circuit->rx_queue, &onion_message, portMAX_DELAY );

    if ( onion_message->type != ONION_CELL || ( (Cell*)onion_message->data )->circ_id != circuit->circ_id ) {
      xQueueSendToBack( circuit->rx_queue, (void*)(&onion_message), portMAX_DELAY );
    } else {
      break;
    }
  }

  ESP_LOGE( MINITOR_TAG, "got cell command %d", ( (Cell*)onion_message->data )->command );

  if ( ( (Cell*)onion_message->data )->command != RELAY ) {
    return -1;
  }

  if ( ( (Cell*)onion_message->data )->command == RELAY ) {
    ESP_LOGE( MINITOR_TAG, "got relay command %d", ( (PayloadRelay*)( (Cell*)onion_message->data )->payload )->command );
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  free_cell( (Cell*)onion_message->data );
  free( onion_message->data );
  free( onion_message );

  return 0;
}

int d_derive_blinded_key( ed25519_key* blinded_key, ed25519_key* master_key, int64_t period_number, int64_t period_length, unsigned char* secret, int secret_length ) {
  int i;
  int wolf_succ;
  unsigned int idx;
  unsigned int idy;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  Sha512 reusable_sha512;
  unsigned char reusable_sha512_sum[WC_SHA512_DIGEST_SIZE];
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  unsigned char tmp_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char out_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char tmp_64_array[8];
  unsigned char zero[32] = { 0 };

  memset( zero, 0, 32 );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );
  wc_InitSha512( &reusable_sha512 );

  idx = ED25519_PRV_KEY_SIZE;
  idy = ED25519_PUB_KEY_SIZE;
  wolf_succ = wc_ed25519_export_key( master_key, out_priv_key, &idx, tmp_pub_key, &idy );

  if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export master key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wolf_succ = wc_Sha512Hash( out_priv_key, ED25519_KEY_SIZE, tmp_priv_key );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to expand master key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"Derive temporary signing key", strlen( "Derive temporary signing key" ) + 1 );
  wc_Sha3_256_Update( &reusable_sha3, tmp_pub_key, ED25519_PUB_KEY_SIZE );

  if ( secret != NULL ) {
    wc_Sha3_256_Update( &reusable_sha3, secret, secret_length );
  }

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_ED_BASEPOINT, HS_ED_BASEPOINT_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"key-blind", strlen( "key-blind" ) );

  tmp_64_array[0] = (unsigned char)( period_number >> 56 );
  tmp_64_array[1] = (unsigned char)( period_number >> 48 );
  tmp_64_array[2] = (unsigned char)( period_number >> 40 );
  tmp_64_array[3] = (unsigned char)( period_number >> 32 );
  tmp_64_array[4] = (unsigned char)( period_number >> 24 );
  tmp_64_array[5] = (unsigned char)( period_number >> 16 );
  tmp_64_array[6] = (unsigned char)( period_number >> 8 );
  tmp_64_array[7] = (unsigned char)period_number;

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_array, sizeof( tmp_64_array ) );

  tmp_64_array[0] = (unsigned char)( period_length >> 56 );
  tmp_64_array[1] = (unsigned char)( period_length >> 48 );
  tmp_64_array[2] = (unsigned char)( period_length >> 40 );
  tmp_64_array[3] = (unsigned char)( period_length >> 32 );
  tmp_64_array[4] = (unsigned char)( period_length >> 24 );
  tmp_64_array[5] = (unsigned char)( period_length >> 16 );
  tmp_64_array[6] = (unsigned char)( period_length >> 8 );
  tmp_64_array[7] = (unsigned char)period_length;

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_array, sizeof( tmp_64_array ) );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  ESP_LOGE( MINITOR_TAG, "param" );

  for ( i = 0; i < WC_SHA3_256_DIGEST_SIZE; i++ ) {
    ESP_LOGE( MINITOR_TAG, "%.2x", reusable_sha3_sum[i] );
  }

  reusable_sha3_sum[0] &= 248;
  reusable_sha3_sum[31] &= 63;
  reusable_sha3_sum[31] |= 64;

  sc_muladd( out_priv_key, tmp_priv_key, reusable_sha3_sum, zero );

  wc_Sha512Update( &reusable_sha512, (unsigned char*)"Derive temporary signing key hash input", strlen( "Derive temporary signing key hash input" ) );
  wc_Sha512Update( &reusable_sha512, tmp_priv_key + 32, 32 );
  wc_Sha512Final( &reusable_sha512, reusable_sha512_sum );

  memcpy( out_priv_key + 32, reusable_sha512_sum, WC_SHA3_256_DIGEST_SIZE );

  memcpy( blinded_key->k, out_priv_key, ED25519_PRV_KEY_SIZE );

  wc_ed25519_make_public( blinded_key, blinded_key->p, ED25519_PUB_KEY_SIZE );

  blinded_key->pubKeySet = 1;

  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Sha512Free( &reusable_sha512 );

  return 0;
}

int d_generate_hs_keys( OnionService* onion_service, const char* onion_service_directory ) {
  int fd;
  int wolf_succ;
  unsigned int idx;
  unsigned int idy;
  unsigned char version = 0x03;
  struct stat st;
  WC_RNG rng;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  unsigned char tmp_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char raw_onion_address[ED25519_PUB_KEY_SIZE + 2 + 1];
  char onion_address[63] = { 0 };
  char working_file[256];

  strcpy( onion_address + 56, ".onion" );

  wc_ed25519_init( &onion_service->master_key );
  onion_service->master_key.no_clamp = 1;

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  /* rmdir( onion_service_directory ); */

  // directory doesn't exist, create the keys
  if ( stat( onion_service_directory, &st ) == -1 ) {
    if ( mkdir( onion_service_directory, 0755 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to create %s for onion service, errno: %d", onion_service_directory, errno );
#endif

      return -1;
    }

    wc_InitRng( &rng );

    wc_ed25519_make_key( &rng, 32, &onion_service->master_key );

    wc_FreeRng( &rng );

    idx = ED25519_PRV_KEY_SIZE;
    idy = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_key( &onion_service->master_key, tmp_priv_key, &idx, tmp_pub_key, &idy );

    if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export service master key, error code: %d", wolf_succ );
#endif

      return -1;
    }

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)".onion checksum", strlen( ".onion checksum" ) );
    wc_Sha3_256_Update( &reusable_sha3, tmp_pub_key, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, &version, 1 );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    memcpy( raw_onion_address, tmp_pub_key, ED25519_PUB_KEY_SIZE );
    memcpy( raw_onion_address + ED25519_PUB_KEY_SIZE, reusable_sha3_sum, 2 );
    raw_onion_address[ED25519_PUB_KEY_SIZE + 2] = version;

    v_base_32_encode( onion_address, raw_onion_address, sizeof( raw_onion_address ) );

    ESP_LOGE( MINITOR_TAG, "onion address: %s", onion_address );

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/hostname" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, onion_address, sizeof( char ) * strlen( onion_address ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_pub_key, ED25519_PUB_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_priv_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }
  // directory exists, load the keys
  } else {
    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( read( fd, tmp_priv_key, sizeof( char ) * ED25519_PUB_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }


    if ( read( fd, tmp_pub_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    wolf_succ = wc_ed25519_import_private_key( tmp_priv_key, ED25519_PRV_KEY_SIZE, tmp_pub_key, ED25519_PUB_KEY_SIZE, &onion_service->master_key );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to import ed25519 key, error code: %d", wolf_succ );
#endif

      return -1;
    }
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  return 0;
}
