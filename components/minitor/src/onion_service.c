#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "../include/config.h"
#include "../h/onion_service.h"
#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/encoding.h"
#include "../h/cell.h"
#include "../h/circuit.h"
#include "../h/connections.h"
#include "../h/core.h"
#include "../h/models/relay.h"
#include "../h/models/revision_counter.h"

/*
void v_handle_onion_service( void* pv_parameters )
{
  time_t now;
  unsigned int hsdir_interval;
  OnionService* onion_service = (OnionService*)pv_parameters;
  OnionMessage* onion_message;

  while ( 1 )
  {
    if ( xQueueReceive( onion_service->rx_queue, &onion_message, 1000 * 60 / portTICK_PERIOD_MS ) == pdTRUE )
    {
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
        case PACKED_CELL:
          break;
      }

      free( onion_message->data );
      free( onion_message );
    }
  }
}
*/

void v_onion_service_handle_local_tcp_data( OnionCircuit* circuit, ServiceTcpTraffic* tcp_traffic )
{
  int i;
  Cell unpacked_cell;
  unsigned char* packed_cell;

  unpacked_cell.circ_id = tcp_traffic->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = tcp_traffic->stream_id;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;

  if ( tcp_traffic->length == 0 )
  {
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_END;
    ( (PayloadRelay*)unpacked_cell.payload )->length = 1;
    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadEnd ) );

    ( (RelayPayloadEnd*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->reason = REASON_DONE;
  }
  else
  {
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_DATA;
    ( (PayloadRelay*)unpacked_cell.payload )->length = (unsigned short)tcp_traffic->length;
    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadData ) );

    ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload = tcp_traffic->data;
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( d_send_packed_relay_cell_and_free( circuit->or_connection, packed_cell, &circuit->relay_list, circuit->hs_crypto ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA" );
#endif
  }
}

void v_onion_service_handle_cell( OnionCircuit* circuit, Cell* unpacked_cell )
{
  switch( unpacked_cell->command )
  {
    case RELAY:
      switch( ( (PayloadRelay*)unpacked_cell->payload )->command )
      {
        // TODO when a relay_begin comes in, create a task to block on the local tcp stream
        case RELAY_BEGIN:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_BEGIN!" );

          if ( d_onion_service_handle_relay_begin( circuit, unpacked_cell ) < 0 )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_BEGIN cell" );
#endif
          }

          break;
        // TODO when a relay_data comes in, send the data to the local tcp stream
        case RELAY_DATA:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_DATA!" );
          if
          (
            d_forward_to_local_connection(
              unpacked_cell->circ_id,
              ( (PayloadRelay*)unpacked_cell->payload )->stream_id,
              ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->payload,
              ( (PayloadRelay*)unpacked_cell->payload )->length
            ) < 0
          )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_DATA cell" );
#endif
          }

          break;
        case RELAY_END:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_END!" );
          v_cleanup_local_connection( unpacked_cell->circ_id, ( (PayloadRelay*)unpacked_cell->payload )->stream_id );

          break;
        case RELAY_TRUNCATED:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_TRUNCATED!" );

          if ( d_onion_service_handle_relay_truncated( circuit, unpacked_cell ) < 0 )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_END cell" );
#endif
          }

          break;
        case RELAY_DROP:
          ESP_LOGE( MINITOR_TAG, "Got a RELAY_DROP!" );
          break;
        // when an intro request comes in, respond to it
        case RELAY_COMMAND_INTRODUCE2:
          if ( d_onion_service_handle_introduce_2( circuit, unpacked_cell ) < 0 )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to handle RELAY_COMMAND_INTRODUCE2 cell" );
#endif
          }

          break;
        default:
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Unequiped to handle relay command %d", ( (PayloadRelay*)unpacked_cell->payload )->command );
#endif
      }

      break;
    // TODO when a destroy comes in close and clean the circuit and local tcp stream
    default:
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Unequiped to handle cell command %d", unpacked_cell->command );
#endif
  }
}

int d_onion_service_handle_relay_begin( OnionCircuit* rend_circuit, Cell* unpacked_cell )
{
  Cell unpacked_connected_cell;
  unsigned char* packed_cell;

  if ( ( (RelayPayloadBegin*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->port != rend_circuit->service->exit_port && ( (RelayPayloadBegin*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->port != 443 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "request was for the wrong port: %d, looking for: %d", ( (RelayPayloadBegin*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->port, rend_circuit->service->exit_port );
#endif

    return -1;
  }

  if ( d_create_local_connection( unpacked_cell->circ_id, ( (PayloadRelay*)unpacked_cell->payload )->stream_id, rend_circuit->service->local_port ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create local connection" );
#endif

    return -1;
  }

  unpacked_connected_cell.circ_id = unpacked_cell->circ_id;
  unpacked_connected_cell.command = RELAY;
  unpacked_connected_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_connected_cell.payload )->command = RELAY_CONNECTED;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->stream_id = ( (PayloadRelay*)unpacked_cell->payload )->stream_id;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_connected_cell.payload )->length = 0;

  packed_cell = pack_and_free( &unpacked_connected_cell );

  if ( d_send_packed_relay_cell_and_free( rend_circuit->or_connection, packed_cell, &rend_circuit->relay_list, rend_circuit->hs_crypto ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_CONNECTED" );
#endif

    return -1;
  }

  return 0;
}

int d_onion_service_handle_relay_truncated( OnionCircuit* rend_circuit, Cell* unpacked_cell )
{
  int i;
  DoublyLinkedOnionRelay* dl_relay;

  v_cleanup_local_connections_by_circ_id( unpacked_cell->circ_id );

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  v_remove_circuit_from_list( rend_circuit, &onion_circuits );

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  d_destroy_onion_circuit( rend_circuit );
  free( rend_circuit );

  return 0;
}

int d_onion_service_handle_introduce_2( OnionCircuit* intro_circuit, Cell* unpacked_cell )
{
  int ret = 0;
  int i;
  int wolf_succ;
  time_t now;
  unsigned char auth_input_mac[MAC_LEN];
  WC_RNG rng;
  curve25519_key hs_handshake_key;
  curve25519_key client_handshake_key;
  DecryptedIntroduce2 unpacked_introduce_data;
  DoublyLinkedRendezvousCookie* db_rendezvous_cookie;
  OnionRelay* rend_relay;
  HsCrypto* hs_crypto;
  OnionCircuit* rend_circuit;
  DoublyLinkedOnionRelay* dl_relay;

  ESP_LOGE( MINITOR_TAG, "circ_id: %.8x", unpacked_cell->circ_id );

  time( &now );

  ESP_LOGE( MINITOR_TAG, "now: %ld, timestap: %ld", now, intro_circuit->service->rend_timestamp );

  if ( now - intro_circuit->service->rend_timestamp < 20 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Rate limit in effect, dropping intro" );
#endif

    return -1;
  }

  wc_curve25519_init( &client_handshake_key );
  wc_curve25519_init( &hs_handshake_key );

  wc_InitRng( &rng );

  if ( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_type != EDSHA3 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key type for RELAY_COMMAND_INTRODUCE2 was not EDSHA3" );
#endif

    ret = -1;
    goto clean_crypto;
  }

  if ( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key_length != 32 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key length for RELAY_COMMAND_INTRODUCE2 was not 32" );
#endif

    ret = -1;
    goto clean_crypto;
  }

  if ( memcmp( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->auth_key, intro_circuit->intro_crypto->auth_key.p, 32 ) != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Auth key for RELAY_COMMAND_INTRODUCE2 does not match" );
#endif

    ret = -1;
    goto clean_crypto;
  }

  wolf_succ = wc_curve25519_import_public_ex( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->client_pk, PK_PUBKEY_LEN, &client_handshake_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import client public key, error code %d", wolf_succ );
#endif

    ret = -1;
    goto clean_crypto;
  }

  // verify and decrypt
  if ( d_verify_and_decrypt_introduce_2( intro_circuit->service, unpacked_cell, intro_circuit, &client_handshake_key ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to verify and decrypt RELAY_COMMAND_INTRODUCE2" );
#endif

    ret = -1;
    goto clean_crypto;
  }

  // unpack the decrypted secction
  if ( d_unpack_introduce_2_data( ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, &unpacked_introduce_data ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to unpack RELAY_COMMAND_INTRODUCE2 decrypted data" );
#endif

    ret = -1;
    goto clean_crypto;
  }

  db_rendezvous_cookie = intro_circuit->service->rendezvous_cookies.head;

  for ( i = 0; i < intro_circuit->service->rendezvous_cookies.length; i++ )
  {
    if ( memcmp( db_rendezvous_cookie->rendezvous_cookie, unpacked_introduce_data.rendezvous_cookie, 20 ) == 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Got a replay, silently dropping" );
#endif

      goto clean_introduce;
    }

    db_rendezvous_cookie = db_rendezvous_cookie->next;
  }

  ESP_LOGE( MINITOR_TAG, "Got new cookie" );

  db_rendezvous_cookie = malloc( sizeof( DoublyLinkedRendezvousCookie ) );

  memcpy( db_rendezvous_cookie->rendezvous_cookie, unpacked_introduce_data.rendezvous_cookie, 20 );

  v_add_rendezvous_cookie_to_list( db_rendezvous_cookie, &intro_circuit->service->rendezvous_cookies );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &hs_handshake_key );

  if ( wolf_succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make hs_handshake_key, error code %d", wolf_succ );
#endif

    ret = -1;
    goto clean_introduce;
  }

  hs_crypto = malloc( sizeof( HsCrypto ) );

  ESP_LOGE( MINITOR_TAG, "Finishing ntor handshake" );

  if ( d_hs_ntor_handshake_finish( unpacked_cell, intro_circuit, &hs_handshake_key, &client_handshake_key, hs_crypto, auth_input_mac ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to finish the RELAY_COMMAND_INTRODUCE2 ntor handshake" );
#endif

    free( hs_crypto );

    ret = -1;
    goto clean_introduce;
  }

  // extend to the specified relay and send the handshake reply
  rend_relay = malloc( sizeof( OnionRelay ) );
  rend_relay->address = 0;
  rend_relay->or_port = 0;

  memcpy( rend_relay->ntor_onion_key, unpacked_introduce_data.onion_key, 32 );

  for ( i = 0; i < unpacked_introduce_data.specifier_count; i++ )
  {
    if ( unpacked_introduce_data.link_specifiers[i]->type == IPv4Link )
    {
      // comes in big endian, lwip wants it little endian
      rend_relay->address |= (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[0];
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[1] ) << 8;
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[2] ) << 16;
      rend_relay->address |= ( (unsigned int)unpacked_introduce_data.link_specifiers[i]->specifier[3] ) << 24;

      rend_relay->or_port |= ( (unsigned short)unpacked_introduce_data.link_specifiers[i]->specifier[4] ) << 8;
      rend_relay->or_port |= (unsigned short)unpacked_introduce_data.link_specifiers[i]->specifier[5];
    }
    else if ( unpacked_introduce_data.link_specifiers[i]->type == LEGACYLink )
    {
      memcpy( rend_relay->identity, unpacked_introduce_data.link_specifiers[i]->specifier, ID_LENGTH );
    }
  }

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  rend_circuit = onion_circuits;

  while ( rend_circuit != NULL )
  {
    if ( rend_circuit->status == CIRCUIT_STANDBY )
    {
      break;
    }

    rend_circuit = rend_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  memcpy( hs_crypto->rendezvous_cookie, unpacked_introduce_data.rendezvous_cookie, 20 );
  memcpy( hs_crypto->point, hs_handshake_key.p.point, PK_PUBKEY_LEN );
  memcpy( hs_crypto->auth_input_mac, auth_input_mac, MAC_LEN );

  if ( rend_circuit == NULL )
  {
    ESP_LOGE( MINITOR_TAG, "Creating new rend circuit" );

    v_send_init_circuit( 2, CIRCUIT_RENDEZVOUS, intro_circuit->service, 0, 0, NULL, rend_relay, hs_crypto );
  }
  else
  {
    dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    dl_relay->relay = rend_relay;

    ESP_LOGE( MINITOR_TAG, "Using existing rend circuit" );

    v_add_relay_to_list( dl_relay, &rend_circuit->relay_list );

    if ( d_router_extend2( rend_circuit, rend_circuit->relay_list.built_length ) < 0 )
    {
      wc_Sha3_256_Free( &hs_crypto->hs_running_sha_forward );
      wc_Sha3_256_Free( &hs_crypto->hs_running_sha_backward );
      wc_AesFree( &hs_crypto->hs_aes_forward );
      wc_AesFree( &hs_crypto->hs_aes_backward );

      free( hs_crypto );

      // MUTEX TAKE
      xSemaphoreTake( circuits_mutex, portMAX_DELAY );

      v_remove_circuit_from_list( rend_circuit, &onion_circuits );

      xSemaphoreGive( circuits_mutex );
      // MUTEX GIVE

      d_destroy_onion_circuit( rend_circuit );

      free( rend_circuit );

      ret = -1;
    }
    else
    {
      rend_circuit->service = intro_circuit->service;
      rend_circuit->status = CIRCUIT_EXTENDED;
      rend_circuit->target_status = CIRCUIT_RENDEZVOUS;
      rend_circuit->hs_crypto = hs_crypto;
    }
  }

  /*
  // make a new standby circuit regardless
  v_send_init_circuit( 1, CIRCUIT_STANDBY, NULL, 0, 0, NULL, NULL, NULL );
  */

  time( &now );
  intro_circuit->service->rend_timestamp = now;

clean_introduce:
  v_free_introduce_2_data( &unpacked_introduce_data );

clean_crypto:
  wc_FreeRng( &rng );

  wc_curve25519_free( &client_handshake_key );
  wc_curve25519_free( &hs_handshake_key );

  return ret;
}

int d_router_join_rendezvous( OnionCircuit* rend_circuit, unsigned char* rendezvous_cookie, unsigned char* hs_pub_key, unsigned char* auth_input_mac )
{
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

  if ( d_send_packed_relay_cell_and_free( rend_circuit->or_connection, packed_cell, &rend_circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send the RELAY_COMMAND_RENDEZVOUS1 cell" );
#endif

    return -1;
  }

  return 0;
}

int d_verify_and_decrypt_introduce_2( OnionService* onion_service, Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* client_handshake_key )
{
  int ret = 0;
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

    ret = -1;
    goto finish;
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

    ret = -1;
    goto finish;
  }

  // decrypt the encrypted section
  wc_AesSetKeyDirect( &aes_key, hs_keys, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wolf_succ = wc_AesCtrEncrypt( &aes_key, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_data, ( (RelayPayloadIntroduce1*)( (PayloadRelay*)unpacked_cell->payload )->relay_payload )->encrypted_length );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY_COMMAND_INTRODUCE2 encrypted data, error code: %d", wolf_succ );
#endif

    ret = -1;
  }

finish:
  wc_Shake256_Free( &reusable_shake );
  wc_Sha3_256_Free( &reusable_sha3 );

  free( intro_secret_hs_input );
  free( info );
  free( hs_keys );

  return ret;
}

int d_hs_ntor_handshake_finish( Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* hs_handshake_key, curve25519_key* client_handshake_key, HsCrypto* hs_crypto, unsigned char* auth_input_mac )
{
  int ret = 0;
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

  ESP_LOGE( MINITOR_TAG, "Init" );

  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  ESP_LOGE( MINITOR_TAG, "Shared secret" );

  // compute rend_secret_hs_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( hs_handshake_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );
#endif

    ret = -1;
    goto finish;
  }

  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  ESP_LOGE( MINITOR_TAG, "Shared secret" );

  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( &intro_circuit->intro_crypto->encrypt_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );
#endif

    ret = -1;
    goto finish;
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

  wc_InitSha3_256( &hs_crypto->hs_running_sha_forward, NULL, INVALID_DEVID );
  wc_InitSha3_256( &hs_crypto->hs_running_sha_backward, NULL, INVALID_DEVID );
  wc_AesInit( &hs_crypto->hs_aes_forward, NULL, INVALID_DEVID );
  wc_AesInit( &hs_crypto->hs_aes_backward, NULL, INVALID_DEVID );

  wc_Sha3_256_Update( &hs_crypto->hs_running_sha_forward, expanded_keys, WC_SHA3_256_DIGEST_SIZE );

  wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, expanded_keys + WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_DIGEST_SIZE );

  wc_AesSetKeyDirect( &hs_crypto->hs_aes_forward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ), AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wc_AesSetKeyDirect( &hs_crypto->hs_aes_backward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ) + AES_256_KEY_SIZE, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

finish:
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );

  free( rend_secret_hs_input );
  free( hs_key_seed );
  free( expanded_keys );

  return ret;
}

/*
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
*/

static DoublyLinkedOnionRelayList* px_get_relays_by_hash( uint8_t* id_hash, int desired_count, DoublyLinkedOnionRelayList* used_relays, int next )
{
  int i;
  DoublyLinkedOnionRelay* db_tmp_relay;
  DoublyLinkedOnionRelayList* relay_list = malloc( sizeof( DoublyLinkedOnionRelayList ) );
  relay_list->length = 0;
  relay_list->head = NULL;
  relay_list->tail = NULL;

  for ( i = 0; i < desired_count; i++ )
  {
    db_tmp_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );

    db_tmp_relay->relay = NULL;
    db_tmp_relay->relay = px_get_hsdir_relay_by_id_hash( id_hash, i, used_relays, next );

    if ( db_tmp_relay->relay == NULL )
    {
      free( db_tmp_relay );

      ESP_LOGE( MINITOR_TAG, "Failed to get hsdir relay by id_hash" );
      goto cleanup;
    }

    v_add_relay_to_list( db_tmp_relay, relay_list );

    db_tmp_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    db_tmp_relay->relay = malloc( sizeof( OnionRelay ) );

    memcpy( db_tmp_relay->relay->identity, relay_list->tail->relay->identity, ID_LENGTH );

    v_add_relay_to_list( db_tmp_relay, used_relays );
  }

  return relay_list;

cleanup:
  db_tmp_relay = relay_list->head;

  for ( i = 0; i < relay_list->length; i++ )
  {
    free( db_tmp_relay->relay );

    if ( i == relay_list->length - 1 )
    {
      free( db_tmp_relay );
    }
    else
    {
      db_tmp_relay = db_tmp_relay->next;
      free( db_tmp_relay->previous );
    }
  }

  free( relay_list );

  return NULL;
}

static DoublyLinkedOnionRelayList* px_get_target_relays( unsigned int hsdir_n_replicas, unsigned char* blinded_pub_key, int time_period, unsigned int hsdir_interval, unsigned int hsdir_spread_store, int next )
{
  int i;
  int j;
  int to_store;
  unsigned char tmp_64_buffer[8];
  unsigned char hs_index[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedOnionRelayList used_relays = {
    .head = NULL,
    .tail = NULL,
    .length = 0,
  };
  Sha3 reusable_sha3;
  DoublyLinkedOnionRelayList* hsdir_index_list;
  DoublyLinkedOnionRelay* hsdir_relay_node;
  DoublyLinkedOnionRelay* next_hsdir_relay_node;
  DoublyLinkedOnionRelay* tmp_relay_node;
  DoublyLinkedOnionRelayList* target_relays = malloc( sizeof( DoublyLinkedOnionRelayList ) );

  memset( target_relays, 0, sizeof( DoublyLinkedOnionRelayList ) );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  for ( i = 0; i < hsdir_n_replicas; i++ )
  {
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

    wc_Sha3_256_Final( &reusable_sha3, hs_index );

    {
      ESP_LOGE( MINITOR_TAG, "" );
      ESP_LOGE( MINITOR_TAG, "hs_index:" );

      for ( j = 0; j < WC_SHA3_256_DIGEST_SIZE; j++ )
      {
        ESP_LOGE( MINITOR_TAG, "%.2x", hs_index[j] );
      }

      ESP_LOGE( MINITOR_TAG, "" );
    }

    to_store = hsdir_spread_store;

    hsdir_index_list = px_get_hsdir_relays_by_id_hash( hs_index, hsdir_spread_store, next, target_relays );

    if ( hsdir_index_list == NULL )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to get hsdir_index_list" );

      while ( target_relays->length > 0 )
      {
        v_pop_relay_from_list_back( target_relays );
      }

      free( target_relays );

      target_relays = NULL;

      goto cleanup;
    }

    hsdir_relay_node = hsdir_index_list->head;

    for ( j = 0; j < hsdir_index_list->length && to_store > 0; j++ )
    {
      next_hsdir_relay_node = hsdir_relay_node->next;

      v_add_relay_to_list( hsdir_relay_node, target_relays );

      ESP_LOGE( MINITOR_TAG, "Target identity: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
        hsdir_relay_node->relay->identity[0],
        hsdir_relay_node->relay->identity[1],
        hsdir_relay_node->relay->identity[2],
        hsdir_relay_node->relay->identity[3],
        hsdir_relay_node->relay->identity[4],
        hsdir_relay_node->relay->identity[5],
        hsdir_relay_node->relay->identity[6],
        hsdir_relay_node->relay->identity[7],
        hsdir_relay_node->relay->identity[8],
        hsdir_relay_node->relay->identity[9],
        hsdir_relay_node->relay->identity[10],
        hsdir_relay_node->relay->identity[11],
        hsdir_relay_node->relay->identity[12],
        hsdir_relay_node->relay->identity[13],
        hsdir_relay_node->relay->identity[14],
        hsdir_relay_node->relay->identity[15],
        hsdir_relay_node->relay->identity[16],
        hsdir_relay_node->relay->identity[17],
        hsdir_relay_node->relay->identity[18],
        hsdir_relay_node->relay->identity[19]
      );

      hsdir_relay_node = next_hsdir_relay_node;

      to_store--;
    }

    for ( ; j < hsdir_index_list->length; j++ )
    {
      free( hsdir_relay_node );

      hsdir_relay_node = hsdir_relay_node->next;
    }

    free( hsdir_index_list );
  }

cleanup:
  while ( used_relays.length > 0 )
  {
    v_pop_relay_from_list_back( &used_relays );
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  return target_relays;
}

/*
int d_send_descriptors( unsigned char* descriptor_text, int descriptor_length, DoublyLinkedOnionRelayList* target_relays )
{
  int ret = 0;
  int i;
  int j;
  OnionRelay* target_relay;
  OnionRelay* start_node;
  DoublyLinkedOnionRelay* target_dl_relay;
  DoublyLinkedOnionRelay* tmp_dl_relay;

  start_node = px_get_random_hsdir_relay( 1, target_relays, NULL );

  target_dl_relay = target_relays->head;

  while ( target_dl_relay != NULL )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = INIT_CIRCUIT;
    onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

    ((CreateCircuitRequest*)onion_message->data)->length = 3;
    ((CreateCircuitRequest*)onion_message->data)->target_status = CIRCUIT_HSDIR_BEGIN_DIR;
    ((CreateCircuitRequest*)onion_message->data)->dl_service = dl_service;
    ((CreateCircuitRequest*)onion_message->data)->start_relay = start_node;
    ((CreateCircuitRequest*)onion_message->data)->destination_relay = target_dl_relay->relay;
  }

  publish_circuit = malloc( sizeof( OnionCircuit ) );

  memset( publish_circuit, 0, sizeof( OnionCircuit ) );

  publish_circuit->rx_queue = xQueueCreate( 2, sizeof( OnionMessage* ) );

  db_target_relay = target_relays->head;

  for ( i = 0; i < target_relays->length; i++ )
  {
    if ( publish_circuit->or_connection != NULL )
    {
      tmp_relay_node = publish_circuit->relay_list.head;

      for ( j = 0; j < publish_circuit->relay_list.length; j++ )
      {
        if ( memcmp( tmp_relay_node->relay->identity, db_target_relay->relay->identity, ID_LENGTH ) == 0 || j == publish_circuit->relay_list.length - 1 )
        {
          if ( j == 0 )
          {
            ESP_LOGE( MINITOR_TAG, "First matches, destroying circuit" );

            if ( d_destroy_onion_circuit( publish_circuit ) < 0 )
            {
#ifdef DEBUG_MINITOR
              ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif
            }

            publish_circuit->or_connection = NULL;
          }
          else
          {
            ESP_LOGE( MINITOR_TAG, "Truncating to length %d", j );

            if ( d_truncate_onion_circuit( publish_circuit, j ) < 0 )
            {
#ifdef DEBUG_MINITOR
              ESP_LOGE( MINITOR_TAG, "Failed to truncate publish circuit" );
#endif

              if ( d_destroy_onion_circuit( publish_circuit ) < 0 )
              {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif
              }

              publish_circuit->or_connection = NULL;

              break;
            }

            ESP_LOGE( MINITOR_TAG, "Trying to extend to %d", db_target_relay->relay->or_port );

            target_relay = malloc( sizeof( OnionRelay ) );
            memcpy( target_relay, db_target_relay->relay, sizeof( OnionRelay ) );

            if ( d_extend_onion_circuit_to( publish_circuit, 3, target_relay ) < 0 )
            {
#ifdef DEBUG_MINITOR
              ESP_LOGE( MINITOR_TAG, "Failed to extend publish circuit" );
#endif

              if ( d_destroy_onion_circuit( publish_circuit ) < 0 )
              {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif
              }

              publish_circuit->or_connection = NULL;
              ESP_LOGE( MINITOR_TAG, "Failed to extend to target, moving on" );
              goto next;
            }
          }

          break;
        }

        tmp_relay_node = tmp_relay_node->next;
      }
    }

    while ( publish_circuit->or_connection == NULL )
    {
      ESP_LOGE( MINITOR_TAG, "Trying to build new connection" );
      target_relay = malloc( sizeof( OnionRelay ) );
      memcpy( target_relay, db_target_relay->relay, sizeof( OnionRelay ) );

      if ( start_node != NULL )
      {
        if ( d_build_onion_circuit_to( publish_circuit, 1, start_node ) < 0 )
        {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to build publish circuit to start node" );
#endif
          publish_circuit->or_connection = NULL;
        }
        else if ( d_extend_onion_circuit_to( publish_circuit, 3, target_relay ) < 0 )
        {
#ifdef DEBUG_MINITOR
          ESP_LOGE( MINITOR_TAG, "Failed to extend publish circuit from start node: %d %d %d", publish_circuit->relay_list.head->relay->or_port, publish_circuit->relay_list.head->next->relay->or_port, publish_circuit->relay_list.head->next->next->relay->or_port );
#endif

          if ( d_destroy_onion_circuit( publish_circuit ) < 0 )
          {
#ifdef DEBUG_MINITOR
            ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif
          }

          start_node = NULL;
          publish_circuit->or_connection = NULL;
          ESP_LOGE( MINITOR_TAG, "Failed to extend to target, moving on" );
          goto next;
        }

        start_node = NULL;
      }
      else if ( d_build_onion_circuit_to( publish_circuit, 3, target_relay ) < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to build publish circuit" );
#endif

        publish_circuit->or_connection = NULL;
        ESP_LOGE( MINITOR_TAG, "Failed to extend to target, moving on" );
        goto next;
      }
    }

    if ( d_post_descriptor( descriptor_text, descriptor_length, publish_circuit ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to post descriptor" );
#endif

      ret = -1;
      goto finish;
    }

next:
    db_target_relay = db_target_relay->next;
  }

  if ( publish_circuit->or_connection != NULL && d_destroy_onion_circuit( publish_circuit ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to destroy publish circuit" );
#endif
  }

finish:
  free( start_node );

  vQueueDelete( publish_circuit->rx_queue );
  free( publish_circuit );

  ESP_LOGE( MINITOR_TAG, "Done sending descriptors" );

  return ret;
}
*/

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

/*
int d_post_descriptor( unsigned char* descriptor_text, int descriptor_length, OnionCircuit* publish_circuit )
{
  char* REQUEST;
  char* ipv4_string;
  const char* REQUEST_CONST = "POST /tor/hs/3/publish HTTP/1.0\r\n"
    "Host: \r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: "
    ;
  const char* header_end = "\r\n\r\n";

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
  ESP_LOGE( MINITOR_TAG, "Trying to malloc payload" );
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_BEGIN_DIR;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 0;

  packed_cell = pack_and_free( &unpacked_cell );

  ESP_LOGE( MINITOR_TAG, "Trying to send relay" );

  if ( d_send_packed_relay_cell_and_free( publish_circuit->or_connection, packed_cell, &publish_circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_BEGIN_DIR cell" );
#endif

    return -1;
  }

  if ( d_recv_cell( publish_circuit, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_CONNECTED cell" );
#endif

    return -1;
  }

  if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_CONNECTED )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Didn't get RELAY_CONNECTED back" );
#endif

    free_cell( &unpacked_cell );

    return -1;
  }

  free_cell( &unpacked_cell );

  sprintf( content_length, "%d", descriptor_length );

  http_header_length = strlen( REQUEST ) + strlen( content_length ) + strlen( header_end );
  tx_limit = http_header_length + descriptor_length;

  unpacked_cell.command = RELAY;

  while ( total_tx_length < tx_limit )
  {
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
    }
    else
    {
      memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, descriptor_text + total_tx_length - http_header_length, ( (PayloadRelay*)unpacked_cell.payload )->length );
      total_tx_length += ( (PayloadRelay*)unpacked_cell.payload )->length;
    }

    //for ( i = 0; i < ( (PayloadRelay*)unpacked_cell.payload )->length; i++ ) {
      //putchar( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload[i] );
    //}

    //putchar( '\n' );

    packed_cell = pack_and_free( &unpacked_cell );

    if ( d_send_packed_relay_cell_and_free( publish_circuit->or_connection, packed_cell, &publish_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA cell" );
#endif

      return -1;
    }
  }

  if ( d_recv_cell( publish_circuit, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_DATA cell" );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "cell command %d", unpacked_cell.command );
  ESP_LOGE( MINITOR_TAG, "relay command %d", ( (PayloadRelay*)unpacked_cell.payload )->command );

  ESP_LOGE( MINITOR_TAG, "%.*s\n", ( (PayloadRelay*)unpacked_cell.payload )->length, ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload );

  free_cell( &unpacked_cell );

  //ESP_LOGE( MINITOR_TAG, "Trying to recv RELAY_END cell" );

  //if ( d_recv_cell( publish_circuit, &unpacked_cell, CIRCID_LEN, &publish_circuit->relay_list, NULL, NULL ) < 0 )
  //{
//#ifdef DEBUG_MINITOR
    //ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_END cell" );
//#endif

    //return -1;
  //}

  //ESP_LOGE( MINITOR_TAG, "cell command %d", unpacked_cell.command );
  //ESP_LOGE( MINITOR_TAG, "relay command %d", ( (PayloadRelay*)unpacked_cell.payload )->command );

  //free_cell( &unpacked_cell );

  return 0;
}
*/

// depricated
/*
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
*/

int d_generate_outer_descriptor( char* filename, ed25519_key* descriptor_signing_key, long int valid_after, ed25519_key* blinded_key, int revision_counter )
{
  int ret = 0;
  int cipher_fd;
  uint8_t cipher_buff[255];
  char plain_file[60];
  int plain_fd;
  char plain_buff[340];
  unsigned int idx;
  int succ;
  int write_len;
  int wolf_succ;
  char revision_counter_str[32];
  unsigned char tmp_signature[64];
  char tmp_buff[187];

  const char* outer_layer_template_0 =
    "hs-descriptor 3\n"
    "descriptor-lifetime 180\n"
    "descriptor-signing-key-cert\n"
    "-----BEGIN ED25519 CERT-----\n"
    ;
    //"*******************************************************************************************************************************************************************************************"
  const char* outer_layer_template_1 =
    "-----END ED25519 CERT-----\n"
    "revision-counter "
    ;
  const char* outer_layer_template_2 =
    "\nsuperencrypted\n"
    "-----BEGIN MESSAGE-----\n"
    ;
  const char* outer_layer_template_3 =
    "-----END MESSAGE-----\n"
    ;
  const char* outer_layer_template_4 =
    //"signature **************************************************************************************"
    "signature "
    ;

  sprintf( revision_counter_str, "%d", revision_counter );

  sprintf( plain_file, "%s_plain", filename );

  plain_fd = open( plain_file, O_CREAT | O_RDWR | O_TRUNC );

  if ( plain_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", plain_file );
#endif

    return -1;
  }

  cipher_fd = open( filename, O_RDONLY );

  if ( cipher_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", filename );
#endif

    close( plain_fd );

    return -1;
  }

  succ = write( plain_fd, HS_DESC_SIG_PREFIX, HS_DESC_SIG_PREFIX_LENGTH );

  if ( succ != HS_DESC_SIG_PREFIX_LENGTH )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_0, strlen( outer_layer_template_0 ) );

  if ( succ != strlen( outer_layer_template_0 ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  if ( d_generate_packed_crosscert( tmp_buff, descriptor_signing_key->p, blinded_key, 0x08, valid_after ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate the auth_key cross cert" );
#endif

    return -1;
  }

  succ = write( plain_fd, tmp_buff, 187 );

  if ( succ != 187 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_1, strlen( outer_layer_template_1 ) );

  if ( succ != strlen( outer_layer_template_1 ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, revision_counter_str, strlen( revision_counter_str ) );

  if ( succ != strlen( revision_counter_str ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_2, strlen( outer_layer_template_2 ) );

  if ( succ != strlen( outer_layer_template_2 ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  do
  {
    succ = read( cipher_fd, cipher_buff, sizeof( cipher_buff ) );

    if ( succ == 0 )
    {
      break;
    }

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // WARNING, cipher buff must be 255 in length
    // to encode in 4:3 ratio without padding some bits
    // for example if we used 256 plain buff would be filled
    // to 342 bytes and would include padding bits which is not
    // acceptable in the middle of a base64 encoded value,
    // only on the end. thus the only reason this works is because
    // only the last read will have non 255 length
    v_base_64_encode( plain_buff, cipher_buff, succ );

    write_len = succ * 4 / 3;

    if ( succ % 3 != 0 )
    {
      write_len++;
    }

    succ = write( plain_fd, plain_buff, write_len );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( plain_buff ) );

  succ = write( plain_fd, outer_layer_template_3, strlen( outer_layer_template_3 ) );

  if ( succ != strlen( outer_layer_template_3 ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  idx = ED25519_SIG_SIZE;
  wolf_succ = ed25519_sign_msg_custom( plain_fd, tmp_signature, &idx, descriptor_signing_key );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign the outer descriptor, error code: %d", wolf_succ );
#endif

    return -1;
  }

  v_base_64_encode( tmp_buff, tmp_signature, 64 );

  succ = write( plain_fd, outer_layer_template_4, strlen( outer_layer_template_4 ) );

  if ( succ != strlen( outer_layer_template_4 ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, tmp_buff, 86 );

  if ( succ != 86 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
  }

finish:
  close( plain_fd );
  close( cipher_fd );

  if ( ret >= 0 )
  {
    succ = unlink( filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );
#endif

      return -1;
    }

    succ = rename( plain_file, filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename first plaintext" );
#endif

      return -1;
    }
  }

  return ret;
}

int d_generate_first_plaintext( char* filename )
{
  int ret = 0;
  int succ;
  int write_len;
  int cipher_fd;
  uint8_t cipher_buff[255];
  int plain_fd;
  char plain_buff[340];
  char plain_file[60];
  int i;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  char tmp_buff[58];

  /*
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
  */

  const char* first_layer_template =
    "desc-auth-type x25519\n"
    "desc-auth-ephemeral-key "
    ;

  const char* auth_client_template =
    "auth-client "
    ;
  const char* begin_encrypted =
    "encrypted\n"
    "-----BEGIN MESSAGE-----\n"
    ;
  const char* end_encrypted =
    "-----END MESSAGE-----"
    ;

  sprintf( plain_file, "%s_plain", filename );

  plain_fd = open( plain_file, O_CREAT | O_WRONLY | O_TRUNC );

  if ( plain_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", plain_file );
#endif

    return -1;
  }

  cipher_fd = open( filename, O_RDONLY );

  if ( cipher_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", filename );
#endif

    close( plain_fd );

    return -1;
  }

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  succ = write( plain_fd, first_layer_template, strlen( first_layer_template ) );

  if ( succ != strlen( first_layer_template ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
  v_base_64_encode( tmp_buff, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  tmp_buff[43] = '\n';

  succ = write( plain_fd, tmp_buff, 44 );

  if ( succ != 44 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  for ( i = 0; i < 16; i++ )
  {
    succ = write( plain_fd, auth_client_template, strlen( auth_client_template ) );

    if ( succ != strlen( auth_client_template ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

      ret = -1;
      goto finish;
    }

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff, reusable_sha3_sum, 8 );
    tmp_buff[11] = ' ';

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff + 12, reusable_sha3_sum, 16 );
    tmp_buff[34] = ' ';

    esp_fill_random( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff + 35, reusable_sha3_sum, 16 );
    tmp_buff[57] = '\n';

    succ = write( plain_fd, tmp_buff, sizeof( tmp_buff ) );

    if ( succ != sizeof( tmp_buff ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

      ret = -1;
      goto finish;
    }
  }

  succ = write( plain_fd, begin_encrypted, strlen( begin_encrypted ) );

  if ( succ != strlen( begin_encrypted ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
    goto finish;
  }

  do
  {
    succ = read( cipher_fd, cipher_buff, sizeof( cipher_buff ) );

    if ( succ == 0 )
    {
      break;
    }

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // WARNING, cipher buff must be 255 in length
    // to encode in 4:3 ratio without padding some bits
    // for example if we used 256 plain buff would be filled
    // to 342 bytes and would include padding bits which is not
    // acceptable in the middle of a base64 encoded value,
    // only on the end. thus the only reason this works is because
    // only the last read will have non 255 length
    v_base_64_encode( plain_buff, cipher_buff, succ );

    write_len = succ * 4 / 3;

    if ( succ % 3 != 0 )
    {
      write_len++;
    }

    succ = write( plain_fd, plain_buff, write_len );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( plain_buff ) );

  succ = write( plain_fd, end_encrypted, strlen( end_encrypted ) );

  if ( succ != strlen( end_encrypted ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", plain_file );
#endif

    ret = -1;
  }

finish:
  close( plain_fd );
  close( cipher_fd );

  if ( ret >= 0 )
  {
    succ = unlink( filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );
#endif

      return -1;
    }

    succ = rename( plain_file, filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename first plaintext" );
#endif

      return -1;
    }
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  return ret;
}

int d_encrypt_descriptor_plaintext( char* filename, unsigned char* secret_data, int secret_data_length, const char* string_constant, int string_constant_length, unsigned char* sub_credential, int64_t revision_counter )
{
  int ret = 0;
  int cipher_fd;
  uint8_t cipher_buff[256];
  int plain_fd;
  char plain_buff[256];
  int succ;
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
  char cipher_file[60];

  sprintf( cipher_file, "%s_cipher", filename );

  cipher_fd = open( cipher_file, O_CREAT | O_WRONLY | O_TRUNC );

  if ( cipher_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", cipher_file );
#endif

    free( secret_input );

    return -1;
  }

  plain_fd = open( filename, O_RDONLY );

  if ( plain_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", filename );
#endif

    free( secret_input );
    close( cipher_fd );

    return -1;
  }

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

  succ = write( cipher_fd, salt, 16 );

  if ( succ != 16 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", cipher_file );
#endif

    ret = -1;
    goto finish;
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

  //memcpy( *ciphertext, salt, 16 );

  wc_AesSetKeyDirect( &reusable_aes_key, keys, AES_256_KEY_SIZE, keys + AES_256_KEY_SIZE, AES_ENCRYPTION );

  do
  {
    succ = read( plain_fd, plain_buff, sizeof( plain_buff ) );

    if ( succ == 0 )
    {
      break;
    }

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    wolf_succ = wc_AesCtrEncrypt( &reusable_aes_key, cipher_buff, (uint8_t*)plain_buff, succ );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt descriptor plaintext, error code: %d", wolf_succ );
#endif

      return -1;
    }

    wc_Sha3_256_Update( &reusable_sha3, cipher_buff, succ );

    succ = write( cipher_fd, cipher_buff, succ );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", cipher_file );
#endif

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( cipher_buff ) );

  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  succ = write( cipher_fd, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );

  if ( succ != WC_SHA3_256_DIGEST_SIZE )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", cipher_file );
#endif

    ret = -1;
    goto finish;
  }

  //memcpy( *ciphertext + 16 + plaintext_length, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );

finish:
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );

  free( secret_input );

  close( cipher_fd );
  close( plain_fd );

  if ( ret >= 0 )
  {
    succ = unlink( filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );
#endif

      return -1;
    }

    succ = rename( cipher_file, filename );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename cipher file %s to %s, errno: %d", cipher_file, filename, errno );
#endif

      return -1;
    }
  }

  return ret;
}

int d_generate_second_plaintext( char* filename, OnionCircuit** intro_circuits, long int valid_after, ed25519_key* descriptor_signing_key )
{
  int ret = 0;
  int fd;
  int i;
  unsigned int idx;
  int succ;
  int wolf_succ;
  unsigned char packed_link_specifiers[1 + 4 + 6 + ID_LENGTH];
  unsigned char tmp_pub_key[CURVE25519_KEYSIZE];
  unsigned char* working_second_layer;
  char tmp_buff[187];

  const char* formats_s =
    "create2-formats 2\n"
    ;
  const char* intro_point_s = "introduction-point ";
  const char* onion_key_s = "onion-key ntor ";
  const char* auth_key_s = "auth-key\n";
  const char* enc_ntor_s = "enc-key ntor ";
  const char* enc_cert_s = "enc-key-cert\n";
  const char* begin_ed_s = "-----BEGIN ED25519 CERT-----\n";
  const char* end_ed_s = "-----END ED25519 CERT-----\n";

  /*
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
    */

  fd = open( filename, O_CREAT | O_WRONLY | O_TRUNC );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s", filename );
#endif

    return -1;
  }

  succ = write( fd, formats_s, strlen( formats_s ) );

  if ( succ != strlen( formats_s ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

    ret = -1;
    goto finish;
  }

  for ( i = 0; i < 3; i++ )
  {
    // write intro point
    succ = write( fd, intro_point_s, strlen( intro_point_s ) );

    if ( succ != strlen( intro_point_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    v_generate_packed_link_specifiers( intro_circuits[i]->relay_list.tail->relay, packed_link_specifiers );
    v_base_64_encode( tmp_buff, packed_link_specifiers, sizeof( packed_link_specifiers ) );
    tmp_buff[42] = '\n';

    succ = write( fd, tmp_buff, 43 );

    if ( succ != 43 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // write onion key
    succ = write( fd, onion_key_s, strlen( onion_key_s ) );

    if ( succ != strlen( onion_key_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    v_base_64_encode( tmp_buff, intro_circuits[i]->relay_list.tail->relay->ntor_onion_key, H_LENGTH );
    tmp_buff[43] = '\n';

    succ = write( fd, tmp_buff, 44 );

    if ( succ != 44 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // write auth key and cert
    succ = write( fd, auth_key_s, strlen( auth_key_s ) );

    if ( succ != strlen( auth_key_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, begin_ed_s, strlen( begin_ed_s ) );

    if ( succ != strlen( begin_ed_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &intro_circuits[i]->intro_crypto->auth_key, tmp_pub_key, &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export intro circuit auth key, error code: %d", wolf_succ );
#endif

      ret = -1;
      goto finish;
    }

    if ( d_generate_packed_crosscert( tmp_buff, tmp_pub_key, descriptor_signing_key, 0x09, valid_after ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate the auth_key cross cert" );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, tmp_buff, 187 );

    if ( succ != 187 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, end_ed_s, strlen( end_ed_s ) );

    if ( succ != strlen( end_ed_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // write enc ntor
    succ = write( fd, enc_ntor_s, strlen( enc_ntor_s ) );

    if ( succ != strlen( enc_ntor_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    idx = CURVE25519_KEYSIZE;
    wolf_succ = wc_curve25519_export_public_ex( &intro_circuits[i]->intro_crypto->encrypt_key, tmp_pub_key, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ != 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ );
#endif

      ret = -1;
      goto finish;
    }

    v_base_64_encode( tmp_buff, tmp_pub_key, CURVE25519_KEYSIZE );
    tmp_buff[43] = '\n';

    succ = write( fd, tmp_buff, 44 );

    if ( succ != 44 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    // write enc key and cert
    succ = write( fd, enc_cert_s, strlen( enc_cert_s ) );

    if ( succ != strlen( enc_cert_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, begin_ed_s, strlen( begin_ed_s ) );

    if ( succ != strlen( begin_ed_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    v_ed_pubkey_from_curve_pubkey( tmp_pub_key, intro_circuits[i]->intro_crypto->encrypt_key.p.point, 0 );

    if ( d_generate_packed_crosscert( tmp_buff, tmp_pub_key, descriptor_signing_key, 0x0B, valid_after ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate the enc-key cross cert" );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, tmp_buff, 187 );

    if ( succ != 187 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }

    succ = write( fd, end_ed_s, strlen( end_ed_s ) );

    if ( succ != strlen( end_ed_s ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s", filename );
#endif

      ret = -1;
      goto finish;
    }
  }

finish:
  close( fd );

  return ret;
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
  packed_link_specifiers[7] = (unsigned char)( relay->or_port >> 8 );
  packed_link_specifiers[8] = (unsigned char)relay->or_port;

  // LEGACYLink specifier
  // set the type
  packed_link_specifiers[9] = LEGACYLink;
  // set the length
  packed_link_specifiers[10] = ID_LENGTH;
  // copy the identity in
  memcpy( packed_link_specifiers + 11, relay->identity, ID_LENGTH );
}

int d_generate_packed_crosscert( char* destination, unsigned char* certified_key, ed25519_key* signing_key, unsigned char cert_type, long int valid_after ) {
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

void v_ed_pubkey_from_curve_pubkey( unsigned char* output, const unsigned char* input, int sign_bit )
{
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

int d_router_establish_intro( OnionCircuit* circuit )
{
  int ret = 0;
  int wolf_succ;
  unsigned int idx;
  int64_t ordered_digest_length = (int64_t)DIGEST_LEN;
  unsigned char ordered_digest_length_buffer[8];
  WC_RNG rng;
  Sha3 reusable_sha3;
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  Cell unpacked_cell;
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

  if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );
#endif

    ret = -1;
    goto finish;
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

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate establish intro signature, error code: %d", wolf_succ );
#endif

    ret = -1;
    goto finish;
  }

  ESP_LOGE( MINITOR_TAG, "Sending establish intro to %d", circuit->relay_list.tail->relay->or_port );

  if ( d_send_packed_relay_cell_and_free( circuit->or_connection, packed_cell, &circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_COMMAND_ESTABLISH_INTRO cell" );
#endif

    ret = -1;
  }

finish:
  wc_Sha3_256_Free( &reusable_sha3 );

  return ret;
}

int d_derive_blinded_key( ed25519_key* blinded_key, ed25519_key* master_key, int64_t period_number, int64_t period_length, unsigned char* secret, int secret_length )
{
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

int d_generate_hs_keys( OnionService* onion_service, const char* onion_service_directory )
{
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

    strcpy( onion_service->hostname, onion_address );

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

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/hostname" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( read( fd, onion_service->hostname, 62 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    onion_service->hostname[62] = 0;

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }
  }

  wc_Sha3_256_Free( &reusable_sha3 );

  return 0;
}

int d_begin_hsdir( OnionCircuit* publish_circuit )
{
  Cell unpacked_cell;
  unsigned char* packed_cell;

  unpacked_cell.circ_id = publish_circuit->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_BEGIN_DIR;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 0;

  packed_cell = pack_and_free( &unpacked_cell );

  ESP_LOGE( MINITOR_TAG, "Trying to send relay" );

  if ( d_send_packed_relay_cell_and_free( publish_circuit->or_connection, packed_cell, &publish_circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_BEGIN_DIR cell" );
#endif

    return -1;
  }

  return 0;
}

int d_post_hs_desc( OnionCircuit* publish_circuit )
{
  char* REQUEST;
  char* ipv4_string;
  const char* REQUEST_CONST = "POST /tor/hs/3/publish HTTP/1.0\r\n"
    "Host: \r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: "
    ;
  const char* header_end = "\r\n\r\n";
  //int total_tx_length = 0;
  int tx_limit;
  char content_length[11] = { 0 };
  int http_header_length;
  int descriptor_length;
  //unsigned char* descriptor_text = publish_circuit->service->hs_descs[publish_circuit->desc_index] + HS_DESC_SIG_PREFIX_LENGTH;
  int desc_fd;
  char desc_buff[RELAY_PAYLOAD_LEN];
  Cell unpacked_cell;
  uint8_t* packed_cell;
  int succ;

  desc_fd = open( publish_circuit->service->hs_descs[publish_circuit->desc_index], O_RDONLY );

  if ( desc_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );
#endif

    return -1;
  }

  descriptor_length = lseek( desc_fd, 0, SEEK_END ) - HS_DESC_SIG_PREFIX_LENGTH;

  ESP_LOGE( MINITOR_TAG, "desc length %d", descriptor_length );

  if ( descriptor_length < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to seek %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );
#endif

    return -1;
  }

  sprintf( content_length, "%d", descriptor_length );

  if ( lseek( desc_fd, HS_DESC_SIG_PREFIX_LENGTH, SEEK_SET ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to seek %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );
#endif

    return -1;
  }

  ipv4_string = pc_ipv4_to_string( publish_circuit->relay_list.head->relay->address );
  REQUEST = malloc( sizeof( char ) * ( strlen( REQUEST_CONST ) + strlen( ipv4_string ) ) );

  memcpy( REQUEST, REQUEST_CONST, 39 );
  strcpy( REQUEST + 39, ipv4_string );
  strcpy( REQUEST + 39 + strlen( ipv4_string ), REQUEST_CONST + 39 );

  free( ipv4_string );

  //http_header_length = strlen( REQUEST ) + strlen( content_length ) + strlen( header_end );

  unpacked_cell.command = RELAY;
  unpacked_cell.circ_id = publish_circuit->circ_id;

  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );
  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_DATA;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  // TODO possibly need to set the stream_id, wasn't clear in torspec
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = RELAY_PAYLOAD_LEN;

  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadData ) );

  ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload = malloc( sizeof( unsigned char ) * ( (PayloadRelay*)unpacked_cell.payload )->length );

  memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, REQUEST, strlen( REQUEST ) );
  http_header_length = strlen( REQUEST );
  free( REQUEST );

  memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + http_header_length, content_length, strlen( content_length ) );
  http_header_length += strlen( content_length );

  memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + http_header_length, header_end, strlen( header_end ) );
  http_header_length += strlen( header_end );

  succ = read( desc_fd, desc_buff, RELAY_PAYLOAD_LEN - http_header_length );

  if ( succ != RELAY_PAYLOAD_LEN - http_header_length )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read %s", publish_circuit->service->hs_descs[publish_circuit->desc_index] );
#endif

    return -1;
  }

  memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload + http_header_length, desc_buff, succ );

  packed_cell = pack_and_free( &unpacked_cell );

  if ( d_send_packed_relay_cell_and_free( publish_circuit->or_connection, packed_cell, &publish_circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA cell" );
#endif

    return -1;
  }

  do
  {
    succ = read( desc_fd, desc_buff, RELAY_PAYLOAD_LEN );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s", publish_circuit->service->hs_descs[publish_circuit->desc_index] );
#endif

      return -1;
    }

    if ( succ == 0 )
    {
      break;
    }

    unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );
    ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_DATA;
    ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
    // TODO possibly need to set the stream_id, wasn't clear in torspec
    ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 1;
    ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
    ( (PayloadRelay*)unpacked_cell.payload )->length = succ;

    ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadData ) );

    ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload = malloc( sizeof( unsigned char ) * succ );

    memcpy( ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload, desc_buff, succ );

    packed_cell = pack_and_free( &unpacked_cell );

    if ( d_send_packed_relay_cell_and_free( publish_circuit->or_connection, packed_cell, &publish_circuit->relay_list, NULL ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_DATA cell" );
#endif

      return -1;
    }
  } while ( succ == RELAY_PAYLOAD_LEN );

  return 0;
}

void v_build_hsdir_circuits( OnionService* service, DoublyLinkedOnionRelayList* target_relays, int desc_index )
{
  OnionRelay* start_node;
  OnionRelay* tmp_node;
  DoublyLinkedOnionRelay* target_dl_relay;

  start_node = px_get_random_hsdir_relay( 1, target_relays, NULL, NULL );

  target_dl_relay = target_relays->head;

  while ( target_dl_relay != NULL )
  {
    tmp_node = malloc( sizeof( OnionRelay ) );
    memcpy( tmp_node, start_node, sizeof( OnionRelay ) );

    v_send_init_circuit( 3, CIRCUIT_HSDIR_BEGIN_DIR, service, desc_index, 0, tmp_node, target_dl_relay->relay, NULL );

    target_dl_relay = target_dl_relay->next;
  }

  free( start_node );
}

int d_push_hsdir( OnionService* service )
{
  int i;
  int wolf_succ;
  int succ;
  unsigned int idx;
  int voting_interval;
  time_t srv_start_time;
  time_t now;
  time_t fresh_until;
  time_t valid_after;
  int time_period;
  int revision_counter;
  WC_RNG rng;
  ed25519_key blinded_keys[2];
  ed25519_key descriptor_signing_key;
  Sha3 reusable_sha3;
  int reusable_text_length;
  unsigned char* reusable_plaintext;
  unsigned char* reusable_ciphertext;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char blinded_pub_keys[2][ED25519_PUB_KEY_SIZE];
  DoublyLinkedOnionRelay* dl_relay;
  DoublyLinkedOnionRelay* next_relay;
  OnionCircuit* tmp_circuit;
  OnionCircuit* intro_circuits[3];
  OnionRelay* start_relay;
  char desc_file[26];

  if ( service->intro_live_count < 3 )
  {
    return -1;
  }

  //MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  tmp_circuit = onion_circuits;

  for ( i = 0; i < 3; i++ )
  {
    while ( tmp_circuit != NULL )
    {
      if ( tmp_circuit->status == CIRCUIT_INTRO_LIVE && tmp_circuit->service == service )
      {
        break;
      }

      tmp_circuit = tmp_circuit->next;
    }

    if ( tmp_circuit == NULL )
    {
      return -1;
    }

    ESP_LOGE( MINITOR_TAG, "intro port %d", tmp_circuit->relay_list.tail->relay->or_port );

    intro_circuits[i] = tmp_circuit;
    tmp_circuit = tmp_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  //MUTEX GIVE

  wc_InitRng( &rng );

  wc_ed25519_init( &blinded_keys[0] );
  wc_ed25519_init( &blinded_keys[1] );
  blinded_keys[0].expanded = 1;
  blinded_keys[1].expanded = 1;

  wc_ed25519_init( &descriptor_signing_key );
  wc_ed25519_make_key( &rng, 32, &descriptor_signing_key );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  wc_FreeRng( &rng );

  // BEGIN mutex
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  valid_after = network_consensus.valid_after;
  fresh_until = network_consensus.fresh_until;

  time_period = d_get_hs_time_period( network_consensus.fresh_until, network_consensus.valid_after, network_consensus.hsdir_interval );

  // my stragety is to get all the target relays within a single mutex lock so that we
  // can garentee that we use the same consensus in case it tries to update during the
  // long upload process
  for ( i = 0; i < 2; i++ )
  {
    succ = d_derive_blinded_key( &blinded_keys[i], &service->master_key, time_period + i, network_consensus.hsdir_interval, NULL, 0 );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to derive the blinded key" );
#endif

      return -1;
    }

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &blinded_keys[i], blinded_pub_keys[i], &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export blinded public key" );
#endif

      return -1;
    }

    service->target_relays[i] = px_get_target_relays( network_consensus.hsdir_n_replicas, blinded_pub_keys[i], time_period + i, network_consensus.hsdir_interval, network_consensus.hsdir_spread_store, i );

    if ( service->target_relays[i] == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to get target_relays" );
#endif

      return -1;
    }
  }

  xSemaphoreGive( network_consensus_mutex );
  // END mutex

  service->hsdir_to_send = service->target_relays[0]->length + service->target_relays[1]->length;
  service->hsdir_sent = 0;

  revision_counter = d_roll_revision_counter( service->master_key.p );

  if ( revision_counter < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to roll the revision_counter" );
#endif

    return -1;
  }

  // i = 0 is first descriptor, 1 is second as per the spec
  for ( i = 0; i < 2; i++ )
  {
    // null terminated
    // /sdcard/abcdefghij_desc_0\0
    strcpy( desc_file, "/sdcard/" );
    memcpy( desc_file + 8, service->hostname, 10 );
    desc_file[18] = 0;
    strcat( desc_file, "_desc_" );
    desc_file[24] = (char)(48 + i);
    desc_file[25] = 0;

    // generate second layer plaintext
    succ = d_generate_second_plaintext( desc_file, intro_circuits, valid_after, &descriptor_signing_key );
    //succ = tmp_d_generate_second_plaintext( desc_file, intro_circuits, valid_after, &descriptor_signing_key );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate second layer descriptor plaintext" );
#endif

      return -1;
    }

    ESP_LOGE( MINITOR_TAG, "Creating sub cred" );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"credential", strlen( "credential" ) );
    wc_Sha3_256_Update( &reusable_sha3, service->master_key.p, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"subcredential", strlen( "subcredential" ) );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, blinded_pub_keys[i], ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    if ( i == 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Storing current sub cred" );

      memcpy( service->current_sub_credential, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    }
    else
    {
      ESP_LOGE( MINITOR_TAG, "Storing previous sub cred" );

      memcpy( service->previous_sub_credential, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    }

    // encrypt second layer plaintext
    succ = d_encrypt_descriptor_plaintext(
      desc_file,
      blinded_pub_keys[i],
      ED25519_PUB_KEY_SIZE,
      "hsdir-encrypted-data",
      strlen( "hsdir-encrypted-data" ),
      reusable_sha3_sum,
      revision_counter
    );

    //free( reusable_plaintext );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt second layer descriptor plaintext" );
#endif

      return -1;
    }

    succ = d_generate_first_plaintext( desc_file );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate first layer descriptor plaintext" );
#endif

      return -1;
    }

    //free( reusable_ciphertext );

    // encrypt first layer plaintext
    succ = d_encrypt_descriptor_plaintext(
      desc_file,
      blinded_pub_keys[i],
      ED25519_PUB_KEY_SIZE,
      "hsdir-superencrypted-data",
      strlen( "hsdir-superencrypted-data" ),
      reusable_sha3_sum,
      revision_counter
    );

    //free( reusable_plaintext );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt first layer descriptor plaintext" );
#endif

      return -1;
    }

    // create outer descriptor wrapper
    succ = d_generate_outer_descriptor(
      desc_file,
      &descriptor_signing_key,
      valid_after,
      &blinded_keys[i],
      revision_counter
    );

    //free( reusable_ciphertext );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate outer descriptor" );
#endif

      return -1;
    }

    // send outer descriptor wrapper to the correct HSDIR nodes
    //succ = d_build_hsdir_circuits( reusable_plaintext + HS_DESC_SIG_PREFIX_LENGTH, reusable_text_length, target_relays[i] );
    //v_build_hsdir_circuits( service, target_relays[i], i );
    start_relay = px_get_random_hsdir_relay( 1, service->target_relays[i], NULL, NULL );
    v_send_init_circuit( 3, CIRCUIT_HSDIR_BEGIN_DIR, service, i, 0, start_relay, service->target_relays[i]->head->relay, NULL );

    /*
    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send descriptor to hsdir hosts" );
#endif

      return -1;
    }
    */

    strcpy( service->hs_descs[i], desc_file );

    //service->hs_descs[i] = reusable_plaintext;
    //service->hs_desc_lengths[i] = reusable_text_length;
    //free( reusable_plaintext );
  }

  /*
  for ( i = 0; i < 2; i++ )
  {
    dl_relay = target_relays[i]->head;

    while ( dl_relay != NULL )
    {
      next_relay = dl_relay->next;

      free( dl_relay );

      dl_relay = next_relay;
    }
  }

  free( target_relays[0] );
  free( target_relays[1] );
  */

  wc_Sha3_256_Free( &reusable_sha3 );
  wc_ed25519_free( &blinded_keys[0] );
  wc_ed25519_free( &blinded_keys[1] );
  wc_ed25519_free( &descriptor_signing_key );

  return 0;
}

void v_cleanup_service_hs_data( OnionService* service, int desc_index )
{
  int i;
  OnionCircuit* tmp_circuit;
  DoublyLinkedOnionRelay* dl_relay;
  DoublyLinkedOnionRelay* next_relay;

  if ( service->hsdir_sent == service->hsdir_to_send )
  {
    v_set_hsdir_timer( service->hsdir_timer );

    i = d_get_standby_count();

    for ( ; i < 2; i++ )
    {
      // create a standby circuit
      v_send_init_circuit(
        1,
        CIRCUIT_STANDBY,
        NULL,
        0,
        0,
        NULL,
        NULL,
        NULL
      );
    }
  }

  dl_relay = service->target_relays[desc_index]->head;

  while ( dl_relay != NULL )
  {
    next_relay = dl_relay->next;

    free( dl_relay );

    dl_relay = next_relay;
  }

  free( service->target_relays[desc_index] );
  //free( service->hs_descs[desc_index] );
}
