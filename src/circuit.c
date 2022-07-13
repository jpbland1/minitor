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
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "../include/config.h"
#include "../h/connections.h"
#include "../h/circuit.h"
#include "../h/cell.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/models/relay.h"

#include "../h/consensus.h"

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

int d_prepare_onion_circuit( OnionCircuit* circuit, int length, OnionRelay* start_relay, OnionRelay* end_relay )
{
  int i;
  DoublyLinkedOnionRelay* dl_relay;

  circuit->circ_id = ++circ_id_counter;

  if ( start_relay != NULL )
  {
    length--;
  }

  if ( end_relay != NULL )
  {
    length--;
  }

  circuit->relay_list.length = 0;
  circuit->relay_list.built_length = 0;

  for ( i = 0; i < length; i++ )
  {
    if ( i == 0 && start_relay == NULL )
    {
      if ( end_relay != NULL )
      {
        if ( d_get_suitable_relay( &circuit->relay_list, 1, NULL, end_relay->identity ) )
        {
          goto fail;
        }
      }
      else
      {
        if ( d_get_suitable_relay( &circuit->relay_list, 1, NULL, NULL ) )
        {
          goto fail;
        }
      }
    }
    else
    {
      if ( start_relay != NULL )
      {
        if ( end_relay != NULL )
        {
          if ( d_get_suitable_relay( &circuit->relay_list, 0, start_relay->identity, end_relay->identity ) )
          {
            goto fail;
          }
        }
        else
        {
          if ( d_get_suitable_relay( &circuit->relay_list, 0, start_relay->identity, NULL ) )
          {
            goto fail;
          }
        }
      }
      else if ( end_relay != NULL )
      {
        if ( d_get_suitable_relay( &circuit->relay_list, 0, NULL, end_relay->identity ) )
        {
          goto fail;
        }
      }
      else
      {
        if ( d_get_suitable_relay( &circuit->relay_list, 0, NULL, NULL ) )
        {
          goto fail;
        }
      }
    }
  }

  // prepend the start_relay to the list
  if ( start_relay != NULL )
  {
    dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    dl_relay->relay = start_relay;

    dl_relay->next = circuit->relay_list.head;
    dl_relay->previous = NULL;

    if ( circuit->relay_list.head != NULL )
    {
      circuit->relay_list.head->previous = dl_relay;
    }
    // NULL head menas NULL tail
    else
    {
      circuit->relay_list.tail = dl_relay;
    }

    circuit->relay_list.head = dl_relay;
    circuit->relay_list.length++;
  }

  // append the destination_relay to the list
  if ( end_relay != NULL )
  {

    dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    dl_relay->relay = end_relay;

    v_add_relay_to_list( dl_relay, &circuit->relay_list );
  }

  return 0;
fail:
  if ( start_relay != NULL )
  {
    free( start_relay );
  }

  if ( end_relay != NULL )
  {
    free( end_relay );
  }

  return -1;
}

int d_get_suitable_relay( DoublyLinkedOnionRelayList* relay_list, int guard, uint8_t* exclude_start, uint8_t* exclude_end )
{
  DoublyLinkedOnionRelay* db_relay;

  db_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
  db_relay->relay = px_get_random_fast_relay( guard, relay_list, exclude_start, exclude_end );

  if ( db_relay->relay == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get guard relay" );
#endif

    free( db_relay );

    return -1;
  }

  v_add_relay_to_list( db_relay, relay_list );

  return 0;
}

int d_get_suitable_onion_relays( DoublyLinkedOnionRelayList* relay_list, int desired_length, uint8_t* exclude_start, uint8_t* exclude_end )
{
  int i;
  DoublyLinkedOnionRelay* db_relay;

  for ( i = relay_list->length; i < desired_length; i++ )
  {
    db_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );

    if ( i == 0 )
    {
      db_relay->relay = px_get_random_fast_relay( 1, NULL, exclude_start, exclude_end );
    }
    else
    {
      db_relay->relay = px_get_random_fast_relay( 0, relay_list, exclude_start, exclude_end );
    }

    if ( db_relay->relay == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to get guard relay" );
#endif

      free( db_relay );

      while ( relay_list->length > 0 )
      {
        v_pop_relay_from_list_back( relay_list );
      }

      return -1;
    }

    v_add_relay_to_list( db_relay, relay_list );
  }

  return 0;
}

// destroy a tor circuit
int d_destroy_onion_circuit( OnionCircuit* circuit, DlConnection* or_connection )
{
  int i;
  Cell* destroy_cell;
  DoublyLinkedOnionRelay* tmp_relay_node;

  destroy_cell = malloc( MINITOR_CELL_LEN );

  // length is header plus 1 for destroy code
  destroy_cell->length = FIXED_CELL_HEADER_SIZE + 1;
  destroy_cell->command = DESTROY;
  destroy_cell->circ_id = circuit->circ_id;
  destroy_cell->payload.destroy_code = NO_DESTROY_CODE;

  // send a destroy cell to the first hop
  if ( or_connection != NULL )
  {
    if ( d_send_cell_and_free( or_connection, destroy_cell ) < 0 )
    {
  #ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send DESTROY cell" );
  #endif
    }

    xSemaphoreGive( connection_access_mutex[or_connection->mutex_index] );
    // MUTEX GIVE
  }

  tmp_relay_node = circuit->relay_list.head;

  for ( i = 0; i < circuit->relay_list.length; i++ )
  {
    if ( i < circuit->relay_list.built_length )
    {
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_forward );
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_backward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_forward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_backward );
      free( tmp_relay_node->relay_crypto );
    }

    ESP_LOGE( MINITOR_TAG, "Freeing relay: %d %d", i, tmp_relay_node->relay->or_port );
    free( tmp_relay_node->relay );

    if ( i == circuit->relay_list.length - 1 )
    {
      free( tmp_relay_node );
    }
    else
    {
      tmp_relay_node = tmp_relay_node->next;
      free( tmp_relay_node->previous );
    }
  }

  ESP_LOGE( MINITOR_TAG, "Freed with target status %d conn_id %d", circuit->target_status, circuit->conn_id );

  circuit->relay_list.length = 0;
  circuit->relay_list.built_length = 0;
  circuit->relay_list.head = NULL;
  circuit->relay_list.tail = NULL;

  if ( circuit->status == CIRCUIT_INTRO_ESTABLISHED || circuit->status == CIRCUIT_INTRO_LIVE )
  {
    wc_ed25519_free( &circuit->intro_crypto->auth_key );
    wc_curve25519_free( &circuit->intro_crypto->encrypt_key );
    free( circuit->intro_crypto );
  }
  else if ( circuit->status == CIRCUIT_RENDEZVOUS )
  {
    wc_Sha3_256_Free( &circuit->hs_crypto->hs_running_sha_forward );
    wc_Sha3_256_Free( &circuit->hs_crypto->hs_running_sha_backward );
    wc_AesFree( &circuit->hs_crypto->hs_aes_forward );
    wc_AesFree( &circuit->hs_crypto->hs_aes_backward );
    free( circuit->hs_crypto );
  }
  else if ( circuit->status == CIRCUIT_CREATED || circuit->status == CIRCUIT_EXTENDED )
  {
    wc_curve25519_free( &circuit->create2_handshake_key );
  }

  if ( or_connection != NULL )
  {
    v_dettach_connection( or_connection );
  }

  return 0;
}

int d_router_truncate( OnionCircuit* circuit, DlConnection* or_connection, int new_length )
{
  int i;
  Cell* truncate_cell;
  DoublyLinkedOnionRelay* tmp_relay_node;

  if ( circuit->relay_list.length == new_length )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Circuit is already at length" );
#endif

    return -1;
  }

  circuit->relay_early_count++;

  tmp_relay_node = circuit->relay_list.tail;

  for ( i = circuit->relay_list.length - 1; i >= new_length; i-- )
  {
    if ( i < circuit->relay_list.built_length )
    {
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_forward );
      wc_ShaFree( &tmp_relay_node->relay_crypto->running_sha_backward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_forward );
      wc_AesFree( &tmp_relay_node->relay_crypto->aes_backward );
      free( tmp_relay_node->relay_crypto );
    }

    free( tmp_relay_node->relay );

    tmp_relay_node = tmp_relay_node->previous;
    free( tmp_relay_node->next );
    tmp_relay_node->next = NULL;
  }

  circuit->relay_list.tail = tmp_relay_node;
  circuit->relay_list.length = new_length;
  circuit->relay_list.built_length = new_length;

  truncate_cell = malloc( MINITOR_CELL_LEN );

  // fixed header, relay header and 1 for destroy code
  truncate_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + 1;
  truncate_cell->command = RELAY;
  truncate_cell->circ_id = circuit->circ_id;

  truncate_cell->payload.relay.relay_command = RELAY_TRUNCATE;
  truncate_cell->payload.relay.recognized = 0;
  truncate_cell->payload.relay.stream_id = 0;
  truncate_cell->payload.relay.digest = 0;
  truncate_cell->payload.relay.length = 1;
  truncate_cell->payload.relay.destroy_code = NO_DESTROY_CODE;

  // send a destroy cell to the first hop
  if ( d_send_relay_cell_and_free( or_connection, truncate_cell, &circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_TRUNCATE cell" );
#endif

    return -1;
  }

  return 0;
}

int d_router_extend2( OnionCircuit* circuit, DlConnection* or_connection, int node_index )
{
  int i;
  int wolf_succ;
  WC_RNG rng;
  DoublyLinkedOnionRelay* target_relay;
  Cell* extend2_cell;
  LinkSpecifier* working_specifier;
  Create2* create2;

  wc_curve25519_init( &circuit->create2_handshake_key );
  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &circuit->create2_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make extend2_handshake_key, error code %d", wolf_succ );
#endif

    goto fail;
  }

  target_relay = circuit->relay_list.head;

  for ( i = 0; i < node_index; i++ )
  {
    target_relay = target_relay->next;
  }

  extend2_cell = malloc( MINITOR_CELL_LEN );

  // construct link specifiers
  extend2_cell->circ_id = circuit->circ_id;
  extend2_cell->command = RELAY_EARLY;
  extend2_cell->payload.relay.relay_command = RELAY_EXTEND2;
  extend2_cell->payload.relay.recognized = 0;
  extend2_cell->payload.relay.stream_id = 0;
  extend2_cell->payload.relay.digest = 0;
  extend2_cell->payload.relay.length = 35 + ID_LENGTH + H_LENGTH + G_LENGTH;

  // fixed header, relay header, relay body length
  extend2_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + extend2_cell->payload.relay.length;

  extend2_cell->payload.relay.extend2.num_specifiers = 2;

  working_specifier = extend2_cell->payload.relay.extend2.link_specifiers;

  working_specifier->type = IPv4Link;
  working_specifier->length = 6;
  working_specifier->specifier[0] = (uint8_t)target_relay->relay->address;
  working_specifier->specifier[1] = (uint8_t)(target_relay->relay->address >> 8);
  working_specifier->specifier[2] = (uint8_t)(target_relay->relay->address >> 16);
  working_specifier->specifier[3] = (uint8_t)(target_relay->relay->address >> 24);
  working_specifier->specifier[4] = (uint8_t)(target_relay->relay->or_port >> 8);
  working_specifier->specifier[5] = (uint8_t)target_relay->relay->or_port;

  working_specifier = (uint8_t*)working_specifier + 2 + 6;

  working_specifier->type = LEGACYLink;
  working_specifier->length = ID_LENGTH;
  memcpy( working_specifier->specifier, target_relay->relay->identity, ID_LENGTH );

  create2 = (uint8_t*)working_specifier + 2 + ID_LENGTH;

  create2->handshake_type = NTOR;
  create2->handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;

  // construct our side of the handshake
  if ( d_ntor_handshake_start( create2->handshake_data, target_relay->relay, &circuit->create2_handshake_key ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    free( extend2_cell );

    goto fail;
  }

  // send the EXTEND2 cell
  if ( d_send_relay_cell_and_free( or_connection, extend2_cell, &circuit->relay_list, NULL ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_EXTEND2 cell" );
#endif

    goto fail;
  }

  return 0;

fail:
  wc_curve25519_free( &circuit->create2_handshake_key );

  return -1;
}

int d_router_extended2( OnionCircuit* circuit, int node_index, Cell* extended2_cell )
{
  int i;
  DoublyLinkedOnionRelay* target_relay;

  target_relay = circuit->relay_list.head;

  for ( i = 0; i < node_index; i++ )
  {
    target_relay = target_relay->next;
  }

  if ( d_ntor_handshake_finish( extended2_cell->payload.relay.extended2.handshake_data, target_relay, &circuit->create2_handshake_key ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    // destroy function will free the handshake key
    return -1;
  }

  wc_curve25519_free( &circuit->create2_handshake_key );

  return 0;
}

int d_router_create2( OnionCircuit* circuit, DlConnection* or_connection )
{
  int wolf_succ;
  WC_RNG rng;
  Cell* create2_cell;

  wc_curve25519_init( &circuit->create2_handshake_key );

  wolf_succ = wc_InitRng( &rng );

  if ( wolf_succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to init rng %d", wolf_succ );
#endif

    goto cleanup;
  }

  wolf_succ = wc_curve25519_make_key( &rng, 32, &circuit->create2_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make create2_handshake_key, error code %d", wolf_succ );
#endif

    goto cleanup;
  }

  create2_cell = malloc( MINITOR_CELL_LEN );

  // make a create2 cell
  create2_cell->circ_id = circuit->circ_id;
  create2_cell->command = CREATE2;
  create2_cell->payload.create2.handshake_type = NTOR;
  create2_cell->payload.create2.handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;

  // fixed header, 2 for handshake_type, 2 for handshake_length and the handshake
  create2_cell->length = FIXED_CELL_HEADER_SIZE + 2 + 2 + create2_cell->payload.create2.handshake_length;

  if ( d_ntor_handshake_start( create2_cell->payload.create2.handshake_data, circuit->relay_list.head->relay, &circuit->create2_handshake_key ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export create2_handshake_key into unpacked_cell" );
#endif

    free( create2_cell );

    goto cleanup;
  }

  if ( d_send_cell_and_free( or_connection, create2_cell ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send CREATE2 cell" );
#endif

    goto cleanup;
  }

  return 0;

cleanup:
  wc_curve25519_free( &circuit->create2_handshake_key );

  return -1;
}

// outer caller will free the unpacked cell
int d_router_created2( OnionCircuit* circuit, Cell* created2_cell )
{
  if ( d_ntor_handshake_finish( created2_cell->payload.created2.handshake_data, circuit->relay_list.head, &circuit->create2_handshake_key ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to finish CREATED2 handshake" );
#endif

    // create2_handshake_key is freed in destroy function
    return -1;
  }

  wc_curve25519_free( &circuit->create2_handshake_key );

  return 0;
}

int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key )
{
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

int d_ntor_handshake_finish( uint8_t* handshake_data, DoublyLinkedOnionRelay* db_relay, curve25519_key* key )
{
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

  if ( wolf_succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import responder public key, error code %d", wolf_succ );
#endif

    goto fail;
  }

  wolf_succ = wc_curve25519_import_public_ex( db_relay->relay->ntor_onion_key, H_LENGTH, &ntor_onion_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import ntor onion public key, error code %d", wolf_succ );
#endif

    goto fail;
  }

  // create secret_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &responder_handshake_public_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(Y,x), error code %d", wolf_succ );
#endif

    goto fail;
  }

  working_secret_input += 32;

  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &ntor_onion_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(B,x), error code %d", wolf_succ );
#endif

    goto fail;
  }

  working_secret_input += 32;

  memcpy( working_secret_input, db_relay->relay->identity, ID_LENGTH );
  working_secret_input += ID_LENGTH;

  memcpy( working_secret_input, db_relay->relay->ntor_onion_key, H_LENGTH );
  working_secret_input += H_LENGTH;

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_secret_input, error code: %d", wolf_succ );
#endif

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

  if ( wolf_succ != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_auth_input, error code: %d", wolf_succ );
#endif

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

  if ( memcmp( reusable_hmac_digest, handshake_data + G_LENGTH, WC_SHA256_DIGEST_SIZE ) != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to match AUTH with our own digest" );
#endif

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

  // free all the heap resources
  wc_curve25519_free( &responder_handshake_public_key );
  wc_curve25519_free( &ntor_onion_key );

  free( secret_input );
  free( auth_input );

  return 0;

fail:
  wc_ShaFree( &db_relay->relay_crypto->running_sha_forward );
  wc_ShaFree( &db_relay->relay_crypto->running_sha_backward );
  wc_AesFree( &db_relay->relay_crypto->aes_forward );
  wc_AesFree( &db_relay->relay_crypto->aes_backward );

  free( db_relay->relay_crypto );

  wc_curve25519_free( &responder_handshake_public_key );
  wc_curve25519_free( &ntor_onion_key );

  free( secret_input );
  free( auth_input );

  return -1;
}

int d_start_v3_handshake( DlConnection* or_connection )
{
  int i;
  int wolf_succ;
  CellShortVariable* versions_cell;
  CellVariable* certs_cell;
  TorCert* working_cert;
  unsigned char* initiator_rsa_identity_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_identity_cert_der_size;
  unsigned char* initiator_rsa_auth_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_auth_cert_der_size;
  WC_RNG rng;

  or_connection->responder_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );
  or_connection->initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );

  wc_InitSha256( &or_connection->initiator_sha );
  wc_InitSha256( &or_connection->responder_sha );

  wc_InitRng( &rng );

  versions_cell = malloc( LEGACY_CIRCID_LEN + 3 + 4 );

  // make a versions cell
  versions_cell->circ_id = 0;
  versions_cell->command = VERSIONS;
  versions_cell->length = 4;
  versions_cell->payload.versions[0] = 3;
  versions_cell->payload.versions[1] = 4;

  v_networkize_variable_short_cell( versions_cell );

  wc_Sha256Update( &or_connection->initiator_sha, (uint8_t*)versions_cell, LEGACY_CIRCID_LEN + 3 + 4 );

  // send the versions cell
  wolf_succ = wolfSSL_send( or_connection->ssl, (uint8_t*)versions_cell, LEGACY_CIRCID_LEN + 3 + 4, 0 );

  free( versions_cell );

  if ( wolf_succ <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send versions cell, error code: %d", wolfSSL_get_error( or_connection->ssl, wolf_succ ) );
#endif

    goto fail;
  }

  // generate certs for certs cell
  if ( d_generate_certs( &or_connection->initiator_rsa_identity_key_der_size, or_connection->initiator_rsa_identity_key_der, initiator_rsa_identity_cert_der, &initiator_rsa_identity_cert_der_size, initiator_rsa_auth_cert_der, &initiator_rsa_auth_cert_der_size, &or_connection->initiator_rsa_auth_key, &rng ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate rsa certificates" );
#endif

    goto fail;
  }

  // generate a certs cell of our own
  certs_cell = malloc( CIRCID_LEN + 3 + 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size );

  certs_cell->circ_id = 0;
  certs_cell->command = CERTS;
  certs_cell->length = 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size;
  certs_cell->payload.certs.num_certs = 2;

  working_cert = certs_cell->payload.certs.certs;

  working_cert->cert_type = IDENTITY_CERT;
  working_cert->cert_length = initiator_rsa_identity_cert_der_size;
  memcpy( working_cert->cert, initiator_rsa_identity_cert_der, working_cert->cert_length );

  working_cert = (uint8_t*)working_cert + 3 + working_cert->cert_length;

  working_cert->cert_type = RSA_AUTH_CERT;
  working_cert->cert_length = initiator_rsa_auth_cert_der_size;
  memcpy( working_cert->cert, initiator_rsa_auth_cert_der, working_cert->cert_length );

  v_networkize_variable_cell( certs_cell );

  wc_Sha256Update( &or_connection->initiator_sha, (uint8_t*)certs_cell, CIRCID_LEN + 3 + 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size );

  wolf_succ = wolfSSL_send( or_connection->ssl, (uint8_t*)certs_cell, CIRCID_LEN + 3 + 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size, 0 );

  free( certs_cell );

  if ( wolf_succ <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send certs cell, error code: %d", wolfSSL_get_error( or_connection->ssl, wolf_succ ) );
#endif

    goto fail_certs;
  }

  wc_FreeRng( &rng );

  free( initiator_rsa_identity_cert_der );
  free( initiator_rsa_auth_cert_der );

  return 0;

// we repeate the free calls here because we need to free the key_ders on fail and its
// much easier to forget to free things at random points the in function rather than
// just repeat calls at the end
fail_certs:
  wc_FreeRsaKey( &or_connection->initiator_rsa_auth_key );
fail:
  wc_FreeRng( &rng );

  free( initiator_rsa_identity_cert_der );
  free( initiator_rsa_auth_cert_der );

  // I need to free this in the fail states of the other steps of the handshake
  free( or_connection->responder_rsa_identity_key_der );
  free( or_connection->initiator_rsa_identity_key_der );

  wc_Sha256Free( &or_connection->responder_sha );
  wc_Sha256Free( &or_connection->initiator_sha );

  return -1;
}

void v_process_versions( DlConnection* or_connection, CellShortVariable* versions_cell, int length )
{
  wc_Sha256Update( &or_connection->responder_sha, (uint8_t*)versions_cell, length );

  // TODO check that our versions are compatable, not neccessary in chutney
}

int d_process_certs( DlConnection* or_connection, CellVariable* certs_cell, int length )
{
  int succ;
  WOLFSSL_X509* peer_cert;

  wc_Sha256Update( &or_connection->responder_sha, (uint8_t*)certs_cell, length );

  v_hostize_variable_cell( certs_cell );

  peer_cert = wolfSSL_get_peer_certificate( or_connection->ssl );

  if ( peer_cert == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed get peer cert" );
#endif

    goto fail;
  }

  succ = d_verify_certs( certs_cell, peer_cert, &or_connection->responder_rsa_identity_key_der_size, or_connection->responder_rsa_identity_key_der );

  wolfSSL_X509_free( peer_cert );

  // verify certs
  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to verify certs" );
#endif

    goto fail;
  }

  return 0;

fail:
  // I need to free this in the fail states of the other steps of the handshake
  wc_FreeRsaKey( &or_connection->initiator_rsa_auth_key );

  free( or_connection->responder_rsa_identity_key_der );
  free( or_connection->initiator_rsa_identity_key_der );

  wc_Sha256Free( &or_connection->responder_sha );
  wc_Sha256Free( &or_connection->initiator_sha );

  return -1;
}

int d_process_challenge( DlConnection* or_connection, CellVariable* challenge_cell, int length )
{
  int ret = 0;
  CellVariable* authenticate_cell;
  WC_RNG rng;
  Sha256 reusable_sha;
  unsigned char reusable_sha_sum[WC_SHA256_DIGEST_SIZE];
  WOLFSSL_X509* peer_cert;
  Hmac tls_secrets_hmac;
  int wolf_succ;

  wc_InitRng( &rng );
  wc_InitSha256( &reusable_sha );

  wc_Sha256Update( &or_connection->responder_sha, (uint8_t*)challenge_cell, length );

  peer_cert = wolfSSL_get_peer_certificate( or_connection->ssl );

  if ( peer_cert == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed get peer cert" );
#endif

    ret = -1;
    goto finish;
  }

  // VARIABLE_CELL_HEADER_SIZE, 4 for the auth_type and auth_length and 352 for the auth body
  authenticate_cell = malloc( VARIABLE_CELL_HEADER_SIZE + 4 + 352 );

  // generate answer for auth challenge
  authenticate_cell->circ_id = 0;
  authenticate_cell->command = AUTHENTICATE;
  authenticate_cell->length = 4 + 352;

  authenticate_cell->payload.authenticate.auth_type = AUTH_ONE;
  authenticate_cell->payload.authenticate.auth_length = 352;

  // fill in type
  memcpy( authenticate_cell->payload.authenticate.auth_1.type, AUTH_ONE_TYPE_STRING, 8 );

  // create the hash of the clients identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, or_connection->initiator_rsa_identity_key_der, or_connection->initiator_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( authenticate_cell->payload.authenticate.auth_1.client_id, reusable_sha_sum, 32 );

  // create the hash of the server's identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, or_connection->responder_rsa_identity_key_der, or_connection->responder_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( authenticate_cell->payload.authenticate.auth_1.server_id, reusable_sha_sum, 32 );

  // create the hash of all server cells so far and fill the authenticate cell with it
  wc_Sha256Final( &or_connection->responder_sha, reusable_sha_sum );
  memcpy( authenticate_cell->payload.authenticate.auth_1.server_log, reusable_sha_sum, 32 );

  // create the hash of all cilent cells so far and fill the authenticate cell with it
  wc_Sha256Final( &or_connection->initiator_sha, reusable_sha_sum );
  memcpy( authenticate_cell->payload.authenticate.auth_1.client_log, reusable_sha_sum, 32 );

  // create a sha hash of the tls cert and copy it in
  wc_Sha256Update( &reusable_sha, peer_cert->derCert->buffer, peer_cert->derCert->length );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( authenticate_cell->payload.authenticate.auth_1.server_cert, reusable_sha_sum, 32 );

  // set the hmac key to the master secret that was negotiated
  wc_HmacSetKey( &tls_secrets_hmac, WC_SHA256, or_connection->ssl->arrays->masterSecret, SECRET_LEN );

  // update the hmac
  wc_HmacUpdate( &tls_secrets_hmac, or_connection->ssl->arrays->clientRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, or_connection->ssl->arrays->serverRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, (unsigned char*)"Tor V3 handshake TLS cross-certification", strlen( "Tor V3 handshake TLS cross-certification" ) + 1 );
  // finalize the hmac
  wc_HmacFinal( &tls_secrets_hmac, reusable_sha_sum );
  wc_HmacFree( &tls_secrets_hmac );
  // free the temporary arrays
  wolfSSL_FreeArrays( or_connection->ssl );

  // copy the tls secrets digest in
  memcpy( authenticate_cell->payload.authenticate.auth_1.tls_secrets, reusable_sha_sum, 32 );

  // fill the rand array
  wc_RNG_GenerateBlock( &rng, authenticate_cell->payload.authenticate.auth_1.rand, 24 );
  // create the signature, exlucde the signature part of the structure
  wc_Sha256Update( &reusable_sha, &(authenticate_cell->payload.authenticate.auth_1), sizeof( AuthenticationOne ) - 128 );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );

  wc_RsaSSL_Sign( reusable_sha_sum, 32, authenticate_cell->payload.authenticate.auth_1.signature, 128, &or_connection->initiator_rsa_auth_key, &rng );

  v_networkize_variable_cell( authenticate_cell );

  wolf_succ = wolfSSL_send( or_connection->ssl, (uint8_t*)authenticate_cell, VARIABLE_CELL_HEADER_SIZE + 4 + 352, 0 );

  free( authenticate_cell );

  if ( wolf_succ <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send authenticate cell, error code: %d", wolfSSL_get_error( or_connection->ssl, wolf_succ ) );
#endif

    ret = -1;
  }

finish:
  wolfSSL_X509_free( peer_cert );

  wc_Sha256Free( &reusable_sha );

  // I need to free this in the fail states of the other steps of the handshake
  free( or_connection->responder_rsa_identity_key_der );
  free( or_connection->initiator_rsa_identity_key_der );

  wc_FreeRsaKey( &or_connection->initiator_rsa_auth_key );

  wc_Sha256Free( &or_connection->responder_sha );
  wc_Sha256Free( &or_connection->initiator_sha );

  wc_FreeRng( &rng );

  return ret;
}

int d_process_netinfo( DlConnection* or_connection, Cell* netinfo_cell )
{
  int i;
  int wolf_succ;
  Cell* res_netinfo_cell;
  uint8_t my_address[16];
  int my_address_length;
  uint8_t other_address[16];
  int other_address_length = 0;
  MyAddr* working_myaddr;

  v_hostize_cell( netinfo_cell );

  my_address_length = netinfo_cell->payload.netinfo.addresses_4.otheraddr.length;

  if ( my_address_length == 4 )
  {
    memcpy( my_address, netinfo_cell->payload.netinfo.addresses_4.otheraddr.address, my_address_length );

    working_myaddr = netinfo_cell->payload.netinfo.addresses_4.myaddr.addresses;

    for ( i = 0; i < netinfo_cell->payload.netinfo.addresses_4.myaddr.num_myaddr; i++ )
    {
      other_address_length = working_myaddr->length;

      if ( other_address_length == 4 )
      {
        memcpy( other_address, working_myaddr->address, other_address_length );
        break;
      }
      else
      {
        // TODO ipv6 support
        other_address_length = -1;
      }

      working_myaddr = (uint8_t*)working_myaddr + 2 + working_myaddr->length;
    }
  }

  // TODO ipv6 support
  if ( my_address_length != 4 || other_address_length == -1 )
  {
    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "port: %d", or_connection->port );
  ESP_LOGE( MINITOR_TAG, "myaddr: %x %x %x %x, otheraddr: %x %x %x %x", my_address[0], my_address[1], my_address[2], my_address[3], other_address[0], other_address[1], other_address[2], other_address[3] );

  res_netinfo_cell = malloc( MINITOR_CELL_LEN );

  // fixed header, 4 for time, 6 for other addr, 1 for num addrs, 6 for my addr
  res_netinfo_cell->length = FIXED_CELL_HEADER_SIZE + 4 + 6 + 1 + 6;

  res_netinfo_cell->circ_id = 0;
  res_netinfo_cell->command = NETINFO;

  time( &( res_netinfo_cell->payload.netinfo.time ) );

  res_netinfo_cell->payload.netinfo.addresses_4.otheraddr.type = IPv4;
  res_netinfo_cell->payload.netinfo.addresses_4.otheraddr.length = other_address_length;
  memcpy( res_netinfo_cell->payload.netinfo.addresses_4.otheraddr.address, other_address, other_address_length );

  res_netinfo_cell->payload.netinfo.addresses_4.myaddr.num_myaddr = 1;

  working_myaddr = res_netinfo_cell->payload.netinfo.addresses_4.myaddr.addresses;

  working_myaddr->type = IPv4;
  working_myaddr->length = my_address_length;
  memcpy( working_myaddr->address, my_address, my_address_length );

  v_networkize_cell( res_netinfo_cell );

  wolf_succ = wolfSSL_send( or_connection->ssl, (uint8_t*)res_netinfo_cell + FIXED_CELL_OFFSET, CELL_LEN, 0 );

  free( res_netinfo_cell );

  if ( wolf_succ <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send NETINFO cell, error code: %d", wolfSSL_get_error( or_connection->ssl, wolf_succ ) );
#endif

    return -1;
  }

  return 0;
}

int d_verify_certs( CellVariable* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der )
{
  int ret = 0;
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
  uint8_t temp_array[128];
  TorCert* working_cert;

  wc_InitRsaKey( &responder_rsa_identity_key, NULL );

  // verify the certs
  time( &now );

  working_cert = certs_cell->payload.certs.certs;

  for ( i = 0; i < certs_cell->payload.certs.num_certs; i++ )
  {
    if ( working_cert->cert_type > IDENTITY_CERT )
    {
      break;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      working_cert->cert,
      working_cert->cert_length,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid certificate" );
#endif

      ret = -1;
      goto finish;
    }

    cert_date = ud_get_cert_date( certificate->notBefore.data, certificate->notBefore.length );

    if ( cert_date == 0 || cert_date > now )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not before time" );
#endif

      ret = -1;
      goto finish;
    }

    cert_date = ud_get_cert_date( certificate->notAfter.data, certificate->notAfter.length );

    if ( cert_date == 0 || cert_date < now )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not after time" );
#endif

      ret = -1;
      goto finish;
    }

    if ( working_cert->cert_type == LINK_KEY )
    {
      link_key_certificate = certificate;
      link_key_count++;

      if ( link_key_count > 1 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many LINK_KEYs" );
#endif

        ret = -1;
        goto finish;
      }

      if ( memcmp( certificate->pubKey.buffer, peer_cert->pubKey.buffer, certificate->pubKey.length ) != 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to match LINK_KEY with tls key" );
#endif

        ret = -1;
        goto finish;
      }
    }
    else if ( working_cert->cert_type == IDENTITY_CERT )
    {
      identity_count++;

      if ( identity_count > 1 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many IDENTITY_CERTs" );
#endif

        ret = -1;
        goto finish;
      }

      idx = 0;
      wolf_succ = wc_RsaPublicKeyDecode( certificate->pubKey.buffer, &idx, &responder_rsa_identity_key, certificate->pubKey.length );

      if ( wolf_succ < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to parse IDENTITY_CERT, error code: %d", wolf_succ );
#endif

        ret = -1;
        goto finish;
      }

      memcpy( responder_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
      *responder_rsa_identity_key_der_size = certificate->pubKey.length;

      // verify the signatures on the keys
      wolf_succ = wc_RsaSSL_Verify(
        link_key_certificate->sig.buffer,
        link_key_certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      if ( wolf_succ <= 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify LINK_KEY signature, error code: %d", wolf_succ );
#endif

        ret = -1;
        goto finish;
      }

      wolf_succ = wc_RsaSSL_Verify(
        certificate->sig.buffer,
        certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      if ( wolf_succ <= 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify IDENTITY_CERT signature, error code: %d", wolf_succ );
#endif

        ret = -1;
        goto finish;
      }
    }

    // advance to next cert, 3 is for the type and length
    working_cert = (uint8_t*)working_cert + working_cert->cert_length + 3;
  }

  if ( link_key_count == 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No LINK_KEYs" );
#endif

    ret = -1;
  }

  if ( identity_count == 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No IDENTITY_CERTs" );
#endif

    ret = -1;
  }

finish:
  if ( identity_count > 0 )
  {
    wolfSSL_X509_free( certificate );
  }

  if ( link_key_count > 0 )
  {
    wolfSSL_X509_free( link_key_certificate );
  }

  wc_FreeRsaKey( &responder_rsa_identity_key );

  return ret;
}

int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng )
{
  struct stat st;
  int fd;
  int wolf_succ;
  unsigned int idx;
  RsaKey initiator_rsa_identity_key;
  uint8_t tmp_initiator_rsa_identity_key_der[1024];
  //unsigned char* tmp_initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 1024 );
  Cert initiator_rsa_identity_cert;
  Cert initiator_rsa_auth_cert;
  WOLFSSL_X509* certificate = NULL;

  // init the rsa keys
  wc_InitRsaKey( &initiator_rsa_identity_key, NULL );
  wc_InitRsaKey( initiator_rsa_auth_key, NULL );

  // rsa identity key doesn't exist, create it and save it
  if ( stat( FILESYSTEM_PREFIX "identity_rsa_key", &st ) == -1 )
  {
    // make and save the identity key to the file system
    wolf_succ = wc_MakeRsaKey( &initiator_rsa_identity_key, 1024, 65537, rng );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key, error code: %d", wolf_succ );
#endif

      goto fail;
    }

    wolf_succ = wc_RsaKeyToDer( &initiator_rsa_identity_key, tmp_initiator_rsa_identity_key_der, 1024 );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key der, error code: %d", wolf_succ );
#endif

      goto fail;
    }

    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_key", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }

    if ( write( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }
  // rsa identity key exists, load it from the file system
  }
  else
  {
    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_key", O_RDONLY ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }

    if ( read( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_key, errno: %d", errno );
#endif

      goto fail;
    }

    idx = 0;
    wolf_succ = wc_RsaPrivateKeyDecode( tmp_initiator_rsa_identity_key_der, &idx, &initiator_rsa_identity_key, 1024 );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to load rsa identity private key der, error code: %d", wolf_succ );
#endif

      goto fail;
    }
  }

  //free( tmp_initiator_rsa_identity_key_der );

  // make and export the auth key
  wolf_succ = wc_MakeRsaKey( initiator_rsa_auth_key, 1024, 65537, rng );

  if ( wolf_succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth key, error code: %d", wolf_succ );
#endif

    goto fail;
  }

  // does not seem to alloc anything, if so no need to free
  wc_InitCert( &initiator_rsa_identity_cert );

  // rsa identity cert doesn't exist, create it and save it
  if ( stat( FILESYSTEM_PREFIX "identity_rsa_cert_der", &st ) == -1 )
  {
    // TODO randomize these
    strncpy( initiator_rsa_identity_cert.subject.country, "US", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.state, "OR", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.locality, "Portland", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.org, "yaSSL", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.unit, "Development", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE );

    *initiator_rsa_identity_cert_der_size = wc_MakeSelfCert( &initiator_rsa_identity_cert, initiator_rsa_identity_cert_der, 2048, &initiator_rsa_identity_key, rng );

    // TODO check that init doesn't alloc anything
    //wc_SetCert_Free( &initiator_rsa_identity_cert );

    if ( *initiator_rsa_identity_cert_der_size <= 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity cert der, error code: %d", *initiator_rsa_identity_cert_der_size );
#endif

      goto fail;
    }

    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_cert_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( write( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_cert_der_size ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      initiator_rsa_identity_cert_der,
      *initiator_rsa_identity_cert_der_size,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid identity certificate" );
#endif

      goto fail;
    }

    memcpy( initiator_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
    *initiator_rsa_identity_key_der_size = certificate->pubKey.length;

    wolfSSL_X509_free( certificate );

    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_key_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( write( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_key_der_size ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
    }
  // rsa identity cert exists, load it from the file system
  }
  else
  {
    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_cert_der", O_RDONLY ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( ( *initiator_rsa_identity_cert_der_size = read( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * 2048 ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_cert_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( ( fd = open( FILESYSTEM_PREFIX "identity_rsa_key_der", O_RDONLY ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( ( *initiator_rsa_identity_key_der_size = read( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * 2048 ) ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
    }

    if ( close( fd ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close " FILESYSTEM_PREFIX "identity_rsa_key_der, errno: %d", errno );
#endif

      goto fail;
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

  //*initiator_rsa_auth_cert_der_size = wc_MakeSelfCert( &initiator_rsa_auth_cert, initiator_rsa_auth_cert_der, 2048, initiator_rsa_auth_key, rng );
  *initiator_rsa_auth_cert_der_size = wc_MakeCert( &initiator_rsa_auth_cert, initiator_rsa_auth_cert_der, 2048, initiator_rsa_auth_key, NULL, rng );

  // TODO check that init doesn't alloc anything
  //wc_SetCert_Free( &initiator_rsa_auth_cert );

  if ( *initiator_rsa_auth_cert_der_size <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth cert der, error code: %d", *initiator_rsa_auth_cert_der_size );
#endif

    goto fail;
  }

  wolf_succ = wc_SignCert( *initiator_rsa_auth_cert_der_size, initiator_rsa_auth_cert.sigType, initiator_rsa_auth_cert_der, 2048, &initiator_rsa_identity_key, NULL, rng );

  if ( wolf_succ <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign rsa auth cert der, error code: %d", wolf_succ );
#endif

    goto fail;
  }

  *initiator_rsa_auth_cert_der_size = wolf_succ;

  wc_FreeRsaKey( &initiator_rsa_identity_key );

  return 0;

fail:
  wc_FreeRsaKey( &initiator_rsa_identity_key );
  wc_FreeRsaKey( initiator_rsa_auth_key );

  return -1;
}
