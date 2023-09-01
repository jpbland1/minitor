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

#include "../include/config.h"
#include "../h/port.h"

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/fe_operations.h"
#include "../h/custom_sc.h"

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

void v_onion_service_handle_local_tcp_data( OnionCircuit* circuit, DlConnection* or_connection, ServiceTcpTraffic* tcp_traffic )
{
  int i;
  Cell* relay_cell;

  relay_cell = malloc( MINITOR_CELL_LEN );

  relay_cell->circ_id = tcp_traffic->circ_id;
  relay_cell->command = RELAY;

  relay_cell->payload.relay.recognized = 0;
  relay_cell->payload.relay.stream_id = tcp_traffic->stream_id;
  relay_cell->payload.relay.digest = 0;

  if ( tcp_traffic->length == 0 )
  {
    relay_cell->payload.relay.relay_command = RELAY_END;
    relay_cell->payload.relay.length = 1;
    relay_cell->payload.relay.destroy_code = REASON_DONE;
  }
  else
  {
    relay_cell->payload.relay.relay_command = RELAY_DATA;
    relay_cell->payload.relay.length = (uint16_t)tcp_traffic->length;
    memcpy( relay_cell->payload.relay.data, tcp_traffic->data, tcp_traffic->length );

    free( tcp_traffic->data );
  }

  relay_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + relay_cell->payload.relay.length;

  if ( d_send_relay_cell_and_free( or_connection, relay_cell, &circuit->relay_list, circuit->hs_crypto ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_DATA" );
  }
}

// at this point we have a lock on the connection access mutex
void v_onion_service_handle_cell( OnionCircuit* circuit, DlConnection* or_connection, Cell* relay_cell )
{
  MinitorMutex access_mutex;

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  if ( relay_cell->command != RELAY )
  {
    MINITOR_LOG( MINITOR_TAG, "Invalid cell command %d", relay_cell->command );

    goto circuit_rebuild;
  }

  switch( relay_cell->payload.relay.relay_command )
  {
    case RELAY_BEGIN:
      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      access_mutex = NULL;

      if ( d_onion_service_handle_relay_begin( circuit, or_connection, relay_cell ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to handle RELAY_BEGIN cell" );

        goto circuit_rebuild;
      }

      break;
    case RELAY_DATA:
      if
      (
        d_forward_to_local_connection(
          relay_cell->circ_id,
          relay_cell->payload.relay.stream_id,
          relay_cell->payload.relay.data,
          relay_cell->payload.relay.length
        ) < 0
      )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to handle RELAY_DATA cell" );

        goto circuit_rebuild;
      }

      break;
    case RELAY_END:
      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      access_mutex = NULL;

      v_cleanup_local_connection( relay_cell->circ_id, relay_cell->payload.relay.stream_id );

      break;
    case RELAY_TRUNCATED:
      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      access_mutex = NULL;

      if ( d_onion_service_handle_relay_truncated( circuit, or_connection, relay_cell ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to handle RELAY_END cell" );

        goto circuit_rebuild;
      }

      break;
    case RELAY_DROP:
      break;
    // when an intro request comes in, respond to it
    case RELAY_COMMAND_INTRODUCE2:
      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      access_mutex = NULL;

      if ( d_onion_service_handle_introduce_2( circuit, relay_cell ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to handle RELAY_COMMAND_INTRODUCE2 cell" );

        goto circuit_rebuild;
      }

      break;
    default:
#ifdef DEBUG_MINITOR
      MINITOR_LOG( MINITOR_TAG, "Unequiped to handle relay command %d", relay_cell->payload.relay.relay_command );
#endif
  }

  if ( access_mutex != NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE
  }

  return;

circuit_rebuild:
  // this will give the mutex
  v_circuit_rebuild_or_destroy( circuit, or_connection );
  // MUTEX GIVE
}

int d_onion_service_handle_relay_begin( OnionCircuit* rend_circuit, DlConnection* or_connection, Cell* begin_cell )
{
  int i;
  int ret = 0;
  Cell* connected_cell;
  char* addr;
  uint16_t port = 0;

  addr = malloc( strlen( (char*)begin_cell->payload.relay.data ) + 1 );

  strcpy( addr, (char*)begin_cell->payload.relay.data );

  for ( i = 0; i < strlen( addr ); i++ )
  {
    if ( addr[i] == ':' )
    {
      // increment past the ':' before port parse starts
      for ( i = i + 1; i < strlen( addr ); i++ )
      {
        port *= 10;
        port += addr[i] - '0';
      }
    }
  }

  if ( port == 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "failed to find RELAY_BEGIN port" );

    ret = -1;
    goto finish;
  }

  if ( port != rend_circuit->service->exit_port && port != 443 )
  {
    MINITOR_LOG( MINITOR_TAG, "request was for the wrong port: %d, looking for: %d", port, rend_circuit->service->exit_port );

    ret = -1;
    goto finish;
  }

  if ( d_create_local_connection( begin_cell->circ_id, begin_cell->payload.relay.stream_id, rend_circuit->service->local_port ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "couldn't create local connection" );

    ret = -1;
    goto finish;
  }

  // re-aquire our connection lock
  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( or_connection->conn_id );

  if ( or_connection == NULL )
  {
    ret = -1;
    goto finish;
  }

  connected_cell = malloc( MINITOR_CELL_LEN );

  connected_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE;
  connected_cell->circ_id = begin_cell->circ_id;
  connected_cell->command = RELAY;

  connected_cell->payload.relay.relay_command = RELAY_CONNECTED;
  connected_cell->payload.relay.recognized = 0;
  connected_cell->payload.relay.stream_id = begin_cell->payload.relay.stream_id;
  connected_cell->payload.relay.digest = 0;
  connected_cell->payload.relay.length = 0;

  if ( d_send_relay_cell_and_free( or_connection, connected_cell, &rend_circuit->relay_list, rend_circuit->hs_crypto ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_CONNECTED" );

    ret = -1;
  }

  MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
  // MUTEX GIVE

finish:
  free( addr );

  return ret;
}

int d_onion_service_handle_relay_truncated( OnionCircuit* rend_circuit, DlConnection* or_connection, Cell* truncated_cell )
{
  int i;
  DoublyLinkedOnionRelay* dl_relay;

  d_destroy_onion_circuit( rend_circuit, or_connection );

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  v_remove_circuit_from_list( rend_circuit, &onion_circuits );

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  free( rend_circuit );

  v_cleanup_local_connections_by_circ_id( truncated_cell->circ_id );

  return 0;
}

int d_onion_service_handle_introduce_2( OnionCircuit* intro_circuit, Cell* introduce_cell )
{
  int ret = 0;
  int i;
  int wolf_succ;
  time_t now;
  uint8_t* introduce_p;
  uint8_t* client_pk;
  uint8_t num_specifiers;
  uint8_t num_extensions;
  unsigned char auth_input_mac[MAC_LEN];
  WC_RNG rng;
  curve25519_key hs_handshake_key;
  curve25519_key client_handshake_key;
  DoublyLinkedRendezvousCookie* db_rendezvous_cookie;
  OnionRelay* rend_relay;
  HsCrypto* hs_crypto;
  OnionCircuit* rend_circuit;
  DoublyLinkedOnionRelay* dl_relay;
  DlConnection* or_connection = NULL;

  time( &now );

  if ( now - intro_circuit->service->rend_timestamp < 5 )
  {
#ifdef DEBUG_MINITOR
    MINITOR_LOG( MINITOR_TAG, "Rate limit in effect, dropping intro" );
#endif

    return -1;
  }

  wc_curve25519_init( &client_handshake_key );
  wc_curve25519_init( &hs_handshake_key );

  wc_InitRng( &rng );

  if ( introduce_cell->payload.relay.introduce2.auth_key_type != EDSHA3 )
  {
    MINITOR_LOG( MINITOR_TAG, "Auth key type for RELAY_COMMAND_INTRODUCE2 was not EDSHA3" );

    ret = -1;
    goto finish;
  }

  if ( introduce_cell->payload.relay.introduce2.auth_key_length != 32 )
  {
    MINITOR_LOG( MINITOR_TAG, "Auth key length for RELAY_COMMAND_INTRODUCE2 was not 32" );

    ret = -1;
    goto finish;
  }

  if ( memcmp( introduce_cell->payload.relay.introduce2.auth_key, intro_circuit->intro_crypto->auth_key.p, 32 ) != 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Auth key for RELAY_COMMAND_INTRODUCE2 does not match" );

    ret = -1;
    goto finish;
  }

  introduce_p = introduce_cell->payload.relay.introduce2.auth_key + 32;

  num_extensions = introduce_p[0];

  introduce_p++;

  // skip over the extensions
  for ( i = 0; i < num_extensions; i++ )
  {
    introduce_p += introduce_p[1] + 2;
  }

  client_pk = introduce_p;

  wolf_succ = wc_curve25519_import_public_ex( client_pk, PK_PUBKEY_LEN, &client_handshake_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to import client public key, error code %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  // skip past the client_pk
  introduce_p += PK_PUBKEY_LEN;

  // verify and decrypt
  if ( d_verify_and_decrypt_introduce_2( intro_circuit->service, introduce_cell, num_extensions, client_pk, introduce_p, intro_circuit, &client_handshake_key ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to verify and decrypt RELAY_COMMAND_INTRODUCE2" );

    ret = -1;
    goto finish;
  }

  db_rendezvous_cookie = intro_circuit->service->rendezvous_cookies.head;

  for ( i = 0; i < intro_circuit->service->rendezvous_cookies.length; i++ )
  {
    if ( memcmp( db_rendezvous_cookie->rendezvous_cookie, ((DecryptedIntroduce2*)introduce_p)->rendezvous_cookie, 20 ) == 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Got a replay, silently dropping" );

      goto finish;
    }

    db_rendezvous_cookie = db_rendezvous_cookie->next;
  }

  db_rendezvous_cookie = malloc( sizeof( DoublyLinkedRendezvousCookie ) );

  // copy rendezvous cookie
  memcpy( db_rendezvous_cookie->rendezvous_cookie, ((DecryptedIntroduce2*)introduce_p)->rendezvous_cookie, 20 );

  v_add_rendezvous_cookie_to_list( db_rendezvous_cookie, &intro_circuit->service->rendezvous_cookies );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &hs_handshake_key );

  if ( wolf_succ != 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to make hs_handshake_key, error code %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  hs_crypto = malloc( sizeof( HsCrypto ) );

  if ( d_hs_ntor_handshake_finish( intro_circuit->intro_crypto->auth_key.p, &intro_circuit->intro_crypto->encrypt_key, &hs_handshake_key, &client_handshake_key, hs_crypto, auth_input_mac, false ) < 0 )
  //if ( d_hs_ntor_handshake_finish( introduce_cell, client_pk, intro_circuit, &hs_handshake_key, &client_handshake_key, hs_crypto, auth_input_mac ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to finish the RELAY_COMMAND_INTRODUCE2 ntor handshake" );

    free( hs_crypto );

    ret = -1;
    goto finish;
  }

  // extend to the specified relay and send the handshake reply
  rend_relay = malloc( sizeof( OnionRelay ) );
  rend_relay->address = 0;
  rend_relay->or_port = 0;

  num_extensions = ((DecryptedIntroduce2*)introduce_p)->num_extensions;

  introduce_p = ((DecryptedIntroduce2*)introduce_p)->extensions;

  // skip extensions
  for ( i = 0; i < num_extensions; i++ )
  {
    introduce_p += introduce_p[1] + 2;
  }

  // onion key type should be 1 for NTOR
  if ( ((IntroOnionKey*)introduce_p)->onion_key_type != ONION_NTOR )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to get KEY_NTOR for onion key type" );

    ret = -1;
    goto finish;
  }

  // onion key length should be 32
  if ( ntohs( ((IntroOnionKey*)introduce_p)->onion_key_length ) != 32 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to get 32 for onion key length" );

    ret = -1;
    goto finish;
  }

  memcpy( rend_relay->ntor_onion_key, ((IntroOnionKey*)introduce_p)->onion_key, 32 );

  // skip onion key section
  introduce_p += 32 + 3;

  num_specifiers = introduce_p[0];
  introduce_p++;

  for ( i = 0; i < num_specifiers; i++ )
  {
    if ( ((LinkSpecifier*)introduce_p)->type == IPv4Link )
    {
      // comes in big endian, lwip wants it little endian
      rend_relay->address |= ((LinkSpecifier*)introduce_p)->specifier[0];
      rend_relay->address |= ((uint32_t)((LinkSpecifier*)introduce_p)->specifier[1]) << 8;
      rend_relay->address |= ((uint32_t)((LinkSpecifier*)introduce_p)->specifier[2]) << 16;
      rend_relay->address |= ((uint32_t)((LinkSpecifier*)introduce_p)->specifier[3]) << 24;

      rend_relay->or_port |= ((uint16_t)((LinkSpecifier*)introduce_p)->specifier[4]) << 8;
      rend_relay->or_port |= ((uint16_t)((LinkSpecifier*)introduce_p)->specifier[5]);
    }
    else if ( ((LinkSpecifier*)introduce_p)->type == LEGACYLink )
    {
      memcpy( rend_relay->identity, ((LinkSpecifier*)introduce_p)->specifier, ID_LENGTH );
    }

    introduce_p += ((LinkSpecifier*)introduce_p)->length + 2;
  }

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  rend_circuit = onion_circuits;

  while ( rend_circuit != NULL )
  {
    if ( rend_circuit->status == CIRCUIT_STANDBY )
    {
      break;
    }

    rend_circuit = rend_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  memcpy( hs_crypto->rendezvous_cookie, db_rendezvous_cookie->rendezvous_cookie, 20 );
  memcpy( hs_crypto->point, hs_handshake_key.p.point, PK_PUBKEY_LEN );
  memcpy( hs_crypto->auth_input_mac, auth_input_mac, MAC_LEN );

  if ( rend_circuit == NULL )
  {
    v_send_init_circuit_internal( 2, CIRCUIT_RENDEZVOUS, intro_circuit->service, NULL, 0, 0, NULL, rend_relay, hs_crypto, NULL );
  }
  else
  {
    dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    memset(dl_relay, 0, sizeof(DoublyLinkedOnionRelay));
    dl_relay->package_window = RELAY_WINDOW_DEFAULT;
    dl_relay->deliver_window = RELAY_WINDOW_DEFAULT;
    dl_relay->relay = rend_relay;

    v_add_relay_to_list( dl_relay, &rend_circuit->relay_list );

    // MUTEX TAKE
    or_connection = px_get_conn_by_id_and_lock( rend_circuit->conn_id );

    if ( or_connection == NULL || d_router_extend2( rend_circuit, or_connection, rend_circuit->relay_list.built_length ) < 0 )
    {

      wc_Sha3_256_Free( &hs_crypto->hs_running_sha_forward );
      wc_Sha3_256_Free( &hs_crypto->hs_running_sha_backward );
      wc_AesFree( &hs_crypto->hs_aes_forward );
      wc_AesFree( &hs_crypto->hs_aes_backward );

      free( hs_crypto );

      // MUTEX TAKE
      MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

      v_remove_circuit_from_list( rend_circuit, &onion_circuits );

      MINITOR_MUTEX_GIVE( circuits_mutex );
      // MUTEX GIVE

      d_destroy_onion_circuit( rend_circuit, or_connection );
      // MUTEX GIVE

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

    if ( or_connection != NULL )
    {
      MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
      // MUTEX GIVE
    }
  }

  time( &( intro_circuit->service->rend_timestamp ) );

finish:
  wc_FreeRng( &rng );

  wc_curve25519_free( &client_handshake_key );
  wc_curve25519_free( &hs_handshake_key );

  return ret;
}

int d_router_join_rendezvous( OnionCircuit* rend_circuit, DlConnection* or_connection, unsigned char* rendezvous_cookie, unsigned char* hs_pub_key, unsigned char* auth_input_mac )
{
  Cell* rend_cell;

  rend_cell = malloc( MINITOR_CELL_LEN );

  rend_cell->circ_id = rend_circuit->circ_id;
  rend_cell->command = RELAY;

  rend_cell->payload.relay.relay_command = RELAY_COMMAND_RENDEZVOUS1;
  rend_cell->payload.relay.recognized = 0;
  rend_cell->payload.relay.stream_id = 0;
  rend_cell->payload.relay.digest = 0;
  rend_cell->payload.relay.length = 20 + PK_PUBKEY_LEN + MAC_LEN;

  rend_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + rend_cell->payload.relay.length;

  memcpy( rend_cell->payload.relay.rend1.rendezvous_cookie, rendezvous_cookie, 20 );
  memcpy( rend_cell->payload.relay.rend1.public_key, hs_pub_key, PK_PUBKEY_LEN );
  memcpy( rend_cell->payload.relay.rend1.auth, auth_input_mac, MAC_LEN );

  if ( d_send_relay_cell_and_free( or_connection, rend_cell, &rend_circuit->relay_list, NULL ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send the RELAY_COMMAND_RENDEZVOUS1 cell" );

    return -1;
  }

  return 0;
}

int d_verify_and_decrypt_introduce_2(
  OnionService* onion_service,
  Cell* introduce_cell,
  uint8_t num_extensions,
  uint8_t* client_pk,
  uint8_t* encrypted_data,
  OnionCircuit* intro_circuit,
  curve25519_key* client_handshake_key
)
{
  int ret = 0;
  int i;
  int encrypted_length;
  unsigned int idx;
  int wolf_succ;
  Aes aes_key;
  unsigned char aes_iv[16] = { 0 };
  wc_Shake reusable_shake;
  wc_Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char* intro_secret_hs_input = malloc( sizeof( unsigned char ) * ( CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH ) );
  unsigned char* working_intro_secret_hs_input = intro_secret_hs_input;
  unsigned char* info = malloc( sizeof( unsigned char ) * ( HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE ) );
  unsigned char* hs_keys = malloc( sizeof( unsigned char ) * ( AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE ) );
  int64_t reusable_length;
  unsigned char reusable_length_buffer[8];

  encrypted_length = introduce_cell->payload.relay.length - (uint16_t)( encrypted_data - introduce_cell->payload.relay.data + MAC_LEN );

  wc_AesInit( &aes_key, NULL, INVALID_DEVID );
  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  // compute intro_secret_hs_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( &intro_circuit->intro_crypto->encrypt_key, client_handshake_key, working_intro_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to compute shared secret, error code: %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, introduce_cell->payload.relay.introduce2.auth_key, introduce_cell->payload.relay.introduce2.auth_key_length );

  working_intro_secret_hs_input += introduce_cell->payload.relay.introduce2.auth_key_length;

  memcpy( working_intro_secret_hs_input, client_pk, 32 );

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, intro_circuit->intro_crypto->encrypt_key.p.point, 32 );

  working_intro_secret_hs_input += 32;

  memcpy( working_intro_secret_hs_input, HS_PROTOID, HS_PROTOID_LENGTH );

  memcpy( info, HS_PROTOID_EXPAND, HS_PROTOID_EXPAND_LENGTH );

  for ( i = 0; i < 2; i++ )
  {
    if ( i == 0 )
    {
      memcpy( info + HS_PROTOID_EXPAND_LENGTH, onion_service->current_sub_credential, WC_SHA3_256_DIGEST_SIZE );
    }
    else
    {
      memcpy( info + HS_PROTOID_EXPAND_LENGTH, onion_service->previous_sub_credential, WC_SHA3_256_DIGEST_SIZE );
    }

    // compute hs_keys
    wc_Shake256_Update( &reusable_shake, intro_secret_hs_input,  CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH );
    wc_Shake256_Update( &reusable_shake, (unsigned char*)HS_PROTOID_KEY, HS_PROTOID_KEY_LENGTH );
    wc_Shake256_Update( &reusable_shake, info, HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE );
    wc_Shake256_Final( &reusable_shake, hs_keys, AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE );

    // verify the mac
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
    wc_Sha3_256_Update( &reusable_sha3, introduce_cell->payload.relay.introduce2.legacy_key_id, 20 );

    reusable_length_buffer[0] = introduce_cell->payload.relay.introduce2.auth_key_type;

    wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 1 );

    reusable_length_buffer[0] = (uint8_t)( introduce_cell->payload.relay.introduce2.auth_key_length >> 8 );
    reusable_length_buffer[1] = (uint8_t)introduce_cell->payload.relay.introduce2.auth_key_length;

    wc_Sha3_256_Update( &reusable_sha3, reusable_length_buffer, 2 );
    wc_Sha3_256_Update( &reusable_sha3, introduce_cell->payload.relay.introduce2.auth_key, introduce_cell->payload.relay.introduce2.auth_key_length );
    wc_Sha3_256_Update( &reusable_sha3, &num_extensions, 1 );

    wc_Sha3_256_Update( &reusable_sha3, client_pk, PK_PUBKEY_LEN );
    wc_Sha3_256_Update( &reusable_sha3, encrypted_data, encrypted_length );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    // compare the mac
    if ( memcmp( reusable_sha3_sum, introduce_cell->payload.relay.data + introduce_cell->payload.relay.length - MAC_LEN, WC_SHA3_256_DIGEST_SIZE ) == 0 )
    {
      i = 0;
      break;
    }
  }

  if ( i >= 2 )
  {
    MINITOR_LOG( MINITOR_TAG, "The mac of the RELAY_COMMAND_INTRODUCE2 cell does not match our calculations" );

    ret = -1;
    goto finish;
  }

  // decrypt the encrypted section
  wc_AesSetKeyDirect( &aes_key, hs_keys, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  wolf_succ = wc_AesCtrEncrypt( &aes_key, encrypted_data, encrypted_data, encrypted_length );

  if ( wolf_succ < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to decrypt RELAY_COMMAND_INTRODUCE2 encrypted data, error code: %d", wolf_succ );

    ret = -1;
  }

finish:
  wc_Shake256_Free( &reusable_shake );
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_AesFree( &aes_key );

  free( intro_secret_hs_input );
  free( info );
  free( hs_keys );

  return ret;
}

int d_hs_ntor_handshake_finish(
  uint8_t* auth_pub_key,
  curve25519_key* encrypt_key,
  curve25519_key* hs_handshake_key,
  curve25519_key* client_handshake_key,
  HsCrypto* hs_crypto,
  uint8_t* auth_input_mac,
  bool is_client
)
{
  int ret = 0;
  unsigned int idx;
  int wolf_succ;
  unsigned char* rend_secret_hs_input = malloc( sizeof( unsigned char ) * ( CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH ) );
  unsigned char* working_rend_secret_hs_input = rend_secret_hs_input;
  unsigned char aes_iv[16] = { 0 };
  wc_Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  wc_Shake reusable_shake;
  unsigned char* expanded_keys = malloc( sizeof( unsigned char ) * ( WC_SHA3_256_DIGEST_SIZE * 2 + AES_256_KEY_SIZE * 2 ) );
  unsigned char* hs_key_seed = malloc( sizeof(  unsigned char ) * WC_SHA256_DIGEST_SIZE );
  int64_t reusable_length;
  unsigned char reusable_length_buffer[8];

  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  // compute rend_secret_hs_input
  if ( is_client == true )
  {
    idx = 32;
    wolf_succ = wc_curve25519_shared_secret_ex( client_handshake_key, hs_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ < 0 || idx != 32 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );

      ret = -1;
      goto finish;
    }
  }
  else
  {
    idx = 32;
    wolf_succ = wc_curve25519_shared_secret_ex( hs_handshake_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ < 0 || idx != 32 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );

      ret = -1;
      goto finish;
    }
  }

  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  if ( is_client == true )
  {
    idx = 32;
    wolf_succ = wc_curve25519_shared_secret_ex( client_handshake_key, encrypt_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ < 0 || idx != 32 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );

      ret = -1;
      goto finish;
    }
  }
  else
  {
    idx = 32;
    wolf_succ = wc_curve25519_shared_secret_ex( encrypt_key, client_handshake_key, working_rend_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ < 0 || idx != 32 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to compute EXP(X,y), error code %d", wolf_succ );

      ret = -1;
      goto finish;
    }
  }

  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  memcpy( working_rend_secret_hs_input, auth_pub_key, ED25519_PUB_KEY_SIZE );
  working_rend_secret_hs_input += ED25519_PUB_KEY_SIZE;

  memcpy( working_rend_secret_hs_input, encrypt_key->p.point, CURVE25519_KEYSIZE );
  working_rend_secret_hs_input += CURVE25519_KEYSIZE;

  memcpy( working_rend_secret_hs_input, client_handshake_key->p.point, CURVE25519_KEYSIZE );
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
  wc_Sha3_256_Update( &reusable_sha3, auth_pub_key, ED25519_PUB_KEY_SIZE );
  wc_Sha3_256_Update( &reusable_sha3, encrypt_key->p.point, CURVE25519_KEYSIZE );
  wc_Sha3_256_Update( &reusable_sha3, hs_handshake_key->p.point, CURVE25519_KEYSIZE );
  wc_Sha3_256_Update( &reusable_sha3, client_handshake_key->p.point, CURVE25519_KEYSIZE );
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

  // TODO its possible we should change the send and decrypt functions instead
  // of setting up keys backwards for clients
  if ( is_client == false )
  {
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_forward, expanded_keys, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, expanded_keys + WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_DIGEST_SIZE );
    wc_AesSetKeyDirect( &hs_crypto->hs_aes_forward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ), AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );
    wc_AesSetKeyDirect( &hs_crypto->hs_aes_backward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ) + AES_256_KEY_SIZE, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );
  }
  else
  {
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, expanded_keys, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_forward, expanded_keys + WC_SHA3_256_DIGEST_SIZE, WC_SHA3_256_DIGEST_SIZE );
    wc_AesSetKeyDirect( &hs_crypto->hs_aes_backward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ), AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );
    wc_AesSetKeyDirect( &hs_crypto->hs_aes_forward, expanded_keys + ( WC_SHA3_256_DIGEST_SIZE * 2 ) + AES_256_KEY_SIZE, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );
  }

finish:
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );

  free( rend_secret_hs_input );
  free( hs_key_seed );
  free( expanded_keys );

  return ret;
}

DoublyLinkedOnionRelayList* px_get_target_relays( unsigned int hsdir_n_replicas, unsigned char* blinded_pub_key, int time_period, unsigned int hsdir_interval, unsigned int hsdir_spread_store, int next )
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
  wc_Sha3 reusable_sha3;
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

    to_store = hsdir_spread_store;

    hsdir_index_list = px_get_responsible_hsdir_relays_by_hs_index( hs_index, hsdir_spread_store, next, target_relays );

    if ( hsdir_index_list == NULL )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to get hsdir_index_list" );

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

      hsdir_relay_node = next_hsdir_relay_node;

      to_store--;
    }

    for ( ; j < hsdir_index_list->length; j++ )
    {
      free( hsdir_relay_node->relay );
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
    "signature "
    ;

  sprintf( revision_counter_str, "%d", revision_counter );

  sprintf( plain_file, "%s_plain", filename );

  plain_fd = open( plain_file, O_CREAT | O_RDWR | O_TRUNC, 0600 );

  if ( plain_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", plain_file );

    return -1;
  }

  cipher_fd = open( filename, O_RDONLY );

  if ( cipher_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", filename );

    close( plain_fd );

    return -1;
  }

  succ = write( plain_fd, HS_DESC_SIG_PREFIX, HS_DESC_SIG_PREFIX_LENGTH );

  if ( succ != HS_DESC_SIG_PREFIX_LENGTH )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_0, strlen( outer_layer_template_0 ) );

  if ( succ != strlen( outer_layer_template_0 ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  if ( d_generate_packed_crosscert( tmp_buff, descriptor_signing_key->p, blinded_key, 0x08, 1, valid_after ) < 0 ) {
    MINITOR_LOG( MINITOR_TAG, "Failed to generate the auth_key cross cert" );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, tmp_buff, 187 );

  if ( succ != 187 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_1, strlen( outer_layer_template_1 ) );

  if ( succ != strlen( outer_layer_template_1 ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, revision_counter_str, strlen( revision_counter_str ) );

  if ( succ != strlen( revision_counter_str ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, outer_layer_template_2, strlen( outer_layer_template_2 ) );

  if ( succ != strlen( outer_layer_template_2 ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s", filename );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( plain_buff ) );

  succ = write( plain_fd, outer_layer_template_3, strlen( outer_layer_template_3 ) );

  if ( succ != strlen( outer_layer_template_3 ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  idx = ED25519_SIG_SIZE;
  wolf_succ = ed25519_sign_msg_custom( plain_fd, tmp_signature, &idx, descriptor_signing_key );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to sign the outer descriptor, error code: %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  v_base_64_encode( tmp_buff, tmp_signature, 64 );

  succ = write( plain_fd, outer_layer_template_4, strlen( outer_layer_template_4 ) );

  if ( succ != strlen( outer_layer_template_4 ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  succ = write( plain_fd, tmp_buff, 86 );

  if ( succ != 86 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );

      return -1;
    }

    succ = rename( plain_file, filename );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to rename first plaintext" );

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
  wc_Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  char tmp_buff[58];

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

  plain_fd = open( plain_file, O_CREAT | O_WRONLY | O_TRUNC, 0600 );

  if ( plain_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", plain_file );

    return -1;
  }

  cipher_fd = open( filename, O_RDONLY );

  if ( cipher_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", filename );

    close( plain_fd );

    return -1;
  }

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  succ = write( plain_fd, first_layer_template, strlen( first_layer_template ) );

  if ( succ != strlen( first_layer_template ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  MINITOR_FILL_RANDOM( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
  v_base_64_encode( tmp_buff, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
  tmp_buff[43] = '\n';

  succ = write( plain_fd, tmp_buff, 44 );

  if ( succ != 44 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

    ret = -1;
    goto finish;
  }

  for ( i = 0; i < 16; i++ )
  {
    succ = write( plain_fd, auth_client_template, strlen( auth_client_template ) );

    if ( succ != strlen( auth_client_template ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

      ret = -1;
      goto finish;
    }

    MINITOR_FILL_RANDOM( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff, reusable_sha3_sum, 8 );
    tmp_buff[11] = ' ';

    MINITOR_FILL_RANDOM( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff + 12, reusable_sha3_sum, 16 );
    tmp_buff[34] = ' ';

    MINITOR_FILL_RANDOM( reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );
    v_base_64_encode( tmp_buff + 35, reusable_sha3_sum, 16 );
    tmp_buff[57] = '\n';

    succ = write( plain_fd, tmp_buff, sizeof( tmp_buff ) );

    if ( succ != sizeof( tmp_buff ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

      ret = -1;
      goto finish;
    }
  }

  succ = write( plain_fd, begin_encrypted, strlen( begin_encrypted ) );

  if ( succ != strlen( begin_encrypted ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s", filename );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( plain_buff ) );

  succ = write( plain_fd, end_encrypted, strlen( end_encrypted ) );

  if ( succ != strlen( end_encrypted ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", plain_file );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );

      return -1;
    }

    succ = rename( plain_file, filename );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to rename first plaintext" );

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
  wc_Sha3 reusable_sha3;
  wc_Shake reusable_shake;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char keys[AES_256_KEY_SIZE + AES_IV_SIZE + WC_SHA3_256_DIGEST_SIZE];
  Aes reusable_aes_key;
  char cipher_file[60];

  sprintf( cipher_file, "%s_cipher", filename );

  cipher_fd = open( cipher_file, O_CREAT | O_WRONLY | O_TRUNC, 0600 );

  if ( cipher_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", cipher_file );

    free( secret_input );

    return -1;
  }

  plain_fd = open( filename, O_RDONLY );

  if ( plain_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", filename );

    free( secret_input );
    close( cipher_fd );

    return -1;
  }

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );
  wc_InitShake256( &reusable_shake, NULL, INVALID_DEVID );
  wc_AesInit( &reusable_aes_key, NULL, INVALID_DEVID );

  MINITOR_FILL_RANDOM( salt, 16 );
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
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", cipher_file );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s", filename );

      ret = -1;
      goto finish;
    }

    wolf_succ = wc_AesCtrEncrypt( &reusable_aes_key, cipher_buff, (uint8_t*)plain_buff, succ );

    if ( wolf_succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to encrypt descriptor plaintext, error code: %d", wolf_succ );

      ret = -1;
      goto finish;
    }

    wc_Sha3_256_Update( &reusable_sha3, cipher_buff, succ );

    succ = write( cipher_fd, cipher_buff, succ );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", cipher_file );

      ret = -1;
      goto finish;
    }
  } while ( succ == sizeof( cipher_buff ) );

  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  succ = write( cipher_fd, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );

  if ( succ != WC_SHA3_256_DIGEST_SIZE )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", cipher_file );

    ret = -1;
    goto finish;
  }

finish:
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_Shake256_Free( &reusable_shake );
  wc_AesFree( &reusable_aes_key );

  free( secret_input );

  close( cipher_fd );
  close( plain_fd );

  if ( ret >= 0 )
  {
    succ = unlink( filename );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to unlink %s, errno: %d", filename, errno );

      return -1;
    }

    succ = rename( cipher_file, filename );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to rename cipher file %s to %s, errno: %d", cipher_file, filename, errno );

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

  fd = open( filename, O_CREAT | O_WRONLY | O_TRUNC, 0600 );

  if ( fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s", filename );

    return -1;
  }

  succ = write( fd, formats_s, strlen( formats_s ) );

  if ( succ != strlen( formats_s ) )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

    ret = -1;
    goto finish;
  }

  for ( i = 0; i < 3; i++ )
  {
    // write intro point
    succ = write( fd, intro_point_s, strlen( intro_point_s ) );

    if ( succ != strlen( intro_point_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    v_generate_packed_link_specifiers( intro_circuits[i]->relay_list.tail->relay, packed_link_specifiers );
    v_base_64_encode( tmp_buff, packed_link_specifiers, sizeof( packed_link_specifiers ) );
    tmp_buff[42] = '\n';

    succ = write( fd, tmp_buff, 43 );

    if ( succ != 43 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    // write onion key
    succ = write( fd, onion_key_s, strlen( onion_key_s ) );

    if ( succ != strlen( onion_key_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    v_base_64_encode( tmp_buff, intro_circuits[i]->relay_list.tail->relay->ntor_onion_key, H_LENGTH );
    tmp_buff[43] = '\n';

    succ = write( fd, tmp_buff, 44 );

    if ( succ != 44 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    // write auth key and cert
    succ = write( fd, auth_key_s, strlen( auth_key_s ) );

    if ( succ != strlen( auth_key_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    succ = write( fd, begin_ed_s, strlen( begin_ed_s ) );

    if ( succ != strlen( begin_ed_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &intro_circuits[i]->intro_crypto->auth_key, tmp_pub_key, &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to export intro circuit auth key, error code: %d", wolf_succ );

      ret = -1;
      goto finish;
    }

    if ( d_generate_packed_crosscert( tmp_buff, tmp_pub_key, descriptor_signing_key, 0x09, 1, valid_after ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to generate the auth_key cross cert" );

      ret = -1;
      goto finish;
    }

    succ = write( fd, tmp_buff, 187 );

    if ( succ != 187 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    succ = write( fd, end_ed_s, strlen( end_ed_s ) );

    if ( succ != strlen( end_ed_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    // write enc ntor
    succ = write( fd, enc_ntor_s, strlen( enc_ntor_s ) );

    if ( succ != strlen( enc_ntor_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    idx = CURVE25519_KEYSIZE;
    wolf_succ = wc_curve25519_export_public_ex( &intro_circuits[i]->intro_crypto->encrypt_key, tmp_pub_key, &idx, EC25519_LITTLE_ENDIAN );

    if ( wolf_succ != 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ );

      ret = -1;
      goto finish;
    }

    v_base_64_encode( tmp_buff, tmp_pub_key, CURVE25519_KEYSIZE );
    tmp_buff[43] = '\n';

    succ = write( fd, tmp_buff, 44 );

    if ( succ != 44 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    // write enc key and cert
    succ = write( fd, enc_cert_s, strlen( enc_cert_s ) );

    if ( succ != strlen( enc_cert_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    succ = write( fd, begin_ed_s, strlen( begin_ed_s ) );

    if ( succ != strlen( begin_ed_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    v_ed_pubkey_from_curve_pubkey( tmp_pub_key, intro_circuits[i]->intro_crypto->encrypt_key.p.point, 0 );

    if ( d_generate_packed_crosscert( tmp_buff, tmp_pub_key, descriptor_signing_key, 0x0B, 1, valid_after ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to generate the enc-key cross cert" );

      ret = -1;
      goto finish;
    }

    succ = write( fd, tmp_buff, 187 );

    if ( succ != 187 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }

    succ = write( fd, end_ed_s, strlen( end_ed_s ) );

    if ( succ != strlen( end_ed_s ) )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s", filename );

      ret = -1;
      goto finish;
    }
  }

finish:
  close( fd );

  return ret;
}

void v_generate_packed_link_specifiers( OnionRelay* relay, unsigned char* packed_link_specifiers )
{
  // set the specifier count
  packed_link_specifiers[0] = 2;

  // IPv4 specifier
  // set the type
  packed_link_specifiers[1] = IPv4Link;
  // set the length
  packed_link_specifiers[2] = 6;
  // set the address and port
  packed_link_specifiers[3] = (unsigned char)relay->address;
  packed_link_specifiers[4] = (unsigned char)( relay->address >> 8 );
  packed_link_specifiers[5] = (unsigned char)( relay->address >> 16 );
  packed_link_specifiers[6] = (unsigned char)( relay->address >> 24 );
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

int d_generate_packed_crosscert( char* destination, unsigned char* certified_key, ed25519_key* signing_key, unsigned char cert_type, uint8_t cert_key_type, long int valid_after )
{
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
  // set the cert key type
  tmp_body[6] = cert_key_type;
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

  if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );

    res = -1;
    goto cleanup;
  }

  idx = ED25519_SIG_SIZE;
  wolf_succ = wc_ed25519_sign_msg( tmp_body, 76, tmp_body + 76, &idx, signing_key );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
    MINITOR_LOG( MINITOR_TAG, "Failed to sign the ed crosscert, error code: %d", wolf_succ );

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
  unsigned char one[32] = { 1 };
  unsigned char input_minus_1[32];
  unsigned char input_plus_1[32];
  unsigned char inverse_input_plus_1[32];

  fe_sub( input_minus_1, input, one );
  fe_add( input_plus_1, input, one );
  fe_invert( inverse_input_plus_1, input_plus_1 );
  fe_mul( output, input_minus_1, inverse_input_plus_1 );

  output[31] = (!!sign_bit) << 7;
}

int d_router_establish_intro( OnionCircuit* circuit, DlConnection* or_connection )
{
  int ret = 0;
  int wolf_succ;
  unsigned int idx;
  int64_t ordered_digest_length = (int64_t)DIGEST_LEN;
  unsigned char ordered_digest_length_buffer[8];
  WC_RNG rng;
  wc_Sha3 reusable_sha3;
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  Cell* establish_cell;
  uint8_t* establish_cell_p;
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
    MINITOR_LOG( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  establish_cell = malloc( MINITOR_CELL_LEN );

  establish_cell->circ_id = circuit->circ_id;
  establish_cell->command = RELAY;

  establish_cell->payload.relay.relay_command = RELAY_COMMAND_ESTABLISH_INTRO;
  establish_cell->payload.relay.recognized = 0;
  establish_cell->payload.relay.stream_id = 0;
  establish_cell->payload.relay.digest = 0;
  establish_cell->payload.relay.length = 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN + 2 + ED25519_SIG_SIZE;

  establish_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + establish_cell->payload.relay.length;

  establish_cell->payload.relay.establish_intro.auth_key_type = EDSHA3;

  // make it network so that our signature is correct
  establish_cell->payload.relay.establish_intro.auth_key_length = htons( ED25519_PUB_KEY_SIZE );
  memcpy( establish_cell->payload.relay.establish_intro.auth_key, tmp_pub_key, ED25519_PUB_KEY_SIZE );

  // skip over auth key
  establish_cell_p = establish_cell->payload.relay.establish_intro.auth_key + ED25519_PUB_KEY_SIZE;

  // set num extensions to 0
  establish_cell_p[0] = 0;
  establish_cell_p++;

  ordered_digest_length_buffer[0] = (unsigned char)( ordered_digest_length >> 56 );
  ordered_digest_length_buffer[1] = (unsigned char)( ordered_digest_length >> 48 );
  ordered_digest_length_buffer[2] = (unsigned char)( ordered_digest_length >> 40 );
  ordered_digest_length_buffer[3] = (unsigned char)( ordered_digest_length >> 32 );
  ordered_digest_length_buffer[4] = (unsigned char)( ordered_digest_length >> 24 );
  ordered_digest_length_buffer[5] = (unsigned char)( ordered_digest_length >> 16 );
  ordered_digest_length_buffer[6] = (unsigned char)( ordered_digest_length >> 8 );
  ordered_digest_length_buffer[7] = (unsigned char)ordered_digest_length;

  // set the key to the pre shared keying material
  wc_Sha3_256_Update( &reusable_sha3, ordered_digest_length_buffer, sizeof( ordered_digest_length_buffer ) );
  wc_Sha3_256_Update( &reusable_sha3, circuit->relay_list.tail->relay_crypto->nonce, DIGEST_LEN );

  // now hash the cell contents so far
  wc_Sha3_256_Update( &reusable_sha3, establish_cell->payload.relay.data, 3 + ED25519_PUB_KEY_SIZE + 1 );

  // set the handshake_auth
  wc_Sha3_256_Final( &reusable_sha3, establish_cell_p );

  establish_cell_p += MAC_LEN;

  // set the signature length
  ((uint16_t*)establish_cell_p)[0] = ED25519_SIG_SIZE;

  establish_cell_p += 2;

  // make a temporary cell and prefix the prefix_str to it
  prefixed_cell = malloc( sizeof( unsigned char ) * ( strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN ) );

  memcpy( prefixed_cell, prefix_str, strlen( prefix_str ) );
  memcpy( prefixed_cell + strlen( prefix_str ), establish_cell->payload.relay.data, 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN );

  idx = ED25519_SIG_SIZE;

  wolf_succ = wc_ed25519_sign_msg(
    prefixed_cell,
    strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN,
    establish_cell_p,
    &idx,
    &circuit->intro_crypto->auth_key
  );

  free( prefixed_cell );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to generate establish intro signature, error code: %d", wolf_succ );

    free( establish_cell );

    ret = -1;
    goto finish;
  }

  if ( d_send_relay_cell_and_free( or_connection, establish_cell, &circuit->relay_list, NULL ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_COMMAND_ESTABLISH_INTRO cell" );

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
  wc_Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[64] = { 0 };
  wc_Sha512 reusable_sha512;
  unsigned char reusable_sha512_sum[WC_SHA512_DIGEST_SIZE];
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  unsigned char tmp_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char reduced_priv_key[64] = { 0 };
  unsigned char out_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char tmp_64_array[8];
  unsigned char zero[32] = { 0 };

  memset( zero, 0, 32 );

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );
  wc_InitSha512( &reusable_sha512 );

  idx = ED25519_PRV_KEY_SIZE;
  idy = ED25519_PUB_KEY_SIZE;

  wolf_succ = wc_ed25519_export_key( master_key, out_priv_key, &idx, tmp_pub_key, &idy );

  if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to export master key, error code: %d", wolf_succ );

    return -1;
  }

  wolf_succ = wc_Sha512Hash( out_priv_key, ED25519_KEY_SIZE, tmp_priv_key );

  if ( wolf_succ < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to expand master key, error code: %d", wolf_succ );

    return -1;
  }

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"Derive temporary signing key", strlen( "Derive temporary signing key" ) + 1 );
  wc_Sha3_256_Update( &reusable_sha3, tmp_pub_key, ED25519_PUB_KEY_SIZE );

  if ( secret != NULL )
  {
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

  memcpy( reduced_priv_key, tmp_priv_key, 32 );

  //sc_reduce( reduced_priv_key );
  //sc_reduce( reusable_sha3_sum );
  //sc_muladd( out_priv_key, reduced_priv_key, reusable_sha3_sum, zero );
  minitor_sc_muladd( out_priv_key, tmp_priv_key, reusable_sha3_sum, zero );

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
  int ret = 0;
  int fd;
  int wolf_succ;
  unsigned int idx;
  unsigned int idy;
  unsigned char version = 0x03;
  struct stat st;
  WC_RNG rng;
  wc_Sha3 reusable_sha3;
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

  // directory doesn't exist, create the keys
  if ( stat( onion_service_directory, &st ) == -1 )
  {
    if ( mkdir( onion_service_directory, 0755 ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to create %s for onion service, errno: %d", onion_service_directory, errno );

      ret = -1;
      goto finish;
    }

    wc_InitRng( &rng );

    wc_ed25519_make_key( &rng, 32, &onion_service->master_key );

    wc_FreeRng( &rng );

    idx = ED25519_PRV_KEY_SIZE;
    idy = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_key( &onion_service->master_key, tmp_priv_key, &idx, tmp_pub_key, &idy );

    if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to export service master key, error code: %d", wolf_succ );

      ret = -1;
      goto finish;
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

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/hostname" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC, 0600 ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    if ( write( fd, onion_address, sizeof( char ) * strlen( onion_address ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC, 0600 ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    if ( write( fd, tmp_pub_key, ED25519_PUB_KEY_SIZE ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC, 0600 ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    if ( write( fd, tmp_priv_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }
  // directory exists, load the keys
  }
  else
  {
    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    if ( read( fd, tmp_priv_key, sizeof( char ) * ED25519_PUB_KEY_SIZE ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }


    if ( read( fd, tmp_pub_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    wolf_succ = wc_ed25519_import_private_key( tmp_priv_key, ED25519_PRV_KEY_SIZE, tmp_pub_key, ED25519_PUB_KEY_SIZE, &onion_service->master_key );

    if ( wolf_succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to import ed25519 key, error code: %d", wolf_succ );

      ret = -1;
      goto finish;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/hostname" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }

    if ( read( fd, onion_service->hostname, 62 ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );

      close( fd );

      ret = -1;
      goto finish;
    }

    onion_service->hostname[62] = 0;

    MINITOR_LOG( MINITOR_TAG, "onion servie hostname: %s", onion_service->hostname );

    if ( close( fd ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );

      ret = -1;
      goto finish;
    }
  }

finish:
  wc_Sha3_256_Free( &reusable_sha3 );

  return ret;
}

int d_begin_hsdir( OnionCircuit* publish_circuit, DlConnection* or_connection )
{
  Cell* begin_cell;

  begin_cell = malloc( MINITOR_CELL_LEN );

  begin_cell->circ_id = publish_circuit->circ_id;
  begin_cell->command = RELAY;

  begin_cell->payload.relay.relay_command = RELAY_BEGIN_DIR;
  begin_cell->payload.relay.recognized = 0;
  begin_cell->payload.relay.stream_id = 1;
  begin_cell->payload.relay.digest = 0;
  begin_cell->payload.relay.length = 0;

  begin_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE;

  if ( d_send_relay_cell_and_free( or_connection, begin_cell, &publish_circuit->relay_list, NULL ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_BEGIN_DIR cell" );

    return -1;
  }

  return 0;
}

int d_post_hs_desc( OnionCircuit* publish_circuit, DlConnection* or_connection )
{
  int ret = 0;
  char* REQUEST;
  char* ipv4_string;
  const char* REQUEST_CONST =
    "POST /tor/hs/3/publish HTTP/1.0\r\n"
    "Host: %s\r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: %s"
    "\r\n\r\n"
    ;
  //int total_tx_length = 0;
  int tx_limit;
  char content_length[11] = { 0 };
  int http_header_length;
  int descriptor_length;
  //unsigned char* descriptor_text = publish_circuit->service->hs_descs[publish_circuit->desc_index] + HS_DESC_SIG_PREFIX_LENGTH;
  int desc_fd;
  char desc_buff[RELAY_PAYLOAD_LEN];
  Cell* data_cell;
  int succ;

  desc_fd = open( publish_circuit->service->hs_descs[publish_circuit->desc_index], O_RDONLY );

  if ( desc_fd < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );

    return -1;
  }

  descriptor_length = lseek( desc_fd, 0, SEEK_END ) - HS_DESC_SIG_PREFIX_LENGTH;

  if ( descriptor_length < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to seek %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );

    ret = -1;
    goto finish;
  }

  sprintf( content_length, "%d", descriptor_length );

  if ( lseek( desc_fd, HS_DESC_SIG_PREFIX_LENGTH, SEEK_SET ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to seek %s for onion service, errno: %d", publish_circuit->service->hs_descs[publish_circuit->desc_index], errno );

    ret = -1;
    goto finish;
  }

  ipv4_string = pc_ipv4_to_string( publish_circuit->relay_list.head->relay->address );

  REQUEST = malloc( sizeof( char ) * ( strlen( REQUEST_CONST ) + strlen( ipv4_string ) + strlen( content_length ) ) );

  sprintf( REQUEST, REQUEST_CONST, ipv4_string, content_length );

  free( ipv4_string );

  data_cell = malloc( MINITOR_CELL_LEN );

  data_cell->command = RELAY;
  data_cell->circ_id = publish_circuit->circ_id;

  data_cell->payload.relay.relay_command = RELAY_DATA;
  data_cell->payload.relay.recognized = 0;
  data_cell->payload.relay.stream_id = 1;
  data_cell->payload.relay.digest = 0;
  data_cell->payload.relay.length = RELAY_PAYLOAD_LEN;

  data_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + data_cell->payload.relay.length;

  memcpy( data_cell->payload.relay.data, REQUEST, strlen( REQUEST ) );

  http_header_length = strlen( REQUEST );

  free( REQUEST );

  succ = read( desc_fd, data_cell->payload.relay.data + http_header_length, RELAY_PAYLOAD_LEN - http_header_length );

  if ( succ != RELAY_PAYLOAD_LEN - http_header_length )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to read %s", publish_circuit->service->hs_descs[publish_circuit->desc_index] );

    free( data_cell );

    ret = -1;
    goto finish;
  }

  if ( d_send_relay_cell_and_free( or_connection, data_cell, &publish_circuit->relay_list, NULL ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_DATA cell" );

    ret = -1;
    goto finish;
  }

  do
  {
    data_cell = malloc( MINITOR_CELL_LEN );

    data_cell->command = RELAY;
    data_cell->circ_id = publish_circuit->circ_id;

    data_cell->payload.relay.relay_command = RELAY_DATA;
    data_cell->payload.relay.recognized = 0;
    data_cell->payload.relay.stream_id = 1;
    data_cell->payload.relay.digest = 0;

    succ = read( desc_fd, data_cell->payload.relay.data, RELAY_PAYLOAD_LEN );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to read %s", publish_circuit->service->hs_descs[publish_circuit->desc_index] );

      free( data_cell );

      ret = -1;
      goto finish;
    }

    if ( succ == 0 )
    {
      free( data_cell );

      break;
    }

    data_cell->payload.relay.length = succ;

    data_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + data_cell->payload.relay.length;

    if ( d_send_relay_cell_and_free( or_connection, data_cell, &publish_circuit->relay_list, NULL ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to send RELAY_DATA cell" );

      ret = -1;
      goto finish;
    }
  } while ( succ == RELAY_PAYLOAD_LEN );

finish:
  close( desc_fd );

  return ret;
}

void v_build_hsdir_circuits( OnionService* service, DoublyLinkedOnionRelayList* target_relays, int desc_index )
{
  OnionRelay* start_node;
  OnionRelay* tmp_node;
  DoublyLinkedOnionRelay* target_dl_relay;

  start_node = px_get_random_fast_relay( 1, target_relays, NULL, NULL );

  target_dl_relay = target_relays->head;

  while ( target_dl_relay != NULL )
  {
    tmp_node = malloc( sizeof( OnionRelay ) );
    memcpy( tmp_node, start_node, sizeof( OnionRelay ) );

    v_send_init_circuit_internal( 3, CIRCUIT_HSDIR_BEGIN_DIR, service, NULL, desc_index, 0, tmp_node, target_dl_relay->relay, NULL, NULL );

    target_dl_relay = target_dl_relay->next;
  }

  free( start_node );
}

int d_push_hsdir( OnionService* service )
{
  int ret = 0;
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
  wc_Sha3 reusable_sha3;
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
  char desc_file[50];

  if ( service->intro_live_count < 3 )
  {
    return -1;
  }

  //MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

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

    intro_circuits[i] = tmp_circuit;
    tmp_circuit = tmp_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
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
  MINITOR_MUTEX_TAKE_BLOCKING( network_consensus_mutex );

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
      MINITOR_LOG( MINITOR_TAG, "Failed to derive the blinded key" );

      ret = -1;
      goto finish;
    }

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &blinded_keys[i], blinded_pub_keys[i], &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to export blinded public key" );

      ret = -1;
      goto finish;
    }

    service->target_relays[i] = px_get_target_relays( network_consensus.hsdir_n_replicas, blinded_pub_keys[i], time_period + i, network_consensus.hsdir_interval, network_consensus.hsdir_spread_store, i );

    if ( service->target_relays[i] == NULL )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to get target_relays" );

      ret = -1;
      goto finish;
    }
  }

  MINITOR_MUTEX_GIVE( network_consensus_mutex );
  // END mutex

  service->hsdir_to_send = service->target_relays[0]->length + service->target_relays[1]->length;
  service->hsdir_sent = 0;

  revision_counter = d_roll_revision_counter( service->master_key.p );

  if ( revision_counter < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to roll the revision_counter" );

    ret = -1;
    goto finish;
  }

  // i = 0 is first descriptor, 1 is second as per the spec
  for ( i = 0; i < 2; i++ )
  {
    // null terminated
    // /sdcard/abcdefghij_desc_0\0
    memset( desc_file, 0, sizeof( desc_file ) );
    strcpy( desc_file, FILESYSTEM_PREFIX );
    memcpy( desc_file + strlen( FILESYSTEM_PREFIX ), service->hostname, 10 );
    desc_file[strlen( FILESYSTEM_PREFIX ) + 10] = 0;
    strcat( desc_file, "_desc_" );
    desc_file[strlen( desc_file ) + 1] = 0;
    desc_file[strlen( desc_file )] = (char)(48 + i);

    // generate second layer plaintext
    succ = d_generate_second_plaintext( desc_file, intro_circuits, valid_after, &descriptor_signing_key );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to generate second layer descriptor plaintext" );

      ret = -1;
      goto finish;
    }

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"credential", strlen( "credential" ) );
    wc_Sha3_256_Update( &reusable_sha3, service->master_key.p, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"subcredential", strlen( "subcredential" ) );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, blinded_pub_keys[i], ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    if ( i == 0 )
    {
      memcpy( service->current_sub_credential, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    }
    else
    {
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

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to encrypt second layer descriptor plaintext" );

      ret = -1;
      goto finish;
    }

    succ = d_generate_first_plaintext( desc_file );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to generate first layer descriptor plaintext" );

      ret = -1;
      goto finish;
    }

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

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to encrypt first layer descriptor plaintext" );

      ret = -1;
      goto finish;
    }

    // create outer descriptor wrapper
    succ = d_generate_outer_descriptor(
      desc_file,
      &descriptor_signing_key,
      valid_after,
      &blinded_keys[i],
      revision_counter
    );

    if ( succ < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to generate outer descriptor" );

      ret = -1;
      goto finish;
    }

    // send outer descriptor wrapper to the correct HSDIR nodes
    //succ = d_build_hsdir_circuits( reusable_plaintext + HS_DESC_SIG_PREFIX_LENGTH, reusable_text_length, target_relays[i] );
    //v_build_hsdir_circuits( service, target_relays[i], i );

    strcpy( service->hs_descs[i], desc_file );
  }

  start_relay = px_get_random_fast_relay( 1, service->target_relays[0], NULL, NULL );
  v_send_init_circuit_internal( 3, CIRCUIT_HSDIR_BEGIN_DIR, service, NULL, 0, 0, start_relay, service->target_relays[0]->head->relay, NULL, NULL );

finish:
  wc_Sha3_256_Free( &reusable_sha3 );
  wc_ed25519_free( &blinded_keys[0] );
  wc_ed25519_free( &blinded_keys[1] );
  wc_ed25519_free( &descriptor_signing_key );

  return ret;
}

void v_cleanup_service_hs_data( OnionService* service, int desc_index )
{
  int i;
  OnionCircuit* tmp_circuit;
  DoublyLinkedOnionRelay* dl_relay;
  DoublyLinkedOnionRelay* next_relay;

  if ( service->hsdir_sent == service->hsdir_to_send )
  {
    MINITOR_LOG( MINITOR_TAG, "Hidden service ready at: %s", service->hostname );

    v_set_hsdir_timer( service->hsdir_timer );

    i = d_get_standby_count();

    for ( ; i < 2; i++ )
    {
      // create a standby circuit
      v_send_init_circuit_internal(
        1,
        CIRCUIT_STANDBY,
        NULL,
        NULL,
        0,
        0,
        NULL,
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
}
