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
#include "../h/onion_client.h"
#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/encoding.h"
#include "../h/cell.h"
#include "../h/circuit.h"
#include "../h/connections.h"
#include "../h/core.h"
#include "../h/models/relay.h"

const char* CLIENT_TAG = "MINITOR_CLIENT";

void* px_create_onion_client( const char* onion_address )
{
  int idx;
  int succ;
  uint8_t blinded_pubkey[ED25519_PUB_KEY_SIZE];
  uint8_t decoded_address[35];
  uint8_t address_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  int time_period;
  wc_Sha3 address_sha3;
  OnionMessage* onion_message;
  OnionClient* client;

  if ( strlen( onion_address ) != 62 )
  {
    MINITOR_LOG( CLIENT_TAG, "Invalid address length" );

    return NULL;
  }

  // verify the onion address
  v_base_32_decode( decoded_address, onion_address, 56 );

  // invalid version
  if ( decoded_address[34] != 3 )
  {
    MINITOR_LOG( CLIENT_TAG, "Invalid address version %d", decoded_address[34] );

    return NULL;
  }

  wc_InitSha3_256( &address_sha3, NULL, INVALID_DEVID );

  wc_Sha3_256_Update( &address_sha3, (uint8_t*)".onion checksum", strlen( ".onion checksum" ) );
  wc_Sha3_256_Update( &address_sha3, decoded_address, ED25519_PUB_KEY_SIZE );
  wc_Sha3_256_Update( &address_sha3, &(decoded_address[34]), 1 );
  wc_Sha3_256_Final( &address_sha3, address_sha3_sum );

  // checksum invalid
  if ( address_sha3_sum[0] != decoded_address[32] || address_sha3_sum[1] != decoded_address[33] )
  {
    MINITOR_LOG( CLIENT_TAG, "Invalid address checksum" );

    client = NULL;
    goto finish;
  }

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( network_consensus_mutex );

  client = malloc( sizeof( OnionClient ) );
  wc_ed25519_init( &client->blinded_key );

  memset( client, 0, sizeof( OnionClient ) );

  // +1 for current
  time_period = d_get_hs_time_period( network_consensus.fresh_until, network_consensus.valid_after, network_consensus.hsdir_interval ) + 1;

  if ( d_derive_blinded_pubkey( &client->blinded_key, decoded_address, time_period, network_consensus.hsdir_interval, NULL, 0 ) )
  {
    MINITOR_MUTEX_GIVE( network_consensus_mutex );
    // MUTEX GIVE

    MINITOR_LOG( CLIENT_TAG, "Failed to derive blinded public key" );

    v_cleanup_client_data( client );
    free( client );
    client = NULL;
    goto finish;
  }

  idx = ED25519_PUB_KEY_SIZE;
  succ = wc_ed25519_export_public( &( client->blinded_key ), blinded_pubkey, &idx );

  if ( succ < 0 || idx != ED25519_PUB_KEY_SIZE )
  {
    MINITOR_MUTEX_GIVE( network_consensus_mutex );
    // MUTEX GIVE

    MINITOR_LOG( CLIENT_TAG, "Failed to export blinded public key" );

    v_cleanup_client_data( client );
    free( client );
    client = NULL;
    goto finish;
  }

  client->target_relays = px_get_target_relays( network_consensus.hsdir_n_replicas, blinded_pubkey, time_period, network_consensus.hsdir_interval, network_consensus.hsdir_spread_store - 1, 1 );

  MINITOR_MUTEX_GIVE( network_consensus_mutex );
  // MUTEX GIVE

  // make the connection strut
  strcpy( client->hostname, onion_address );
  memcpy( client->onion_pubkey, decoded_address, 32 );
  client->stream_queues[0] = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );

  v_send_init_circuit_external( 3, CIRCUIT_CLIENT_HSDIR, NULL, client, 0, 0, NULL, client->target_relays->head->relay, NULL, NULL );

  // wait for the connected or failed response
  MINITOR_DEQUEUE_BLOCKING( client->stream_queues[0], (void*)(&onion_message) );

  if ( onion_message == NULL || onion_message->type != CLIENT_RENDEZVOUS_CIRCUIT_READY )
  {
    v_cleanup_client_data( client );
    MINITOR_QUEUE_DELETE( client->stream_queues[0] );
    free( client );
    client = NULL;
  }

  free( onion_message );

  // attach the circuit to our client connection
  //client->rend_circuit = onion_message->data;

finish:
  wc_Sha3_256_Free( &address_sha3 );

  return (void*)client;
}

void v_cleanup_client_data( OnionClient* client )
{
  int i;
  OnionCircuit* tmp_circuit;
  DoublyLinkedOnionRelay* dl_relay;
  DoublyLinkedOnionRelay* next_relay;
  DlConnection* or_connection;

  dl_relay = client->target_relays->head;

  while ( dl_relay != NULL )
  {
    next_relay = dl_relay->next;

    free( dl_relay );

    dl_relay = next_relay;
  }

  free( client->target_relays );

  for ( i = 0; i < 3; i++ )
  {
    if ( client->intro_relays[i] != NULL )
    {
      free( client->intro_relays[i] );
    }

    if ( client->intro_cryptos[i] != NULL )
    {
      wc_ed25519_free( &client->intro_cryptos[i]->auth_key );
      wc_curve25519_free( &client->intro_cryptos[i]->encrypt_key );

      free( client->intro_cryptos[i] );
    }
  }

  if ( client->hsdesc != NULL )
  {
    free( client->hsdesc );
    client->hsdesc = NULL;
  }

  if ( client->rend_circuit != NULL )
  {
    // MUTEX TAKE
    or_connection = px_get_conn_by_id_and_lock( client->rend_circuit->conn_id );

    v_circuit_remove_destroy( client->rend_circuit, or_connection );
    // MUTEX GIVE
  }

  if ( client->intro_circuit != NULL )
  {
    // MUTEX TAKE
    or_connection = px_get_conn_by_id_and_lock( client->intro_circuit->conn_id );

    v_circuit_remove_destroy( client->intro_circuit, or_connection );
    // MUTEX GIVE
  }

  wc_ed25519_free( &client->blinded_key );
}

int d_connect_onion_client( void* client_p, uint16_t port )
{
  int i;
  int succ;
  int stream_id;
  OnionClient* client = client_p;
  Cell* begin_cell;
  DlConnection* or_connection;
  OnionMessage* onion_message;
  MinitorMutex access_mutex = NULL;

  for ( i = 0; i < 15; i++ )
  {
    if ( client->stream_queues[i] == NULL )
    {
      stream_id = i;
      break;
    }
  }

  if ( i > 15 )
  {
    return -1;
  }

  client->stream_queues[stream_id] = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( client->rend_circuit->conn_id );

  if ( or_connection == NULL )
  {
    return MINITOR_ERROR;
  }

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  begin_cell = malloc( MINITOR_CELL_LEN );

  begin_cell->command = RELAY;
  begin_cell->circ_id = client->rend_circuit->circ_id;

  begin_cell->payload.relay.relay_command = RELAY_BEGIN;
  begin_cell->payload.relay.recognized = 0;
  begin_cell->payload.relay.stream_id = stream_id;
  begin_cell->payload.relay.digest = 0;

  MINITOR_LOG( CLIENT_TAG, "stream_id: %d", begin_cell->payload.relay.stream_id );

  // set the addrport
  sprintf( begin_cell->payload.relay.data, ":%d", port );

  // set the flags to 0
  begin_cell->payload.relay.data[strlen( begin_cell->payload.relay.data ) + 1] = 0;
  begin_cell->payload.relay.data[strlen( begin_cell->payload.relay.data ) + 2] = 0;
  begin_cell->payload.relay.data[strlen( begin_cell->payload.relay.data ) + 3] = 0;
  begin_cell->payload.relay.data[strlen( begin_cell->payload.relay.data ) + 4] = 0;

  begin_cell->payload.relay.length = strlen( begin_cell->payload.relay.data ) + 1 + 4;

  begin_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + begin_cell->payload.relay.length;

  succ = d_send_relay_cell_and_free( or_connection, begin_cell, &client->rend_circuit->relay_list, client->rend_circuit->hs_crypto );

  MINITOR_MUTEX_GIVE( access_mutex );
  // MUTEX GIVE

  if ( succ < 0 )
  {
    stream_id = MINITOR_CLIENT_ERROR;
    goto finish;
  }

  MINITOR_DEQUEUE_BLOCKING( client->stream_queues[stream_id], (void*)(&onion_message) );

  if ( onion_message == NULL || onion_message->type != CLIENT_RELAY_CONNECTED )
  {
    stream_id = MINITOR_CLIENT_ERROR;

    if ( onion_message == NULL )
    {
      goto finish;
    }
  }

  free( onion_message );

finish:
  return stream_id;
}

int d_write_onion_client( void* client_p, int stream_id, uint8_t* write_buf, uint32_t length )
{
  int i = 0;
  int succ;
  OnionClient* client = client_p;
  Cell* data_cell;
  DlConnection* or_connection;
  MinitorMutex access_mutex = NULL;

  if ( length == 0 )
  {
    return -1;
  }

  if ( client->stream_queues[stream_id] == NULL )
  {
    return MINITOR_STREAM_ERROR;
  }

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( client->rend_circuit->conn_id );

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  do
  {
    data_cell = malloc( MINITOR_CELL_LEN );

    data_cell->command = RELAY;
    data_cell->circ_id = client->rend_circuit->circ_id;

    data_cell->payload.relay.relay_command = RELAY_DATA;
    data_cell->payload.relay.recognized = 0;
    data_cell->payload.relay.stream_id = stream_id;
    data_cell->payload.relay.digest = 0;

    if ( length >= RELAY_PAYLOAD_LEN )
    {
      data_cell->payload.relay.length = RELAY_PAYLOAD_LEN;
    }
    else
    {
      data_cell->payload.relay.length = length;
    }

    memcpy( data_cell->payload.relay.data, write_buf + i, data_cell->payload.relay.length );

    data_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + data_cell->payload.relay.length;

    i += data_cell->payload.relay.length;
    length -= data_cell->payload.relay.length;

    succ = d_send_relay_cell_and_free( or_connection, data_cell, &client->rend_circuit->relay_list, client->rend_circuit->hs_crypto );

    if ( succ < 0 )
    {
      break;
    }
  } while ( length > 0 );

  MINITOR_MUTEX_GIVE( access_mutex );
  // MUTEX GIVE

  return i;
}

int d_read_onion_client( void* client_p, int stream_id, uint8_t* read_buf, uint32_t length )
{
  int i = 0;
  int succ;
  OnionClient* client = client_p;
  OnionMessage* onion_message;

  if ( length == 0 )
  {
    return -1;
  }

  if ( client->stream_queues[stream_id] == NULL )
  {
    return MINITOR_STREAM_ERROR;
  }

  if ( client->read_leftover != NULL )
  {
    if ( client->read_leftover_length > length )
    {
      memcpy( read_buf, client->read_leftover + client->read_leftover_offset, length );

      client->read_leftover_length -= length;
      client->read_leftover_offset += length;

      return length;
    }
    else
    {
      memcpy( read_buf, client->read_leftover + client->read_leftover_offset, client->read_leftover_length );

      i += client->read_leftover_length;
      length -= client->read_leftover_length;

      free( client->read_leftover );

      client->read_leftover = NULL;
    }
  }

  do
  {
    MINITOR_DEQUEUE_BLOCKING( client->stream_queues[stream_id], (void*)(&onion_message) );

    if ( onion_message == NULL || onion_message->type != CLIENT_RELAY_DATA || onion_message->length == 0 )
    {
      if ( onion_message == NULL || onion_message->type != CLIENT_RELAY_END )
      {
        if ( i == 0 )
        {
          // client is dead and must be restarted
          i = MINITOR_CLIENT_ERROR;
        }
      }

      if ( onion_message != NULL )
      {
        if ( onion_message->type == CLIENT_RELAY_END )
        {
          MINITOR_QUEUE_DELETE( client->stream_queues[stream_id] );
          client->stream_queues[stream_id] = NULL;
        }

        free( onion_message );
        break;
      }
    }

    if ( onion_message->length > length )
    {
      memcpy( read_buf + i, onion_message->data, length );

      client->read_leftover = onion_message->data;
      client->read_leftover_offset = length;
      client->read_leftover_length = onion_message->length - length;

      i += length;
      length -= length;
    }
    else
    {
      memcpy( read_buf + i, onion_message->data, onion_message->length );

      client->read_leftover = NULL;

      i += onion_message->length;
      length -= onion_message->length;

      free( onion_message->data );
    }

    free( onion_message );
  } while ( length > 0 );

  return i;
}

int d_close_onion_client_stream( void* client_p, int stream_id )
{
  OnionClient* client = client_p;
  Cell* end_cell;
  DlConnection* or_connection;
  MinitorMutex access_mutex = NULL;

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( client->rend_circuit->conn_id );

  if ( or_connection == NULL )
  {
    return -1;
  }

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  if ( client->stream_queues[stream_id] == NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    return -1;
  }

  MINITOR_QUEUE_DELETE( client->stream_queues[stream_id] );
  client->stream_queues[stream_id] = NULL;

  end_cell = malloc( MINITOR_CELL_LEN );

  end_cell->command = RELAY;
  end_cell->circ_id = client->rend_circuit->circ_id;

  end_cell->payload.relay.relay_command = RELAY_END;
  end_cell->payload.relay.recognized = 0;
  end_cell->payload.relay.stream_id = stream_id;
  end_cell->payload.relay.digest = 0;
  end_cell->payload.relay.length = 1;
  end_cell->payload.relay.destroy_code = REASON_DONE;
  end_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + end_cell->payload.relay.length;

  if ( d_send_relay_cell_and_free( or_connection, end_cell, &client->rend_circuit->relay_list, client->rend_circuit->hs_crypto ) < 0 )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    return -1;
  }

  MINITOR_MUTEX_GIVE( access_mutex );
  // MUTEX GIVE

  return 0;
}

void v_close_onion_client( void* client_p )
{
  int i;
  OnionClient* client = client_p;
  Cell* close_cell;
  DlConnection* or_connection;

  v_cleanup_client_data( client );

  // MUST be freed elsewhere
}

int d_derive_blinded_pubkey( ed25519_key* blinded_key, uint8_t* master_pubkey, int64_t period_number, int64_t period_length, uint8_t* secret, int secret_length )
{
  int ret = 0;
  uint8_t tmp_64_array[8];
  uint8_t keyblind_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  uint8_t reduced_sha_sum[64];
  uint8_t pubkey_copy[32];
  uint8_t zero[32] = { 0 };
  uint8_t blinded_pubkey[32];
  wc_Sha3 keyblind_sha3;
  ge_p3 a;
  ge_p2 a_prime;

  wc_InitSha3_256( &keyblind_sha3, NULL, INVALID_DEVID );

  // calculate h
  wc_Sha3_256_Update( &keyblind_sha3, (unsigned char*)"Derive temporary signing key", strlen( "Derive temporary signing key" ) + 1 );
  wc_Sha3_256_Update( &keyblind_sha3, master_pubkey, ED25519_PUB_KEY_SIZE );

  if ( secret != NULL )
  {
    wc_Sha3_256_Update( &keyblind_sha3, secret, secret_length );
  }

  wc_Sha3_256_Update( &keyblind_sha3, (unsigned char*)HS_ED_BASEPOINT, HS_ED_BASEPOINT_LENGTH );
  wc_Sha3_256_Update( &keyblind_sha3, (unsigned char*)"key-blind", strlen( "key-blind" ) );

  tmp_64_array[0] = (uint8_t)( period_number >> 56 );
  tmp_64_array[1] = (uint8_t)( period_number >> 48 );
  tmp_64_array[2] = (uint8_t)( period_number >> 40 );
  tmp_64_array[3] = (uint8_t)( period_number >> 32 );
  tmp_64_array[4] = (uint8_t)( period_number >> 24 );
  tmp_64_array[5] = (uint8_t)( period_number >> 16 );
  tmp_64_array[6] = (uint8_t)( period_number >> 8 );
  tmp_64_array[7] = (uint8_t)period_number;

  wc_Sha3_256_Update( &keyblind_sha3, tmp_64_array, sizeof( tmp_64_array ) );

  tmp_64_array[0] = (uint8_t)( period_length >> 56 );
  tmp_64_array[1] = (uint8_t)( period_length >> 48 );
  tmp_64_array[2] = (uint8_t)( period_length >> 40 );
  tmp_64_array[3] = (uint8_t)( period_length >> 32 );
  tmp_64_array[4] = (uint8_t)( period_length >> 24 );
  tmp_64_array[5] = (uint8_t)( period_length >> 16 );
  tmp_64_array[6] = (uint8_t)( period_length >> 8 );
  tmp_64_array[7] = (uint8_t)period_length;

  wc_Sha3_256_Update( &keyblind_sha3, tmp_64_array, sizeof( tmp_64_array ) );
  wc_Sha3_256_Final( &keyblind_sha3, keyblind_sha3_sum );

  // clamp h
  keyblind_sha3_sum[0] &= 248;
  keyblind_sha3_sum[31] &= 63;
  keyblind_sha3_sum[31] |= 64;

  memcpy( pubkey_copy, master_pubkey, ED25519_PUB_KEY_SIZE );
  pubkey_copy[31] ^= (1 << 7);

  // compute A'
  if ( ge_frombytes_negate_vartime( &a, pubkey_copy ) != 0 )
  {
    ret = -1;
    goto finish;
  }

  memcpy( reduced_sha_sum, keyblind_sha3_sum, 32 );

  //sc_reduce( reduced_sha_sum );

  ge_double_scalarmult_vartime( &a_prime, reduced_sha_sum, &a, zero );

  // turn A' into bytes
  ge_tobytes( blinded_pubkey, &a_prime );

  // import the blinded public key
  if ( wc_ed25519_import_public( blinded_pubkey, ED25519_PUB_KEY_SIZE, blinded_key ) < 0 )
  {
    ret = -1;
  }

finish:
  wc_Sha3_256_Free( &keyblind_sha3 );

  return ret;
}

int d_get_hs_desc( OnionCircuit* circuit, DlConnection* or_connection )
{
  char* REQUEST;
  char* ipv4_string;
  const char* REQUEST_CONST =
    "GET /tor/hs/3/%s HTTP/1.0\r\n"
    "Host: %s\r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n\r\n"
    ;
  int succ;
  uint8_t blinded_pub_key[ED25519_PUB_KEY_SIZE];
  // 32 * 4 / 3 = 43, 44 for the NULL terminator
  char encoded_pub_key[44];
  int idx;
  Cell* data_cell;

  idx = ED25519_PUB_KEY_SIZE;
  succ = wc_ed25519_export_public( &( circuit->client->blinded_key ), blinded_pub_key, &idx );

  if ( succ < 0 || idx != ED25519_PUB_KEY_SIZE )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to export blinded public key d_get_hs_desc" );

    return -1;
  }

  v_base_64_encode( encoded_pub_key, blinded_pub_key, ED25519_PUB_KEY_SIZE );
  encoded_pub_key[43] = 0;

  ipv4_string = pc_ipv4_to_string( circuit->relay_list.head->relay->address );

  REQUEST = malloc( strlen( REQUEST_CONST ) + strlen( encoded_pub_key ) + strlen( ipv4_string ) );

  sprintf( REQUEST, REQUEST_CONST, encoded_pub_key, ipv4_string );

  free( ipv4_string );

  data_cell = malloc( MINITOR_CELL_LEN );

  data_cell->command = RELAY;
  data_cell->circ_id = circuit->circ_id;

  data_cell->payload.relay.relay_command = RELAY_DATA;
  data_cell->payload.relay.recognized = 0;
  data_cell->payload.relay.stream_id = 1;
  data_cell->payload.relay.digest = 0;
  data_cell->payload.relay.length = strlen( REQUEST );

  data_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + data_cell->payload.relay.length;

  memcpy( data_cell->payload.relay.data, REQUEST, strlen( REQUEST ) );

  free( REQUEST );

  MINITOR_LOG( CLIENT_TAG, "%.*s", data_cell->payload.relay.length, data_cell->payload.relay.data );

  if ( d_send_relay_cell_and_free( or_connection, data_cell, &circuit->relay_list, NULL ) < 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to send RELAY_DATA cell" );

    return -1;
  }

  return 0;
}

int d_parse_hsdesc( OnionCircuit* circuit, Cell* cell )
{
  int i;
  int j;
  int idx;
  int succ;
  int wolf_succ;
  uint8_t* first_layer;
  uint8_t* first_layer_p;
  int first_layer_length;
  time_t now;
  const char* http_header_finish = "\r\n\r\n";
  const char* http_ok = "HTTP/1.0 200 OK\r\n";
  const char* content_length_string = "Content-Length: ";
  int content_length_found = 0;
  const char* version_string = "hs-descriptor 3\n";
  int version_found = 0;
  const char* lifetime_string = "descriptor-lifetime ";
  int lifetime_found = 0;
  int desc_lifetime = 0;
  const char* signing_key_cert_string = "descriptor-signing-key-cert\n-----BEGIN ED25519 CERT-----\n";
  int signing_key_cert_found = 0;
  const char* end_key_cert_string = "-----END ED25519 CERT-----\n";
  int end_key_cert_found = 0;
  int cert_start;
  const char* revision_counter_string = "revision-counter ";
  int revision_counter_found = 0;
  uint64_t revision_counter = 0;
  const char* superencrypted_string = "superencrypted\n-----BEGIN MESSAGE-----\n";
  int superencrypted_found = 0;
  int superencrypted_start = 0;
  int superencrypted_end = 0;
  const char* end_message_string = "-----END MESSAGE-----";
  int end_message_found = 0;
  const char* signature_string = "signature ";
  int signature_found = 0;
  uint8_t blinded_pubkey[ED25519_PUB_KEY_SIZE];
  ed25519_key descriptor_signing_key;
  uint8_t signature[64];
  int unpacked_crosscert_length;
  TorCrosscert* unpacked_crosscert;
  TorCrosscertExtension* extension;
  int alloced_relays = 0;

  for ( i = 0; i < cell->payload.relay.length; i++ )
  {
    if ( circuit->client->hsdesc_header_finish_found < strlen( http_header_finish ) )
    {
      if ( circuit->client->hsdesc_ok_found < strlen( http_ok ) )
      {
        if ( cell->payload.relay.data[i] != http_ok[circuit->client->hsdesc_ok_found] )
        {
          circuit->client->hsdesc_header_finish_found = 0;
          circuit->client->hsdesc_ok_found = 0;
          circuit->client->hsdesc_content_length = 0;
          circuit->client->hsdesc_size = 0;

          return -1;
        }

        circuit->client->hsdesc_ok_found++;
      }
      else if ( content_length_found < strlen( content_length_string ) )
      {
        if ( cell->payload.relay.data[i] == content_length_string[content_length_found] )
        {
          content_length_found++;
        }
        else
        {
          content_length_found = 0;
        }

        if ( content_length_found == strlen( content_length_string ) )
        {
          circuit->client->hsdesc_content_length = atoi( cell->payload.relay.data + i + 1 );
        }
      }
      else if ( cell->payload.relay.data[i] == http_header_finish[circuit->client->hsdesc_header_finish_found] )
      {
        circuit->client->hsdesc_header_finish_found++;
      }
      else
      {
        circuit->client->hsdesc_header_finish_found = 0;
      }
    }
    else
    {
      if ( circuit->client->hsdesc_size == 0 )
      {
        circuit->client->hsdesc = malloc( circuit->client->hsdesc_content_length + HS_DESC_SIG_PREFIX_LENGTH );
        strcpy( circuit->client->hsdesc, HS_DESC_SIG_PREFIX );
        circuit->client->hsdesc_size = HS_DESC_SIG_PREFIX_LENGTH;
      }

      memcpy( circuit->client->hsdesc + circuit->client->hsdesc_size, cell->payload.relay.data + i, cell->payload.relay.length - i );
      circuit->client->hsdesc_size += cell->payload.relay.length - i;

      break;
    }
  }

  if ( circuit->client->hsdesc_size == circuit->client->hsdesc_content_length + HS_DESC_SIG_PREFIX_LENGTH )
  {
    wc_ed25519_init( &descriptor_signing_key );

    for ( i = 0; i < circuit->client->hsdesc_size; i++ )
    {
      if ( version_found < strlen( version_string ) )
      {
        if ( circuit->client->hsdesc[i] == version_string[version_found] )
        {
          version_found++;
        }
        else
        {
          version_found = 0;
        }
      }
      else if ( lifetime_found < strlen( lifetime_string ) )
      {
        if ( circuit->client->hsdesc[i] == lifetime_string[lifetime_found] )
        {
          lifetime_found++;
        }
        else
        {
          lifetime_found = 0;
        }

        if ( lifetime_found == strlen( lifetime_string ) )
        {
          desc_lifetime = atoi( circuit->client->hsdesc + i + 1 ) * 60;
        }
      }
      else if ( signing_key_cert_found < strlen( signing_key_cert_string ) )
      {
        if ( circuit->client->hsdesc[i] == signing_key_cert_string[signing_key_cert_found] )
        {
          signing_key_cert_found++;
        }
        else
        {
          signing_key_cert_found = 0;
        }

        if ( signing_key_cert_found == strlen( signing_key_cert_string ) )
        {
          cert_start = i + 1;
        }
      }
      else if ( end_key_cert_found < strlen( end_key_cert_string ) )
      {
        if ( circuit->client->hsdesc[i] == end_key_cert_string[end_key_cert_found] )
        {
          end_key_cert_found++;
        }
        else
        {
          end_key_cert_found = 0;
        }

        if ( end_key_cert_found == strlen( end_key_cert_string ) )
        {
          unpacked_crosscert_length = ( i - cert_start - strlen( end_key_cert_string ) + 1 ) * 3 / 4;

          if ( ( i - cert_start - strlen( end_key_cert_string ) + 1 ) % 4 != 0 )
          {
            unpacked_crosscert_length++;
          }

          unpacked_crosscert = malloc( unpacked_crosscert_length );

          // adding 1 makes it the length, not the end positon
          d_base_64_decode( unpacked_crosscert, circuit->client->hsdesc + cert_start, i - cert_start - strlen( end_key_cert_string ) + 1 );

          if ( unpacked_crosscert->version != 1 )
          {
            free( unpacked_crosscert );
            goto fail;
          }

          if ( unpacked_crosscert->cert_type != 8 )
          {
            free( unpacked_crosscert );
            goto fail;
          }

          time( &now );

          if ( unpacked_crosscert->epoch_hours < now / 60 / 60 )
          {
            free( unpacked_crosscert );
            goto fail;
          }

          if ( unpacked_crosscert->cert_key_type != 1 )
          {
            free( unpacked_crosscert );
            goto fail;
          }

          extension = unpacked_crosscert->extensions;

          for ( j = 0; j < unpacked_crosscert->num_extensions; j++ )
          {
            if ( extension->ext_type != 4 )
            {
              extension = extension->ext_data + extension->ext_length;

              continue;
            }

            if ( ntohs( extension->ext_length ) != ED25519_PUB_KEY_SIZE )
            {
              free( unpacked_crosscert );
              goto fail;
            }

            idx = ED25519_PUB_KEY_SIZE;
            succ = wc_ed25519_export_public( &( circuit->client->blinded_key ), blinded_pubkey, &idx );

            if ( succ < 0 || idx != ED25519_PUB_KEY_SIZE )
            {
              MINITOR_LOG( CLIENT_TAG, "Failed to export blinded public key" );

              free( unpacked_crosscert );
              goto fail;
            }

            if ( memcmp( extension->ext_data, blinded_pubkey, ED25519_PUB_KEY_SIZE ) != 0 )
            {
              free( unpacked_crosscert );
              goto fail;
            }

            extension = extension->ext_data + ntohs( extension->ext_length );
          }

          // proves that this signing key was signed by the blinded private key holder
          wolf_succ = wc_ed25519_verify_msg( (uint8_t*)extension, 64, (uint8_t*)unpacked_crosscert, (uint8_t*)extension - (uint8_t*)unpacked_crosscert, &succ, &( circuit->client->blinded_key ) );

          if ( wolf_succ < 0 || succ == 0 )
          {
            MINITOR_LOG( CLIENT_TAG, "Failed to verify the outer layer ed crosscert signature, error code: %d", wolf_succ );

            free( unpacked_crosscert );
            goto fail;
          }

          succ = wc_ed25519_import_public( unpacked_crosscert->certified_key, ED25519_PUB_KEY_SIZE, &descriptor_signing_key );

          if ( succ < 0 )
          {
            free( unpacked_crosscert );
            goto fail;
          }

          free( unpacked_crosscert );
        }
      }
      else if ( revision_counter_found < strlen( revision_counter_string ) )
      {
        if ( circuit->client->hsdesc[i] == revision_counter_string[revision_counter_found] )
        {
          revision_counter_found++;
        }
        else
        {
          revision_counter_found = 0;
        }

        if ( revision_counter_found == strlen( revision_counter_string ) )
        {
          //revision_counter = atoi( circuit->client->hsdesc + i + 1 );
          revision_counter = atol( circuit->client->hsdesc + i + 1 );
        }
      }
      else if ( superencrypted_found < strlen( superencrypted_string ) )
      {
        if ( circuit->client->hsdesc[i] == superencrypted_string[superencrypted_found] )
        {
          superencrypted_found++;
        }
        else
        {
          superencrypted_found = 0;
        }

        if ( superencrypted_found == strlen( superencrypted_string ) )
        {
          superencrypted_start = i + 1;
        }
      }
      else if ( end_message_found < strlen( end_message_string ) )
      {
        if ( circuit->client->hsdesc[i] == end_message_string[end_message_found] )
        {
          end_message_found++;
        }
        else
        {
          end_message_found = 0;
        }

        if ( end_message_found == strlen( end_message_string ) )
        {
          // TODO it seems our length is no good because the base64 string includes \n every so often
          first_layer_length = ( i - strlen( end_message_string ) + 1 - superencrypted_start ) * 3 / 4;

          if ( ( i - strlen( end_message_string ) + 1 - superencrypted_start ) % 4 != 0 )
          {
            first_layer_length++;
          }

          superencrypted_end = i - strlen( end_message_string ) + 1;
        }
      }
      else if ( signature_found < strlen( signature_string ) )
      {
        if ( circuit->client->hsdesc[i] == signature_string[signature_found] )
        {
          signature_found++;
        }
        else
        {
          signature_found = 0;
        }

        if ( signature_found == strlen( signature_string ) )
        {
          d_base_64_decode( signature, circuit->client->hsdesc + i + 1, 86 );

          // proves that this hsdesc was signed by the descriptor signing key
          wolf_succ = wc_ed25519_verify_msg( signature, 64, circuit->client->hsdesc, i - strlen( signature_string ) + 1, &succ, &descriptor_signing_key );

          if ( wolf_succ < 0 || succ == 0 )
          {
            MINITOR_LOG( CLIENT_TAG, "Failed to verify the first_layer ed crosscert signature, error code: %d", wolf_succ );

            goto fail;
          }

          first_layer_p = malloc( first_layer_length );

          first_layer_length = d_base_64_decode( first_layer_p, circuit->client->hsdesc + superencrypted_start, superencrypted_end - superencrypted_start );

          free( circuit->client->hsdesc );
          circuit->client->hsdesc = NULL;

          succ = d_decrypt_descriptor_ciphertext(
            first_layer_p,
            first_layer_p,
            first_layer_length,
            circuit->client->onion_pubkey,
            blinded_pubkey,
            ED25519_PUB_KEY_SIZE,
            "hsdir-superencrypted-data",
            strlen( "hsdir-superencrypted-data" ),
            revision_counter,
            circuit->client->sub_credential
          );

          if ( succ < 0 )
          {
            MINITOR_LOG( CLIENT_TAG, "Failed to decrypt first_layer", wolf_succ );

            free( first_layer_p );
            goto fail;
          }

          // skip the iv
          first_layer = first_layer_p + 16;

          const char* encrypted_string = "encrypted\n-----BEGIN MESSAGE-----\n";
          int encrypted_found = 0;
          int encrypted_start = 0;
          uint8_t* second_layer;
          uint8_t* second_layer_p;
          int second_layer_length;

          for ( i = 0; i < first_layer_length - 16; i++ )
          {
            // TODO implement auth keys
            if ( encrypted_found < strlen( encrypted_string ) )
            {
              if ( first_layer[i] == encrypted_string[encrypted_found] )
              {
                encrypted_found++;
              }
              else
              {
                encrypted_found = 0;
              }

              if ( encrypted_found == strlen( encrypted_string ) )
              {
                encrypted_start = i + 1;
                end_message_found = 0;
              }
            }
            else if ( end_message_found < strlen( end_message_string ) )
            {
              if ( first_layer[i] == end_message_string[end_message_found] )
              {
                end_message_found++;
              }
              else
              {
                end_message_found = 0;
              }

              if ( end_message_found == strlen( end_message_string ) )
              {
                second_layer_length = ( i - strlen( end_message_string ) + 1 - encrypted_start ) * 3 / 4;

                if ( ( i - strlen( end_message_string ) + 1 - encrypted_start ) % 4 != 0 )
                {
                  second_layer_length++;
                }

                second_layer_p = malloc( second_layer_length );

                second_layer_length = d_base_64_decode( second_layer_p, first_layer + encrypted_start, i - strlen( end_message_string ) + 1 - encrypted_start );

                free( first_layer_p );

                succ = d_decrypt_descriptor_ciphertext(
                  second_layer_p,
                  second_layer_p,
                  second_layer_length,
                  circuit->client->onion_pubkey,
                  blinded_pubkey,
                  ED25519_PUB_KEY_SIZE,
                  "hsdir-encrypted-data",
                  strlen( "hsdir-encrypted-data" ),
                  revision_counter,
                  circuit->client->sub_credential
                );

                if ( succ < 0 )
                {
                  MINITOR_LOG( CLIENT_TAG, "Failed to decrypt second_layer", wolf_succ );

                  free( second_layer_p );
                  goto fail;
                }

                const char* formats_string = "create2-formats 2\n";
                int formats_found = 0;
                const char* intro_point_string = "introduction-point ";
                int intro_point_found = 0;
                const char* onion_key_string = "onion-key ntor ";
                int onion_key_found = 0;
                const char* auth_key_string = "auth-key\n-----BEGIN ED25519 CERT-----\n";
                int auth_key_found = 0;
                int auth_key_start = 0;
                const char* enc_key_string = "enc-key ntor ";
                int enc_key_found = 0;
                uint8_t enc_pub_key[CURVE25519_KEYSIZE];
                const char* enc_cert_string = "enc-key-cert\n-----BEGIN ED25519 CERT-----\n";
                int enc_cert_found = 0;
                int enc_cert_start = 0;
                int enc_cert_end_found = 0;
                uint8_t num_specifiers;
                int link_specifiers_length;
                int link_specifiers_start = 0;

                uint8_t* link_specifiers_p;
                LinkSpecifier* link_specifiers;

                bool ipv4_spec_found = false;
                bool legacy_spec_found = false;

                // skip the iv
                second_layer = second_layer_p + 16;

                for ( i = 0; i < second_layer_length - 16; i++ )
                {
                  if ( formats_found < strlen( formats_string ) )
                  {
                    if ( second_layer[i] == formats_string[formats_found] )
                    {
                      formats_found++;
                    }
                    else
                    {
                      formats_found = 0;
                    }
                  }
                  else if ( intro_point_found < strlen( intro_point_string ) )
                  {
                    if ( second_layer[i] == intro_point_string[intro_point_found] )
                    {
                      intro_point_found++;
                    }
                    else
                    {
                      intro_point_found = 0;
                    }

                    if ( intro_point_found == strlen( intro_point_string ) )
                    {
                      circuit->client->intro_relays[circuit->client->num_intro_relays] = malloc( sizeof( OnionRelay ) );
                      circuit->client->intro_cryptos[circuit->client->num_intro_relays] = malloc( sizeof( IntroCrypto ) );

                      memset( circuit->client->intro_relays[circuit->client->num_intro_relays], 0, sizeof( OnionRelay ) );
                      memset( circuit->client->intro_cryptos[circuit->client->num_intro_relays], 0, sizeof( IntroCrypto ) );

                      wc_ed25519_init( &circuit->client->intro_cryptos[circuit->client->num_intro_relays]->auth_key );
                      wc_curve25519_init( &circuit->client->intro_cryptos[circuit->client->num_intro_relays]->encrypt_key );

                      alloced_relays++;

                      link_specifiers_start = i + 1;

                      for ( ; i < second_layer_length; i++ )
                      {
                        if ( second_layer[i] == '\n' )
                        {
                          link_specifiers_length = i - link_specifiers_start * 3 / 4;

                          if ( ( i - link_specifiers_start ) % 4 != 0 )
                          {
                            link_specifiers_length++;
                          }

                          link_specifiers_p = malloc( link_specifiers_length );

                          d_base_64_decode( link_specifiers_p, second_layer + link_specifiers_start, i - link_specifiers_start );

                          break;
                        }
                      }

                      if ( i >= second_layer_length )
                      {
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Failed to find link specifier" );

                        goto cleanup_relays;
                      }

                      link_specifiers = link_specifiers_p;

                      num_specifiers = ((uint8_t*)link_specifiers)[0];

                      link_specifiers = (uint8_t*)link_specifiers + 1;

                      for ( j = 0; j < num_specifiers; j++ )
                      {
                        if ( link_specifiers->type == IPv4Link )
                        {
                          if ( link_specifiers->length != 6 )
                          {
                            free( link_specifiers_p );
                            free( second_layer_p );

                            MINITOR_LOG( CLIENT_TAG, "Invalid ipv4 link specifier" );

                            goto cleanup_relays;
                          }

                          circuit->client->intro_relays[circuit->client->num_intro_relays]->address = link_specifiers->specifier[0];
                          circuit->client->intro_relays[circuit->client->num_intro_relays]->address |= (uint32_t)link_specifiers->specifier[1] << 8;
                          circuit->client->intro_relays[circuit->client->num_intro_relays]->address |= (uint32_t)link_specifiers->specifier[2] << 16;
                          circuit->client->intro_relays[circuit->client->num_intro_relays]->address |= (uint32_t)link_specifiers->specifier[3] << 24;

                          circuit->client->intro_relays[circuit->client->num_intro_relays]->or_port = (uint32_t)link_specifiers->specifier[4] << 8;
                          circuit->client->intro_relays[circuit->client->num_intro_relays]->or_port |= (uint32_t)link_specifiers->specifier[5];

                          ipv4_spec_found = true;
                        }
                        else if ( link_specifiers->type == LEGACYLink )
                        {
                          if ( link_specifiers->length != ID_LENGTH )
                          {
                            free( link_specifiers_p );
                            free( second_layer_p );

                            MINITOR_LOG( CLIENT_TAG, "Invalid legacy link specifier" );

                            goto cleanup_relays;
                          }

                          memcpy( circuit->client->intro_relays[circuit->client->num_intro_relays]->identity, link_specifiers->specifier, ID_LENGTH );

                          legacy_spec_found = true;
                        }

                        link_specifiers = link_specifiers->specifier + link_specifiers->length;
                      }

                      if ( ipv4_spec_found == false || legacy_spec_found == false )
                      {
                        free( link_specifiers_p );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Failed to find both link specifiers" );

                        goto cleanup_relays;
                      }

                      free( link_specifiers_p );
                    }
                  }
                  else if ( onion_key_found < strlen( onion_key_string ) )
                  {
                    if ( second_layer[i] == onion_key_string[onion_key_found] )
                    {
                      onion_key_found++;
                    }
                    else
                    {
                      onion_key_found = 0;
                    }

                    if ( onion_key_found == strlen( onion_key_string ) )
                    {
                      d_base_64_decode( circuit->client->intro_relays[circuit->client->num_intro_relays]->ntor_onion_key, second_layer + i + 1, 43 );
                    }
                  }
                  else if ( auth_key_found < strlen( auth_key_string ) )
                  {
                    if ( second_layer[i] == auth_key_string[auth_key_found] )
                    {
                      auth_key_found++;
                    }
                    else
                    {
                      auth_key_found = 0;
                    }

                    if ( auth_key_found == strlen( auth_key_string ) )
                    {
                      auth_key_start = i + 1;
                      end_key_cert_found = 0;
                    }
                  }
                  else if ( end_key_cert_found < strlen( end_key_cert_string ) )
                  {
                    if ( second_layer[i] == end_key_cert_string[end_key_cert_found] )
                    {
                      end_key_cert_found++;
                    }
                    else
                    {
                      end_key_cert_found = 0;
                    }

                    if ( end_key_cert_found == strlen( end_key_cert_string ) )
                    {
                      unpacked_crosscert_length = ( i - auth_key_start - strlen( end_key_cert_string ) + 1 ) * 3 / 4;

                      if ( ( i - auth_key_start - strlen( end_key_cert_string ) + 1 ) % 4 != 0 )
                      {
                        unpacked_crosscert_length++;
                      }

                      unpacked_crosscert = malloc( unpacked_crosscert_length );

                      d_base_64_decode( unpacked_crosscert, second_layer + auth_key_start, i - auth_key_start - strlen( end_key_cert_string ) + 1 );

                      if ( unpacked_crosscert->version != 1 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid crosscert version" );

                        goto cleanup_relays;
                      }

                      if ( unpacked_crosscert->cert_type != 9 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid crosscert type" );

                        goto cleanup_relays;
                      }

                      time( &now );

                      if ( unpacked_crosscert->epoch_hours < now / 60 / 60 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid crosscert epoch hours" );

                        goto cleanup_relays;
                      }

                      if ( unpacked_crosscert->cert_key_type != 1 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid crosscert cert key type" );

                        goto cleanup_relays;
                      }

                      extension = unpacked_crosscert->extensions;

                      for ( j = 0; j < unpacked_crosscert->num_extensions; j++ )
                      {
                        if ( extension->ext_type != 4 )
                        {
                          extension = extension->ext_data + extension->ext_length;

                          continue;
                        }

                        if ( ntohs( extension->ext_length ) != ED25519_PUB_KEY_SIZE )
                        {
                          free( unpacked_crosscert );
                          free( second_layer_p );

                          MINITOR_LOG( CLIENT_TAG, "Invalid crosscert ext length" );

                          goto cleanup_relays;
                        }

                        if ( memcmp( extension->ext_data, descriptor_signing_key.p, ED25519_PUB_KEY_SIZE ) != 0 )
                        {
                          free( unpacked_crosscert );
                          free( second_layer_p );

                          MINITOR_LOG( CLIENT_TAG, "Invalid crosscert ext data" );

                          goto cleanup_relays;
                        }

                        extension = extension->ext_data + ntohs( extension->ext_length );
                      }

                      // proves that this signing key was signed by the blinded private key holder
                      wolf_succ = wc_ed25519_verify_msg( (uint8_t*)extension, 64, (uint8_t*)unpacked_crosscert, (uint8_t*)extension - (uint8_t*)unpacked_crosscert, &succ, &( descriptor_signing_key ) );

                      if ( wolf_succ < 0 || succ == 0 )
                      {
                        MINITOR_LOG( CLIENT_TAG, "Failed to verify the ed crosscert signature, error code: %d", wolf_succ );

                        free( unpacked_crosscert );
                        free( second_layer_p );

                        goto cleanup_relays;
                      }


                      if ( wc_ed25519_import_public( unpacked_crosscert->certified_key, ED25519_PUB_KEY_SIZE, &( circuit->client->intro_cryptos[circuit->client->num_intro_relays]->auth_key ) ) < 0 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Failed to import auth key" );

                        goto cleanup_relays;
                      }

                      free( unpacked_crosscert );
                    }
                  }
                  else if ( enc_key_found < strlen( enc_key_string ) )
                  {
                    if ( second_layer[i] == enc_key_string[enc_key_found] )
                    {
                      enc_key_found++;
                    }
                    else
                    {
                      enc_key_found = 0;
                    }

                    if ( enc_key_found == strlen( enc_key_string ) )
                    {
                      d_base_64_decode( enc_pub_key, second_layer + i + 1, 43 );

                      if ( wc_curve25519_import_public_ex( enc_pub_key, CURVE25519_KEYSIZE, &( circuit->client->intro_cryptos[circuit->client->num_intro_relays]->encrypt_key ), EC25519_LITTLE_ENDIAN ) < 0 )
                      {
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Failed to import encrypt key" );

                        goto cleanup_relays;
                      }
                    }
                  }
                  else if ( enc_cert_found < strlen( enc_cert_string ) )
                  {
                    if ( second_layer[i] == enc_cert_string[enc_cert_found] )
                    {
                      enc_cert_found++;
                    }
                    else
                    {
                      enc_cert_found = 0;
                    }

                    if ( enc_cert_found == strlen( enc_cert_string ) )
                    {
                      enc_cert_start = i + 1;
                      enc_cert_end_found = 0;
                    }
                  }
                  else if ( enc_cert_end_found < strlen( end_key_cert_string ) )
                  {
                    if ( second_layer[i] == end_key_cert_string[enc_cert_end_found] )
                    {
                      enc_cert_end_found++;
                    }
                    else
                    {
                      enc_cert_end_found = 0;
                    }

                    if ( enc_cert_end_found == strlen( end_key_cert_string ) )
                    {
                      unpacked_crosscert_length = ( i - enc_cert_start - strlen( end_key_cert_string ) + 1 ) * 3 / 4;

                      if ( ( i - enc_cert_start - strlen( end_key_cert_string ) + 1 ) % 4 != 0 )
                      {
                        unpacked_crosscert_length++;
                      }

                      unpacked_crosscert = malloc( unpacked_crosscert_length );

                      // adding 1 makes it the length, not the end positon
                      d_base_64_decode( (uint8_t*)unpacked_crosscert, second_layer + enc_cert_start, i - enc_cert_start - strlen( end_key_cert_string ) + 1 );

                      if ( unpacked_crosscert->version != 1 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid croscert version" );

                        goto cleanup_relays;
                      }

                      if ( unpacked_crosscert->cert_type != 11 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid croscert type" );

                        goto cleanup_relays;
                      }

                      time( &now );

                      if ( unpacked_crosscert->epoch_hours < now / 60 / 60 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid epoch hours" );

                        goto cleanup_relays;
                      }

                      if ( unpacked_crosscert->cert_key_type != 1 )
                      {
                        free( unpacked_crosscert );
                        free( second_layer_p );

                        MINITOR_LOG( CLIENT_TAG, "Invalid cert key type" );

                        goto cleanup_relays;
                      }

                      extension = unpacked_crosscert->extensions;

                      for ( j = 0; j < unpacked_crosscert->num_extensions; j++ )
                      {
                        if ( extension->ext_type != 4 )
                        {
                          extension = extension->ext_data + extension->ext_length;

                          continue;
                        }

                        if ( ntohs( extension->ext_length ) != ED25519_PUB_KEY_SIZE )
                        {
                          free( unpacked_crosscert );
                          free( second_layer_p );

                          MINITOR_LOG( CLIENT_TAG, "Invalid ext length" );

                          goto cleanup_relays;
                        }

                        if ( memcmp( extension->ext_data, descriptor_signing_key.p, ED25519_PUB_KEY_SIZE ) != 0 )
                        {
                          free( unpacked_crosscert );
                          free( second_layer_p );

                          MINITOR_LOG( CLIENT_TAG, "Invalid ext data" );

                          goto cleanup_relays;
                        }

                        extension = extension->ext_data + ntohs( extension->ext_length );
                      }

                      // proves that this signing key was signed by the blinded private key holder
                      wolf_succ = wc_ed25519_verify_msg( (uint8_t*)extension, 64, (uint8_t*)unpacked_crosscert, (uint8_t*)extension - (uint8_t*)unpacked_crosscert, &succ, &descriptor_signing_key );

                      if ( wolf_succ < 0 || succ == 0 )
                      {
                        MINITOR_LOG( CLIENT_TAG, "Failed to verify the ed crosscert signature, error code: %d", wolf_succ );

                        free( unpacked_crosscert );
                        free( second_layer_p );
                        goto cleanup_relays;
                      }


                      /*
                      // TODO figure out what to do with the certified key
                      if ( wc_ed25519_import_public_ex( unpacked_crosscert->certified_key, ED25519_PUB_KEY_SIZE, &TODO, EC25519_LITTLE_ENDIAN ) < 0 )
                      {
                        goto fail;
                      }
                      */

                      free( unpacked_crosscert );

                      circuit->client->num_intro_relays++;

                      intro_point_found = 0;
                      onion_key_found = 0;
                      auth_key_found = 0;
                      end_key_cert_found = 0;
                      enc_key_found = 0;
                      enc_cert_found = 0;
                      enc_cert_end_found = 0;

                      // we only want 3 intro points
                      if ( circuit->client->num_intro_relays >= 3 )
                      {
                        break;
                      }
                    }
                  }
                }

                free( second_layer_p );

                if ( circuit->client->num_intro_relays > 0 )
                {
                  MINITOR_FILL_RANDOM( circuit->client->rendezvous_cookie, 20 );

                  v_send_init_circuit_internal( 3, CIRCUIT_CLIENT_INTRO, NULL, circuit->client, 0, 0, NULL, circuit->client->intro_relays[0], NULL, circuit->client->intro_cryptos[0] );

                  // relay now belongs to the circuit, don't free
                  circuit->client->intro_relays[0] = NULL;
                  circuit->client->intro_cryptos[0] = NULL;

                  wc_ed25519_free( &descriptor_signing_key );

                  return 0;
                }

                MINITOR_LOG( CLIENT_TAG, "Failed to find intro relays" );

                goto cleanup_relays;
              }
            }
          }

          free( first_layer_p );

          MINITOR_LOG( CLIENT_TAG, "Failed to find second layer" );

          goto fail;
        }
      }
    }

    MINITOR_LOG( CLIENT_TAG, "Failed to find first layer" );

    goto fail;
  }

  return 1;

cleanup_relays:
  for ( i = 0; i < alloced_relays; i++ )
  {
    wc_ed25519_free( &circuit->client->intro_cryptos[i]->auth_key );
    wc_curve25519_free( &circuit->client->intro_cryptos[i]->encrypt_key );

    free( circuit->client->intro_relays[i] );
    free( circuit->client->intro_cryptos[i] );

    circuit->client->intro_relays[i] = NULL;
    circuit->client->intro_cryptos[i] = NULL;
  }

fail:
  wc_ed25519_free( &descriptor_signing_key );

  circuit->client->hsdesc_header_finish_found = 0;
  circuit->client->hsdesc_ok_found = 0;
  circuit->client->hsdesc_content_length = 0;
  circuit->client->hsdesc_size = 0;

  if ( circuit->client->hsdesc != NULL )
  {
    free( circuit->client->hsdesc );
    circuit->client->hsdesc = NULL;
  }

  return -1;
}

int d_decrypt_descriptor_ciphertext(
  uint8_t* plaintext,
  uint8_t* ciphertext,
  int length,
  uint8_t* onion_pubkey,
  uint8_t* secret_data,
  int secret_data_length,
  char* string_constant,
  int string_constant_length,
  uint64_t revision_counter,
  uint8_t* sub_credential
)
{
  int wolf_succ;
  int ret = 0;
  uint8_t keys[AES_256_KEY_SIZE + AES_IV_SIZE + WC_SHA3_256_DIGEST_SIZE];
  uint8_t* secret_input = malloc( secret_data_length + WC_SHA3_256_DIGEST_SIZE + sizeof( int64_t ) );
  uint8_t reusable_length_buffer[8];
  uint64_t reusable_length;
  uint8_t mac[WC_SHA3_256_DIGEST_SIZE];
  Aes decryption_key;
  wc_Shake keys_shake;
  wc_Sha3 mac_sha3;

  wc_InitSha3_256( &mac_sha3, NULL, INVALID_DEVID );
  wc_InitShake256( &keys_shake, NULL, INVALID_DEVID );
  wc_AesInit( &decryption_key, NULL, INVALID_DEVID );

  memcpy( secret_input, secret_data, secret_data_length );

  wc_Sha3_256_Update( &mac_sha3, (unsigned char*)"credential", strlen( "credential" ) );
  wc_Sha3_256_Update( &mac_sha3, onion_pubkey, ED25519_PUB_KEY_SIZE );
  wc_Sha3_256_Final( &mac_sha3, sub_credential );

  wc_Sha3_256_Update( &mac_sha3, (unsigned char*)"subcredential", strlen( "subcredential" ) );
  wc_Sha3_256_Update( &mac_sha3, sub_credential, WC_SHA3_256_DIGEST_SIZE );
  wc_Sha3_256_Update( &mac_sha3, secret_data, ED25519_PUB_KEY_SIZE );
  wc_Sha3_256_Final( &mac_sha3, sub_credential );

  memcpy( secret_input + secret_data_length, sub_credential, WC_SHA3_256_DIGEST_SIZE );

  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[0] = (unsigned char)( revision_counter >> 56 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[1] = (unsigned char)( revision_counter >> 48 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[2] = (unsigned char)( revision_counter >> 40 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[3] = (unsigned char)( revision_counter >> 32 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[4] = (unsigned char)( revision_counter >> 24 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[5] = (unsigned char)( revision_counter >> 16 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[6] = (unsigned char)( revision_counter >> 8 );
  ( secret_input + secret_data_length + WC_SHA3_256_DIGEST_SIZE )[7] = (unsigned char)revision_counter;

  wc_Shake256_Update( &keys_shake, secret_input, secret_data_length + WC_SHA3_256_DIGEST_SIZE + sizeof( int64_t ) );
  // first 16 bytes of ciphertext is the salt
  wc_Shake256_Update( &keys_shake, ciphertext, 16 );
  wc_Shake256_Update( &keys_shake, (unsigned char*)string_constant, string_constant_length );
  wc_Shake256_Final( &keys_shake, keys, sizeof( keys ) );

  reusable_length = WC_SHA256_DIGEST_SIZE;

  reusable_length_buffer[0] = (uint8_t)( reusable_length >> 56 );
  reusable_length_buffer[1] = (uint8_t)( reusable_length >> 48 );
  reusable_length_buffer[2] = (uint8_t)( reusable_length >> 40 );
  reusable_length_buffer[3] = (uint8_t)( reusable_length >> 32 );
  reusable_length_buffer[4] = (uint8_t)( reusable_length >> 24 );
  reusable_length_buffer[5] = (uint8_t)( reusable_length >> 16 );
  reusable_length_buffer[6] = (uint8_t)( reusable_length >> 8 );
  reusable_length_buffer[7] = (uint8_t)reusable_length;

  wc_Sha3_256_Update( &mac_sha3, reusable_length_buffer, sizeof( reusable_length_buffer ) );
  wc_Sha3_256_Update( &mac_sha3, keys + AES_256_KEY_SIZE + AES_IV_SIZE, WC_SHA256_DIGEST_SIZE );

  reusable_length = 16;

  reusable_length_buffer[0] = (uint8_t)( reusable_length >> 56 );
  reusable_length_buffer[1] = (uint8_t)( reusable_length >> 48 );
  reusable_length_buffer[2] = (uint8_t)( reusable_length >> 40 );
  reusable_length_buffer[3] = (uint8_t)( reusable_length >> 32 );
  reusable_length_buffer[4] = (uint8_t)( reusable_length >> 24 );
  reusable_length_buffer[5] = (uint8_t)( reusable_length >> 16 );
  reusable_length_buffer[6] = (uint8_t)( reusable_length >> 8 );
  reusable_length_buffer[7] = (uint8_t)reusable_length;

  wc_Sha3_256_Update( &mac_sha3, reusable_length_buffer, sizeof( reusable_length_buffer ) );
  // does salt and encrypted in one go
  wc_Sha3_256_Update( &mac_sha3, ciphertext, length - 32 );
  wc_Sha3_256_Final( &mac_sha3, mac );

  if ( memcmp( mac, ciphertext + length - WC_SHA256_DIGEST_SIZE, WC_SHA256_DIGEST_SIZE ) != 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "mac does not match calculated" );

    ret = -1;
    goto finish;
  }

  // counter mode is the same for encrypt and decrypt
  wc_AesSetKeyDirect( &decryption_key, keys, AES_256_KEY_SIZE, keys + AES_256_KEY_SIZE, AES_ENCRYPTION );

  wolf_succ = wc_AesCtrEncrypt( &decryption_key, plaintext + AES_IV_SIZE, ciphertext + AES_IV_SIZE, length - AES_IV_SIZE - WC_SHA256_DIGEST_SIZE );

  if ( wolf_succ < 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to encrypt descriptor plaintext, error code: %d", wolf_succ );

    ret = -1;
  }

finish:
  wc_Sha3_256_Free( &mac_sha3 );
  wc_Shake256_Free( &keys_shake );
  wc_AesFree( &decryption_key );

  free( secret_input );

  return ret;
}

int d_client_send_intro( OnionCircuit* circuit, DlConnection* or_connection )
{
  int succ;
  int wolf_succ;
  int ret = 0;
  int i;
  int num_extensions;
  uint8_t hs_keys[AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE];
  uint8_t* client_pk;
  uint8_t intro_secret_hs_input[CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH];
  uint8_t info[HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE];
  uint64_t reusable_length;
  uint8_t reusable_length_buffer[8];
  Cell* intro_cell;
  DecryptedIntroduce2* decrypted;
  IntroOnionKey* intro_onion_key;
  LinkSpecifier* specifier;
  Aes encrypt_key;
  unsigned char aes_iv[16] = { 0 };
  wc_Shake hs_keys_shake;
  wc_Sha3 mac_sha3;
  WC_RNG rng;
  uint8_t* mac;
  int idx;

  wc_InitRng( &rng );
  wc_curve25519_init( &circuit->client->client_handshake_key );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &circuit->client->client_handshake_key );

  if ( wolf_succ != 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to make client_handshake_key, error code %d", wolf_succ );

    wc_FreeRng( &rng );

    return -1;
  }

  wc_AesInit( &encrypt_key, NULL, INVALID_DEVID );
  wc_InitShake256( &hs_keys_shake, NULL, INVALID_DEVID );
  wc_InitSha3_256( &mac_sha3, NULL, INVALID_DEVID );

  // compute intro_secret_hs_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( &circuit->client->client_handshake_key, &circuit->intro_crypto->encrypt_key, intro_secret_hs_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to compute shared secret, error code: %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  memcpy( intro_secret_hs_input + 32, circuit->intro_crypto->auth_key.p, ED25519_PUB_KEY_SIZE );

  idx = CURVE25519_KEYSIZE;
  wolf_succ = wc_curve25519_export_public_ex( &circuit->client->client_handshake_key, intro_secret_hs_input + 32 + 32, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ );

    ret = -1;
    goto finish;
  }

  memcpy( intro_secret_hs_input + 32 + 32 + 32, circuit->intro_crypto->encrypt_key.p.point, 32 );

  memcpy( intro_secret_hs_input + 32 + 32 + 32 + 32, HS_PROTOID, HS_PROTOID_LENGTH );

  // compute info
  memcpy( info, HS_PROTOID_EXPAND, HS_PROTOID_EXPAND_LENGTH );
  memcpy( info + HS_PROTOID_EXPAND_LENGTH, circuit->client->sub_credential, WC_SHA3_256_DIGEST_SIZE );

  // compute hs_keys
  wc_Shake256_Update( &hs_keys_shake, intro_secret_hs_input,  CURVE25519_KEYSIZE + ED25519_PUB_KEY_SIZE + CURVE25519_KEYSIZE + CURVE25519_KEYSIZE + HS_PROTOID_LENGTH );
  wc_Shake256_Update( &hs_keys_shake, (uint8_t*)HS_PROTOID_KEY, HS_PROTOID_KEY_LENGTH );
  wc_Shake256_Update( &hs_keys_shake, info, HS_PROTOID_EXPAND_LENGTH + WC_SHA3_256_DIGEST_SIZE );
  wc_Shake256_Final( &hs_keys_shake, hs_keys, AES_256_KEY_SIZE + WC_SHA3_256_DIGEST_SIZE );

  intro_cell = malloc( MINITOR_CELL_LEN );

  intro_cell->command = RELAY;
  intro_cell->circ_id = circuit->circ_id;

  intro_cell->payload.relay.relay_command = RELAY_COMMAND_INTRODUCE1;
  intro_cell->payload.relay.recognized = 0;
  intro_cell->payload.relay.stream_id = 0;
  intro_cell->payload.relay.digest = 0;

  memset( intro_cell->payload.relay.introduce2.legacy_key_id, 0, 20 );
  intro_cell->payload.relay.introduce2.auth_key_type = EDSHA3;
  intro_cell->payload.relay.introduce2.auth_key_length = htons( ED25519_PUB_KEY_SIZE );
  memcpy( intro_cell->payload.relay.introduce2.auth_key, circuit->intro_crypto->auth_key.p, ED25519_PUB_KEY_SIZE );

  client_pk = intro_cell->payload.relay.introduce2.auth_key + 33;

  idx = CURVE25519_KEYSIZE;
  wolf_succ = wc_curve25519_export_public_ex( &circuit->client->client_handshake_key, client_pk, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ );

    free( intro_cell );
    ret = -1;
    goto finish;
  }

  // num_extensions = 0
  intro_cell->payload.relay.introduce2.auth_key[32] = 0;

  decrypted = intro_cell->payload.relay.introduce2.auth_key + 33 + CURVE25519_KEYSIZE;

  memcpy( decrypted->rendezvous_cookie, circuit->client->rendezvous_cookie, 20 );

  decrypted->num_extensions = 0;

  intro_onion_key = decrypted->extensions;

  intro_onion_key->onion_key_type = ONION_NTOR;
  // this section will be encrypted, networkize wont be able to get this
  intro_onion_key->onion_key_length = htons( H_LENGTH );
  //intro_onion_key->onion_key_length = htons( intro_onion_key->onion_key_length );
  memcpy( intro_onion_key->onion_key, circuit->client->rend_circuit->relay_list.tail->relay->ntor_onion_key, H_LENGTH );

  // set num_specifiers
  intro_onion_key->onion_key[H_LENGTH] = 2;

  specifier = intro_onion_key->onion_key + H_LENGTH + 1;

  specifier->type = IPv4Link;
  specifier->length = 6;

  specifier->specifier[0] = (uint8_t)circuit->client->rend_circuit->relay_list.tail->relay->address;
  specifier->specifier[1] = (uint8_t)( circuit->client->rend_circuit->relay_list.tail->relay->address >> 8 );
  specifier->specifier[2] = (uint8_t)( circuit->client->rend_circuit->relay_list.tail->relay->address >> 16 );
  specifier->specifier[3] = (uint8_t)( circuit->client->rend_circuit->relay_list.tail->relay->address >> 24 );

  specifier->specifier[4] = (uint8_t)( circuit->client->rend_circuit->relay_list.tail->relay->or_port >> 8 );
  specifier->specifier[5] = (uint8_t)circuit->client->rend_circuit->relay_list.tail->relay->or_port;

  // to next specifier
  specifier = specifier->specifier + 6;

  specifier->type = LEGACYLink;
  specifier->length = ID_LENGTH;
  memcpy( specifier->specifier, circuit->client->rend_circuit->relay_list.tail->relay->identity, ID_LENGTH );

  mac = specifier->specifier + ID_LENGTH;

  // encrypt the encrypted section
  wc_AesSetKeyDirect( &encrypt_key, hs_keys, AES_256_KEY_SIZE, aes_iv, AES_ENCRYPTION );

  // mac is at +1 so subtracting the start gives us length
  wolf_succ = wc_AesCtrEncrypt( &encrypt_key, decrypted->rendezvous_cookie, decrypted->rendezvous_cookie, mac - decrypted->rendezvous_cookie );

  if ( wolf_succ < 0 )
  {
    MINITOR_LOG( CLIENT_TAG, "Failed to decrypt RELAY_COMMAND_INTRODUCE2 encrypted data, error code: %d", wolf_succ );

    free( intro_cell );
    ret = -1;
    goto finish;
  }

  // compute the mac
  reusable_length = WC_SHA256_DIGEST_SIZE;
  reusable_length_buffer[0] = (unsigned char)( reusable_length >> 56 );
  reusable_length_buffer[1] = (unsigned char)( reusable_length >> 48 );
  reusable_length_buffer[2] = (unsigned char)( reusable_length >> 40 );
  reusable_length_buffer[3] = (unsigned char)( reusable_length >> 32 );
  reusable_length_buffer[4] = (unsigned char)( reusable_length >> 24 );
  reusable_length_buffer[5] = (unsigned char)( reusable_length >> 16 );
  reusable_length_buffer[6] = (unsigned char)( reusable_length >> 8 );
  reusable_length_buffer[7] = (unsigned char)reusable_length;

  wc_Sha3_256_Update( &mac_sha3, reusable_length_buffer, 8 );
  wc_Sha3_256_Update( &mac_sha3, hs_keys + AES_256_KEY_SIZE, WC_SHA3_256_DIGEST_SIZE );

  wc_Sha3_256_Update( &mac_sha3, intro_cell->payload.relay.data, mac - intro_cell->payload.relay.data );
  wc_Sha3_256_Final( &mac_sha3, mac );

  intro_cell->payload.relay.length = mac + WC_SHA3_256_DIGEST_SIZE - intro_cell->payload.relay.data;

  intro_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + intro_cell->payload.relay.length;

  succ = d_send_relay_cell_and_free( or_connection, intro_cell, &circuit->relay_list, NULL );

  if ( succ < 0 )
  {
    ret = -1;
  }

finish:
  if ( ret < 0 )
  {
    wc_curve25519_free( &circuit->client->client_handshake_key );
  }

  wc_Shake256_Free( &hs_keys_shake );
  wc_Sha3_256_Free( &mac_sha3 );
  wc_AesFree( &encrypt_key );
  wc_FreeRng( &rng );

  return ret;
}

int d_client_establish_rendezvous( OnionCircuit* circuit, DlConnection* or_connection )
{
  int ret;
  Cell* establish_cell;

  establish_cell = malloc( MINITOR_CELL_LEN );

  establish_cell->command = RELAY;
  establish_cell->circ_id = circuit->circ_id;

  establish_cell->payload.relay.relay_command = RELAY_COMMAND_ESTABLISH_RENDEZVOUS;
  establish_cell->payload.relay.recognized = 0;
  establish_cell->payload.relay.stream_id = 0;
  establish_cell->payload.relay.digest = 0;
  establish_cell->payload.relay.length = 20;

  memcpy( establish_cell->payload.relay.data, circuit->client->rendezvous_cookie, 20 );

  establish_cell->length = FIXED_CELL_HEADER_SIZE + RELAY_CELL_HEADER_SIZE + establish_cell->payload.relay.length;

  ret = d_send_relay_cell_and_free( or_connection, establish_cell, &circuit->relay_list, NULL );

  if ( ret < 0 )
  {
    return -1;
  }

  return 0;
}

int d_client_join_rendezvous( OnionCircuit* circuit, DlConnection* or_connection, Cell* rend_cell )
{
  int ret = 0;
  curve25519_key hs_handshake_key;
  OnionMessage* onion_message;
  HsCrypto* hs_crypto;

  wc_curve25519_init( &hs_handshake_key );

  if ( wc_curve25519_import_public_ex( rend_cell->payload.relay.rend2.public_key, CURVE25519_KEYSIZE, &hs_handshake_key, EC25519_LITTLE_ENDIAN ) < 0 )
  {
    ret = -1;
    goto finish;
  }

  hs_crypto = malloc( sizeof( HsCrypto ) );

  if ( d_hs_ntor_handshake_finish( circuit->client->intro_cryptos[circuit->client->active_intro_relay]->auth_key.p, &circuit->client->intro_cryptos[circuit->client->active_intro_relay]->encrypt_key, &hs_handshake_key, &circuit->client->client_handshake_key, hs_crypto, rend_cell->payload.relay.rend2.auth, true ) < 0 )
  {
    free( hs_crypto );

    ret = -1;
    goto finish;
  }

  circuit->hs_crypto = hs_crypto;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = CLIENT_RENDEZVOUS_CIRCUIT_READY;

  MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[0], (void*)(&onion_message) );

finish:
  wc_curve25519_free( &circuit->client->client_handshake_key );
  wc_curve25519_free( &hs_handshake_key );

  return ret;
}

int d_client_relay_data( OnionCircuit* circuit, Cell* data_cell )
{
  OnionMessage* onion_message;

  if ( circuit->client->stream_queues[data_cell->payload.relay.stream_id] == NULL )
  {
    return -1;
  }

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = CLIENT_RELAY_DATA;
  onion_message->length = data_cell->payload.relay.length;
  onion_message->data = malloc( onion_message->length );

  memcpy( onion_message->data, data_cell->payload.relay.data, onion_message->length );

  MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[data_cell->payload.relay.stream_id], (void*)(&onion_message) );
}

int d_client_relay_end( OnionCircuit* circuit, Cell* end_cell )
{
  OnionMessage* onion_message;

  MINITOR_LOG( CLIENT_TAG, "stream_id %d", end_cell->payload.relay.stream_id );

  if ( circuit->client->stream_queues[end_cell->payload.relay.stream_id] == NULL )
  {
    return -1;
  }

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = CLIENT_RELAY_END;

  MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[end_cell->payload.relay.stream_id], (void*)(&onion_message) );
}

int d_client_relay_connected( OnionCircuit* circuit, Cell* connected_cell )
{
  OnionMessage* onion_message;

  MINITOR_LOG( CLIENT_TAG, "stream_id %d", connected_cell->payload.relay.stream_id );

  if ( circuit->client->stream_queues[connected_cell->payload.relay.stream_id] == NULL )
  {
    return -1;
  }

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = CLIENT_RELAY_CONNECTED;

  MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[connected_cell->payload.relay.stream_id], (void*)(&onion_message) );
}

void v_onion_client_handle_cell( OnionCircuit* circuit, DlConnection* or_connection, Cell* cell )
{
  MinitorMutex access_mutex;

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  if ( cell->command != RELAY )
  {
    MINITOR_LOG( CLIENT_TAG, "Invalid cell command %d", cell->command );

    goto circuit_rebuild;
  }

  switch ( cell->payload.relay.relay_command )
  {
    case RELAY_DATA:
      if ( d_client_relay_data( circuit, cell ) < 0 )
      {
        MINITOR_LOG( CLIENT_TAG, "Failed to d_forward_to_client" );

        goto circuit_rebuild;
      }

      break;
    case RELAY_END:
      if ( d_client_relay_end( circuit, cell ) < 0 )
      {
        MINITOR_LOG( CLIENT_TAG, "Failed to d_client_relay_end" );

        goto circuit_rebuild;
      }

      break;
    case RELAY_CONNECTED:
      if ( d_client_relay_connected( circuit, cell ) < 0 )
      {
        MINITOR_LOG( CLIENT_TAG, "Failed to d_client_relay_connected" );

        goto circuit_rebuild;
      }

      break;
    // we just want to get out of there
    case RELAY_TRUNCATED:
        goto circuit_rebuild;
      break;
    // do nothing
    case RELAY_DROP:
      break;
    case RELAY_COMMAND_RENDEZVOUS2:
      if ( d_client_join_rendezvous( circuit, or_connection, cell ) < 0 )
      {
        MINITOR_LOG( CLIENT_TAG, "Failed to d_client_join_rendezvous" );

        goto circuit_rebuild;
      }

      circuit->status = CIRCUIT_CLIENT_RENDEZVOUS_LIVE;

      break;
    default:
      MINITOR_LOG( CLIENT_TAG, "Got an unknown relay command from onion client cell: %d", cell->payload.relay.relay_command );
      break;
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
