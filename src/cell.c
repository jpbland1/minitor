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
#include <string.h>
#include "esp_log.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "../include/config.h"

#include "../h/cell.h"
#include "../h/structures/onion_message.h"

void v_hostize_variable_short_cell( CellShortVariable* cell )
{
  int i;

  cell->circ_id = ntohs( cell->circ_id );
  cell->length = ntohs( cell->length );

  switch ( cell->command )
  {
    case VERSIONS:
      for ( i = 0; i < cell->length / 2; i++ )
      {
        cell->payload.versions[i] = ntohs( cell->payload.versions[i] );
      }

      break;

    default:
      break;
  }
}

void v_hostize_variable_cell( CellVariable* cell )
{
  int i;
  TorCert* cert;

  cell->circ_id = ntohl( cell->circ_id );
  cell->length = ntohs( cell->length );

  switch ( cell->command )
  {
    case CERTS:
      cert = cell->payload.certs.certs;

      for ( i = 0; i < cell->payload.certs.num_certs; i++ )
      {
        // cert length
        cert->cert_length = ntohs( cert->cert_length );

        cert = (uint8_t*)cert + 3 + cert->cert_length;
      }

      break;

    case AUTH_CHALLENGE:
      cell->payload.auth_challenge.num_methods = ntohs( cell->payload.auth_challenge.num_methods );

      for ( i = 0; i < cell->payload.auth_challenge.num_methods; i++ )
      {
        cell->payload.auth_challenge.methods[i] = ntohs( cell->payload.auth_challenge.methods[i] );
      }

      break;

    default:
      break;
  }
}

void v_hostize_cell( Cell* cell )
{
  cell->circ_id = ntohl( cell->circ_id );

  switch ( cell->command )
  {
    case RELAY:
      cell->payload.relay.stream_id = ntohs( cell->payload.relay.stream_id );
      cell->payload.relay.length = ntohs( cell->payload.relay.length );

      switch ( cell->payload.relay.relay_command )
      {
        case RELAY_BEGIN:
          // flags of relay_begin are after the address string
          ((uint32_t*)cell->payload.relay.data + strlen( (char*)cell->payload.relay.data ) + 1)[0] = ntohl(((uint32_t*)cell->payload.relay.data + strlen( (char*)cell->payload.relay.data ) + 1)[0]);

          break;

        case RELAY_CONNECTED:
          if ( cell->payload.relay.connected.address_4 != 0 )
          {
            cell->payload.relay.connected.ttl_4 = ntohl( cell->payload.relay.connected.ttl_4 );
          }
          else if ( cell->payload.relay.connected.address_type == 6 )
          {
            cell->payload.relay.connected.ttl_6 = ntohl( cell->payload.relay.connected.ttl_6 );
          }

          break;

        case RELAY_EXTENDED2:
          cell->payload.relay.extended2.handshake_length = ntohs( cell->payload.relay.extended2.handshake_length );

          break;

        case RELAY_COMMAND_INTRODUCE2:
          cell->payload.relay.introduce2.auth_key_length = ntohs( cell->payload.relay.introduce2.auth_key_length );

          break;

        default:
          break;
      }

      break;

    case NETINFO:
      cell->payload.netinfo.time = ntohl( cell->payload.netinfo.time );

      break;

    case CREATED2:
      cell->payload.created2.handshake_length = ntohs( cell->payload.created2.handshake_length );

      break;

    default:
      break;
  }
}

void v_networkize_variable_short_cell( CellShortVariable* cell )
{
  int i;

  switch ( cell->command )
  {
    case VERSIONS:
      for ( i = 0; i < cell->length / 2; i++ )
      {
        cell->payload.versions[i] = htons( cell->payload.versions[i] );
      }

      break;
  }

  cell->circ_id = htons( cell->circ_id );
  cell->length = htons( cell->length );
}

void v_networkize_variable_cell ( CellVariable* cell )
{
  int i;
  int length;
  TorCert* cert;

  switch ( cell->command )
  {
    case AUTHENTICATE:
      cell->payload.authenticate.auth_type = htons( cell->payload.authenticate.auth_type );
      cell->payload.authenticate.auth_length = htons( cell->payload.authenticate.auth_length );

      break;

    case CERTS:
      cert = cell->payload.certs.certs;

      for ( i = 0; i < cell->payload.certs.num_certs; i++ )
      {
        length = cert->cert_length;
        cert->cert_length = htons( cert->cert_length );

        cert = (uint8_t*)cert + 3 + length;
      }

      break;

    default:
      break;
  }

  cell->circ_id = htonl( cell->circ_id );
  cell->length = htons( cell->length );
}

void v_networkize_cell( Cell* cell )
{
  int i;
  uint8_t* tmp_p;
  Create2* create2;

  switch ( cell->command )
  {
    case RELAY:
    case RELAY_EARLY:
      cell->payload.relay.stream_id = htons( cell->payload.relay.stream_id );
      cell->payload.relay.length = htons( cell->payload.relay.length );

      switch ( cell->payload.relay.relay_command )
      {
        case RELAY_CONNECTED:
          if ( cell->payload.relay.connected.address_4 != 0 )
          {
            cell->payload.relay.connected.ttl_4 = htonl( cell->payload.relay.connected.ttl_4 );
          }
          else if ( cell->payload.relay.connected.address_type == 6 )
          {
            cell->payload.relay.connected.ttl_6 = htonl( cell->payload.relay.connected.ttl_6 );
          }

          break;
        case RELAY_EXTEND2:
          tmp_p = cell->payload.relay.extend2.link_specifiers;

          // skip over the link specifiers
          for ( i = 0; i < cell->payload.relay.extend2.num_specifiers; i++ )
          {
            tmp_p += tmp_p[1] + 2;
          }

          create2 = tmp_p;

          create2->handshake_type = htons( create2->handshake_type );
          create2->handshake_length = htons( create2->handshake_length );

          break;
        case RELAY_COMMAND_ESTABLISH_INTRO:
          // this has already been networkized for the handshake auth, need to hostize it for this
          tmp_p = cell->payload.relay.establish_intro.auth_key + ntohs( cell->payload.relay.establish_intro.auth_key_length ) + 1;

          // extensions
          for ( i = 0; i < cell->payload.relay.establish_intro.auth_key[ntohs( cell->payload.relay.establish_intro.auth_key_length )]; i++ )
          {
            if ( tmp_p[0] == EXTENSION_ED25519 )
            {
              tmp_p += 16 + 32 + 64;
            }
          }

          tmp_p += MAC_LEN;

          // signature length
          ((uint16_t*)tmp_p)[0] = htons( ((uint16_t*)tmp_p)[0] );

          // auth key length needs to be hostized before the signature is created, and before this function is called
          //cell->payload.relay.establish_intro.auth_key_length = htons( cell->payload.relay.establish_intro.auth_key_length );

          break;
        default:
          //ESP_LOGE( MINITOR_TAG, "unhandled relay command %d", cell->payload.relay.relay_command );
          break;
      }

      break;

    case NETINFO:
      cell->payload.netinfo.time = htonl( cell->payload.netinfo.time );

      break;

    case CREATE2:
      cell->payload.create2.handshake_type = htons( cell->payload.create2.handshake_type );
      cell->payload.create2.handshake_length = htons( cell->payload.create2.handshake_length );
      
      break;

    default:
      //ESP_LOGE( MINITOR_TAG, "unhandled command %d", cell->command );

      break;
  }

  cell->circ_id = htonl( cell->circ_id );

  if ( ( cell->command == RELAY || cell->command == RELAY_EARLY ) && cell->payload.relay.relay_command != RELAY_BEGIN_DIR )
  {
    esp_fill_random( (uint8_t*)cell + FIXED_CELL_OFFSET + cell->length, CELL_LEN - cell->length );
  }
  else
  {
    memset( (uint8_t*)cell + FIXED_CELL_OFFSET + cell->length, 0, CELL_LEN - cell->length );
  }
}

int d_send_cell_and_free( DlConnection* or_connection, Cell* cell )
{
  int succ;

  v_networkize_cell( cell );

  succ = wolfSSL_send( or_connection->ssl, (uint8_t*)cell + FIXED_CELL_OFFSET, CELL_LEN, 0 );

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send packed cell" );
#endif
  }

  free( cell );

  return succ;
}

int d_send_relay_cell_and_free( DlConnection* or_connection, Cell* cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto )
{
  int ret = 0;
  int i;
  int succ;
  unsigned char tmp_digest[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedOnionRelay* db_relay = relay_list->head;

  v_networkize_cell( cell );

  for ( i = 0; i < relay_list->built_length - 1; i++ )
  {
    db_relay = db_relay->next;
  }

  if ( hs_crypto == NULL )
  {
    wc_ShaUpdate( &db_relay->relay_crypto->running_sha_forward, cell->payload.data, PAYLOAD_LEN );
    wc_ShaGetHash( &db_relay->relay_crypto->running_sha_forward, tmp_digest );
  }
  else
  {
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, cell->payload.data, PAYLOAD_LEN );
    wc_Sha3_256_GetHash( &hs_crypto->hs_running_sha_backward, tmp_digest );
  }

  // TODO verify this is at + 10
  memcpy( &(cell->payload.relay.digest), tmp_digest, 4 );

  // encrypt the RELAY_EARLY cell's payload from R_(node_index-1) to R_0
  for ( i = relay_list->built_length - 1; i >= 0; i-- )
  {
    succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_forward, cell->payload.data, cell->payload.data, PAYLOAD_LEN );

    if ( succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload, error code: %d", succ );
#endif

      ret = -1;
      goto finish;
    }

    db_relay = db_relay->previous;
  }

  if ( hs_crypto != NULL )
  {
    succ = wc_AesCtrEncrypt( &hs_crypto->hs_aes_backward, cell->payload.data, cell->payload.data, PAYLOAD_LEN );

    if ( succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload using hs crypto, error code: %d", succ );
#endif

      ret = -1;
      goto finish;
    }
  }

  // send the RELAY_EARLY to the first node in the circuit
  succ = wolfSSL_send( or_connection->ssl, (uint8_t*)cell + FIXED_CELL_OFFSET, CELL_LEN, 0 );

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY cell" );
#endif

    ret = -1;
    goto finish;
  }

finish:
  free( cell );

  return ret;
}

int d_recv_cell( WOLFSSL* ssl, uint8_t** cell, int circ_id_length )
{
  int i;
  int rx_length;
  int rx_length_total = 0;
  // length of the header may change if we run into a variable length cell
  int header_length = circ_id_length + 1;
  // limit will change
  int rx_limit = header_length;
  // we want to make it big enough for an entire cell to fit
  //unsigned char rx_buffer[CELL_LEN];
  // variable length of the cell if there is one
  unsigned short length = 0;

  // initially just make the packed cell big enough for a standard header,
  // we'll realloc it later
  *cell = malloc( CELL_LEN );
  //*packed_cell = malloc( header_length );

  while ( 1 )
  {
    // read in at most rx_length, rx_length will be either the length of
    // the cell or the length of the header
    if ( rx_limit - rx_length_total > CELL_LEN )
    {
      rx_length = wolfSSL_recv( ssl, *cell + rx_length_total, CELL_LEN, 0 );
    }
    else
    {
      rx_length = wolfSSL_recv( ssl, *cell + rx_length_total, rx_limit - rx_length_total, 0 );
    }

    // if rx_length is 0 then we've hit an error and should return -1
    if ( rx_length <= 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to wolfSSL_recv rx_length: %d, error code: %d", rx_length, wolfSSL_get_error( ssl, rx_length ) );
#endif

      free( *cell );

      return -1;
    }

    // put the contents of the rx_buffer into the packed cell and increment the
    // rx_length_total
    //memcpy( *packed_cell + rx_length_total, rx_buffer, rx_length );
    rx_length_total += rx_length;

    // if the total number of bytes we've read in is the fixed header length,
    // check for a versions variable length cell, if we have one, extend the
    // header length to include the length field
    if ( rx_length_total == circ_id_length + 1 )
    {
      if ( (*cell)[circ_id_length] == VERSIONS || (*cell)[circ_id_length] >= VPADDING )
      {
        header_length = circ_id_length + 3;
        rx_limit = header_length;
        //*packed_cell = realloc( *packed_cell, header_length );
      }
    }

    // if we've reached the header we're ready to realloc and move the rx_limit
    // to the length of the cell
    if ( rx_length_total == header_length )
    {
      // set the rx_limit to the length of the cell
      if ( (*cell)[circ_id_length] == VERSIONS || (*cell)[circ_id_length] >= VPADDING )
      {
        length = ( (unsigned short)(*cell)[circ_id_length + 1] ) << 8;
        length |= (unsigned short)(*cell)[circ_id_length + 2];
        rx_limit = header_length + length;
      }
      else
      {
        rx_limit = CELL_LEN;
      }

      if ( rx_limit > CELL_LEN )
      {
        *cell = realloc( *cell, rx_limit );
      }
    }

    // if we've hit the rx_limit then we're done recv-ing the packed cell,
    // the rx_limit will increase after we've recv-ed the header so we
    // won't hit this prematurely
    if ( rx_length_total == rx_limit )
    {
      break;
    }
  }

  if ( circ_id_length == CIRCID_LEN && (*cell)[circ_id_length] != VERSIONS && (*cell)[circ_id_length] < VPADDING )
  {
    *cell = realloc( *cell, MINITOR_CELL_LEN );

    i = MINITOR_CELL_LEN;
    i = ( i / 2 ) - 1;

    for ( ; i > 0; i-- )
    {
      ((uint16_t*)(*cell))[i] = ((uint16_t*)(*cell))[i - 1];
    }
  }

  return rx_limit;
}

int d_decrypt_cell( Cell* cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto )
{
  int i;
  int wolf_succ;
  Sha tmp_sha;
  Sha3 tmp_sha3;
  DoublyLinkedOnionRelay* db_relay;
  unsigned char zeros[4] = { 0 };
  unsigned char tmp_digest[WC_SHA_DIGEST_SIZE];
  unsigned char tmp_sha3_digest[WC_SHA3_256_DIGEST_SIZE];
  int fully_recognized = 0;

  if ( cell->command != RELAY )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, cell was not relay %d", cell->command );
#endif

    return -1;
  }

  if ( relay_list == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, relay list was null" );
#endif

    return -1;
  }

  db_relay = relay_list->head;
  //wc_InitSha( &tmp_sha );

  for ( i = 0; i < relay_list->built_length; i++ )
  {
    wolf_succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_backward, cell->payload.data, cell->payload.data, PAYLOAD_LEN );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, error code: %d", wolf_succ );
#endif

      return -1;
    }

    if ( cell->payload.relay.recognized == 0 )
    {
      wc_ShaCopy( &db_relay->relay_crypto->running_sha_backward, &tmp_sha );

      // before digest
      wc_ShaUpdate( &tmp_sha, (uint8_t*)(&cell->payload), 5 );
      // zeros in lieu of the digest
      wc_ShaUpdate( &tmp_sha, zeros, 4 );
      wc_ShaUpdate( &tmp_sha, (uint8_t*)(&cell->payload.relay.length), PAYLOAD_LEN - 9 );
      wc_ShaGetHash( &tmp_sha, tmp_digest );

      if ( memcmp( tmp_digest, (uint8_t*)(&cell->payload.relay.digest), 4 ) == 0 )
      {
        //wc_ShaFree( &db_relay->relay_crypto->running_sha_backward );
        wc_ShaCopy( &tmp_sha, &db_relay->relay_crypto->running_sha_backward );
        fully_recognized = 1;
        break;
      }
    }

    db_relay = db_relay->next;
  }

  if ( !fully_recognized && hs_crypto == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Relay cell was not recognized on circuit" );
#endif
    wc_ShaFree( &tmp_sha );

    return -1;
  }
  else if ( !fully_recognized && hs_crypto != NULL )
  {
    wolf_succ = wc_AesCtrEncrypt( &hs_crypto->hs_aes_forward, (uint8_t*)(&cell->payload), (uint8_t*)(&cell->payload), PAYLOAD_LEN );

    if ( wolf_succ < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload using hs_aes_forward, error code: %d", wolf_succ );
#endif

      return -1;
    }

    if ( cell->payload.relay.recognized == 0 )
    {
      wc_Sha3_256_Copy( &hs_crypto->hs_running_sha_forward, &tmp_sha3 );

      wc_Sha3_256_Update( &tmp_sha3, (uint8_t*)(&cell->payload), 5 );
      wc_Sha3_256_Update( &tmp_sha3, zeros, 4 );
      wc_Sha3_256_Update( &tmp_sha3, (uint8_t*)(&cell->payload.relay.length), PAYLOAD_LEN - 9 );
      wc_Sha3_256_GetHash( &tmp_sha3, tmp_sha3_digest );

      if ( memcmp( tmp_sha3_digest, (uint8_t*)(&cell->payload.relay.digest), 4 ) == 0 )
      {
        wc_Sha3_256_Free( &hs_crypto->hs_running_sha_forward );
        wc_Sha3_256_Copy( &tmp_sha3, &hs_crypto->hs_running_sha_forward );
      }
      else
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Relay cell was not recognized on hidden service" );
#endif
        wc_Sha3_256_Free( &tmp_sha3 );

        return -1;
      }
    }
    else
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Cell recognized not set to 0" );
#endif

      return -1;
    }
  }

  return 0;
}
