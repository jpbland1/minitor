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

#include "user_settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "../include/config.h"

#include "../h/cell.h"
#include "../h/structures/onion_message.h"

int d_send_packed_cell_and_free( DlConnection* or_connection, unsigned char* packed_cell )
{
  int succ;

  if ( b_verify_or_connection( or_connection ) == false )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Inavlid or_connection, bailing" );
#endif

    succ = -1;
    goto finish;
  }

  // MUTEX TAKE
  xSemaphoreTake( or_connection->access_mutex, portMAX_DELAY );

  succ = wolfSSL_send( or_connection->ssl, packed_cell, CELL_LEN, 0 );

  xSemaphoreGive( or_connection->access_mutex );
  // MUTEX GIVE

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send packed cell" );
#endif
  }

finish:
  free( packed_cell );

  return succ;
}

int d_send_packed_relay_cell_and_free( DlConnection* or_connection, unsigned char* packed_cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto )
{
  int ret = 0;
  int i;
  int succ;
  unsigned char tmp_digest[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedOnionRelay* db_relay = relay_list->head;

  for ( i = 0; i < relay_list->built_length - 1; i++ )
  {
    db_relay = db_relay->next;
  }

  if ( hs_crypto == NULL )
  {
    wc_ShaUpdate( &db_relay->relay_crypto->running_sha_forward, packed_cell + 5, PAYLOAD_LEN );
    wc_ShaGetHash( &db_relay->relay_crypto->running_sha_forward, tmp_digest );
  }
  else
  {
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, packed_cell + 5, PAYLOAD_LEN );
    wc_Sha3_256_GetHash( &hs_crypto->hs_running_sha_backward, tmp_digest );
  }

  memcpy( packed_cell + 10, tmp_digest, 4 );

  // encrypt the RELAY_EARLY cell's payload from R_(node_index-1) to R_0
  for ( i = relay_list->built_length - 1; i >= 0; i-- )
  {
    succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_forward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

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
    succ = wc_AesCtrEncrypt( &hs_crypto->hs_aes_backward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

    if ( succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload using hs crypto, error code: %d", succ );
#endif

      ret = -1;
      goto finish;
    }
  }

  if ( b_verify_or_connection( or_connection ) == false )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Inavlid or_connection, bailing" );
#endif

    ret = -1;
    goto finish;
  }

  // MUTEX TAKE
  xSemaphoreTake( or_connection->access_mutex, portMAX_DELAY );

  // send the RELAY_EARLY to the first node in the circuit
  succ = wolfSSL_send( or_connection->ssl, packed_cell, CELL_LEN, 0 );

  xSemaphoreGive( or_connection->access_mutex );
  // MUTEX GIVE

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY cell" );
#endif

    ret = -1;
    goto finish;
  }

finish:
  free( packed_cell );

  return ret;
}

// recv a cell from our or connection
/*
int d_recv_cell( OnionCircuit* circuit, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha, HsCrypto* hs_crypto )
{
  int retry;
  int succ;
  uint8_t* packed_cell;

  // retry in case we killed a final relay before processing a RELAY_END
  for ( retry = 3; retry > 0; retry-- )
  {
//
    // MUTEX TAKE
    xSemaphoreTake( or_connections_mutex, portMAX_DELAY );

    succ = b_verify_or_connection( circuit->or_connection, &or_connections );

    xSemaphoreGive( or_connections_mutex );
    // MUTEX GIVE

    if ( succ == 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Inavlid or_connection, bailing" );
#endif

      return -1;
    }
//

    succ = xQueueReceive( circuit->rx_queue, &packed_cell, 1000 * 10 / portTICK_PERIOD_MS );

    if ( succ == pdFALSE || packed_cell == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to recv packed cell" );
#endif

      if ( packed_cell != NULL )
      {
        free( packed_cell );
      }

      return -1;
    }

    if ( d_decrypt_packed_cell( packed_cell, circ_id_length, relay_list, hs_crypto, &unpacked_cell->recv_index ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "failed to decrypt packed cell" );
#endif

      free( onion_message->data );
      free( onion_message );

      continue;
    }

    if ( sha != NULL )
    {
      wc_Sha256Update( sha, packed_cell, onion_message->length );
    }

    free( onion_message );

    // set the unpacked cell and return success
    unpack_and_free( unpacked_cell, packed_cell, circ_id_length );

    return 0;
  }

  return -1;
}
*/

int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length )
{
  int rx_length;
  int rx_length_total = 0;
  // length of the header may change if we run into a variable length cell
  int header_length = circ_id_length + 1;
  // limit will change
  int rx_limit = header_length;
  // we want to make it big enough for an entire cell to fit
  unsigned char rx_buffer[CELL_LEN];
  // variable length of the cell if there is one
  unsigned short length = 0;

  // initially just make the packed cell big enough for a standard header,
  // we'll realloc it later
  *packed_cell = malloc( sizeof( unsigned char ) * header_length );

  // to be given by the task that wants us to read

  while ( 1 )
  {
    // read in at most rx_length, rx_length will be either the length of
    // the cell or the length of the header
    if ( rx_limit - rx_length_total > CELL_LEN )
    {
      rx_length = wolfSSL_recv( ssl, rx_buffer, CELL_LEN, 0 );
    }
    else
    {
      rx_length = wolfSSL_recv( ssl, rx_buffer, rx_limit - rx_length_total, 0 );
    }

    // if rx_length is 0 then we've hit an error and should return -1
    if ( rx_length <= 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to wolfSSL_recv rx_length: %d, error code: %d", rx_length, wolfSSL_get_error( ssl, rx_length ) );
#endif

      free( *packed_cell );

      return -1;
    }

    // put the contents of the rx_buffer into the packed cell and increment the
    // rx_length_total
    memcpy( *packed_cell + rx_length_total, rx_buffer, rx_length );
    rx_length_total += rx_length;
    /* for ( i = 0; i < rx_length; i++ ) { */
      /* (*packed_cell)[rx_length_total] = rx_buffer[i]; */
      /* rx_length_total++; */
    /* } */

    // if the total number of bytes we've read in is the fixed header length,
    // check for a versions variable length cell, if we have one, extend the
    // header length to include the length field
    if ( rx_length_total == circ_id_length + 1 )
    {
      if ( (*packed_cell)[circ_id_length] == VERSIONS || (*packed_cell)[circ_id_length] >= VPADDING )
      {
        header_length = circ_id_length + 3;
        rx_limit = header_length;
        *packed_cell = realloc( *packed_cell, header_length );
      }
    }

    // if we've reached the header we're ready to realloc and move the rx_limit
    // to the length of the cell
    if ( rx_length_total == header_length )
    {
      // set the rx_limit to the length of the cell
      if ( (*packed_cell)[circ_id_length] == VERSIONS || (*packed_cell)[circ_id_length] >= VPADDING )
      {
        length = ( (unsigned short)(*packed_cell)[circ_id_length + 1] ) << 8;
        length |= (unsigned short)(*packed_cell)[circ_id_length + 2];
        rx_limit = header_length + length;
      }
      else
      {
        rx_limit = CELL_LEN;
      }

      // realloc the cell to the correct size
      *packed_cell = realloc( *packed_cell, rx_limit );
    }

    // if we've hit the rx_limit then we're done recv-ing the packed cell,
    // the rx_limit will increase after we've recv-ed the header so we
    // won't hit this prematurely
    if ( rx_length_total == rx_limit )
    {
      break;
    }
  }

  return rx_limit;
}

int d_decrypt_packed_cell( uint8_t* packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto, int* recv_index )
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

  if ( packed_cell[circ_id_length] == RELAY )
  {
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
      wolf_succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_backward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

      if ( wolf_succ < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, error code: %d", wolf_succ );
#endif

        return -1;
      }

      if ( packed_cell[6] == 0 && packed_cell[7] == 0 )
      {
        wc_ShaCopy( &db_relay->relay_crypto->running_sha_backward, &tmp_sha );

        wc_ShaUpdate( &tmp_sha, packed_cell + 5, 5 );
        wc_ShaUpdate( &tmp_sha, zeros, 4 );
        wc_ShaUpdate( &tmp_sha, packed_cell + 14, PAYLOAD_LEN - 9 );
        wc_ShaGetHash( &tmp_sha, tmp_digest );

        if ( memcmp( tmp_digest, packed_cell + 10, 4 ) == 0 )
        {
          //wc_ShaFree( &db_relay->relay_crypto->running_sha_backward );
          wc_ShaCopy( &tmp_sha, &db_relay->relay_crypto->running_sha_backward );
          fully_recognized = 1;
          break;
        }
      }

      db_relay = db_relay->next;
    }

    // set the recv_index so we know which node in the circuit sent the cell
    *recv_index = i;

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
      wolf_succ = wc_AesCtrEncrypt( &hs_crypto->hs_aes_forward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

      if ( wolf_succ < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload using hs_aes_forward, error code: %d", wolf_succ );
#endif

        return -1;
      }

      if ( packed_cell[6] == 0 && packed_cell[7] == 0 )
      {
        wc_Sha3_256_Copy( &hs_crypto->hs_running_sha_forward, &tmp_sha3 );

        wc_Sha3_256_Update( &tmp_sha3, packed_cell + 5, 5 );
        wc_Sha3_256_Update( &tmp_sha3, zeros, 4 );
        wc_Sha3_256_Update( &tmp_sha3, packed_cell + 14, PAYLOAD_LEN - 9 );
        wc_Sha3_256_GetHash( &tmp_sha3, tmp_sha3_digest );

        if ( memcmp( tmp_sha3_digest, packed_cell + 10, 4 ) == 0 )
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
  }

  return 0;
}
