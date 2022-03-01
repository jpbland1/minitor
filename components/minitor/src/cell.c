#include <stdlib.h>
#include <string.h>

#include "user_settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "../h/cell.h"

int d_send_packed_relay_cell_and_free( WOLFSSL* ssl, unsigned char* packed_cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto ) {
  int ret = 0;
  int i;
  int wolf_succ;
  unsigned char tmp_digest[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedOnionRelay* db_relay = relay_list->head;

  for ( i = 0; i < relay_list->built_length - 1; i++ ) {
    db_relay = db_relay->next;
  }

  if ( hs_crypto == NULL ) {
    wc_ShaUpdate( &db_relay->relay_crypto->running_sha_forward, packed_cell + 5, PAYLOAD_LEN );
    wc_ShaGetHash( &db_relay->relay_crypto->running_sha_forward, tmp_digest );
  } else {
    wc_Sha3_256_Update( &hs_crypto->hs_running_sha_backward, packed_cell + 5, PAYLOAD_LEN );
    wc_Sha3_256_GetHash( &hs_crypto->hs_running_sha_backward, tmp_digest );
  }

  memcpy( packed_cell + 10, tmp_digest, 4 );

  // encrypt the RELAY_EARLY cell's payload from R_(node_index-1) to R_0
  for ( i = relay_list->built_length - 1; i >= 0; i-- ) {
    wolf_succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_forward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload, error code: %d", wolf_succ );
#endif

      ret = -1;
      goto finish;
    }

    db_relay = db_relay->previous;
  }

  if ( hs_crypto != NULL ) {
    wolf_succ = wc_AesCtrEncrypt( &hs_crypto->hs_aes_backward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload using hs crypto, error code: %d", wolf_succ );
#endif

      ret = -1;
      goto finish;
    }
  }

  // send the RELAY_EARLY to the first node in the circuit
  if ( wolfSSL_send( ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
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

// recv a cell from our ssl connection
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha, OnionCircuit* rend_circuit ) {
  int rx_limit;
  unsigned char* packed_cell;

  rx_limit = d_recv_packed_cell( ssl, &packed_cell, circ_id_length, relay_list, rend_circuit, &unpacked_cell->recv_index );

  if ( rx_limit < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't recv packed cell" );
#endif

    return -1;
  }

  if ( sha != NULL )
  {
    wc_Sha256Update( sha, packed_cell, rx_limit );
  }

  // set the unpacked cell and return success
  return unpack_and_free( unpacked_cell, packed_cell, circ_id_length );
}

int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, OnionCircuit* rend_circuit, int* recv_index )
{
  int i;
  int wolf_succ;
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
  Sha tmp_sha;
  Sha3 tmp_sha3;
  DoublyLinkedOnionRelay* db_relay;
  unsigned char zeros[4] = { 0 };
  unsigned char tmp_digest[WC_SHA_DIGEST_SIZE];
  unsigned char tmp_sha3_digest[WC_SHA3_256_DIGEST_SIZE];
  int fully_recognized = 0;

  // initially just make the packed cell big enough for a standard header,
  // we'll realloc it later
  *packed_cell = malloc( sizeof( unsigned char ) * header_length );

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

  if ( (*packed_cell)[circ_id_length] == RELAY )
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
      wolf_succ = wc_AesCtrEncrypt( &db_relay->relay_crypto->aes_backward, *packed_cell + 5, *packed_cell + 5, PAYLOAD_LEN );

      if ( wolf_succ < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, error code: %d", wolf_succ );
#endif

        return -1;
      }

      if ( (*packed_cell)[6] == 0 && (*packed_cell)[7] == 0 )
      {
        wc_ShaCopy( &db_relay->relay_crypto->running_sha_backward, &tmp_sha );

        wc_ShaUpdate( &tmp_sha, *packed_cell + 5, 5 );
        wc_ShaUpdate( &tmp_sha, zeros, 4 );
        wc_ShaUpdate( &tmp_sha, *packed_cell + 14, PAYLOAD_LEN - 9 );
        wc_ShaGetHash( &tmp_sha, tmp_digest );

        if ( memcmp( tmp_digest, *packed_cell + 10, 4 ) == 0 )
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

    if ( !fully_recognized && rend_circuit == NULL )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Relay cell was not recognized on circuit" );
#endif
      wc_ShaFree( &tmp_sha );

      return -1;
    }
    else if ( !fully_recognized && rend_circuit != NULL )
    {
      ESP_LOGE( MINITOR_TAG, "Trying hs crypto" );

      wolf_succ = wc_AesCtrEncrypt( &rend_circuit->hs_crypto->hs_aes_forward, *packed_cell + 5, *packed_cell + 5, PAYLOAD_LEN );

      if ( wolf_succ < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload using hs_aes_forward, error code: %d", wolf_succ );
#endif

        return -1;
      }

      if ( (*packed_cell)[6] == 0 && (*packed_cell)[7] == 0 )
      {
        ESP_LOGE( MINITOR_TAG, "hs crypto recognized" );

        wc_Sha3_256_Copy( &rend_circuit->hs_crypto->hs_running_sha_forward, &tmp_sha3 );

        wc_Sha3_256_Update( &tmp_sha3, *packed_cell + 5, 5 );
        wc_Sha3_256_Update( &tmp_sha3, zeros, 4 );
        wc_Sha3_256_Update( &tmp_sha3, *packed_cell + 14, PAYLOAD_LEN - 9 );
        wc_Sha3_256_GetHash( &tmp_sha3, tmp_sha3_digest );

        if ( memcmp( tmp_sha3_digest, *packed_cell + 10, 4 ) == 0 )
        {
          ESP_LOGE( MINITOR_TAG, "hs crypto digest match" );

          wc_Sha3_256_Free( &rend_circuit->hs_crypto->hs_running_sha_forward );
          wc_Sha3_256_Copy( &tmp_sha3, &rend_circuit->hs_crypto->hs_running_sha_forward );
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

  return rx_limit;
}
