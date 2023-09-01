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
#include <time.h>

#include "wolfssl/options.h"

#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "../include/config.h"
#include "../h/port.h"

#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/core.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/models/relay.h"

NetworkConsensus working_network_consensus;
bool have_network_consensus = false;
bool have_relay_descriptors = false;
bool external_want_consensus = false;

MinitorQueue insert_relays_queue;
MinitorQueue fetch_relays_queue;
MinitorQueue external_consensus_queue;
MinitorTask crypto_insert_handle = NULL;
MinitorMutex waiting_relays_lock;

static char working_line[200];
int working_line_length = 0;
static char working_desc_line[200];
int working_desc_line_length = 0;
static char working_cert[500];
int working_cert_length = 0;
int parse_consensus_sate;
int parse_descriptors_sate;
OnionRelay parse_relay[1];
int fetch_relays_length = 0;
OnionRelay* fetch_relays[9];
uint8_t working_master_key[H_LENGTH];
uint8_t working_identity[ID_LENGTH];
uint8_t working_ntor_onion_key[ID_LENGTH];
bool all_relays_waiting = false;
bool fetch_in_progress = false;

static void v_get_id_hash( uint8_t* identity, uint8_t* id_hash, int time_period, int hsdir_interval, uint8_t* srv )
{
  uint8_t tmp_64_buffer[8];
  wc_Sha3 reusable_sha3;

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"node-idx", strlen( "node-idx" ) );
  wc_Sha3_256_Update( &reusable_sha3, identity, H_LENGTH );

  wc_Sha3_256_Update( &reusable_sha3, srv, 32 );

  tmp_64_buffer[0] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 56 );
  tmp_64_buffer[1] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 48 );
  tmp_64_buffer[2] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 40 );
  tmp_64_buffer[3] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 32 );
  tmp_64_buffer[4] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 24 );
  tmp_64_buffer[5] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 16 );
  tmp_64_buffer[6] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 8 );
  tmp_64_buffer[7] = (unsigned char)( (uint64_t)( time_period ) );

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  tmp_64_buffer[0] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 56 );
  tmp_64_buffer[1] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 48 );
  tmp_64_buffer[2] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 40 );
  tmp_64_buffer[3] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 32 );
  tmp_64_buffer[4] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 24 );
  tmp_64_buffer[5] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 16 );
  tmp_64_buffer[6] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 8 );
  tmp_64_buffer[7] = (unsigned char)( (uint64_t)( hsdir_interval ) );

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  wc_Sha3_256_Final( &reusable_sha3, id_hash );

  wc_Sha3_256_Free( &reusable_sha3 );
}

void v_handle_crypto_and_insert( void* pv_parameters )
{
  int ret;
  int process_count = 0;
  int null_count = 0;
  bool needs_desc;
  bool enqueue;
  OnionRelay* onion_relay;
  NetworkConsensus* working_consensus = (NetworkConsensus*)pv_parameters;

  MINITOR_LOG( MINITOR_TAG, "START v_handle_crypto_and_insert", process_count );

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( crypto_insert_finish );

  while ( MINITOR_DEQUEUE_BLOCKING( insert_relays_queue, &onion_relay ) )
  {
    if ( onion_relay == NULL )
    {
      null_count++;
      MINITOR_LOG( MINITOR_TAG, "NULL count %d", null_count );

      if ( null_count == 2 )
      {
        MINITOR_LOG( MINITOR_TAG, "%d total relays processed", process_count );

        MINITOR_MUTEX_GIVE( crypto_insert_finish );
        // MUTEX GIVE

        MINITOR_QUEUE_DELETE( insert_relays_queue );
        MINITOR_TASK_DELETE( NULL );
        return;
      }

      continue;
    }

#ifdef DEBUG_MINITOR
#ifdef MINITOR_CHUTNEY
    MINITOR_LOG( MINITOR_TAG, "%d relays processed so far", process_count );
#else
    if ( process_count % 50 == 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "%d relays processed so far", process_count );
    }
#endif

    process_count++;
#endif

    needs_desc = onion_relay->hsdir_seek == 0 && onion_relay->cache_seek == 0 && onion_relay->fast_seek == 0;

#ifdef MINITOR_CHUTNEY
    onion_relay->address = MINITOR_CHUTNEY_ADDRESS;
#endif

    if ( onion_relay->hsdir == true )
    {
      if ( !needs_desc )
      {
        v_get_id_hash( onion_relay->master_key, onion_relay->id_hash_previous, working_consensus->time_period, working_consensus->hsdir_interval, working_consensus->previous_shared_rand );
        v_get_id_hash( onion_relay->master_key, onion_relay->id_hash, working_consensus->time_period + 1, working_consensus->hsdir_interval, working_consensus->shared_rand );
      }

      while ( d_create_hsdir_relay( onion_relay ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to d_create_hsdir_relay, retrying" );
      }
    }

    if (
      onion_relay->dir_cache == true &&
      d_get_staging_cache_relay_count() < CACHE_RELAY_MAX
    )
    {
      while ( d_create_cache_relay( onion_relay ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to d_create_cache_relay, retrying" );
      }
    }

    // some hsdir relays are not suitable and this will exclude them
    if (
      onion_relay->fast == true &&
#ifndef MINITOR_CHUTNEY
      onion_relay->stable == true &&
#endif
      d_get_staging_fast_relay_count() < FAST_RELAY_MAX
    )
    {
      while ( d_create_fast_relay( onion_relay ) < 0 )
      {
        MINITOR_LOG( MINITOR_TAG, "Failed to d_create_fast_relay, retrying" );
      }
    }

    if ( needs_desc )
    {
      // MUTEX TAKE
      MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

      // if we're not fetching or all relays are waiting
      if ( !fetch_in_progress && fetch_relays_length < 9 )
      {
        // enqueue to the relay to be fetched
        MINITOR_ENQUEUE_BLOCKING( fetch_relays_queue, &onion_relay );

        fetch_relays_length++;

        MINITOR_MUTEX_GIVE( waiting_relays_lock );
        // MUTEX GIVE
      }
      else
      {
        MINITOR_MUTEX_GIVE( waiting_relays_lock );
        // MUTEX GIVE

        while ( d_create_waiting_relay( onion_relay ) < 0 )
        {
          MINITOR_LOG( MINITOR_TAG, "Failed to d_create_waiting_relay, retrying" );
        }

        free( onion_relay );
      }
    }
    else
    {
      free( onion_relay );
    }

    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

    if ( !fetch_in_progress )
    {
      while ( fetch_relays_length < 9 )
      {
        onion_relay = px_get_waiting_relay();

        if ( onion_relay == NULL )
        {
          break;
        }

        MINITOR_ENQUEUE_BLOCKING( fetch_relays_queue, &onion_relay );
        fetch_relays_length++;
      }
    }

    MINITOR_MUTEX_GIVE( waiting_relays_lock );
    // MUTEX GIVE
  }
}

static void v_ipv4_to_string( unsigned int address, char* string )
{
  int i;
  int length = 0;
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

    sprintf( string + length, "%d", tmp_byte );
    length += tmp_length;

    if ( i != 3 ) {
      string[length] = '.';
      length++;
    }
  }

  string[length] = 0;
}

static int d_parse_date_string( char* date_string )
{
  struct tm tmp_time;

  tmp_time.tm_year = atoi( date_string ) - 1900;
  tmp_time.tm_mon = atoi( date_string + 5 ) - 1;
  tmp_time.tm_mday = atoi( date_string + 8 );
  tmp_time.tm_hour = atoi( date_string + 11 );
  tmp_time.tm_min = atoi( date_string + 14 );
  tmp_time.tm_sec = atoi( date_string + 17 );

  return MINITOR_TIMEGM( &tmp_time );
}

static int d_parse_line( int fd, char* line, int limit )
{
  int ret;
  char out_char;
  int length = 0;

  while ( 1 )
  {
    ret = read( fd, &out_char, sizeof( char ) );

    if ( ret < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to read consensus line, errno: %d", errno );

      return -1;
    }

    if ( ret == 0 || out_char == '\n' || length == limit )
    {
      line[length] = 0;
      return length;
    }

    line[length] = out_char;
    length++;
  }
}

static int d_parse_network_consensus_from_file( int fd, NetworkConsensus* result_network_consensus )
{
  char line[200];

  while ( 1 )
  {
    if ( d_parse_line( fd, line, sizeof( line ) ) < 0 )
    {
      return -1;
    }

    if ( result_network_consensus->method == 0 && memcmp( line, "consensus-method ", strlen( "consensus-method " ) ) == 0 )
    {
      result_network_consensus->method = atoi( line + strlen( "consensus-method " ) );
    }
    else if ( result_network_consensus->valid_after == 0 && memcmp( line, "valid-after ", strlen( "valid-after " ) ) == 0 )
    {
      result_network_consensus->valid_after = d_parse_date_string( line + strlen( "valid-after " ) );
    }
    else if ( result_network_consensus->fresh_until == 0 && memcmp( line, "fresh-until ", strlen( "fresh-until " ) ) == 0 )
    {
      result_network_consensus->fresh_until = d_parse_date_string( line + strlen( "fresh-until " ) );
    }
    else if ( result_network_consensus->valid_until == 0 && memcmp( line, "valid-until ", strlen( "valid-until " ) ) == 0 )
    {
      result_network_consensus->valid_until = d_parse_date_string( line + strlen( "valid-until " ) );
    }
    else if ( memcmp( line, "shared-rand-current-value ", strlen( "shared-rand-current-value " ) ) == 0 )
    {
      d_base_64_decode( result_network_consensus->shared_rand, line + strlen( line ) - 44, 43 );
    }
    else if ( memcmp( line, "shared-rand-previous-value ", strlen( "shared-rand-previous-value " ) ) == 0 )
    {
      d_base_64_decode( result_network_consensus->previous_shared_rand, line + strlen( line ) - 44, 43 );
    }
    else if ( memcmp( line, "dir-source", strlen( "dir-source" ) ) == 0 )
    {
      return 0;
    }
  }
}

static int d_parse_line_to_consensus( NetworkConsensus* consensus, char* line )
{
  if ( consensus->method == 0 && memcmp( line, "consensus-method ", strlen( "consensus-method " ) ) == 0 )
  {
    consensus->method = atoi( line + strlen( "consensus-method " ) );
  }
  else if ( consensus->valid_after == 0 && memcmp( line, "valid-after ", strlen( "valid-after " ) ) == 0 )
  {
    consensus->valid_after = d_parse_date_string( line + strlen( "valid-after " ) );
  }
  else if ( consensus->fresh_until == 0 && memcmp( line, "fresh-until ", strlen( "fresh-until " ) ) == 0 )
  {
    consensus->fresh_until = d_parse_date_string( line + strlen( "fresh-until " ) );
  }
  else if ( consensus->valid_until == 0 && memcmp( line, "valid-until ", strlen( "valid-until " ) ) == 0 )
  {
    consensus->valid_until = d_parse_date_string( line + strlen( "valid-until " ) );
  }
  else if ( memcmp( line, "shared-rand-current-value ", strlen( "shared-rand-current-value " ) ) == 0 )
  {
    d_base_64_decode( consensus->shared_rand, line + strlen( line ) - 44, 43 );
  }
  else if ( memcmp( line, "shared-rand-previous-value ", strlen( "shared-rand-previous-value " ) ) == 0 )
  {
    d_base_64_decode( consensus->previous_shared_rand, line + strlen( line ) - 44, 43 );
  }
  else if ( memcmp( line, "dir-source", strlen( "dir-source" ) ) == 0 )
  {
    return 1;
  }

  return 0;
}

int d_consensus_request( OnionCircuit* circuit, DlConnection* or_connection )
{
  int fd;
  const char* REQUEST = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n"
      "Host: 127.0.0.1\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";

  // clear out the old consensus
  fd = open( FILESYSTEM_PREFIX "consensus", O_CREAT | O_TRUNC, 0600 );

  if ( fd <= 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "consensus, errno %d", errno );

    return -1;
  }

  close( fd );

  return d_router_relay_data_cell( circuit, or_connection, CONSENSUS_STREAM_ID, REQUEST, strlen( REQUEST ) );
}

static int d_parse_consensus_r( char* line, int line_length, OnionRelay* parse_relay )
{
  int i;
  int space_count = 0;

  if ( memcmp( line, "r ", strlen( "r " ) ) == 0 )
  {
    for ( i = 0; i < line_length; i++ )
    {
      if ( line[i] == ' ' )
      {
        switch ( space_count )
        {
          case 1:
            d_base_64_decode( parse_relay->identity, line + i + 1, 27 );
            break;
          case 2:
            d_base_64_decode( parse_relay->digest, line + i + 1, 27 );
            break;
          case 5:
            parse_relay->address = inet_addr( line + i + 1 );
            break;
          case 6:
            parse_relay->or_port = atoi( line + i + 1 );
            break;
          default:
            break;
        }

        space_count++;

        if ( space_count > 6 )
        {
          return 1;
        }
      }
    }
  }

  return 0;
}

static int d_parse_consensus_s( char* line, int line_length, OnionRelay* parse_relay )
{
  int i;
  int space_count = 0;

  if ( memcmp( line, "s ", strlen( "s " ) ) == 0 )
  {
    for ( i = 0; i < line_length; i++ )
    {
      if ( line[i] == ' ' )
      {
        if ( !parse_relay->exit && memcmp( line + i + 1, "Exit", strlen( "Exit" ) ) == 0 )
        {
          parse_relay->exit = true;
        }
        else if ( !parse_relay->fast && memcmp( line + i + 1, "Fast", strlen( "Fast" ) ) == 0 )
        {
          parse_relay->fast = true;
        }
        else if ( !parse_relay->guard && memcmp( line + i + 1, "Guard", strlen( "Guard" ) ) == 0 )
        {
          parse_relay->guard = true;
        }
        /*
        else if ( !parse_relay->hsdir && memcmp( line + i + 1, "HSDir", strlen( "HSDir" ) ) == 0 )
        {
          parse_relay->hsdir = true;
        }
        */
        else if ( !parse_relay->stable && memcmp( line + i + 1, "Stable", strlen( "Stable" ) ) == 0 )
        {
          parse_relay->stable = true;
        }
      }
    }

    return 1;
  }

  return 0;
}

static int d_parse_consensus_pr( char* line, int line_length, OnionRelay* parse_relay )
{
  int i;
  int space_count = 0;

  if ( memcmp( line, "pr ", strlen( "pr " ) ) == 0 )
  {
    for ( i = 0; i < line_length; i++ )
    {
      if ( line[i] == ' ' )
      {
        if (
          !parse_relay->dir_cache &&
          (
            memcmp( line + i + 1, "DirCache=1-2", strlen( "DirCache=1-2" ) ) == 0 ||
            memcmp( line + i + 1, "DirCache=2", strlen( "DirCache=2" ) ) == 0
          )
        )
        {
          parse_relay->dir_cache = true;
        }
        else if (
          !parse_relay->hsdir &&
          (
            memcmp( line + i + 1, "HSDir=1-2", strlen( "HSDir=1-2" ) ) == 0 ||
            memcmp( line + i + 1, "HSDir=2", strlen( "HSDir=2" ) ) == 0
          )
        )
        {
          parse_relay->hsdir = true;
        }
      }
    }

    return 1;
  }

  return 0;
}

static int d_parse_consensus_w( char* line, int line_length, OnionRelay* parse_relay )
{
  int i;
  int space_count = 0;

  if ( memcmp( line, "w ", strlen( "w " ) ) == 0 )
  {
    for ( i = 0; i < line_length; i++ )
    {
      if ( line[i] == ' ' && memcmp( line + i + 1, "Bandwidth=", strlen( "Bandwidth=" ) ) == 0 )
      {
        parse_relay->bandwidth = atoi( line + i + 1 + strlen( "Bandwidth=" ) );
      }
    }

    return 1;
  }

  return 0;
}

int d_parse_consensus( OnionCircuit* circuit, DlConnection* or_connection, Cell* data_cell )
{
  int i;
  int fd;
  int ret;
  OnionRelay* out_relay;

  // error
  if ( data_cell->command != RELAY || ( data_cell->payload.relay.relay_command != RELAY_DATA && data_cell->payload.relay.relay_command != RELAY_END ) )
  {
    goto fail;
  }

  // end of file
  if ( data_cell->payload.relay.relay_command == RELAY_END )
  {
    working_line_length = 0;

    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

    all_relays_waiting = true;

    // if we are not already fetching descriptors
    if ( !fetch_in_progress )
    {
      ret = d_router_begin_dir( circuit, or_connection, DESCRIPTORS_STREAM_ID );

      fetch_in_progress = true;
    }

    MINITOR_MUTEX_GIVE( waiting_relays_lock );
    // MUTEX GIVE

    out_relay = NULL;
    MINITOR_ENQUEUE_BLOCKING( insert_relays_queue, &out_relay );

    return 0;
  }

  // open the consensus
  fd = open( FILESYSTEM_PREFIX "consensus", O_WRONLY | O_APPEND );

  if ( fd <= 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "consensus, errno %d", errno );

    goto fail;
  }

  // write the cell contents
  if ( write( fd, data_cell->payload.relay.data, data_cell->payload.relay.length ) != data_cell->payload.relay.length )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to write " FILESYSTEM_PREFIX "consensus, errno %d", errno );

    close( fd );

    goto fail;
  }

  close( fd );

  for ( i = 0; i < data_cell->payload.relay.length; i++ )
  {
    if ( data_cell->payload.relay.data[i] != '\n' )
    {
      working_line[working_line_length] = data_cell->payload.relay.data[i];
      working_line_length++;

      // wrap around, we actually don't care about lines that are too long
      if ( working_line_length >= sizeof( working_line ) )
      {
        working_line_length = 0;
      }
    }
    else
    {
      // if we don't have the consensus and we finish the working consensus
      if ( have_network_consensus == false && d_parse_line_to_consensus( &working_network_consensus, working_line ) == 1 )
      {
        have_network_consensus = true;

        // create the insert queue
        insert_relays_queue = MINITOR_QUEUE_CREATE( 9, sizeof( OnionRelay* ) );

        // create the insert queue and task
        b_create_insert_task( &crypto_insert_handle, &working_network_consensus );
      }
      else if ( have_network_consensus == true )
      {
        switch ( parse_consensus_sate )
        {
          case FIND_R:
            ret = d_parse_consensus_r( working_line, working_line_length, parse_relay );
            break;
          case FIND_S:
            ret = d_parse_consensus_s( working_line, working_line_length, parse_relay );
            break;
          case FIND_PR:
            ret = d_parse_consensus_pr( working_line, working_line_length, parse_relay );
            break;
          case FIND_W:
            ret = d_parse_consensus_w( working_line, working_line_length, parse_relay );
            break;
          default:
            goto fail;
        }

        if ( ret < 0 )
        {
          goto fail;
        }
        else if ( ret == 1 )
        {
          // advance to next state
          parse_consensus_sate++;
        }

        if ( parse_consensus_sate > FIND_W )
        {
          // if we actually want the relay
          if (
            ( parse_relay->fast && parse_relay->stable && d_get_staging_fast_relay_count() < FAST_RELAY_MAX ) ||
            ( parse_relay->dir_cache && d_get_staging_cache_relay_count() < CACHE_RELAY_MAX ) ||
            parse_relay->hsdir
          )
          {
            out_relay = malloc( sizeof( OnionRelay ) );

            memcpy( out_relay, parse_relay, sizeof( OnionRelay ) );

            MINITOR_ENQUEUE_BLOCKING( insert_relays_queue, &out_relay );

            memset( parse_relay, 0, sizeof( OnionRelay ) );
          }

          // MUTEX TAKE
          MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

          // if we have 9 and are not already fetching descriptors
          if ( fetch_relays_length == 9 && !fetch_in_progress )
          {
            ret = d_router_begin_dir( circuit, or_connection, DESCRIPTORS_STREAM_ID );

            fetch_in_progress = true;
          }

          MINITOR_MUTEX_GIVE( waiting_relays_lock );
          // MUTEX GIVE

          // reset the state if we pass the end state
          parse_consensus_sate = 0;
        }
      }

      working_line_length = 0;
    }
  }

  return 0;

fail:
  MINITOR_LOG( MINITOR_TAG, "failed" );

  if ( crypto_insert_handle != NULL )
  {
    MINITOR_TASK_DELETE( crypto_insert_handle );
    MINITOR_QUEUE_DELETE( insert_relays_queue );
  }

  return -1;
}

int d_descriptors_request( OnionCircuit* circuit, DlConnection* or_connection, OnionRelay** list, int list_length )
{
  int i;
  int j;
  const char* REQUEST_1 = "GET /tor/server/d/";
  const char* REQUEST_2 = " HTTP/1.0\r\nHost: 127.0.0.1\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[600];

  sprintf( REQUEST, REQUEST_1 );

  for ( i = 0; i < list_length; i++ )
  {
    for ( j = 0; j < 20; j++ )
    {
      if ( list[i]->digest[j] >> 4 < 10 )
      {
        REQUEST[18 + 2 * j + i * 41] = 48 + ( list[i]->digest[j] >> 4 );
      }
      else
      {
        REQUEST[18 + 2 * j + i * 41] = 65 + ( ( list[i]->digest[j] >> 4 ) - 10 );
      }

      if ( ( list[i]->digest[j] & 0x0f ) < 10  )
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 48 + ( list[i]->digest[j] & 0x0f );
      }
      else
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 65 + ( ( list[i]->digest[j] & 0x0f ) - 10 );
      }
    }

    if ( i != list_length - 1 )
    {
      REQUEST[18 + 40 + i * 41] = '+';
    }
  }

  // 41 for each digest+, -1 for the last one
  sprintf( REQUEST + 18 + list_length * 41 - 1, REQUEST_2 );

  return d_router_relay_data_cell( circuit, or_connection, DESCRIPTORS_STREAM_ID, REQUEST, strlen( REQUEST ) );
}

static int d_parse_http_version_line( char* line, int line_len )
{
  int http_status;
  int i;

  if ( memcmp( "HTTP", line, strlen( "HTTP" ) ) == 0 )
  {
    for ( i = 0; i < line_len; i++ )
    {
      if ( line[i] == ' ' )
      {
        // parse the integer response code after the space
        http_status = atoi( line + i + 1 );

        // if its not a 200 or 300 code
        if ( http_status >= 400 || http_status < 200 )
        {
          return -1;
        }

        return 1;
      }
    }
  }

  return 0;
}

static int d_parse_router_line( char* line, int line_len, OnionRelay* parse_relay )
{
  int i;
  int space_count = 0;

  if ( memcmp( "router ", line, strlen( "router " ) ) == 0 )
  {
    for ( i = 0; i < line_len; i++ )
    {
      if ( line[i] == ' ' )
      {
        space_count++;

        // found ip
        if ( space_count == 2 )
        {
          parse_relay->address = inet_addr( line + i + 1 );
        }
        /// found or port
        else if ( space_count == 3 )
        {
          parse_relay->or_port = atoi( line + i + 1 );
        }
      }
    }

    return 1;
  }

  return 0;
}

static int d_parse_proto_line( char* line, int line_len, OnionRelay* parse_relay )
{
  int i;
  int j;
  const char* tags[] =
  {
    "Exit",
    "Fast",
    "Guard",
    "HSDir",
    "Stable",
  };

  if ( memcmp( "proto ", line, strlen( "proto " ) ) == 0 )
  {
    for ( i = 0; i < line_len; i++ )
    {
      if ( line[i] == ' ' )
      {
        // loop over all the tags we care about
        for ( j = 0; j < sizeof( tags ); j++ )
        {
          // if we have the tag
          if ( memcmp( tags[j], line + i + 1, strlen( tags[j] ) ) )
          {
            switch ( j )
            {
              // exit
              case 0:
                parse_relay->exit = true;

                break;
              // fast
              case 1:
                parse_relay->fast = true;

                break;
              // guard
              case 2:
                parse_relay->guard = true;

                break;
              // hsdir
              case 3:
                for( ; i < line_len; i++ )
                {
                  // if we hit a space
                  if ( line[i + 1] == ' ' )
                  {
                    break;
                  }
                  // if we find version 2
                  else if ( line[i + 1] == '2' )
                  {
                    // set hsdir to true
                    parse_relay->hsdir = true;
                  }
                }

                break;
              // stable
              case 4:
                parse_relay->stable = true;

                break;
            }

            break;
          }
        }
      }
    }

    return 1;
  }

  return 0;
}

static void v_parse_identity_digest( char* signing_key_64, int signing_key_64_len, uint8_t* identity )
{
  wc_Sha identity_sha[1];
  uint8_t signing_key[140];

  wc_InitSha( &identity_sha );

  d_base_64_decode( signing_key, signing_key_64, signing_key_64_len );
  wc_ShaUpdate( identity_sha, signing_key, 140 );
  wc_ShaFinal( identity_sha, identity );

  wc_ShaFree( identity_sha );
}

int d_parse_descriptors( OnionCircuit* circuit, DlConnection* or_connection, Cell* data_cell )
{
  int i;
  int j;
  int space_count;
  int ret = 0;
  time_t now;
  time_t voting_interval;
  time_t srv_start_time;
  bool more_relays;
  bool all_waiting;
  OnionRelay* send_relay;

  // end of file
  if ( data_cell->payload.relay.relay_command == RELAY_END )
  {
    parse_descriptors_sate = REQUEST_DESCRIPTORS;

    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

    for ( i = 0; i < fetch_relays_length; i++ )
    {
      // send this relay to the filesystem queue
      MINITOR_ENQUEUE_BLOCKING( insert_relays_queue, (void*)(&fetch_relays[i]) );
    }

    fetch_in_progress = false;

    fetch_relays_length = 0;

    // this has to be checked in the mutex
    more_relays = d_get_waiting_relay_count() > 0;

    all_waiting = all_relays_waiting;

    MINITOR_MUTEX_GIVE( waiting_relays_lock );
    // MUTEX GIVE

    if ( all_waiting )
    {
      if ( more_relays )
      {
        ret = d_router_begin_dir( circuit, or_connection, DESCRIPTORS_STREAM_ID );
      }
      else
      {
        all_relays_waiting = false;

        // send NULL to signal final relay
        send_relay = NULL;
        MINITOR_ENQUEUE_BLOCKING( insert_relays_queue, (void*)(&send_relay) );

        // wait for the insert task to finish
        // MUTEX TAKE
        MINITOR_MUTEX_TAKE_BLOCKING( crypto_insert_finish );

        MINITOR_MUTEX_GIVE( crypto_insert_finish );
        // MUTEX GIVE

        // MUTEX TAKE
        MINITOR_MUTEX_TAKE_BLOCKING( network_consensus_mutex );

        memcpy( &network_consensus, &working_network_consensus, sizeof( NetworkConsensus ) );

        // if we didn't find these values explicitly set
        if ( network_consensus.hsdir_interval == 0 )
        {
#ifdef MINITOR_CHUTNEY
          network_consensus.hsdir_interval = 8;
#else
          network_consensus.hsdir_interval = HSDIR_INTERVAL_DEFAULT;
#endif
        }

        if ( network_consensus.hsdir_n_replicas == 0 )
        {
          network_consensus.hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
        }

        if ( network_consensus.hsdir_spread_store == 0 )
        {
#ifdef MINITOR_CHUTNEY
          network_consensus.hsdir_spread_store = 3;
#else
          network_consensus.hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;
#endif
        }

        ret = d_finalize_staged_relay_lists( network_consensus.valid_until );

        if ( ret == 0 )
        {
          time( &now );

#ifdef MINITOR_CHUTNEY
          voting_interval = network_consensus.fresh_until - network_consensus.valid_after;

          // 24 is SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES
          srv_start_time = network_consensus.valid_after - ( ( ( ( network_consensus.valid_after / voting_interval ) ) % ( SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES ) ) * voting_interval );

          // start the update timer a half second after the consensus update
          if ( now > ( srv_start_time + ( 25 * voting_interval ) ) )
          {
            MINITOR_TIMER_SET_MS_BLOCKING( consensus_timer, 1000 * ( 25 * voting_interval ) );
          }
          else
          {
            MINITOR_TIMER_SET_MS_BLOCKING( consensus_timer, 1000 * ( ( srv_start_time + ( 25 * voting_interval ) ) - now ) );
          }
#else
          MINITOR_TIMER_SET_MS_BLOCKING( consensus_timer, ( network_consensus.valid_until - now ) * 1000 );
#endif
        }

        MINITOR_MUTEX_GIVE( network_consensus_mutex );
        // MUTEX GIVE

        // MUTEX GIVE
        if ( ret == 0 )
          ret = 1;
      }
    }

    if ( ret < 0 )
    {
      goto fail;
    }

    return ret;
  }

  if ( parse_descriptors_sate == REQUEST_DESCRIPTORS )
  {
    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

    // wait for at least 1 relay to come through
    while ( fetch_relays_length == 0 )
    {
      MINITOR_MUTEX_GIVE( waiting_relays_lock );
      // MUTEX GIVE

      sleep( 100 );

      // MUTEX TAKE
      MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );
    }

    for ( i = 0; i < fetch_relays_length; i++ )
    {
      // insert task should have loaded up the queue with relays
      MINITOR_DEQUEUE_BLOCKING( fetch_relays_queue, &fetch_relays[i] );
    }

    fetch_in_progress = true;

    ret = d_descriptors_request( circuit, or_connection, fetch_relays, fetch_relays_length );
    MINITOR_MUTEX_GIVE( waiting_relays_lock );
    // MUTEX GIVE

    if ( ret == 0 )
    {
      parse_descriptors_sate = FIND_STATUS;
    }
    else if ( ret < 0 )
    {
      goto fail;
    }

    return ret;
  }

  for ( i = 0; i < data_cell->payload.relay.length; i++ )
  {
    if ( data_cell->payload.relay.data[i] != '\n' )
    {
      working_desc_line[working_desc_line_length] = data_cell->payload.relay.data[i];
      working_desc_line_length++;

      // wrap around, we actually don't care about lines that are too long
      if ( working_desc_line_length >= sizeof( working_desc_line ) )
      {
        working_desc_line_length = 0;
      }
    }
    else
    {
      switch ( parse_descriptors_sate )
      {
        case FIND_STATUS:
          switch ( d_parse_http_version_line( working_desc_line, working_desc_line_length ) )
          {
            // no match
            case 0:
              break;
            // match and valid code
            case 1:
              parse_descriptors_sate = FIND_MASTER_KEY_ED25519;

              break;
            default:
              goto fail;
          }

          break;
        // all router elements are in a single line
        /*
        case FIND_ROUTER:
          switch ( d_parse_router_line( working_desc_line, working_desc_line_length, parse_relay ) )
          {
            // no match
            case 0:
              break;
            // match and valid code
            case 1:
              parse_descriptors_sate = FIND_MASTER_KEY_ED25519;

              break;
            default:
              break;
          }

          break;
          */

        /*
        case FIND_IDENTITY_ED25519:
          if ( memcmp( "identity-ed25519", working_line, strlen( "identity-ed25519" ) ) == 0 )
          {
            parse_descriptors_sate = PARSE_IDENTITY_ED25519_BEGIN;
          }

          break;

        case PARSE_IDENTITY_ED25519_BEGIN:
          if ( memcmp( "-----BEGIN ED25519 CERT-----", working_line, strlen( "-----BEGIN ED25519 CERT-----" ) ) == 0 )
          {
            parse_descriptors_sate = PARSE_IDENTITY_ED25519_END;
          }

          break;

        case PARSE_IDENTITY_ED25519_END:
          if ( memcmp( "-----END ED25519 CERT-----", working_line, strlen( "-----END ED25519 CERT-----" ) ) == 0 )
          {
            // TODO parse identity
            working_cert_length = 0;

            parse_descriptors_sate = FIND_MASTER_KEY_ED25519;
          }
          else
          {
            memcpy( working_cert + working_cert_length, working_line, working_line_length );
            working_cert_length += working_line_length;
          }

          break;
        */

        case FIND_MASTER_KEY_ED25519:
          if ( memcmp( "master-key-ed25519 ", working_desc_line, strlen( "master-key-ed25519 " ) ) == 0 )
          {
            // parse master key
            d_base_64_decode( working_master_key, working_desc_line + strlen( "master-key-ed25519 " ), 43 );

            parse_descriptors_sate = FIND_SIGNING_KEY;
          }

          break;

        /*
        case FIND_PROTO:
          switch ( d_parse_proto_line( working_desc_line, working_desc_line_length, parse_relay ) )
          {
            case 0:
              break;
            case 1:
              // skip this router if it doesn't have a tag we need
              if ( parse_relay->hsdir != true && ( parse_relay->fast != true || parse_relay->stable != true ) )
              {
                parse_descriptors_sate = FIND_ROUTER;
              }
              else
              {
                parse_descriptors_sate = FIND_SIGNING_KEY;
              }

              break;
          }

          break;
        */

        case FIND_SIGNING_KEY:
          if ( memcmp( "signing-key", working_desc_line, strlen( "signing-key" ) ) == 0 )
          {
            working_cert_length = 0;
            parse_descriptors_sate = PARSE_SIGNING_RSA_BEGIN;
          }

          break;

        case PARSE_SIGNING_RSA_BEGIN:
          if ( memcmp( "-----BEGIN RSA PUBLIC KEY-----", working_desc_line, strlen( "-----BEGIN RSA PUBLIC KEY-----" ) ) == 0 )
          {
            parse_descriptors_sate = PARSE_SIGNING_RSA_END;
          }

          break;

        case PARSE_SIGNING_RSA_END:
          if ( memcmp( "-----END RSA PUBLIC KEY-----", working_desc_line, strlen( "-----END RSA PUBLIC KEY-----" ) ) == 0 )
          {
            v_parse_identity_digest( working_cert, working_cert_length, working_identity );
            working_cert_length = 0;

            parse_descriptors_sate = NTOR_ONION_KEY;
          }
          else
          {
            memcpy( working_cert + working_cert_length, working_desc_line, working_desc_line_length );
            working_cert_length += working_desc_line_length;
          }

          break;

        case NTOR_ONION_KEY:
          if ( memcmp( "ntor-onion-key ", working_desc_line, strlen( "ntor-onion-key " ) ) == 0 )
          {
            // parse the onion key
            d_base_64_decode( working_ntor_onion_key, working_desc_line + strlen( "ntor-onion-key " ), 43 );

            // MUTEX TAKE
            MINITOR_MUTEX_TAKE_BLOCKING( waiting_relays_lock );

            for ( j = 0; j < fetch_relays_length; j++ )
            {
              // match the digest
              if ( memcmp( working_identity, fetch_relays[j]->identity, ID_LENGTH ) == 0 )
              {
                // copy the fetched elements
                memcpy( fetch_relays[j]->master_key, working_master_key, H_LENGTH );
                memcpy( fetch_relays[j]->ntor_onion_key, working_ntor_onion_key, H_LENGTH );

                break;
              }
            }

            MINITOR_MUTEX_GIVE( waiting_relays_lock );
            // MUTEX GIVE

            if ( j >= fetch_relays_length )
            {
              goto fail;
            }

            parse_descriptors_sate = FIND_MASTER_KEY_ED25519;
          }

          break;
      }

      working_desc_line_length = 0;
    }
  }

  return 0;

fail:
  MINITOR_LOG( MINITOR_TAG, "failed desc" );
  if ( crypto_insert_handle != NULL )
  {
    MINITOR_TASK_DELETE( crypto_insert_handle );
    MINITOR_QUEUE_DELETE( insert_relays_queue );
  }

  return -1;
}

bool b_consensus_outdated()
{
  struct stat st;
  int fd;
  int i;
  int valid_until_found = 0;
  const char* valid_until_str = "valid-until ";
  char date_str[20];
  int rx_length;
  time_t now;
  time_t valid_until_time;
  int err;

  // TODO fill variables from d_download_consensus
  if ( stat( FILESYSTEM_PREFIX, &st ) == -1 )
  {
    if ( mkdir( FILESYSTEM_PREFIX, 0755 ) < 0 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to create %s for onion service, errno: %d", FILESYSTEM_PREFIX, errno );

      return true;
    }
  }

#ifdef MINITOR_CHUTNEY
  return true;
#endif

  // check if our current consensus is still fresh, no need to re-download
  fd = open( FILESYSTEM_PREFIX "consensus", O_RDONLY );

  if ( fd <= 0 )
  {
    return true;
  }

  i = 0;

  while ( valid_until_found < strlen( valid_until_str ) )
  {
    rx_length = read( fd, date_str, sizeof( char ) );

    i++;

    if ( rx_length != sizeof( char ) || i > 500 )
    {
      MINITOR_LOG( MINITOR_TAG, "Failed to find valid-until value" );

      break;
    }

    if ( date_str[0] == valid_until_str[valid_until_found] )
    {
      valid_until_found++;

      if ( valid_until_found == strlen( valid_until_str ) )
      {
        rx_length = read( fd, date_str, sizeof( date_str ) );
        date_str[19] = 0;

        if ( rx_length == sizeof( date_str ) )
        {
          time( &now );
          valid_until_time = d_parse_date_string( date_str );

          // consensus is still valid
          if (
            now < valid_until_time &&
            valid_until_time == d_get_hsdir_relay_valid_until() &&
            d_load_hsdir_relay_count() >= 0 &&
            valid_until_time == d_get_cache_relay_valid_until() &&
            d_load_cache_relay_count() >= 0 &&
            valid_until_time == d_get_fast_relay_valid_until() &&
            d_load_fast_relay_count() >= 0
          )
          {
            MINITOR_LOG( MINITOR_TAG, "Using valid consensus already downloaded" );

            err = lseek( fd, 0, SEEK_SET );

            if ( err < 0 )
            {
              MINITOR_LOG( MINITOR_TAG, "Failed to lseek " FILESYSTEM_PREFIX "consensus, errno: %d", errno );

              close( fd );

              return true;
            }

            // BEGIN mutex for the network consensus
            MINITOR_MUTEX_TAKE_BLOCKING( network_consensus_mutex );

            network_consensus.method = 0;
            network_consensus.valid_after = 0;
            network_consensus.fresh_until = 0;
            network_consensus.valid_until = 0;
            network_consensus.hsdir_interval = HSDIR_INTERVAL_DEFAULT;
            network_consensus.hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
            network_consensus.hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;

            if ( d_parse_network_consensus_from_file( fd, &network_consensus ) < 0 )
            {
              MINITOR_LOG( MINITOR_TAG, "Failed to parse network consensus from file" );

              close( fd );

              return true;
            }

            MINITOR_MUTEX_GIVE( network_consensus_mutex );
            // END mutex for the network consensus

            // reset timer here to the difference of valid_until and now
            MINITOR_TIMER_SET_MS_BLOCKING( consensus_timer, ( valid_until_time - now ) * 1000 );

            return false;
          }
        }

        break;
      }
    }
    else
    {
      valid_until_found = 0;
    }
  }

  return true;
}

int d_reset_relay_files()
{
  if (
    d_reset_staging_hsdir_relays() < 0 ||
    d_reset_staging_cache_relays() < 0 ||
    d_reset_staging_fast_relays() < 0 ||
    d_reset_waiting_relays() < 0
  )
  {
    return -1;
  }

  if ( d_reset_waiting_relays() < 0 )
  {
    return -1;
  }

  return 0;
}

int d_get_hs_time_period( time_t fresh_until, time_t valid_after, int hsdir_interval )
{
  time_t voting_interval;
  time_t srv_start_time;
  time_t tp_start_time;
  int rotation_offset;
  int time_period;

  voting_interval = fresh_until - valid_after;
  rotation_offset = SHARED_RANDOM_N_ROUNDS * voting_interval / 60;

  // SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES = 24
  srv_start_time = valid_after - ( ( ( ( valid_after / voting_interval ) ) % ( SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES ) ) * voting_interval );
  tp_start_time = ( srv_start_time / 60 - rotation_offset + hsdir_interval ) * 60;

  time_period = ( valid_after / 60 - rotation_offset ) / hsdir_interval;

  if ( valid_after < srv_start_time || valid_after >= tp_start_time )
  {
    time_period--;
  }

  return time_period;
}

// fetch the network consensus so we can correctly create circuits
int d_fetch_consensus()
{
  int ret = 0;
  OnionMessage* onion_message;

  // tell the core daemon we want to be notified
  external_want_consensus = true;

  // send a message to make the circuit
  v_send_init_circuit_fetch_external();

  // wait for the fetch response
  MINITOR_DEQUEUE_BLOCKING( external_consensus_queue, &onion_message );

  external_want_consensus = false;

  if ( onion_message == NULL )
  {
    return -1;
  }

  if ( onion_message->type != CONSENSUS_FETCHED )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to fetch the network consensus" );

    ret = -1;
  }

  external_want_consensus = false;

  free( onion_message );

  return ret;
}
