#include <stdlib.h>
#include <time.h>

#include "esp_log.h"
#include "lwip/sockets.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "../include/config.h"
#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/encoding.h"
#include "../h/models/db.h"
#include "../h/models/relay.h"
#include "../h/models/network_consensus.h"

static int d_parse_date_string( char* date_string ) {
  struct tm tmp_time;

  tmp_time.tm_year = atoi( date_string ) - 1900;
  tmp_time.tm_mon = atoi( date_string + 5 ) - 1;
  tmp_time.tm_mday = atoi( date_string + 8 );
  tmp_time.tm_hour = atoi( date_string + 11 );
  tmp_time.tm_min = atoi( date_string + 14 );
  tmp_time.tm_sec = atoi( date_string + 17 );

  return mktime( &tmp_time );
}

// TODO handle http errors
static int d_download_consensus() {
  const char* REQUEST = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n"
#ifdef MINITOR_CHUTNEY
      "Host: "MINITOR_CHUTNEY_ADDRESS_STR"\r\n"
#else
      "Host: "MINITOR_DIR_ADDR_STR"\r\n"
#endif
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  int i;
  char* rx_buffer;
  struct sockaddr_in dest_addr;
  int sock_fd;
  int fd;
  int err;
  int rx_length;
  int rx_total = 0;
  char end_header = 0;

  // buffer that holds data returned from the socket
  rx_buffer = malloc( sizeof( char ) * 6144 );

    // set the address of the directory server
#ifdef MINITOR_CHUTNEY
  dest_addr.sin_addr.s_addr = MINITOR_CHUTNEY_ADDRESS;
  dest_addr.sin_port = htons( MINITOR_CHUTNEY_PORT );
#else
  dest_addr.sin_addr.s_addr = MINITOR_DIR_ADDR;
  dest_addr.sin_port = htons( MINITOR_DIR_PORT );
#endif

  dest_addr.sin_family = AF_INET;

  // create a socket to access the consensus
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

    return -1;
  }

  // send the http request to the dir server
  err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

    return -1;
  }

  if ( ( fd = open( "/sdcard/consensus", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  while ( 1 ) {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( sock_fd, rx_buffer, 6144, 0 );

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

    rx_total += rx_length;

    i = 0;

    if ( end_header < 4 ) {
      for ( i = 0; i < rx_length; i++ ) {
        // skip over the http header, when we get two \r\n s in a row we
        // know we're at the end
        // increment end_header whenever we get part of a carrage retrun
        if ( rx_buffer[i] == '\r' || rx_buffer[i] == '\n' ) {
          end_header++;

          if ( end_header >= 4 ) {
            break;
          }
        // otherwise reset the count
        } else {
          end_header = 0;
        }
      }
    }

    if ( end_header >= 4 ) {
      if ( write( fd, rx_buffer + i, sizeof( char ) * ( rx_length - i ) ) < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/consensus, errno: %d", errno );
#endif

        return -1;
      }
    }
  }

  free( rx_buffer );

  if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  // we're done reading data from the directory server, shutdown and close the socket
  shutdown( sock_fd, 0 );
  close( sock_fd );

  return 0;
}

static int d_parse_line( int fd, char* line, int limit ) {
  int ret;
  char out_char;
  int length = 0;

  while ( 1 ) {
    ret = read( fd, &out_char, sizeof( char ) );

    if ( ret < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read consensus line, errno: %d", errno );
#endif

      return -1;
    }

    if ( ret == 0 || out_char == '\n' || length == limit ) {
      line[length] = 0;
      return length;
    }

    line[length] = out_char;
    length++;
  }
}

static int d_parse_network_consensus( int fd, NetworkConsensus* result_network_consensus ) {
  char line[512];

  while ( 1 ) {
    if ( d_parse_line( fd, line, sizeof( line ) ) < 0 ) {
      return -1;
    }

    if ( result_network_consensus->method == 0 && memcmp( line, "consensus-method ", strlen( "consensus-method " ) ) == 0 ) {
      result_network_consensus->method = atoi( line + strlen( "consensus-method " ) );
    } else if ( result_network_consensus->valid_after == 0 && memcmp( line, "valid-after ", strlen( "valid-after " ) ) == 0 ) {
      result_network_consensus->valid_after = d_parse_date_string( line + strlen( "valid-after " ) );
    } else if ( result_network_consensus->fresh_until == 0 && memcmp( line, "fresh-until ", strlen( "fresh-until " ) ) == 0 ) {
      result_network_consensus->fresh_until = d_parse_date_string( line + strlen( "fresh-until " ) );
    } else if ( result_network_consensus->valid_until == 0 && memcmp( line, "valid-until ", strlen( "valid-until " ) ) == 0 ) {
      result_network_consensus->valid_until = d_parse_date_string( line + strlen( "valid-until " ) );
    } else if ( memcmp( line, "shared-rand-current-value ", strlen( "shared-rand-current-value " ) ) == 0 ) {
      v_base_64_decode( result_network_consensus->shared_rand, line + strlen( line ) - 44, 43 );
    } else if ( memcmp( line, "shared-rand-previous-value ", strlen( "shared-rand-previous-value " ) ) == 0 ) {
      v_base_64_decode( result_network_consensus->previous_shared_rand, line + strlen( line ) - 44, 43 );
    } else if ( memcmp( line, "dir-source", strlen( "dir-source" ) ) == 0 ) {
      return 0;
    }
  }
}

static void v_parse_r_tag( OnionRelay* canidate_relay, char* line ) {
  int i;
  int space_count = 1;

  for ( i = 2; i < strlen( line ); i++ ) {
    switch ( space_count ) {
      case 2:
        v_base_64_decode( canidate_relay->identity, line + i, 27 );
        i += 27;
        break;
      case 3:
        v_base_64_decode( canidate_relay->digest, line + i, 27 );
        i += 27;
        break;
      case 6:
        canidate_relay->address = inet_addr( line + i );
        break;
      case 7:
        canidate_relay->or_port = atoi( line + i );
        break;
      case 8:
        canidate_relay->dir_port = atoi( line + i );
        break;
      default:
        break;
    }

    while ( line[i] != ' ' && i < strlen( line ) ) {
      i++;
    }

    space_count++;
  }
}

static void v_parse_s_tag( OnionRelay* canidate_relay, char* line ) {
  int i;
  int found_index = 0;
  const char* exit = "Exit";
  int exit_found = 0;
  const char* fast = "Fast";
  int fast_found = 0;
  const char* guard = "Guard";
  int guard_found = 0;
  const char* hsdir = "HSDir";
  int hsdir_found = 0;
  const char* stable = "Stable";
  int stable_found = 0;

  for ( i = 2; i < strlen( line ); i++ ) {
    if ( found_index <= 0 && i + strlen( exit ) <= strlen( line ) && memcmp( line + i, exit, strlen( exit ) ) ) {
      exit_found = 1;
      found_index = 1;
    } else if ( found_index <= 1 && i + strlen( fast ) <= strlen( line ) && memcmp( line + i, fast, strlen( fast ) ) ) {
      fast_found = 1;
      found_index = 2;
    } else if ( found_index <= 2 && i + strlen( guard ) <= strlen( line ) && memcmp( line + i, guard, strlen( guard ) ) ) {
      guard_found = 1;
      found_index = 3;
    } else if ( found_index <= 3 && i + strlen( hsdir ) <= strlen( line ) && memcmp( line + i, hsdir, strlen( hsdir ) ) ) {
      hsdir_found = 1;
      found_index = 4;
    } else if ( found_index <= 4 && i + strlen( stable ) <= strlen( line ) && memcmp( line + i, stable, strlen( stable ) ) ) {
      stable_found = 1;
      found_index = 5;
      break;
    }

    while ( line[i] != ' ' && i < strlen( line ) ) {
      i++;
    }
  }

  if ( fast_found && stable_found ) {
    canidate_relay->suitable = 1;
  }

  canidate_relay->can_exit = exit_found;
  canidate_relay->can_guard = guard_found;
  canidate_relay->is_guard = 0;
  canidate_relay->hsdir = hsdir_found;
}

static int d_parse_single_relay( int fd, OnionRelay* canidate_relay ) {
  int ret;
  int done = 0;
  char line[512];

  do {
    ret = d_parse_line( fd, line, sizeof( line ) );

    if ( ret == 0 ) {
      return 1;
    }

    if ( ret < 0 ) {
      return -1;
    }
  } while ( line[0] != 'r' || line[1] != ' ' );

  while ( !done ) {
    switch ( line[0] ) {
      case 'r':
        v_parse_r_tag( canidate_relay, line );
        break;
      case 's':
        v_parse_s_tag( canidate_relay, line );
        done = 1;
        break;
      case 'v':
        break;
      case 'w':
        break;
      case 'p':
        // TODO parse the pr tag if we need to make sure node have the same link protocol
        // and HS protocols
        break;
    }

    if ( d_parse_line( fd, line, sizeof( line ) ) < 0 ) {
      return -1;
    }
  }

  return 0;
}

static int d_parse_downloaded_consensus( NetworkConsensus** result_network_consensus ) {
  int i = 0;
  int fd;
  int ret;
  OnionRelay canidate_relay;

  if ( ( fd = open( "/sdcard/consensus", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  if ( *result_network_consensus == NULL ) {
    *result_network_consensus = malloc( sizeof( NetworkConsensus ) );
  }

  (*result_network_consensus)->method = 0;
  (*result_network_consensus)->valid_after = 0;
  (*result_network_consensus)->fresh_until = 0;
  (*result_network_consensus)->valid_until = 0;
  (*result_network_consensus)->hsdir_interval = HSDIR_INTERVAL_DEFAULT;
  (*result_network_consensus)->hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
  (*result_network_consensus)->hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;

  if ( d_parse_network_consensus( fd, *result_network_consensus ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to parse network consensus from file" );
#endif

    ret = -1;
    goto finish;
  }

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  network_consensus.method = (*result_network_consensus)->method;
  network_consensus.valid_after = (*result_network_consensus)->valid_after;
  network_consensus.fresh_until = (*result_network_consensus)->fresh_until;
  network_consensus.valid_until = (*result_network_consensus)->valid_until;

  memcpy( network_consensus.previous_shared_rand, (*result_network_consensus)->previous_shared_rand, 32 );
  memcpy( network_consensus.shared_rand, (*result_network_consensus)->shared_rand, 32 );

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus

  if ( d_reset_hsdir_relay_tree() < 0 ) {
    ret = -1;
    goto finish;
  }

  if ( d_open_database() < 0 ) {
    ret = -1;
    goto finish;
  }

  ret = 0;

  do {
    memset( &canidate_relay, 0, sizeof( canidate_relay ) );

    ret = d_parse_single_relay( fd, &canidate_relay );

    if ( ret == 0 ) {
      if ( canidate_relay.hsdir ) {
/*
        wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"node-idx", strlen( "node-idx" ) );
        wc_Sha3_256_Update( &reusable_sha3, canidate_relay.identity, ID_LENGTH );
        wc_Sha3_256_Update( &reusable_sha3, (*result_network_consensus)->previous_shared_rand, 32 );

        tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 56 );
        tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 48 );
        tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 40 );
        tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 32 );
        tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 24 );
        tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 16 );
        tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 8 );
        tmp_64_buffer[7] = (unsigned char)( (int64_t)( time_period - 1 ) );

        wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

        tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 56 );
        tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 48 );
        tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 40 );
        tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 32 );
        tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 24 );
        tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 16 );
        tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( (*result_network_consensus)->hsdir_interval ) ) >> 8 );
        tmp_64_buffer[7] = (unsigned char)( (int64_t)( (*result_network_consensus)->hsdir_interval ) );

        wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

        wc_Sha3_256_Final( &reusable_sha3, canidate_relay.previous_hash );
*/
        v_get_id_hash( canidate_relay.identity, canidate_relay.id_hash );

        if ( d_create_hsdir_relay( &canidate_relay ) < 0 ) {
          ret = -1;
          goto finish;
        }
      }

      i = ( i + 1 ) % 10;

      if ( i == 0 ) {
        if ( d_close_database() < 0 ) {
          ret = -1;
          goto finish;
        }

        if ( d_open_database() < 0 ) {
          ret = -1;
          goto finish;
        }
      }
    } else if ( ret < 0 ) {
      goto finish;
    }
  } while ( ret == 0 );

  if ( d_close_database() < 0 ) {
    ret = -1;
    goto finish;
  }

  ret = 0;

finish:
  if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  return ret;
}

// fetch the network consensus so we can correctly create circuits
int d_fetch_consensus_info() {
  int ret = 0;
  NetworkConsensus* result_network_consensus;
  time_t now = 0;

  // TODO the return value of null is ambigious, it could be null because there isn't a row or
  // it could be because the database is messed up, we need to be able to distinguish
  result_network_consensus = px_get_network_consensus();
  time( &now );

  if ( result_network_consensus == NULL || result_network_consensus->fresh_until <= now ) {
    /* ESP_LOGE( MINITOR_TAG, "now: %ld, fresh_until: %ld", now, result_network_consensus->fresh_until ); */
    /* ESP_LOGE( MINITOR_TAG, "result_network_consensus->fresh_until <= now: %d", result_network_consensus->fresh_until <= now ); */
    if ( d_download_consensus() < 0 ) {
      ret = -1;
      goto finish;
    }
  }

  if ( d_parse_downloaded_consensus( &result_network_consensus ) < 0 ) {
    ret = -1;
    goto finish;
  }

  if ( d_destroy_consensus() < 0 ) {
    ret = -1;
    goto finish;
  }

  if ( d_create_consensus( result_network_consensus ) < 0 ) {
    ret = -1;
    goto finish;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "finished setting consensus" );
#endif

finish:
  if ( result_network_consensus != NULL ) {
    free( result_network_consensus );
  }

  // return 0 for no errors
  return ret;
}

void v_get_id_hash( uint8_t* identity, uint8_t* id_hash )
{
  int time_period;
  uint8_t tmp_64_buffer[8];
  Sha3 reusable_sha3;

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  time_period = ( network_consensus.valid_after / 60 - 12 * 60 ) / network_consensus.hsdir_interval;

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"node-idx", strlen( "node-idx" ) );
  wc_Sha3_256_Update( &reusable_sha3, identity, ID_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, network_consensus.shared_rand, 32 );

  tmp_64_buffer[0] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 56 );
  tmp_64_buffer[1] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 48 );
  tmp_64_buffer[2] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 40 );
  tmp_64_buffer[3] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 32 );
  tmp_64_buffer[4] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 24 );
  tmp_64_buffer[5] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 16 );
  tmp_64_buffer[6] = (unsigned char)( ( (uint64_t)( time_period ) ) >> 8 );
  tmp_64_buffer[7] = (unsigned char)( (uint64_t)( time_period ) );

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  tmp_64_buffer[0] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 56 );
  tmp_64_buffer[1] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 48 );
  tmp_64_buffer[2] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 40 );
  tmp_64_buffer[3] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 32 );
  tmp_64_buffer[4] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 24 );
  tmp_64_buffer[5] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 16 );
  tmp_64_buffer[6] = (unsigned char)( ( (uint64_t)( network_consensus.hsdir_interval ) ) >> 8 );
  tmp_64_buffer[7] = (unsigned char)( (uint64_t)( network_consensus.hsdir_interval ) );

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  wc_Sha3_256_Final( &reusable_sha3, id_hash );

  wc_Sha3_256_Free( &reusable_sha3 );

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus
}
