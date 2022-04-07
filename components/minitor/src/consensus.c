#include <stdlib.h>
#include <time.h>

#include "esp_log.h"
#include "lwip/sockets.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "../include/config.h"
#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/encoding.h"
#include "../h/models/db.h"
#include "../h/models/relay.h"
#include "../h/models/network_consensus.h"

// TODO change back to 0 when issi ram is operating in quad mode
int hsdir_tree_occupied = 1;
NetworkConsensus* next_network_consensus;
int fetch_speed_sample = 0;
uint64_t fastest_fetch_time = 0xffffffffffffffff;
uint8_t fastest_identity[ID_LENGTH];

SemaphoreHandle_t fastest_cache_mutex;
QueueHandle_t insert_relays_queue;
QueueHandle_t fetch_relays_queue;

typedef struct FetchDescriptorState
{
  OnionRelay* relays[3];
  int num_relays;
  int sock_fd;
  int using_cache_relay;
  uint8_t cache_identity[ID_LENGTH];
  uint64_t start;
} FetchDescriptorState;

static void v_get_id_hash( uint8_t* identity, uint8_t* id_hash, int time_period, int hsdir_interval, uint8_t* srv )
{
  uint8_t tmp_64_buffer[8];
  Sha3 reusable_sha3;

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

  {
    //ESP_LOGE( MINITOR_TAG, "time_period: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x", tmp_64_buffer[0], tmp_64_buffer[1], tmp_64_buffer[2], tmp_64_buffer[3], tmp_64_buffer[4], tmp_64_buffer[5], tmp_64_buffer[6], tmp_64_buffer[7]  );
  }

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  tmp_64_buffer[0] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 56 );
  tmp_64_buffer[1] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 48 );
  tmp_64_buffer[2] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 40 );
  tmp_64_buffer[3] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 32 );
  tmp_64_buffer[4] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 24 );
  tmp_64_buffer[5] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 16 );
  tmp_64_buffer[6] = (unsigned char)( ( (uint64_t)( hsdir_interval ) ) >> 8 );
  tmp_64_buffer[7] = (unsigned char)( (uint64_t)( hsdir_interval ) );

  {
    //ESP_LOGE( MINITOR_TAG, "hsdir_interval: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x", tmp_64_buffer[0], tmp_64_buffer[1], tmp_64_buffer[2], tmp_64_buffer[3], tmp_64_buffer[4], tmp_64_buffer[5], tmp_64_buffer[6], tmp_64_buffer[7]  );
  }

  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

  wc_Sha3_256_Final( &reusable_sha3, id_hash );


  if ( identity[0] == 0xee && identity[1] == 0xef && identity[2] == 0xb7 && identity[3] == 0x52 )
  {
    {
      ESP_LOGE( MINITOR_TAG, "BEGIN NODE-IDX CHECK" );
      ESP_LOGE( MINITOR_TAG, "prefix: %s", "node-idx" );
      ESP_LOGE( MINITOR_TAG, "identity: %.2x %.2x %.2x %.2x", identity[0], identity[1], identity[2], identity[3] );
      ESP_LOGE( MINITOR_TAG, "srv: %.2x %.2x %.2x %.2x", srv[0], srv[1], srv[2], srv[3] );
      ESP_LOGE( MINITOR_TAG, "time_period: %d", time_period );
      ESP_LOGE( MINITOR_TAG, "hsdir_interval: %d", hsdir_interval );
      ESP_LOGE( MINITOR_TAG, "id_hash: %.2x %.2x %.2x %.2x", id_hash[0], id_hash[1], id_hash[2], id_hash[3] );
    }
  }

  wc_Sha3_256_Free( &reusable_sha3 );
}

static void v_handle_crypto_and_insert( void* pv_parameters )
{
  int process_count = 0;
  int shutdown_count = 0;
  OnionRelay* onion_relay;
  NetworkConsensus* working_consensus = (NetworkConsensus*)pv_parameters;

  // MUTEX TAKE
  xSemaphoreTake( crypto_insert_finish, portMAX_DELAY );

  while ( xQueueReceive( insert_relays_queue, &onion_relay, portMAX_DELAY ) )
  {

    if ( onion_relay == NULL )
    {
      shutdown_count++;

      if ( shutdown_count >= 2 )
      {
        ESP_LOGE( MINITOR_TAG, "%d total relays processed", process_count );
        xSemaphoreGive( crypto_insert_finish );
        // MUTEX GIVE
        vTaskDelete( NULL );
      }

      continue;
    }
    else
    {
#ifdef DEBUG_MINITOR
#ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "%d relays processed so far", process_count );
#else
      if ( process_count % 50 == 0 )
      {
        ESP_LOGE( MINITOR_TAG, "%d relays processed so far", process_count );
      }
#endif

      process_count++;
#endif
    }

    v_get_id_hash( onion_relay->master_key, onion_relay->id_hash_previous, working_consensus->time_period, working_consensus->hsdir_interval, working_consensus->previous_shared_rand );
    v_get_id_hash( onion_relay->master_key, onion_relay->id_hash, working_consensus->time_period + 1, working_consensus->hsdir_interval, working_consensus->shared_rand );

#ifdef MINITOR_CHUTNEY
    if ( d_get_hsdir_count() <= 10 )
#else
    if ( d_get_hsdir_count() <= 50 && onion_relay->suitable == 1 )
#endif
    {
      if ( d_create_hsdir_relay_in_file( onion_relay ) < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Failed to insert into file, quiting without giving" );
        vTaskDelete( NULL );
      }
    }

    if ( d_add_hsdir_relay_to_list( onion_relay ) < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to add to list" );
      vTaskDelete( NULL );
    }

    free( onion_relay );
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

static int d_get_suitable_dir_addr( struct sockaddr_in* dest_addr, char* ip_addr_str, uint8_t* out_identity )
{
  int i;
  int ret = 0;
  char* authority_string;
  OnionRelay* cache_relay;

  if ( d_get_cache_relay_count() == 0 )
  {
    i = esp_random() % tor_authorities_count;

    authority_string = tor_authorities[i];

    for ( i = 0; i < strlen( authority_string ); i++ )
    {
      if ( authority_string[i] == '=' )
      {
        //ESP_LOGE( MINITOR_TAG, "Got port: %d", atoi( authority_string + i + 1 ) );
        dest_addr->sin_port = htons( atoi( authority_string + i + 1 ) );
        break;
      }
      else if ( authority_string[i] == ' ' )
      {
        memcpy( ip_addr_str, authority_string, i );
        ip_addr_str[i] = 0;;
        //ESP_LOGE( MINITOR_TAG, "Got ip: %s", ip_addr_str );
      }
    }
  }
  else
  {
    // MUTEX TAKE
    xSemaphoreTake( fastest_cache_mutex, portMAX_DELAY );

    if ( fetch_speed_sample >= 30 )
    {
      cache_relay = px_get_hsdir_relay_by_identity( fastest_identity );
      ret = 2;
    }
    else
    {
      cache_relay = px_get_dir_cache_relay();
      ret = 1;
    }

    xSemaphoreGive( fastest_cache_mutex );
    // MUTEX GIVE

    if ( cache_relay == NULL )
    {
      return -1;
    }

    //ESP_LOGE( MINITOR_TAG, "\n\nUSING CACHE %d FOR DIR", cache_relay->dir_port );

    if ( out_identity != NULL )
    {
      memcpy( out_identity, cache_relay->identity, ID_LENGTH );
    }

    v_ipv4_to_string( cache_relay->address, ip_addr_str );
    dest_addr->sin_port = htons( cache_relay->dir_port );

    free( cache_relay );
  }

  dest_addr->sin_addr.s_addr = inet_addr( ip_addr_str );
  dest_addr->sin_family = AF_INET;

  return ret;
}

// split up the fetch task, start should make the request and then peace out,
// let d_finish_descriptor_fetch actually recv the descriptors
static int d_start_descriptor_fetch( FetchDescriptorState* fetch_state )
{
  int ret = 0;
  const char* REQUEST_FMT = "GET /tor/server/d/%s%s%s HTTP/1.0\r\n"
      "Host: %s\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[230];
  char ip_addr_str[16];
  struct sockaddr_in dest_addr;

  int i;
  int j;
  int err;

  fetch_state->using_cache_relay = d_get_suitable_dir_addr( &dest_addr, ip_addr_str, fetch_state->cache_identity );

  if ( fetch_state->using_cache_relay < 0 )
  {
    return -1;
  }

  switch ( fetch_state->num_relays )
  {
    case 1:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "", "", ip_addr_str );
      break;
    case 2:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", "", ip_addr_str );
      break;
    case 3:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", ip_addr_str );
      break;
  }

  for ( i = 0; i < fetch_state->num_relays; i++ )
  {
    for ( j = 0; j < 20; j++ )
    {
      if ( fetch_state->relays[i]->digest[j] >> 4 < 10 )
      {
        REQUEST[18 + 2 * j + i * 41] = 48 + ( fetch_state->relays[i]->digest[j] >> 4 );
      }
      else
      {
        REQUEST[18 + 2 * j + i * 41] = 65 + ( ( fetch_state->relays[i]->digest[j] >> 4 ) - 10 );
      }

      if ( ( fetch_state->relays[i]->digest[j] & 0x0f ) < 10  )
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 48 + ( fetch_state->relays[i]->digest[j] & 0x0f );
      }
      else
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 65 + ( ( fetch_state->relays[i]->digest[j] & 0x0f ) - 10 );
      }
    }
  }

  //ESP_LOGE( MINITOR_TAG, "%s", REQUEST );

  fetch_state->start = esp_timer_get_time();

  // create a socket to access the descriptor
  fetch_state->sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( fetch_state->sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server" );
#endif

    return -1;
  }

  // connect the socket to the dir server address
  err = connect( fetch_state->sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( err != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

    goto fail;
  }

  // send the http request to the dir server
  err = send( fetch_state->sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

    goto fail;
  }

  return 0;

fail:
  shutdown( fetch_state->sock_fd, 0 );
  close( fetch_state->sock_fd );

  return -1;
}

static int d_finish_descriptor_fetch( FetchDescriptorState* fetch_state )
{
  int i;
  int j;
  int ret = 0;
  int rx_length = 0;
  char rx_buffer[512];
  int end_header = 0;
  int relays_set = 0;
  int matched_relay = 0;
  uint64_t end;

  const char* master_key = "\nmaster-key-ed25519 ";
  int master_key_found = 0;
  char master_key_64[43] = { 0 };
  int master_key_64_length = 0;

  const char* ntor_onion_key = "\nntor-onion-key ";
  int ntor_onion_key_found = 0;
  char ntor_onion_key_64[43] = { 0 };
  int ntor_onion_key_64_length = 0;

  const char* signing_key = "\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n";
  int signing_key_found = 0;
  char signing_key_64[187] = { 0 };
  int signing_key_64_length = 0;
  uint8_t der[141];
  uint8_t identity_digest[ID_LENGTH];
  Sha tmp_sha;

  wc_InitSha( &tmp_sha );

  // keep reading forever, we will break inside when the transfer is over
  while ( relays_set < fetch_state->num_relays )
  {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( fetch_state->sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

      ret = -1;
      goto finish;
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    }
    else if ( rx_length == 0 )
    {
      break;
    }

    // iterate over each byte we got back from the socket recv
    // NOTE that we can't rely on all the data being there, we
    // have to treat each byte as though we only have that byte
    for ( i = 0; i < rx_length && relays_set < fetch_state->num_relays; i++ )
    {
      // skip over the http header, when we get two \r\n s in a row we
      // know we're at the end
      if ( end_header < 4 )
      {
        // increment end_header whenever we get part of a carrage retrun
        if ( rx_buffer[i] == '\r' || rx_buffer[i] == '\n' )
        {
          end_header++;
        // otherwise reset the count
        }
        else
        {
          end_header = 0;
        }
      // if we have 4 end_header we're onto the actual data
      }
      else
      {
        if ( ntor_onion_key_found != -1 )
        {
          if ( ntor_onion_key_found == strlen( ntor_onion_key ) )
          {
            ntor_onion_key_64[ntor_onion_key_64_length] = rx_buffer[i];
            ntor_onion_key_64_length++;

            if ( ntor_onion_key_64_length == 43 )
            {
              ntor_onion_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == ntor_onion_key[ntor_onion_key_found] )
          {
            ntor_onion_key_found++;
          }
          else
          {
            ntor_onion_key_found = 0;
          }
        }

        if ( master_key_found != -1 )
        {
          if ( master_key_found == strlen( master_key ) )
          {
            master_key_64[master_key_64_length] = rx_buffer[i];
            master_key_64_length++;

            if ( master_key_64_length == 43 )
            {
              master_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == master_key[master_key_found] )
          {
            master_key_found++;
          }
          else
          {
            master_key_found = 0;
          }
        }

        if ( signing_key_found != -1 )
        {
          if ( signing_key_found == strlen( signing_key ) )
          {
            if ( rx_buffer[i] != '\n' )
            {
              signing_key_64[signing_key_64_length] = rx_buffer[i];
              signing_key_64_length++;
            }

            if ( signing_key_64_length == 187 )
            {
              v_base_64_decode( der, signing_key_64, 187 );
              wc_ShaUpdate( &tmp_sha, der, 140 );
              wc_ShaFinal( &tmp_sha, identity_digest );

              for ( j = 0; j < fetch_state->num_relays; j++ )
              {
                if ( memcmp( identity_digest, fetch_state->relays[j]->identity, ID_LENGTH ) == 0 )
                {
                  matched_relay = j;
                  break;
                }
              }
              signing_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == signing_key[signing_key_found] )
          {
            signing_key_found++;
          }
          else
          {
            signing_key_found = 0;
          }
        }

        if ( master_key_found == -1 && ntor_onion_key_found == -1 && signing_key_found == -1 )
        {
          v_base_64_decode( fetch_state->relays[matched_relay]->ntor_onion_key, ntor_onion_key_64, 43 );
          v_base_64_decode( fetch_state->relays[matched_relay]->master_key, master_key_64, 43 );

          relays_set++;
          master_key_64_length = 0;
          master_key_found = 0;
          ntor_onion_key_64_length = 0;
          ntor_onion_key_found = 0;
          signing_key_64_length = 0;
          signing_key_found = 0;
        }
      }
    }
  }

finish:
  wc_ShaFree( &tmp_sha );

  shutdown( fetch_state->sock_fd, 0 );
  close( fetch_state->sock_fd );

  end = esp_timer_get_time();

  // MUTEX TAKE
  xSemaphoreTake( fastest_cache_mutex, portMAX_DELAY );

  if ( ret < 0 && fetch_state->using_cache_relay == 2 )
  {
    fetch_speed_sample = 0;
    fastest_fetch_time = 0xffffffffffffffff;
  }
  else if ( fetch_state->using_cache_relay == 1 )
  {
    fetch_speed_sample++;

    if ( end - fetch_state->start < fastest_fetch_time )
    {
      fastest_fetch_time = end - fetch_state->start;
      memcpy( fastest_identity, fetch_state->cache_identity, ID_LENGTH );
    }
  }

  xSemaphoreGive( fastest_cache_mutex );
  // MUTEX GIVE

  return ret;
}

static void v_handle_relay_fetch( void* pv_parameters )
{
  int i;
  int j;
  int succ = pdFALSE;
  OnionRelay* onion_relay;
  NetworkConsensus* working_consensus = (NetworkConsensus*)pv_parameters;
  FetchDescriptorState fetch_states[2];
  struct pollfd fetch_poll[2];
  int running_fetches = 0;
  int final_relay_hit = 0;
  int waiting_relay = 0;
  int relays_fetched = 0;

  memset( fetch_states, 0, sizeof( fetch_states ) );

  for ( i = 0; i < 2; i++ )
  {
    fetch_poll[i].fd = -1;
  }

  while ( final_relay_hit == 0 || running_fetches > 0 )
  {
    // wait half a second at most before checking our polls
    if ( final_relay_hit == 0 && waiting_relay == 0 )
    {
      succ = xQueueReceive( fetch_relays_queue, &onion_relay, 500 / portTICK_PERIOD_MS );
    }

    if ( succ == pdTRUE && final_relay_hit == 0 )
    {
      if ( onion_relay == NULL )
      {
        final_relay_hit = 1;

#ifdef MINITOR_CHUTNEY
        ESP_LOGE( MINITOR_TAG, "Got final relay to fetch" );
#endif

        for ( i = 0; i < 2; i++ )
        {
          if ( fetch_states[i].num_relays > 0 && fetch_states[i].num_relays < 3 )
          {
            while ( d_start_descriptor_fetch( &fetch_states[i] ) < 0 )
            {
              ESP_LOGE( MINITOR_TAG, "Failed to start fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );
            }

            fetch_poll[i].fd = fetch_states[i].sock_fd;
            fetch_poll[i].events = POLLIN;
            running_fetches++;
          }
        }
      }
      else
      {
        // find a fetch to put our new relay in
        for ( i = 0; i < 2; i++ )
        {
          if ( fetch_states[i].num_relays < 3 )
          {
            fetch_states[i].relays[fetch_states[i].num_relays] = onion_relay;
            fetch_states[i].num_relays++;

            if ( fetch_states[i].num_relays == 3 )
            {
              while ( d_start_descriptor_fetch( &fetch_states[i] ) < 0 )
              {
                ESP_LOGE( MINITOR_TAG, "Failed to start fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );
              }

              fetch_poll[i].fd = fetch_states[i].sock_fd;
              fetch_poll[i].events = POLLIN;
              running_fetches++;
            }

            waiting_relay = 0;

            break;
          }
        }

        if ( i >= 2 )
        {
          waiting_relay = 1;
        }
      }
    }

    if ( running_fetches > 0 )
    {
      if ( final_relay_hit == 1 )
      {
        succ = poll( fetch_poll, 2, -1 );
      }
      else
      {
        succ = poll( fetch_poll, 2, 0 );
      }

      if ( succ > 0 )
      {
        for ( i = 0; i < 2; i++ )
        {
          if ( ( fetch_poll[i].revents & POLLIN ) == POLLIN )
          {
            // we're going to assume that once a socket is ready to read, we can read the entire thing
            if ( d_finish_descriptor_fetch( &fetch_states[i] ) < 0 )
            {
              ESP_LOGE( MINITOR_TAG, "Failed to finish fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );

              while ( d_start_descriptor_fetch( &fetch_states[i] ) < 0 )
              {
                ESP_LOGE( MINITOR_TAG, "Failed to start fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );
              }

              fetch_poll[i].fd = fetch_states[i].sock_fd;
              fetch_poll[i].events = POLLIN;
            }
            else
            {
              // send the fetched relays off to the insert task
              for ( j = 0; j < fetch_states[i].num_relays; j++ )
              {
                xQueueSendToBack( insert_relays_queue, (void*)(&fetch_states[i].relays[j]), portMAX_DELAY );
                relays_fetched++;
              }

              fetch_poll[i].fd = -1;
              memset( &fetch_states[i], 0, sizeof( FetchDescriptorState ) );
              running_fetches--;
            }
          }
        }
      }
    }
  }

  // send null, the insert task receives 2 before shutting down
  onion_relay = NULL;
  xQueueSendToBack( insert_relays_queue, (void*)(&onion_relay), portMAX_DELAY );

  ESP_LOGE( MINITOR_TAG, "This task fetched %d relays", relays_fetched );
  vTaskDelete( NULL );
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

  return mktime( &tmp_time );
}

/*
static int d_fetch_descriptor_info( OnionRelay* relays, int num_relays )
{
  const char* REQUEST_FMT = "GET /tor/server/d/%s%s%s HTTP/1.0\r\n"
      "Host: %s\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[230];
  char ip_addr_str[16];

  const char* master_key = "\nmaster-key-ed25519 ";
  int master_key_found = 0;
  char master_key_64[43] = { 0 };
  int master_key_64_length = 0;

  const char* ntor_onion_key = "\nntor-onion-key ";
  int ntor_onion_key_found = 0;
  char ntor_onion_key_64[43] = { 0 };
  int ntor_onion_key_64_length = 0;

  const char* signing_key = "\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n";
  int signing_key_found = 0;
  char signing_key_64[187] = { 0 };
  int signing_key_64_length = 0;
  uint8_t der[141];
  uint8_t identity_digest[ID_LENGTH];

  Sha tmp_sha;

  int ret = 0;
  int i;
  int j;
  int relays_set;
  int matched_relay;
  int retries = 0;
  int rx_length;
  int sock_fd;
  int err;
  char end_header = 0;
  // buffer thath holds data returned from the socket
  char rx_buffer[512];
  struct sockaddr_in dest_addr;
  uint64_t start;
  uint64_t end;
  int using_cache_relay;

  using_cache_relay = d_get_suitable_dir_relay( &dest_addr, ip_addr_str, cache_identity );

  if ( using_cache_relay < 0 )
  {
    return -1;
  }

  switch ( num_relays )
  {
    case 1:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "", "", ip_addr_str );
      break;
    case 2:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", "", ip_addr_str );
      break;
    case 3:
      sprintf( REQUEST, REQUEST_FMT, "dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", "+dddddddddddddddddddddddddddddddddddddddd", ip_addr_str );
      break;
  }

  start = esp_timer_get_time();

  // create a socket to access the descriptor
  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server" );
#endif

    return -1;
  }

  wc_InitSha( &tmp_sha );

  // connect the socket to the dir server address
  err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( err != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    ret = -1;
    goto finish;
  }

  for ( i = 0; i < num_relays; i++ )
  {
    for ( j = 0; j < 20; j++ )
    {
      if ( relays[i].digest[j] >> 4 < 10 )
      {
        REQUEST[18 + 2 * j + i * 41] = 48 + ( relays[i].digest[j] >> 4 );
      }
      else
      {
        REQUEST[18 + 2 * j + i * 41] = 65 + ( ( relays[i].digest[j] >> 4 ) - 10 );
      }

      if ( ( relays[i].digest[j] & 0x0f ) < 10  )
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 48 + ( relays[i].digest[j] & 0x0f );
      }
      else
      {
        REQUEST[18 + 2 * j + 1 + i * 41] = 65 + ( ( relays[i].digest[j] & 0x0f ) - 10 );
      }
    }
  }

  //ESP_LOGE( MINITOR_TAG, "%s", REQUEST );

  // send the http request to the dir server
  err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

    ret = -1;
    goto finish;
  }

  relays_set = 0;

  // keep reading forever, we will break inside when the transfer is over
  while ( relays_set < num_relays )
  {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

      ret = -1;
      goto finish;
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    }
    else if ( rx_length == 0 )
    {
      break;
    }

    // iterate over each byte we got back from the socket recv
    // NOTE that we can't rely on all the data being there, we
    // have to treat each byte as though we only have that byte
    for ( i = 0; i < rx_length && relays_set < num_relays; i++ )
    {
      // skip over the http header, when we get two \r\n s in a row we
      // know we're at the end
      if ( end_header < 4 )
      {
        // increment end_header whenever we get part of a carrage retrun
        if ( rx_buffer[i] == '\r' || rx_buffer[i] == '\n' )
        {
          end_header++;
        // otherwise reset the count
        }
        else
        {
          end_header = 0;
        }
      // if we have 4 end_header we're onto the actual data
      }
      else
      {
        if ( ntor_onion_key_found != -1 )
        {
          if ( ntor_onion_key_found == strlen( ntor_onion_key ) )
          {
            ntor_onion_key_64[ntor_onion_key_64_length] = rx_buffer[i];
            ntor_onion_key_64_length++;

            if ( ntor_onion_key_64_length == 43 )
            {
              //v_base_64_decode( relays[relay_order[relay_index]].ntor_onion_key, ntor_onion_key_64, 43 );
              ntor_onion_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == ntor_onion_key[ntor_onion_key_found] )
          {
            ntor_onion_key_found++;
          }
          else
          {
            ntor_onion_key_found = 0;
          }
        }

        if ( master_key_found != -1 )
        {
          if ( master_key_found == strlen( master_key ) )
          {
            master_key_64[master_key_64_length] = rx_buffer[i];
            master_key_64_length++;

            if ( master_key_64_length == 43 )
            {
              //v_base_64_decode( relays[relay_order[relay_index]].master_key, master_key_64, 43 );
              master_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == master_key[master_key_found] )
          {
            master_key_found++;
          }
          else
          {
            master_key_found = 0;
          }
        }

        if ( signing_key_found != -1 )
        {
          if ( signing_key_found == strlen( signing_key ) )
          {
            if ( rx_buffer[i] != '\n' )
            {
              signing_key_64[signing_key_64_length] = rx_buffer[i];
              signing_key_64_length++;
            }

            if ( signing_key_64_length == 187 )
            {
              v_base_64_decode( der, signing_key_64, 187 );
              wc_ShaUpdate( &tmp_sha, der, 140 );
              wc_ShaFinal( &tmp_sha, identity_digest );

              for ( j = 0; j < num_relays; j++ )
              {
                if ( memcmp( identity_digest, relays[j].identity, ID_LENGTH ) == 0 )
                {
                  matched_relay = j;
                  //ESP_LOGE( MINITOR_TAG, "matched relay: %d", matched_relay );
                  break;
                }
              }
              signing_key_found = -1;
            }
          }
          else if ( rx_buffer[i] == signing_key[signing_key_found] )
          {
            signing_key_found++;
          }
          else
          {
            signing_key_found = 0;
          }
        }

        if ( master_key_found == -1 && ntor_onion_key_found == -1 && signing_key_found == -1 )
        {
          v_base_64_decode( relays[matched_relay].ntor_onion_key, ntor_onion_key_64, 43 );
          v_base_64_decode( relays[matched_relay].master_key, master_key_64, 43 );

          relays_set++;
          master_key_64_length = 0;
          master_key_found = 0;
          ntor_onion_key_64_length = 0;
          ntor_onion_key_found = 0;
          signing_key_64_length = 0;
          signing_key_found = 0;
        }
      }
    }
  }

finish:
  wc_ShaFree( &tmp_sha );

  shutdown( sock_fd, 0 );
  close( sock_fd );

  end = esp_timer_get_time();

  if ( ret < 0 )
  {
    if ( using_fastest == 1 )
    {
      fetch_speed_sample = 0;
      fastest_fetch_time = 0xffffffffffffffff;
    }
  }
  else if ( using_cache_relay == 1 )
  {
    if ( using_fastest == 0 )
    {
      fetch_speed_sample++;
    }

    if ( end - start < fastest_fetch_time )
    {
      fastest_fetch_time = end - start;
      memcpy( fastest_identity, cache_identity, ID_LENGTH );
    }
  }

  return ret;
}
*/

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
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read consensus line, errno: %d", errno );
#endif

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
      v_base_64_decode( result_network_consensus->shared_rand, line + strlen( line ) - 44, 43 );
    }
    else if ( memcmp( line, "shared-rand-previous-value ", strlen( "shared-rand-previous-value " ) ) == 0 )
    {
      v_base_64_decode( result_network_consensus->previous_shared_rand, line + strlen( line ) - 44, 43 );
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
    v_base_64_decode( consensus->shared_rand, line + strlen( line ) - 44, 43 );
  }
  else if ( memcmp( line, "shared-rand-previous-value ", strlen( "shared-rand-previous-value " ) ) == 0 )
  {
    v_base_64_decode( consensus->previous_shared_rand, line + strlen( line ) - 44, 43 );
  }
  else if ( memcmp( line, "dir-source", strlen( "dir-source" ) ) == 0 )
  {
    return 1;
  }

  return 0;
}

static void v_parse_r_tag( OnionRelay* canidate_relay, char* line )
{
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

static void v_parse_s_tag( OnionRelay* canidate_relay, char* line )
{
  int i;
  int j;
  const char* tags[] = {
    "Exit",
    "Fast",
    "Guard",
    "HSDir",
    "Stable",
  };
  int found_vals[5] = { 0, 0, 0, 0, 0 };

  for ( i = 2; i < strlen( line ); i++ )
  {
    for ( j = 0; j < 5; j++ )
    {
      if ( found_vals[j] == 0 && strlen( tags[j] ) + i <= strlen( line ) && memcmp( line + i, tags[j], strlen( tags[j] ) ) == 0 )
      {
        found_vals[j] = 1;
      }
    }

    while ( line[i] != ' ' && i < strlen( line ) )
    {
      i++;
    }
  }

  if ( found_vals[1] && found_vals[4] ) {
    canidate_relay->suitable = 1;
  }

  canidate_relay->can_exit = found_vals[0];
  canidate_relay->can_guard = found_vals[2];
  canidate_relay->is_guard = 0;
  canidate_relay->hsdir = found_vals[3];
}

static void v_parse_pr_tag( OnionRelay* canidate_relay, char* line )
{
  int i;
  int found_index = 0;
  const char* dir_cache = "DirCache";
  int dir_cache_found = 0;

  for ( i = 3; i < strlen( line ); i++ )
  {
    if ( found_index <= 0 && i + strlen( dir_cache ) <= strlen( line ) && memcmp( line + i, dir_cache, strlen( dir_cache ) ) )
    {
      dir_cache_found = 1;
      found_index = 1;
      break;
    }

    while ( line[i] != ' ' && i < strlen( line ) )
    {
      i++;
    }
  }

  canidate_relay->dir_cache = dir_cache_found;
}

static int d_parse_line_to_relay( OnionRelay* relay, char* line )
{
  if ( line[0] == 'r' && line[1] == ' ' )
  {
    v_parse_r_tag( relay, line );
  }
  else if ( line[0] == 's' && line[1] == ' ' )
  {
    v_parse_s_tag( relay, line );
  }
  else if ( line[0] == 'p' && line[1] == 'r' && line[2] == ' ' )
  {
    v_parse_pr_tag( relay, line );
    return 1;
  }

  return 0;
}

static int d_download_consensus()
{
  int ret = 0;
  const char* REQUEST_FMT = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n"
      "Host: %s\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[120];
  char ip_addr_str[16];
  char date_str[20];
  char line[200];
  int line_length = 0;
  char* authority_string;
  int i;
  char* rx_buffer;
  struct sockaddr_in dest_addr;
  int sock_fd;
  int fd;
  int err;
  int rx_length;
  int rx_total = 0;
  char end_header = 0;
  const char* valid_until_str = "valid-until ";
  int valid_until_found = 0;
  time_t now;
  time_t valid_until_time;
  OnionRelay parse_relay;
  OnionRelay* tmp_relay;
  int finished_consensus = 0;
  NetworkConsensus* consensus;
  int found_hsdir = 0;

#ifndef MINITOR_CHUTNEY
  // check if our current consensus is still fresh, no need to re-download
  fd = open( "/sdcard/consensus", O_RDONLY );

  if ( fd >= 0 )
  {
    i = 0;

    while ( valid_until_found < strlen( valid_until_str ) )
    {
      rx_length = read( fd, date_str, sizeof( char ) );

      i++;

      if ( rx_length != sizeof( char ) || i > 500 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to find valid-until value" );
#endif
        break;
      }

      if ( date_str[0] == valid_until_str[valid_until_found] )
      {
        valid_until_found++;

        if ( valid_until_found == strlen( valid_until_str ) )
        {
          rx_length = read( fd, date_str, sizeof( date_str ) );
          date_str[19] = 0;
          ESP_LOGE( MINITOR_TAG, "date_str: %s", date_str );

          if ( rx_length == sizeof( date_str ) )
          {
            time( &now );
            valid_until_time = d_parse_date_string( date_str );

            // consensus is still valid
            if ( now < valid_until_time && valid_until_time == d_get_hsdir_list_valid_until() && d_load_hsdir_relays_from_file() == 0 )
            {
              ESP_LOGE( MINITOR_TAG, "Using valid consensus already downloaded" );

              err = lseek( fd, 0, SEEK_SET );

              if ( err < 0 )
              {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to lseek /sdcard/consensus, errno: %d", errno );
#endif

                close( fd );

                return -1;
              }

              // BEGIN mutex for the network consensus
              xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

              network_consensus.method = 0;
              network_consensus.valid_after = 0;
              network_consensus.fresh_until = 0;
              network_consensus.valid_until = 0;

#ifdef MINITOR_CHUTNEY
              network_consensus.hsdir_interval = 8;
#else
              network_consensus.hsdir_interval = HSDIR_INTERVAL_DEFAULT;
#endif

              network_consensus.hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
              network_consensus.hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;

              if ( d_parse_network_consensus_from_file( fd, &network_consensus ) )
              {
#ifdef DEBUG_MINITOR
                ESP_LOGE( MINITOR_TAG, "Failed to parse network consensus from file" );
#endif

                close( fd );

                return -1;
              }

              xSemaphoreGive( network_consensus_mutex );
              // END mutex for the network consensus

              return 0;
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
  }

  close( fd );
#endif

  if ( d_reset_hsdir_relay_tree_file() < 0 )
  {
    return -1;
  }

  if ( d_reset_hsdir_list() < 0 )
  {
    return -1;
  }

  if ( d_get_suitable_dir_addr( &dest_addr, ip_addr_str, NULL ) < 0 )
  {
    return -1;
  }

  sprintf( REQUEST, REQUEST_FMT, ip_addr_str );

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

  if ( err != 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

    close( sock_fd );

    return -1;
  }

  // send the http request to the dir server
  err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    return -1;
  }

  if ( ( fd = open( "/sdcard/consensus", O_CREAT | O_TRUNC ) ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/consensus, errno: %d", errno );
#endif

    shutdown( sock_fd, 0 );
    close( sock_fd );

    return -1;
  }

  close( fd );

  memset( &parse_relay, 0, sizeof( OnionRelay ) );
  consensus = malloc( sizeof( NetworkConsensus ) );
  rx_buffer = malloc( sizeof( char ) * 4092 );

  consensus->method = 0;
  consensus->valid_after = 0;
  consensus->fresh_until = 0;
  consensus->valid_until = 0;

#ifdef MINITOR_CHUTNEY
  consensus->hsdir_interval = 8;
#else
  consensus->hsdir_interval = HSDIR_INTERVAL_DEFAULT;
#endif

  consensus->hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
  consensus->hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;

  while ( 1 )
  {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( sock_fd, rx_buffer, 4092, 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

      ret = -1;
      goto finish;
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    } else if ( rx_length == 0 ) {
      break;
    }

    i = 0;

    if ( end_header < 4 )
    {
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

    if ( end_header >= 4 )
    {
      // first write chunck to consensus to file
      if ( ( fd = open( "/sdcard/consensus", O_WRONLY | O_APPEND ) ) < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/consensus, errno: %d", errno );
#endif

        ret = -1;
        goto finish;
      }

      if ( write( fd, rx_buffer + i, sizeof( char ) * ( rx_length - i ) ) < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/consensus, errno: %d", errno );
#endif

        ret = -1;
        goto finish;
      }

      close( fd );

      // then parse out the relays line by line and send them off for processing
      // i is already set to be after the header or 0 if the header was passed
      for ( ; i < rx_length; i++ )
      {
        if ( rx_buffer[i] != '\n' )
        {
          line[line_length] = rx_buffer[i];
          line_length++;

          // wrap around, we actually don't care about lines that are too long
          if ( line_length >= sizeof( line ) )
          {
            line_length = 0;
          }
        }
        else
        {
          // NULL terminator
          line[line_length] = 0;

          if ( finished_consensus == 0 && d_parse_line_to_consensus( consensus, line ) == 1 )
          {
            finished_consensus = 1;

            consensus->time_period = d_get_hs_time_period( consensus->fresh_until, consensus->valid_after, consensus->hsdir_interval );

            // sizeof pointer, not the actual struct
            insert_relays_queue = xQueueCreate( 9, sizeof( OnionRelay* ) );
            fetch_relays_queue = xQueueCreate( 9, sizeof( OnionRelay* ) );

            fastest_cache_mutex = xSemaphoreCreateMutex();

            // create two v_handle_relay_fetch to increase throughput
            xTaskCreatePinnedToCore(
              v_handle_relay_fetch,
              "H_RELAY_FETCH",
              3072,
              (void*)(consensus),
              7,
              NULL,
              tskNO_AFFINITY
            );

            xTaskCreatePinnedToCore(
              v_handle_relay_fetch,
              "H_RELAY_FETCH",
              3072,
              (void*)(consensus),
              7,
              NULL,
              tskNO_AFFINITY
            );

            xTaskCreatePinnedToCore(
              v_handle_crypto_and_insert,
              "H_CRYPTO_INSERT",
              3072,
              (void*)(consensus),
              8,
              NULL,
              tskNO_AFFINITY
            );
          }
          // 1 means the relay is ready to have its descriptors fetched
          else if ( finished_consensus == 1 && d_parse_line_to_relay( &parse_relay, line ) == 1 )
          {
            if ( parse_relay.hsdir == 1 )
            {
              found_hsdir++;
              tmp_relay = malloc( sizeof( OnionRelay ) );
              memcpy( tmp_relay, &parse_relay, sizeof( OnionRelay ) );
              xQueueSendToBack( fetch_relays_queue, (void*)(&tmp_relay), portMAX_DELAY );
            }

            memset( &parse_relay, 0, sizeof( OnionRelay ) );
          }

          line_length = 0;
        }
      }
    }

    rx_total += rx_length;
  }

  ESP_LOGE( MINITOR_TAG, "Found %d hsdir relays in the consensus", found_hsdir );

  // send two nulls, each fetch task will forward it to the insert task which
  // will wait for 2 before quitting
  tmp_relay = NULL;
  xQueueSendToBack( fetch_relays_queue, (void*)(&tmp_relay), portMAX_DELAY );
  xQueueSendToBack( fetch_relays_queue, (void*)(&tmp_relay), portMAX_DELAY );

  // take the semaphore so we know the crypto and insert task finished
  ret = xSemaphoreTake( crypto_insert_finish, 1000 * 60 / portTICK_PERIOD_MS );

  if ( ret != pdTRUE )
  {
    ret = -1;
    goto finish;
  }

  xSemaphoreGive( crypto_insert_finish );

  if ( d_finalize_hsdir_relays_file() < 0 || d_set_hsdir_list_valid_until( consensus->valid_until ) < 0 )
  {
    ret = -1;
    goto finish;
  }

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  network_consensus.method = consensus->method;
  network_consensus.valid_after = consensus->valid_after;
  network_consensus.fresh_until = consensus->fresh_until;
  network_consensus.valid_until = consensus->valid_until;

  memcpy( network_consensus.previous_shared_rand, consensus->previous_shared_rand, 32 );
  memcpy( network_consensus.shared_rand, consensus->shared_rand, 32 );

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus

finish:
  if ( finished_consensus == 1 )
  {
    vQueueDelete( fetch_relays_queue );
    vQueueDelete( insert_relays_queue );
    vSemaphoreDelete( fastest_cache_mutex );
  }

  free( rx_buffer );
  free( consensus );

  // we're done reading data from the directory server, shutdown and close the socket
  shutdown( sock_fd, 0 );
  close( sock_fd );

  return ret;
}

static int d_parse_single_relay( int fd, OnionRelay* canidate_relay ) {
  int ret;
  int done = 0;
  char line[512];

  do 
  {
    ret = d_parse_line( fd, line, sizeof( line ) );

    if ( ret == 0 )
    {
      return 1;
    }

    if ( ret < 0 )
    {
      return -1;
    }
  } while ( line[0] != 'r' || line[1] != ' ' );

  while ( !done )
  {
    switch ( line[0] )
    {
      case 'r':
        v_parse_r_tag( canidate_relay, line );
        break;
      case 's':
        v_parse_s_tag( canidate_relay, line );
        break;
      case 'v':
        break;
      case 'w':
        break;
      case 'p':
        if ( line[1] == 'r' )
        {
          v_parse_pr_tag( canidate_relay, line );
          done = 1;
        }
        break;
    }

    if ( d_parse_line( fd, line, sizeof( line ) ) < 0 )
    {
      return -1;
    }
  }

  return 0;
}

/*
static int d_parse_downloaded_consensus( NetworkConsensus** result_network_consensus )
{
  time_t now;
  time_t tp_start_time;
  int valid_delay;
  int i = 0;
  int j;
  int fd;
  int ret = 0;
  int voting_interval;
  FetchDescriptorState fetch_states[3];
  OnionRelay* tmp_relay;
  struct pollfd fetch_poll[3];
  int final_relay_hit = 0;
  int parse_succ;
  int poll_succ;
  int running_fetches = 0;
  int total_parsed = 0;

  memset( fetch_states, 0, sizeof( fetch_states ) );

  for ( i = 0; i < 3; i++ )
  {
    fetch_poll[i].fd = -1;
  }

  if ( ( fd = open( "/sdcard/consensus", O_RDONLY ) ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  if ( *result_network_consensus == NULL )
  {
    *result_network_consensus = malloc( sizeof( NetworkConsensus ) );
  }

  (*result_network_consensus)->method = 0;
  (*result_network_consensus)->valid_after = 0;
  (*result_network_consensus)->fresh_until = 0;
  (*result_network_consensus)->valid_until = 0;

#ifdef MINITOR_CHUTNEY
  (*result_network_consensus)->hsdir_interval = 8;
#else
  (*result_network_consensus)->hsdir_interval = HSDIR_INTERVAL_DEFAULT;
#endif

  (*result_network_consensus)->hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT;
  (*result_network_consensus)->hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT;

  if ( d_parse_network_consensus_from_file( fd, *result_network_consensus ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to parse network consensus from file" );
#endif

    ret = -1;
    goto finish;
  }

#ifndef MINITOR_CHUTNEY
  if ( d_get_hsdir_list_valid_until() == (*result_network_consensus)->valid_until )
  {
    ESP_LOGE( MINITOR_TAG, "hsdir_list already setup and valid" );

    if ( d_load_hsdir_relays_from_file() < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to load relays from file" );
      ret = -1;
    }
    else
    {
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

      next_network_consensus = NULL;
    }

    goto finish;
  }
#endif

  if ( d_reset_hsdir_relay_tree_file() < 0 )
  {
    ret = -1;
    goto finish;
  }

  if ( d_reset_hsdir_list() < 0 )
  {
    ret = -1;
    goto finish;
  }

  (*result_network_consensus)->time_period = d_get_hs_time_period( (*result_network_consensus)->fresh_until, (*result_network_consensus)->valid_after, (*result_network_consensus)->hsdir_interval );

  // sizeof pointer, not the actual struct
  insert_relays_queue = xQueueCreate( 9, sizeof( OnionRelay* ) );

  xTaskCreatePinnedToCore(
    v_handle_crypto_and_insert,
    "H_CRYPTO_INSERT",
    3072,
    (void*)(*result_network_consensus),
    8,
    NULL,
    1
  );

  do
  {
    // while there are still relays left
    while ( final_relay_hit == 0 )
    {
      // find a fetch state that has less than 3 relays in it
      for ( i = 0; i < 3; i++ )
      {
        if ( fetch_states[i].num_relays < 3 )
        {
          break;
        }
      }

      // if we couldn't find a non-full fetch, then bail out and just focus on polling
      if ( i >= 3 )
      {
        break;
      }

      parse_succ = d_parse_single_relay( fd, &fetch_states[i].relays[fetch_states[i].num_relays] );

#ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "Parsed relay: %d", ++total_parsed );
#endif

      // we either have a new relay or have hit the last relay and need to run our free fetch with the 1-2 relays in it
      if ( parse_succ >= 0 )
      {
        if ( fetch_states[i].relays[fetch_states[i].num_relays].hsdir == 1 || parse_succ != 0 )
        {
          // got a new relay, increment num_relays
          if ( parse_succ == 0 )
          {
            fetch_states[i].num_relays++;
          }
          else
          {
            final_relay_hit = 1;
          }

          // we either have 3 or have more than 1 and hit the final relay in consensus where ret != 0
          if ( fetch_states[i].num_relays == 3 || ( final_relay_hit == 1 && fetch_states[i].num_relays > 0 ) )
          {
            while ( d_start_descriptor_fetch( &fetch_states[i] ) < 0 )
            {
              ESP_LOGE( MINITOR_TAG, "Failed to start fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );
            }

            fetch_poll[i].fd = fetch_states[i].sock_fd;
            fetch_poll[i].events = POLLIN;
            running_fetches++;
          }
        }
      }
      else
      {
        ret = -1;
        goto finish;
      }
    }

    for ( j = 0; j < 3; j++ )
    {
#ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "About to poll: %d with num_relays: %d", fetch_poll[j].fd, fetch_states[j].num_relays );
#endif
    }

    // if we hit the final relay or have no more fetches to fill, wait forever
    if ( final_relay_hit == 1 || i >= 3 )
    {
#ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "Waiting forever on poll" );
#endif

      poll_succ = poll( fetch_poll, 3, -1 );
    }
    // otherwise just peek so we can keep on building fetches
    else
    {
      poll_succ = poll( fetch_poll, 3, 0 );
    }

    if ( poll_succ > 0 )
    {
      for ( i = 0; i < 3; i++ )
      {
        if ( ( fetch_poll[i].revents & POLLIN ) == POLLIN )
        {
          // we're going to assume that once a socket is ready to read, we can read the entire thing
          if ( d_finish_descriptor_fetch( &fetch_states[i] ) < 0 )
          {
            ESP_LOGE( MINITOR_TAG, "Failed to finish fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );

            while ( d_start_descriptor_fetch( &fetch_states[i] ) < 0 )
            {
              ESP_LOGE( MINITOR_TAG, "Failed to start fetch of relay descriptors, retrying: %d", fetch_states[i].num_relays );
            }

            fetch_poll[i].fd = fetch_states[i].sock_fd;
            fetch_poll[i].events = POLLIN;
          }
          else
          {
            // send the fetched relays off to the insert task
            for ( j = 0; j < fetch_states[i].num_relays; j++ )
            {
              tmp_relay = malloc( sizeof( OnionRelay ) );

              memcpy( tmp_relay, &fetch_states[i].relays[j], sizeof( OnionRelay ) );
              xQueueSendToBack( insert_relays_queue, (void*)(&tmp_relay), portMAX_DELAY );
            }

            fetch_poll[i].fd = -1;
            memset( &fetch_states[i], 0, sizeof( FetchDescriptorState ) );
            running_fetches--;
          }
        }
      }
    }
  } while ( final_relay_hit == 0 || running_fetches > 0 );

  tmp_relay = NULL;
  xQueueSendToBack( insert_relays_queue, (void*)(&tmp_relay), portMAX_DELAY );

  // take the semaphore so we know the crypto and insert task finished
  ret = xSemaphoreTake( crypto_insert_finish, 1000 * 5 / portTICK_PERIOD_MS );

  if ( ret != pdTRUE )
  {
    xSemaphoreGive( crypto_insert_finish );

    ret = -1;
    goto finish;
  }

  xSemaphoreGive( crypto_insert_finish );

  vQueueDelete( insert_relays_queue );

  ret = 0;
  valid_delay = 0;

  if ( d_finalize_hsdir_relays_file() < 0 || d_set_hsdir_list_valid_until( (*result_network_consensus)->valid_until ) < 0 )
  {
    ret = -1;
    goto finish;
  }

  time( &now );

  if ( (*result_network_consensus)->valid_after > now )
  {
    valid_delay = 1000 * ( (*result_network_consensus)->valid_after - now ) / portTICK_PERIOD_MS;
  }

  if ( valid_delay != 0 )
  {
    ESP_LOGE( MINITOR_TAG, "Triggering consensus switch in %lu seconds", ( (*result_network_consensus)->valid_after - now ) );
    next_network_consensus = *result_network_consensus;

    xTimerChangePeriod( consensus_valid_timer, valid_delay, portMAX_DELAY );
    xTimerStart( consensus_valid_timer, portMAX_DELAY );
  }

  if ( valid_delay == 0 )
  {
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

    next_network_consensus = NULL;
  }

finish:
  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/consensus, errno: %d", errno );
#endif

    return -1;
  }

  return ret;
}
*/

int d_get_hs_time_period( time_t fresh_until, time_t valid_after, int hsdir_interval )
{
  time_t voting_interval;
  time_t srv_start_time;
  time_t tp_start_time;
  int rotation_offset;
  int time_period;

  ESP_LOGE( MINITOR_TAG, "fresh_until: %ld, valid_after: %ld, hsdir_interval: %d", fresh_until, valid_after, hsdir_interval );
  voting_interval = fresh_until - valid_after;
  rotation_offset = SHARED_RANDOM_N_ROUNDS * voting_interval / 60;

  // SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES = 24
  srv_start_time = valid_after - ( ( ( ( valid_after / voting_interval ) ) % ( SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES ) ) * voting_interval );
  tp_start_time = ( srv_start_time / 60 - rotation_offset + hsdir_interval ) * 60;

  ESP_LOGE( MINITOR_TAG, "Roation offset: %d", rotation_offset );
  time_period = ( valid_after / 60 - rotation_offset ) / hsdir_interval;

  if ( valid_after < srv_start_time || valid_after >= tp_start_time )
  {
    time_period--;
  }

  ESP_LOGE( MINITOR_TAG, "Time period used: %d", time_period );

  return time_period;
}

int d_set_next_consenus()
{
  int succ = 0;

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  network_consensus.method = next_network_consensus->method;
  network_consensus.valid_after = next_network_consensus->valid_after;
  network_consensus.fresh_until = next_network_consensus->fresh_until;
  network_consensus.valid_until = next_network_consensus->valid_until;

  ESP_LOGE( MINITOR_TAG, "consensus change" );
  ESP_LOGE( MINITOR_TAG, "shared_rand_cmp %d", memcmp( network_consensus.shared_rand, next_network_consensus->shared_rand, 32 ) );
  ESP_LOGE( MINITOR_TAG, "previous_shared_rand_cmp %d", memcmp( network_consensus.previous_shared_rand, next_network_consensus->previous_shared_rand, 32 ) );

  memcpy( network_consensus.previous_shared_rand, next_network_consensus->previous_shared_rand, 32 );
  memcpy( network_consensus.shared_rand, next_network_consensus->shared_rand, 32 );

  //succ = d_load_hsdir_relays_from_file();

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus

  free( next_network_consensus );

  return succ;
}

// fetch the network consensus so we can correctly create circuits
int d_fetch_consensus_info()
{
  int ret = 0;
  //NetworkConsensus* result_network_consensus;
  time_t now = 0;
  int voting_interval;
  time_t next_srv_time;

  // TODO the return value of null is ambigious, it could be null because there isn't a row or
  // it could be because the database is messed up, we need to be able to distinguish
  //result_network_consensus = px_get_network_consensus();
  //time( &now );

  //if ( result_network_consensus == NULL || result_network_consensus->fresh_until <= now )
  //{
    if ( d_download_consensus() < 0 )
    {
      ret = -1;
      goto finish;
    }
  //}

/*
  if ( d_parse_downloaded_consensus( &result_network_consensus ) < 0 )
  {
    ret = -1;
    goto finish;
  }
*/

  if ( d_destroy_consensus() < 0 )
  {
    ret = -1;
    goto finish;
  }

  if ( d_create_consensus( &network_consensus ) < 0 )
  {
    ret = -1;
    goto finish;
  }

  time( &now );

#ifdef MINITOR_CHUTNEY
  // in chutney we want to update when a new shared rand is expected, not when we lose freshness
  voting_interval = network_consensus.fresh_until - network_consensus.valid_after;

  // 24 is SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES
  // get it on voting interval after, just to be careful
  next_srv_time = network_consensus.valid_after + ( ( 24 - ( ( ( network_consensus.valid_after / voting_interval ) ) % 24 ) + 1 ) * voting_interval );
  xTimerChangePeriod( consensus_timer, 1000 * ( next_srv_time - now ) / portTICK_PERIOD_MS, portMAX_DELAY );
  xTimerStart( consensus_timer, portMAX_DELAY );
#else
  xTimerChangePeriod( consensus_timer, 1000 * ( network_consensus.valid_until - now ) / portTICK_PERIOD_MS, portMAX_DELAY );
  xTimerStart( consensus_timer, portMAX_DELAY );
#endif

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "finished fetching consensus" );
#endif

finish:
  // return 0 for no errors
  return ret;
}
