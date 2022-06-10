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
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "esp_log.h"
#include "user_settings.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/consensus.h"
#include "../../h/models/relay.h"

uint32_t hsdir_relay_count = 0;
uint32_t cache_relay_count = 0;
uint32_t fast_relay_count = 0;

uint32_t staging_hsdir_relay_count = 0;
uint32_t staging_cache_relay_count = 0;
uint32_t staging_fast_relay_count = 0;

static int d_add_relay_to_list( OnionRelay* onion_relay, const char* filename )
{
  int fd;

  fd = open( filename, O_WRONLY | O_APPEND );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  if ( write( fd, onion_relay, sizeof( OnionRelay )  ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s, errno: %d", filename, errno );
#endif

    close( fd );

    return -1;
  }

  close( fd );

  return 0;
}

int d_create_hsdir_relay( OnionRelay* onion_relay )
{
  int ret = d_add_relay_to_list( onion_relay, FILESYSTEM_PREFIX "hsdir_list_stg" );

  if ( ret == 0 )
  {
    staging_hsdir_relay_count++;
  }

  return ret;
}

int d_create_cache_relay( OnionRelay* onion_relay )
{
  int ret = d_add_relay_to_list( onion_relay, FILESYSTEM_PREFIX "cache_list_stg" );

  if ( ret == 0 )
  {
    staging_cache_relay_count++;
  }

  return ret;
}

int d_create_fast_relay( OnionRelay* onion_relay )
{
  int ret = d_add_relay_to_list( onion_relay, FILESYSTEM_PREFIX "fast_list_stg" );

  if ( ret == 0 )
  {
    staging_fast_relay_count++;
  }

  return ret;
}

DoublyLinkedOnionRelayList* px_get_responsible_hsdir_relays_by_hs_index( uint8_t* hs_index, int desired_count, int current, DoublyLinkedOnionRelayList* used_relays )
{
  int i;
  int count = 0;
  int fd;
  int succ;
  OnionRelay* onion_relay;
  DoublyLinkedOnionRelay* db_relay;
  DoublyLinkedOnionRelay* new_db_relay;
  DoublyLinkedOnionRelayList* working_list;
  DoublyLinkedOnionRelayList* greater_list;
  DoublyLinkedOnionRelayList least_list;

  greater_list = malloc( sizeof( DoublyLinkedOnionRelayList ) );
  onion_relay = malloc( sizeof( OnionRelay ) );

  memset( greater_list, 0, sizeof( DoublyLinkedOnionRelayList ) );
  memset( &least_list, 0, sizeof( DoublyLinkedOnionRelayList ) );
  memset( onion_relay, 0, sizeof( OnionRelay ) );

  fd = open( FILESYSTEM_PREFIX "hsdir_list", O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "hsdir_list, errno: %d", errno );
#endif

    return -1;
  }

  succ = lseek( fd, sizeof( time_t ), SEEK_SET );

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to lseek " FILESYSTEM_PREFIX "hsdir_list, errno: %d", errno );
#endif

    close( fd );

    return NULL;
  }

  while ( 1 )
  {
    succ = read( fd, onion_relay, sizeof( OnionRelay ) );

    if ( succ != sizeof( OnionRelay ) )
    {
      break;
    }

    count++;

    //ESP_LOGE( MINITOR_TAG, "or_port: %d", onion_relay->or_port );

    db_relay = used_relays->head;

    while ( db_relay != NULL )
    {
      if ( memcmp( db_relay->relay->identity, onion_relay->identity, ID_LENGTH ) == 0 )
      {
        break;
      }

      db_relay = db_relay->next;
    }

    if ( db_relay != NULL )
    {
      continue;
    }

    if ( current == 1 )
    {
      succ = memcmp( onion_relay->id_hash, hs_index, H_LENGTH );
    }
    else
    {
      succ = memcmp( onion_relay->id_hash_previous, hs_index, H_LENGTH );
    }

    if ( succ > 0 )
    {
      working_list = greater_list;
    }
    else if ( greater_list->length < desired_count )
    {
      working_list = &least_list;
    }
    else
    {
      continue;
    }

    db_relay = working_list->head;

    // find the node i am lower than
    while ( db_relay != NULL )
    {
      if ( current == 1 )
      {
        succ = memcmp( onion_relay->id_hash, db_relay->relay->id_hash, H_LENGTH );
      }
      else
      {
        succ = memcmp( onion_relay->id_hash_previous, db_relay->relay->id_hash_previous, H_LENGTH );
      }

      if ( succ > 0 )
      {
        break;
      }

      db_relay = db_relay->next;
    }

    new_db_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    memset( new_db_relay, 0, sizeof( DoublyLinkedOnionRelay ) );
    new_db_relay->relay = onion_relay;

    if ( db_relay == NULL )
    {
      v_add_relay_to_list( new_db_relay, working_list );
    }
    else
    {
      new_db_relay->next = db_relay;
      new_db_relay->previous = db_relay->previous;

      if ( db_relay->previous != NULL )
      {
        db_relay->previous->next = new_db_relay;
      }

      db_relay->previous = new_db_relay;

      if ( working_list->head == db_relay )
      {
        working_list->head = new_db_relay;
      }

      working_list->length++;
    }

    if ( working_list->length > desired_count )
    {
      working_list->head = working_list->head->next;
      free( working_list->head->previous->relay );
      free( working_list->head->previous );
      working_list->head->previous = NULL;
      working_list->length--;
    }

    onion_relay = malloc( sizeof( OnionRelay ) );
    memset( onion_relay, 0, sizeof( OnionRelay ) );
  }

  free( onion_relay );

  // merge the two lists, order no loger matters
  while ( greater_list->length < desired_count && least_list.tail != NULL )
  {
    db_relay = least_list.tail;

    least_list.tail = db_relay->previous;

    if ( least_list.tail != NULL )
    {
      least_list.tail->next = NULL;
    }

    least_list.length--;

    v_add_relay_to_list( db_relay, greater_list );
  }

  while ( least_list.length > 0 )
  {
    v_pop_relay_from_list_back( &least_list );
  }

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read " FILESYSTEM_PREFIX "hsdir_list, errno: %d", errno );
#endif
    while ( greater_list->length > 0 )
    {
      v_pop_relay_from_list_back( greater_list );
    }

    free( greater_list );

    close( fd );

    return NULL;
  }

  close( fd );

  return greater_list;
}

static OnionRelay* get_random_relay_from_list( const char* filename, int count )
{
  int fd;
  int rand = esp_random() % count;
  OnionRelay* ret_relay = malloc( sizeof( OnionRelay ) );

  fd = open( filename, O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s, errno: %d", filename, errno );
#endif

    free( ret_relay );

    return NULL;
  }

  // min of rand is zero so this won't go over by 1
  if ( lseek( fd, sizeof( time_t ) + rand * sizeof( OnionRelay ), SEEK_SET ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to lseek %s, errno: %d", filename, errno );
#endif

    goto fail;
  }

  if ( read( fd, ret_relay, sizeof( OnionRelay ) ) != sizeof( OnionRelay ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read %s, errno: %d", filename, errno );
#endif

    goto fail;
  }

  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close %s, errno: %d", filename, errno );
#endif

    free( ret_relay );

    return NULL;
  }

  return ret_relay;

fail:
  free( ret_relay );
  close( fd );

  return NULL;
}

OnionRelay* px_get_random_cache_relay( bool staging )
{
  if ( staging == true )
  {
    return get_random_relay_from_list( FILESYSTEM_PREFIX "cache_list_stg", staging_cache_relay_count );
  }
  else
  {
    return get_random_relay_from_list( FILESYSTEM_PREFIX "cache_list", cache_relay_count );
  }
}

OnionRelay* px_get_random_fast_relay( bool want_guard, DoublyLinkedOnionRelayList* relay_list, uint8_t* exclude_start, uint8_t* exclude_end )
{
  OnionRelay* fast_relay = NULL;
  DoublyLinkedOnionRelay* db_relay;

  do
  {
    fast_relay = get_random_relay_from_list( FILESYSTEM_PREFIX "fast_list", fast_relay_count );

    if ( fast_relay == NULL )
    {
      return fast_relay;
    }

    if ( want_guard == true && fast_relay->can_guard == false )
    {
      free( fast_relay );
      fast_relay = NULL;
    }
    else if (
      ( exclude_start != NULL && memcmp( fast_relay->identity, exclude_start, ID_LENGTH ) == 0 ) ||
      ( exclude_end != NULL && memcmp( fast_relay->identity, exclude_end, ID_LENGTH ) == 0 )
    )
    {
      free( fast_relay );
      fast_relay = NULL;
    }
    else if ( relay_list != NULL )
    {
      db_relay = relay_list->head;

      while ( db_relay != NULL )
      {
        if ( memcmp( db_relay->relay->identity, fast_relay->identity, ID_LENGTH ) == 0 )
        {
          free( fast_relay );
          fast_relay = NULL;

          break;
        }

        db_relay = db_relay->next;
      }
    }
  } while( fast_relay == NULL );

  return fast_relay;
}

OnionRelay* px_get_cache_relay_by_identity( uint8_t* identity, bool staging )
{
  int fd;
  char filepath[60];
  OnionRelay* ret_relay = malloc( sizeof( OnionRelay ) );

  if ( staging == true )
  {
    strcpy( filepath, FILESYSTEM_PREFIX "cache_list_stg" );
  }
  else
  {
    strcpy( filepath, FILESYSTEM_PREFIX "cache_list" );
  }

  fd = open( filepath, O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s, errno: %d", filepath, errno );
#endif

    free( ret_relay );

    return NULL;
  }

  // min of rand is zero so this won't go over by 1
  if ( lseek( fd, sizeof( time_t ), SEEK_SET ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to lseek %s, errno: %d", filepath, errno );
#endif

    goto fail;
  }

  do
  {
    if ( read( fd, ret_relay, sizeof( OnionRelay ) ) != sizeof( OnionRelay ) )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read next relay from %s", filepath );
#endif

      goto fail;
    }
  } while ( memcmp( ret_relay->identity, identity, ID_LENGTH ) != 0 );

  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close %s, errno: %d", filepath, errno );
#endif

    free( ret_relay );

    return NULL;
  }

  return ret_relay;

fail:
  free( ret_relay );
  close( fd );

  return NULL;
}

int d_get_hsdir_relay_count()
{
  return hsdir_relay_count;
}

int d_get_cache_relay_count()
{
  return cache_relay_count;
}

int d_get_fast_relay_count()
{
  return fast_relay_count;
}

int d_get_staging_hsdir_relay_count()
{
  return staging_hsdir_relay_count;
}

int d_get_staging_cache_relay_count()
{
  return staging_cache_relay_count;
}

int d_get_staging_fast_relay_count()
{
  return staging_fast_relay_count;
}

static int d_reset_relay_list( const char* filename )
{
  int fd;
  time_t dummy_until = 0;

  fd = open( filename, O_CREAT | O_WRONLY | O_TRUNC );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to reset %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  if ( write( fd, &dummy_until, sizeof( time_t )  ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s, errno: %d", filename, errno );
#endif

    close( fd );

    return -1;
  }

  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close %s, errno: %d", filename, errno );
#endif
  }

  return 0;
}

int d_reset_staging_hsdir_relays()
{
  staging_hsdir_relay_count = 0;

  return d_reset_relay_list( FILESYSTEM_PREFIX "hsdir_list_stg" );
}

int d_reset_staging_cache_relays()
{
  staging_cache_relay_count = 0;

  return d_reset_relay_list( FILESYSTEM_PREFIX "cache_list_stg" );
}

int d_reset_staging_fast_relays()
{
  staging_fast_relay_count = 0;

  return d_reset_relay_list( FILESYSTEM_PREFIX "fast_list_stg" );
}

static int d_get_relay_list_valid_until( const char* filename )
{
  int fd;
  time_t valid_until;

  fd = open( filename, O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  if ( read( fd, &valid_until, sizeof( time_t )  ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read %s, errno: %d", filename, errno );
#endif

    close( fd );

    return -1;
  }

  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  return valid_until;
}

int d_get_hsdir_relay_valid_until()
{
  return d_get_relay_list_valid_until( FILESYSTEM_PREFIX "hsdir_list" );
}

int d_get_cache_relay_valid_until()
{
  return d_get_relay_list_valid_until( FILESYSTEM_PREFIX "cache_list" );
}

int d_get_fast_relay_valid_until()
{
  return d_get_relay_list_valid_until( FILESYSTEM_PREFIX "fast_list" );
}

static int d_set_relay_list_valid_until( time_t valid_until, const char* filename )
{
  int fd;

  fd = open( filename, O_WRONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  if ( write( fd, &valid_until, sizeof( time_t )  ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write %s, errno: %d", filename, errno );
#endif

    close( fd );

    return -1;
  }

  if ( close( fd ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  return valid_until;
}

int d_set_staging_hsdir_relay_valid_until( time_t valid_until )
{
  return d_set_relay_list_valid_until( valid_until, FILESYSTEM_PREFIX "hsdir_list_stg" );
}

int d_set_staging_cache_relay_valid_until( time_t valid_until )
{
  return d_set_relay_list_valid_until( valid_until, FILESYSTEM_PREFIX "cache_list_stg" );
}

int d_set_staging_fast_relay_valid_until( time_t valid_until )
{
  return d_set_relay_list_valid_until( valid_until, FILESYSTEM_PREFIX "fast_list_stg" );
}

static int d_get_relay_list_count( const char* filename )
{
  struct stat st;

  if ( stat( filename, &st ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to stat %s, errno: %d", filename, errno );
#endif

    return -1;
  }

  // subtract the valid until time size
  return ( st.st_size - sizeof( time_t ) ) / sizeof( OnionRelay );
}

int d_load_hsdir_relay_count()
{
  hsdir_relay_count = d_get_relay_list_count( FILESYSTEM_PREFIX "hsdir_list" );

  return hsdir_relay_count;
}

int d_load_cache_relay_count()
{
  cache_relay_count = d_get_relay_list_count( FILESYSTEM_PREFIX "cache_list" );

  return cache_relay_count;
}

int d_load_fast_relay_count()
{
  fast_relay_count = d_get_relay_list_count( FILESYSTEM_PREFIX "fast_list" );

  return fast_relay_count;
}

int d_finalize_staged_relay_lists()
{
  struct stat st;

  if ( stat( FILESYSTEM_PREFIX "hsdir_list", &st ) == 0 )
  {
    if ( unlink( FILESYSTEM_PREFIX "hsdir_list" ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink " FILESYSTEM_PREFIX "hsdir_list, errno: %d", errno );
#endif

      return -1;
    }
  }

  if ( stat( FILESYSTEM_PREFIX "cache_list", &st ) == 0 )
  {
    if ( unlink( FILESYSTEM_PREFIX "cache_list" ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink " FILESYSTEM_PREFIX "cache_list, errno: %d", errno );
#endif

      return -1;
    }
  }

  if ( stat( FILESYSTEM_PREFIX "fast_list", &st ) == 0 )
  {
    if ( unlink( FILESYSTEM_PREFIX "fast_list" ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to unlink " FILESYSTEM_PREFIX "fast_list, errno: %d", errno );
#endif

      return -1;
    }
  }

  if ( rename( FILESYSTEM_PREFIX "hsdir_list_stg", FILESYSTEM_PREFIX "hsdir_list" ) < 0 )
  {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename " FILESYSTEM_PREFIX "hsdir_list, errno: %d", errno );
#endif

      return -1;
  }

  if ( rename( FILESYSTEM_PREFIX "cache_list_stg", FILESYSTEM_PREFIX "cache_list" ) < 0 )
  {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename " FILESYSTEM_PREFIX "cache_list, errno: %d", errno );
#endif

      return -1;
  }

  if ( rename( FILESYSTEM_PREFIX "fast_list_stg", FILESYSTEM_PREFIX "fast_list" ) < 0 )
  {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to rename " FILESYSTEM_PREFIX "fast_list, errno: %d", errno );
#endif

      return -1;
  }

  hsdir_relay_count = staging_hsdir_relay_count;
  cache_relay_count = staging_cache_relay_count;
  fast_relay_count = staging_fast_relay_count;

  return 0;
}
