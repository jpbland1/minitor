#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "sqlite3.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/models/db.h"
#include "../../h/models/relay.h"

static void v_parse_onion_relay( sqlite3_stmt* statement, OnionRelay* onion_relay ) {
  memcpy( onion_relay->identity, sqlite3_column_text( statement, 0 ), ID_LENGTH );
  memcpy( onion_relay->digest, sqlite3_column_text( statement, 1 ), ID_LENGTH );
  memcpy( onion_relay->ntor_onion_key, sqlite3_column_text( statement, 2 ), H_LENGTH );
  onion_relay->address = sqlite3_column_int( statement, 3 );
  onion_relay->or_port = sqlite3_column_int( statement, 4 );
  onion_relay->dir_port = sqlite3_column_int( statement, 5 );
  onion_relay->hsdir = sqlite3_column_int( statement, 6 );
  onion_relay->suitable = sqlite3_column_int( statement, 7 );
  memcpy( onion_relay->previous_hash, sqlite3_column_text( statement, 8 ), H_LENGTH );
  memcpy( onion_relay->current_hash, sqlite3_column_text( statement, 9 ), H_LENGTH );
}

static char* pc_get_not_in_string( DoublyLinkedOnionRelayList* relay_list, unsigned char* exclude ) {
  int i;
  int size = 0;
  char* not_in_query;

  if ( exclude != NULL ) {
    if ( relay_list->length > 6 ) {
      size = 4;
    } else {
      size = 3;
    }
  }

  if ( relay_list->length > 7 ) {
    size += 7 * 3;
    size += ( relay_list->length - 7 ) * 4;
  } else {
    size += relay_list->length * 3;
  }

  not_in_query = malloc( sizeof( char ) * size );
  not_in_query[size - 1] = '\0';

  for ( i = 0; i < relay_list->length; i++ ) {
    if ( i < 7 ) {
      not_in_query[i * 3] = '?';
      not_in_query[i * 3 + 1] = '3' + i;
    } else {
      not_in_query[i * 3] = '?';
      not_in_query[i * 3 + 1] = '0' + ( i - 7 ) / 10 + 1;
      not_in_query[i * 3 + 2] = '0' + ( i - 7 ) % 10;
    }

    if (  i != relay_list->length - 1 || exclude != NULL ) {
      not_in_query[i * 3 + 2] = ',';
    }
  }

  if (  exclude != NULL ) {
    if ( relay_list->length > 6 ) {
      not_in_query[size - 4] = '?';
      not_in_query[size - 3] = '0' + ( relay_list->length - 7 ) / 10 + 1;
      not_in_query[size - 2] = '0' + ( relay_list->length - 7 ) % 10;
    } else {
      not_in_query[size - 3] = '?';
      not_in_query[size - 2] = '3' + relay_list->length;
    }
  }

  return not_in_query;
}

int d_create_relay_table() {
  int ret;
  char* err;

  ret = sqlite3_exec( minitor_db,
"CREATE TABLE IF NOT EXISTS main.OnionRelays ("
  "identity CHAR(20) NOT NULL UNIQUE,"
  "digest CHAR(20) NOT NULL,"
  "ntor_onion_key CHAR(32) NOT NULL,"
  "address INT4 NOT NULL,"
  "or_port INT2 NOT NULL,"
  "dir_port INT2 NOT NULL,"
  "hsdir INT1 DEFAULT 0,"
  "suitable INT1 DEFAULT 0,"
  "guard INT1 DEFAULT 0,"
  "previous_hash CHAR(32) NOT NULL,"
  "current_hash CHAR(32) NOT NULL,"
  "can_guard INT1 NOT NULL,"
  "can_exit INT1 NOT NULL"
");",
    NULL, NULL, &err );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create OnionRelay Table, err msg: %s", err );
#endif

    sqlite3_free( err );

    return -1;
  }

  ret = sqlite3_exec( minitor_db,
"UPDATE main.OnionRelays SET guard = 0;",
    NULL, NULL, &err );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create OnionRelay Table, err msg: %s", err );
#endif

    sqlite3_free( err );

    return -1;
  }

  return 0;
}

int d_create_relay( OnionRelay* onion_relay ) {
  int ret;
  sqlite3_stmt* statement;

  /* if ( d_open_database() < 0 ) { */
    /* return -1; */
  /* } */

  ret = sqlite3_prepare_v2( minitor_db,
"INSERT INTO main.OnionRelays"
  " ( identity, digest, ntor_onion_key, address, or_port, dir_port, hsdir, suitable, previous_hash, current_hash, can_guard, can_exit )"
  " VALUES ( ?1, ?2, ?3, ?4, ?5, ?6 , ?7, ?8, ?9, ?10, ?11, ?12 );",
    -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay create statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)onion_relay->identity, ID_LENGTH, SQLITE_STATIC );
  sqlite3_bind_text( statement, 2, (const char*)onion_relay->digest, ID_LENGTH, SQLITE_STATIC );
  sqlite3_bind_text( statement, 3, (const char*)onion_relay->ntor_onion_key, H_LENGTH, SQLITE_STATIC );
  sqlite3_bind_int( statement, 4, onion_relay->address );
  sqlite3_bind_int( statement, 5, onion_relay->or_port );
  sqlite3_bind_int( statement, 6, onion_relay->dir_port );
  sqlite3_bind_int( statement, 7, onion_relay->hsdir );
  sqlite3_bind_int( statement, 8, onion_relay->suitable );
  sqlite3_bind_text( statement, 9, (const char*)onion_relay->previous_hash, H_LENGTH, SQLITE_STATIC );
  sqlite3_bind_text( statement, 10, (const char*)onion_relay->current_hash, H_LENGTH, SQLITE_STATIC );
  sqlite3_bind_int( statement, 11, onion_relay->can_guard );
  sqlite3_bind_int( statement, 12, onion_relay->can_exit );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to insert OnionRelay, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  sqlite3_finalize( statement );

  /* if ( d_close_database() < 0 ) { */
    /* return -1; */
  /* } */

  return 0;

cleanup:
  /* d_close_database(); */
  return -1;
}

OnionRelay* px_get_relay( unsigned char* identity ) {
  int ret;
  sqlite3_stmt* statement;
  OnionRelay* onion_relay;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  onion_relay = malloc( sizeof( OnionRelay ) );

  ret = sqlite3_prepare_v2( minitor_db, "SELECT identity, digest, ntor_onion_key, address, or_port, dir_port, hsdir, suitable, previous_hash, current_hash FROM main.OnionRelays WHERE identity = ?1", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)identity, ID_LENGTH, SQLITE_STATIC );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelay, err code: %d", ret );
#endif

    goto cleanup;
  }

  v_parse_onion_relay( statement, onion_relay );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return onion_relay;

cleanup:
  d_close_database();
db_fail:
  free( onion_relay );
  return NULL;
}

OnionRelay* px_get_random_relay( DoublyLinkedOnionRelayList* relay_list, unsigned char* exclude ) {
  int i;
  int rand_index;
  int ret;
  char* full_query;
  char* not_in_query;
  const char* partial_count_query = "SELECT COUNT(identity) FROM main.OnionRelays WHERE suitable = 1 AND identity NOT IN (%s);";
  const char* partial_data_query = "SELECT identity, digest, ntor_onion_key, address, or_port, dir_port, hsdir, suitable, previous_hash, current_hash FROM main.OnionRelays WHERE suitable = 1 AND identity NOT IN (%s) LIMIT 1 OFFSET ?1;";
  sqlite3_stmt* statement;
  OnionRelay* onion_relay;
  DoublyLinkedOnionRelay* db_onion_relay;

  if ( relay_list->length < 1 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Relay list must have at least one element" );
#endif

    return NULL;
  }

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  onion_relay = malloc( sizeof( OnionRelay ) );

  not_in_query = pc_get_not_in_string( relay_list, exclude );

  full_query = malloc( sizeof( unsigned char ) * ( strlen( partial_count_query ) + strlen( not_in_query ) ) );

  sprintf( full_query, partial_count_query, not_in_query );

  ESP_LOGE( MINITOR_TAG, "full_query: %s", full_query );

  ret = sqlite3_prepare_v2( minitor_db, full_query, -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay count non guard relays, err code: %d", ret );
#endif

    goto cleanup;
  }

  db_onion_relay = relay_list->head;

  for ( i = 0; i < relay_list->length; i++ ) {
    sqlite3_bind_text( statement, 3 + i, (char*)db_onion_relay->relay->identity, ID_LENGTH, SQLITE_STATIC );

    db_onion_relay = db_onion_relay->next;
  }

  if ( exclude != NULL ) {
    sqlite3_bind_text( statement, 3 + relay_list->length, (char*)exclude, ID_LENGTH, SQLITE_STATIC );
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelay count relays, err code: %d", ret );
#endif

    goto cleanup;
  }

  rand_index = esp_random() % sqlite3_column_int( statement, 0 );

  sqlite3_finalize( statement );
  free( full_query );

  full_query = malloc( sizeof( unsigned char ) * ( strlen( partial_data_query ) + strlen( not_in_query ) ) );

  sprintf( full_query, partial_data_query, not_in_query );

  ESP_LOGE( MINITOR_TAG, "full_query: %s", full_query );

  ret = sqlite3_prepare_v2( minitor_db, full_query, -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get random relay, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_int( statement, 1, rand_index );

  db_onion_relay = relay_list->head;

  for ( i = 0; i < relay_list->length; i++ ) {
    sqlite3_bind_text( statement, 3 + i, (char*)db_onion_relay->relay->identity, ID_LENGTH, SQLITE_STATIC );

    db_onion_relay = db_onion_relay->next;
  }

  if ( exclude != NULL ) {
    sqlite3_bind_text( statement, 3 + relay_list->length, (char*)exclude, ID_LENGTH, SQLITE_STATIC );
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelay non guard relays, err code: %d", ret );
#endif

    goto cleanup;
  }

  v_parse_onion_relay( statement, onion_relay );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  free( not_in_query );
  free( full_query );

  return onion_relay;

cleanup:
  d_close_database();
db_fail:
  free( not_in_query );
  free( full_query );
  free( onion_relay );
  return NULL;
}

OnionRelay* px_get_random_relay_non_guard( unsigned char* exclude ) {
  int rand_index;
  int ret;
  sqlite3_stmt* statement;
  OnionRelay* onion_relay;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  onion_relay = malloc( sizeof( OnionRelay ) );

  if ( exclude != NULL ) {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT COUNT(identity) FROM main.OnionRelays WHERE guard = 0 AND can_guard = 1 AND suitable = 1 AND identity != ?1;", -1, &statement, NULL );
  } else {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT COUNT(identity) FROM main.OnionRelays WHERE guard = 0 AND can_guard = 1 AND suitable = 1;", -1, &statement, NULL );
  }

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay count non guard relays, err code: %d", ret );
#endif

    goto cleanup;
  }

  if ( exclude != NULL ) {
    sqlite3_bind_text( statement, 1, (const char*)exclude, ID_LENGTH, SQLITE_STATIC );
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelay count non guard relays, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  rand_index = esp_random() % sqlite3_column_int( statement, 0 );

  sqlite3_finalize( statement );

  if ( exclude != NULL ) {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT identity, digest, ntor_onion_key, address, or_port, dir_port, hsdir, suitable, previous_hash, current_hash FROM main.OnionRelays WHERE guard = 0 AND suitable = 1 AND identity != ?1 LIMIT 1 OFFSET ?2;", -1, &statement, NULL );
  } else {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT identity, digest, ntor_onion_key, address, or_port, dir_port, hsdir, suitable, previous_hash, current_hash FROM main.OnionRelays WHERE guard = 0 AND suitable = 1 LIMIT 1 OFFSET ?1;", -1, &statement, NULL );
  }

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get non guard relay, err code: %d", ret );
#endif

    goto cleanup;
  }

  if ( exclude != NULL ) {
    sqlite3_bind_text( statement, 1, (const char*)exclude, ID_LENGTH, SQLITE_STATIC );
    sqlite3_bind_int( statement, 2, rand_index );
  } else {
    sqlite3_bind_int( statement, 1, rand_index );
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelay non guard relays, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  v_parse_onion_relay( statement, onion_relay );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return onion_relay;

cleanup:
  d_close_database();
db_fail:
  free( onion_relay );
  return NULL;
}

int d_get_hsdir_count() {
  int ret;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_prepare_v2( minitor_db, "SELECT COUNT(identity) FROM main.OnionRelays WHERE hsdir = 1;", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay count hsdir, err code: %d", ret );
#endif

    goto cleanup;
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to count OnionRelay hsdir, err code: %d", ret );
#endif

    goto cleanup;
  }

  ret = sqlite3_column_int( statement, 0 );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return ret;

cleanup:
  d_close_database();
db_fail:
  return -1;
}

unsigned char* puc_get_hash_by_index( int index, int previous ) {
  int ret;
  unsigned char* hash;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  hash = malloc( sizeof( unsigned char ) * H_LENGTH );

  if ( previous ) {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT previous_hash FROM main.OnionRelays WHERE hsdir = 1 ORDER BY previous_hash LIMIT 1 OFFSET ?1;", -1, &statement, NULL );
  } else {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT current_hash FROM main.OnionRelays WHERE hsdir = 1 ORDER BY current_hash LIMIT 1 OFFSET ?1;", -1, &statement, NULL );
  }

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get hash by index, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_int( statement, 1, index );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to query OnionRelay get hash by index, err code: %d", ret );
#endif

    goto cleanup;
  }

  memcpy( hash, sqlite3_column_text( statement, 0 ), H_LENGTH );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return hash;

cleanup:
  d_close_database();
db_fail:
  sqlite3_finalize( statement );
  free( hash );
  return NULL;
}

OnionRelay* px_get_relay_by_hash_index( int index, int previous ) {
  int ret;
  OnionRelay* onion_relay;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  onion_relay = malloc( sizeof( OnionRelay ) );

  if ( previous ) {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT identity FROM main.OnionRelays WHERE hsdir = 1 ORDER BY previous_hash LIMIT 1 OFFSET ?1;", -1, &statement, NULL );
  } else {
    ret = sqlite3_prepare_v2( minitor_db, "SELECT identity FROM main.OnionRelays WHERE hsdir = 1 ORDER BY current_hash LIMIT 1 OFFSET ?1;", -1, &statement, NULL );
  }

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get identity by index, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_int( statement, 1, index );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to query OnionRelay get identity by index, err code: %d", ret );
#endif

    goto cleanup;
  }

  memcpy( onion_relay->identity, sqlite3_column_text( statement, 0 ), ID_LENGTH );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return onion_relay;

cleanup:
  d_close_database();
db_fail:
  free( onion_relay );
  return NULL;
}

static DoublyLinkedOnionRelayList* px_get_relays_by_hash( unsigned char* hash, int relay_count, DoublyLinkedOnionRelayList* used_relay_list, int previous ) {
  int i;
  int ret;
  sqlite3_stmt* statement;
  const char* current_string = "current_hash";
  const char* previous_string = "previous_hash";
  const char* partial_main_query = "SELECT identity FROM main.OnionRelays WHERE %s >= ?1 AND hsdir = 1%s ORDER BY %s LIMIT ?2;";
  const char* partial_secondary_query = "SELECT identity FROM main.OnionRelays WHERE hsdir = 1%s ORDER BY %s LIMIT ?1;";
  const char* not_in_string = " AND identity NOT IN (%s)";
  char* full_query;
  char* not_in_optional;
  char* not_in_query;
  DoublyLinkedOnionRelay* db_onion_relay;
  DoublyLinkedOnionRelayList* relay_list;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  relay_list = malloc( sizeof( DoublyLinkedOnionRelayList ) );

  relay_list->length = 0;
  relay_list->head = NULL;
  relay_list->tail = NULL;

  if ( used_relay_list->length > 0 ) {
    not_in_query = pc_get_not_in_string( used_relay_list, NULL );
    not_in_optional = malloc( sizeof( char ) * ( strlen( not_in_string ) + strlen( not_in_query ) ) );
    sprintf( not_in_optional, not_in_string, not_in_query );
    free( not_in_query );
  } else {
    not_in_optional = malloc( sizeof( char ) );
    not_in_optional[0] = '\0';
  }

  if ( previous ) {
    full_query = malloc( sizeof( char ) * ( strlen( partial_main_query ) + strlen( not_in_optional ) + 2 * strlen( previous_string ) ) + 1 );
    sprintf( full_query, partial_main_query, previous_string, not_in_optional, previous_string );
  } else {
    full_query = malloc( sizeof( char ) * ( strlen( partial_main_query ) + strlen( not_in_optional ) + 2 * strlen( current_string ) ) + 1 );
    sprintf( full_query, partial_main_query, current_string, not_in_optional, current_string );
  }

  ESP_LOGE( MINITOR_TAG, "full_query: %s", full_query );

  ret = sqlite3_prepare_v2( minitor_db, full_query, -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get relays by hash statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)hash, H_LENGTH, SQLITE_STATIC );
  sqlite3_bind_int( statement, 2, relay_count );

  db_onion_relay = used_relay_list->head;

  for ( i = 0; i < used_relay_list->length; i++ ) {
    sqlite3_bind_text( statement, 3 + i, (const char*)db_onion_relay->relay->identity, ID_LENGTH, SQLITE_STATIC );

    db_onion_relay = db_onion_relay->next;
  }

  while ( 1 ) {
    ret = sqlite3_step( statement );

    if ( ret != SQLITE_ROW ) {
      if ( ret != SQLITE_DONE ) {
        ESP_LOGE( MINITOR_TAG, "Failed querying for relays by hash, err code: %d", ret );

        goto cleanup;
      }

      break;
    }

    ESP_LOGE( MINITOR_TAG, "Got row" );
    db_onion_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
    db_onion_relay->next = NULL;
    db_onion_relay->previous = NULL;
    db_onion_relay->relay = malloc( sizeof( OnionRelay ) );

    memcpy( db_onion_relay->relay->identity, sqlite3_column_text( statement, 0 ), ID_LENGTH );

    v_add_relay_to_list( db_onion_relay, relay_list );
  }

  sqlite3_finalize( statement );

  if ( relay_list->length < relay_count ) {
    free( full_query );

    if ( previous ) {
      full_query = malloc( sizeof( char ) * ( strlen( partial_secondary_query ) + strlen( not_in_optional ) + strlen( previous_string ) ) + 1 );
      sprintf( full_query, partial_secondary_query, not_in_optional, previous_string );
    } else {
      full_query = malloc( sizeof( char ) * ( strlen( partial_secondary_query ) + strlen( not_in_optional ) + strlen( current_string ) ) + 1 );
      sprintf( full_query, partial_secondary_query, not_in_optional, current_string );
    }

    ESP_LOGE( MINITOR_TAG, "full_query: %s", full_query );

    ret = sqlite3_prepare_v2( minitor_db, full_query, -1, &statement, NULL );

    if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to prepare OnionRelay get relays by hash statement, err code: %d", ret );
#endif

      goto cleanup;
    }

    sqlite3_bind_int( statement, 1, relay_count - relay_list->length );

    db_onion_relay = used_relay_list->head;

    for ( i = 0; i < used_relay_list->length; i++ ) {
      sqlite3_bind_text( statement, 3 + i, (const char*)db_onion_relay->relay->identity, ID_LENGTH, SQLITE_STATIC );

      db_onion_relay = db_onion_relay->next;
    }

    while ( 1 ) {
      ret = sqlite3_step( statement );

      if ( ret != SQLITE_ROW ) {
        if ( ret != SQLITE_DONE ) {
          ESP_LOGE( MINITOR_TAG, "Failed querying for secondary relays by hash, err code: %d", ret );

          goto cleanup;
        }

        break;
      }

      ESP_LOGE( MINITOR_TAG, "Got row from secondary" );
      db_onion_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
      db_onion_relay->next = NULL;
      db_onion_relay->previous = NULL;
      db_onion_relay->relay = malloc( sizeof( OnionRelay ) );

      v_parse_onion_relay( statement, db_onion_relay->relay );

      v_add_relay_to_list( db_onion_relay, relay_list );
    }

    sqlite3_finalize( statement );
  }

  if ( relay_list->length < relay_count ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get OnionRelays by their hash" );
#endif

    goto cleanup;
  }

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  free( full_query );
  free( not_in_optional );

  return relay_list;

cleanup:
  d_close_database();
db_fail:
  free( full_query );
  free( not_in_optional );

  db_onion_relay = relay_list->head;

  for ( i = 0; i < relay_list->length; i++ ) {
    free( db_onion_relay->relay );

    if ( i == relay_list->length - 1 ) {
      free( db_onion_relay );
    } else {
      db_onion_relay = db_onion_relay->next;
      free( db_onion_relay->previous );
    }
  }

  free( relay_list );
  return NULL;
}

DoublyLinkedOnionRelayList* px_get_relays_by_current_hash( unsigned char* hash, int relay_count, DoublyLinkedOnionRelayList* used_relay_list ) {
  return px_get_relays_by_hash( hash, relay_count, used_relay_list, 0 );
}

DoublyLinkedOnionRelayList* px_get_relays_by_previous_hash( unsigned char* hash, int relay_count, DoublyLinkedOnionRelayList* used_relay_list ) {
  return px_get_relays_by_hash( hash, relay_count, used_relay_list, 1 );
}

static int d_update_relay_guard( unsigned char* identity, int guard ) {
  int ret;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_prepare_v2( minitor_db, "UPDATE main.OnionRelays SET guard = ?1 WHERE identity = ?2;", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare update OnionRelay guard statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_int( statement, 1, guard );
  sqlite3_bind_text( statement, 2, (const char*)identity, ID_LENGTH, SQLITE_STATIC );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to update OnionRelay guard field, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    return -1;
  }

  return sqlite3_changes( minitor_db );

cleanup:
  d_close_database();
  return -1;
}

int d_mark_relay_as_guard( unsigned char* identity ) {
  return d_update_relay_guard( identity, 1 );
}

int d_unmark_relay_as_guard( unsigned char* identity ) {
  return d_update_relay_guard( identity, 0 );
}

int d_destroy_all_relays() {
  int ret;
  char* err;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_exec( minitor_db, "DELETE FROM main.OnionRelays;", NULL, NULL, &err );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to delete OnionRelays, err msg: %s", err );
#endif

    sqlite3_free( err );

    goto cleanup;
  }

  if ( d_close_database() < 0 ) {
    return -1;
  }

  return 0;

cleanup:
  d_close_database();
  return -1;
}
