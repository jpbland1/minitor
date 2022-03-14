#include "../../include/config.h"
#include "../../h/models/db.h"
#include "../../h/models/relay.h"
#include "../../h/models/network_consensus.h"
#include "../../h/models/revision_counter.h"

sqlite3* minitor_db;

static void v_sqlite3_error_callback( void* vp_arg, int d_err_code, const char* cp_msg ) {
  unsigned char* feff;
  ESP_LOGE( "MINITOR_SQLITE", "(%d): %s", d_err_code, cp_msg );

  if ( d_err_code == 7 ) {
    feff = malloc( sizeof( unsigned char ) * 8000 );

    if ( feff ) {
      ESP_LOGE( "MINITOR_SQLITE", "malloc of 8000 worked fine" );
    } else {
      ESP_LOGE( "MINITOR_SQLITE", "malloc of 8000 did not work" );
      ESP_LOGE( "MINITOR_SQLITE", "heap_caps_get_free_size: %u", heap_caps_get_free_size( MALLOC_CAP_8BIT ) );
      ESP_LOGE( "MINITOR_SQLITE", "sqlite3_memory_used: %lld", sqlite3_memory_used() );
    }
  }
}

int d_initialize_database() {
  int ret;

#ifdef DEBUG_MINITOR
  if ( ( ret = sqlite3_config( SQLITE_CONFIG_LOG, v_sqlite3_error_callback, NULL ) ) != SQLITE_OK ) {
    ESP_LOGE( MINITOR_TAG, "Failed to setup sqlite3 error log: %d", ret );

    return -1;
  }
#endif

  sqlite3_initialize();

  if ( d_open_database() < 0 ) {
    return -1;
  }

  if ( d_reset_hsdir_relay_tree() < 0 ) {
    return -1;
  }

  if ( d_create_consensus_table() < 0 ) {
    return -1;
  }

  if ( d_create_revision_counter_table() < 0 ) {
    return -1;
  }

  if ( d_close_database() < 0 ) {
    return -1;
  }

  return 0;
}

int d_open_database() {
  int ret;

  if ( ( ret = sqlite3_open( "/sdcard/minitor_db.db", &minitor_db ) ) != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open database, err code: %d", ret );
#endif

    return -1;
  }

  return 0;
}

int d_release_memory() {
  int ret;

  if ( ( ret = sqlite3_db_release_memory( minitor_db ) ) != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to release database memory, err code: %d", ret );
#endif

    return -1;
  }

  return 0;
}

int d_close_database() {
  int ret;

  if ( ( ret = sqlite3_db_release_memory( minitor_db ) ) != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to release database memory, err code: %d", ret );
#endif

    return -1;
  }

  if ( ( ret = sqlite3_close( minitor_db ) ) != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to close database, err code: %d", ret );
#endif

    return -1;
  }

  return 0;
}
