#include <stddef.h>
#include "esp_log.h"
#include "sqlite3.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/models/db.h"
#include "../../h/models/revision_counter.h"

int d_create_revision_counter_table() {
  int ret;
  char* err;

  ret = sqlite3_exec( minitor_db,
"CREATE TABLE IF NOT EXISTS main.RevisionCounters ("
  "onion_pub_key CHAR(32) NOT NULL,"
  "time_period INT4 NOT NULL,"
  "revision_counter INT4 NOT NULL"
");",
  NULL, NULL, &err);

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create RevisionCounters Table, err msg: %s", err );
#endif

    sqlite3_free( err );

    return -1;
  }

  return 0;
}

int d_roll_revision_counter( unsigned char* onion_pub_key, int time_period ) {
  int ret;
  int revision_counter = 0;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_prepare_v2( minitor_db, "SELECT revision_counter FROM main.RevisionCounters WHERE onion_pub_key = ?1 AND time_period = ?2;", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare SELECT RevisionCounters statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)onion_pub_key, 32, SQLITE_STATIC );
  sqlite3_bind_int( statement, 2, time_period );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE && ret != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to SELECT RevisionCounters, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  if ( ret == SQLITE_ROW ) {
    revision_counter = sqlite3_column_int( statement, 0 ) + 1;
  }

  sqlite3_finalize( statement );

  ret = sqlite3_prepare_v2( minitor_db, "DELETE FROM main.RevisionCounters WHERE onion_pub_key = ?1;", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare DELETE RevisionCounters statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)onion_pub_key, 32, SQLITE_STATIC );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to DELETE RevisionCounters before set, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  sqlite3_finalize( statement );

  ret = sqlite3_prepare_v2( minitor_db,
"INSERT INTO main.RevisionCounters"
  " ( onion_pub_key, time_period, revision_counter )"
  " VALUES ( ?1, ?2, ?3 );",
    -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare INSERT RevisionCounters statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_text( statement, 1, (const char*)onion_pub_key, 32, SQLITE_STATIC );
  sqlite3_bind_int( statement, 2, time_period );
  sqlite3_bind_int( statement, 3, revision_counter );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to INSERT RevisionCounters, err code: %d", ret );
#endif

    sqlite3_finalize( statement );

    goto cleanup;
  }

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    return -1;
  }

  return revision_counter;

cleanup:
  d_close_database();
  return -1;
}
