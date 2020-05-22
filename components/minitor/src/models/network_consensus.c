#include <stdlib.h>
#include "sqlite3.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/models/db.h"
#include "../../h/models/network_consensus.h"

int d_create_consensus_table() {
  int ret;
  char* err;

  ret = sqlite3_exec( minitor_db,
"CREATE TABLE IF NOT EXISTS main.NetworkConsensus ("
  "method INT4 NOT NULL,"
  "valid_after INT8 NOT NULL,"
  "fresh_until INT8 NOT NULL,"
  "valid_until INT8 NOT NULL,"
  "previous_shared_rand CHAR(32) NOT NULL,"
  "shared_rand CHAR(32) NOT NULL,"
  "hsdir_interval INT4 NOT NULL,"
  "hsdir_n_replicas INT4 NOT NULL,"
  "hsdir_spread_store INT4 NOT NULL"
");",
    NULL, NULL, &err );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create NetworkConsensus Table, err msg: %s", err );
#endif

    sqlite3_free( err );

    return -1;
  }

  return 0;
}

int d_create_consensus( NetworkConsensus* network_consensus ) {
  int ret;
  sqlite3_stmt* statement;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_prepare_v2( minitor_db,
"INSERT INTO main.NetworkConsensus"
  "( method, valid_after, fresh_until, valid_until, previous_shared_rand, shared_rand, hsdir_interval, hsdir_n_replicas, hsdir_spread_store )"
  "VALUES( ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 );",
    -1, &statement, NULL);

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare NetworkConsensus create statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_bind_int( statement, 1, network_consensus->method );
  sqlite3_bind_int( statement, 2, network_consensus->valid_after );
  sqlite3_bind_int( statement, 3, network_consensus->fresh_until );
  sqlite3_bind_int( statement, 4, network_consensus->valid_until );
  sqlite3_bind_text( statement, 5, (const char*)network_consensus->previous_shared_rand, 32, SQLITE_STATIC );
  sqlite3_bind_text( statement, 6, (const char*)network_consensus->shared_rand, 32, SQLITE_STATIC );
  sqlite3_bind_int( statement, 7, network_consensus->hsdir_interval );
  sqlite3_bind_int( statement, 8, network_consensus->hsdir_n_replicas );
  sqlite3_bind_int( statement, 9, network_consensus->hsdir_spread_store );

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_DONE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to insert NetworkConsensus, err code: %d", ret );
#endif

    goto cleanup;
  }

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    return -1;
  }

  return 0;

cleanup:
  d_close_database();
  return -1;
}

NetworkConsensus* px_get_network_consensus() {
  int ret;
  sqlite3_stmt* statement;
  NetworkConsensus* network_consensus;

  if ( d_open_database() < 0 ) {
    return NULL;
  }

  network_consensus = malloc( sizeof( NetworkConsensus ) );

  ret = sqlite3_prepare_v2( minitor_db, "SELECT method, valid_after, fresh_until, valid_until, previous_shared_rand, shared_rand, hsdir_interval, hsdir_n_replicas, hsdir_spread_store FROM main.NetworkConsensus LIMIT 1;", -1, &statement, NULL );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to prepare NetworkConsensus get statement, err code: %d", ret );
#endif

    goto cleanup;
  }

  if ( ( ret = sqlite3_step( statement ) ) != SQLITE_ROW ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to get NetworkConsensus, err code: %d", ret );
#endif

    sqlite3_finalize( statement );
    goto cleanup;
  }

  network_consensus->method = sqlite3_column_int( statement, 0 );
  network_consensus->valid_after = sqlite3_column_int( statement, 1 );
  network_consensus->fresh_until = sqlite3_column_int( statement, 2 );
  network_consensus->valid_until = sqlite3_column_int( statement, 3 );
  memcpy( network_consensus->previous_shared_rand, sqlite3_column_text( statement, 4 ), 32 );
  memcpy( network_consensus->shared_rand, sqlite3_column_text( statement, 5 ), 32 );
  network_consensus->hsdir_interval = sqlite3_column_int( statement, 6 );
  network_consensus->hsdir_n_replicas = sqlite3_column_int( statement, 7 );
  network_consensus->hsdir_spread_store = sqlite3_column_int( statement, 8 );

  sqlite3_finalize( statement );

  if ( d_close_database() < 0 ) {
    goto db_fail;
  }

  return network_consensus;

cleanup:
  d_close_database();
db_fail:
  free( network_consensus );
  return NULL;
}

int d_destroy_consensus() {
  int ret;
  char* err;

  if ( d_open_database() < 0 ) {
    return -1;
  }

  ret = sqlite3_exec( minitor_db, "DELETE FROM main.NetworkConsensus;", NULL, NULL, &err );

  if ( ret != SQLITE_OK ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to delete NetworkConsensus, err msg: %s", err );
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
