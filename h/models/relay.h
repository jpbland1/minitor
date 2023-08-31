#ifndef MINITOR_MODELS_RELAY_H
#define MINITOR_MODELS_RELAY_H

#include "../structures/consensus.h"

typedef struct AvlBlock
{
  int parent_addr;
  int left_addr;
  int right_addr;
  int8_t balance;
} AvlBlock;

typedef struct BinaryRelay
{
  AvlBlock avl_blocks[3];
  OnionRelay relay;
} BinaryRelay;

int d_create_hsdir_relay( OnionRelay* onion_relay );
int d_create_cache_relay( OnionRelay* onion_relay );
int d_create_fast_relay( OnionRelay* onion_relay );
int d_create_waiting_relay( OnionRelay* onion_relay );
OnionRelay* px_get_waiting_relay();
DoublyLinkedOnionRelayList* px_get_responsible_hsdir_relays_by_hs_index( uint8_t* hs_index, int desired_count, int current, DoublyLinkedOnionRelayList* used_relays );
OnionRelay* px_get_random_cache_relay( bool staging );
OnionRelay* px_get_random_backup_cache_relay();
OnionRelay* px_get_random_fast_relay( bool want_guard, DoublyLinkedOnionRelayList* relay_list, uint8_t* exclude_start, uint8_t* exclude_end );
OnionRelay* px_get_cache_relay_by_identity( uint8_t* identity, bool staging );
int d_get_hsdir_relay_count();
int d_get_cache_relay_count();
int d_get_fast_relay_count();
int d_get_staging_hsdir_relay_count();
int d_get_staging_cache_relay_count();
int d_get_staging_fast_relay_count();
int d_get_waiting_relay_count();
int d_reset_staging_hsdir_relays();
int d_reset_staging_cache_relays();
int d_reset_staging_fast_relays();
int d_reset_waiting_relays();
int d_get_hsdir_relay_valid_until();
int d_get_cache_relay_valid_until();
int d_get_fast_relay_valid_until();
int d_set_staging_hsdir_relay_valid_until( time_t valid_until );
int d_set_staging_cache_relay_valid_until( time_t valid_until );
int d_set_staging_fast_relay_valid_until( time_t valid_until );
int d_load_hsdir_relay_count();
int d_load_cache_relay_count();
int d_load_fast_relay_count();
int d_finalize_staged_relay_lists();

#endif
