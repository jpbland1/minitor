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

int d_reset_hsdir_relay_tree();
int d_create_hsdir_relay( OnionRelay* onion_relay );
int d_traverse_hsdir_relays_in_order( BinaryRelay* b_relay, int next_addr, int* previous_addr, int offset, int avl_index );
OnionRelay* px_get_hsdir_relay_by_identity( uint8_t* identity );
DoublyLinkedOnionRelayList* px_get_hsdir_relays_by_id_hash( uint8_t* id_hash, int desired_count, int current, DoublyLinkedOnionRelayList* used_relays );
OnionRelay* px_get_hsdir_relay_by_id_hash( uint8_t* id_hash, int offset, DoublyLinkedOnionRelayList* used_relays, int current );
OnionRelay* px_get_random_hsdir_relay( int want_guard, DoublyLinkedOnionRelayList* relay_list, uint8_t* exclude_start, uint8_t* exclude_end );
int d_get_hsdir_count();
int d_mark_hsdir_relay_as_guard( uint8_t* identity );
int d_unmark_hsdir_relay_as_guard( uint8_t* identity );
int d_reset_hsdir_relay_tree_file();
int d_finalize_hsdir_relays_file();
int d_load_hsdir_relays_from_file();
int d_create_hsdir_relay_in_file( OnionRelay* onion_relay );
int d_get_cache_relay_count();
OnionRelay* px_get_dir_cache_relay();
int d_reset_hsdir_list();
int d_add_hsdir_relay_to_list( OnionRelay* onion_relay );
int d_get_hsdir_list_valid_until();
int d_set_hsdir_list_valid_until( time_t valid_until );

extern int avl_roots[3];

#endif
