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
  AvlBlock avl_blocks[2];
  OnionRelay relay;
} BinaryRelay;

int d_reset_hsdir_relay_tree();
int d_create_hsdir_relay( OnionRelay* onion_relay );
int d_traverse_hsdir_relays_in_order( BinaryRelay* b_relay, int next_addr, int* previous_addr, int offset, int current );
OnionRelay* px_get_hsdir_relay_by_id_hash( uint8_t* id_hash, uint8_t* identity, int offset, DoublyLinkedOnionRelayList* used_relays, int current );
OnionRelay* px_get_hsdir_relay_by_id( uint8_t* identity );
OnionRelay* px_get_random_hsdir_relay( int want_guard, DoublyLinkedOnionRelayList* relay_list, uint8_t* exclude );
int d_get_hsdir_count();
int d_mark_hsdir_relay_as_guard( uint8_t* identity, uint8_t* id_hash );
int d_unmark_hsdir_relay_as_guard( uint8_t* identity, uint8_t* id_hash );

extern int current_root_addr;
extern int previous_root_addr;

#endif
