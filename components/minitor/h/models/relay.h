#ifndef MINITOR_MODELS_RELAY_H
#define MINITOR_MODELS_RELAY_H

#include "../structures/consensus.h"

int d_create_relay_table();
int d_create_relay( OnionRelay* onion_relay );
OnionRelay* px_get_relay( unsigned char* identity );
OnionRelay* px_get_random_relay_standalone();
OnionRelay* px_get_random_relay( DoublyLinkedOnionRelayList* relay_list, unsigned char* exclude );
OnionRelay* px_get_random_relay_non_guard( unsigned char* exclude );
int d_get_hsdir_count();
unsigned char* puc_get_hash_by_index( int index, int previous );
OnionRelay* px_get_relay_by_hash_index( int index, int previous );
DoublyLinkedOnionRelayList* px_get_relays_by_current_hash( unsigned char* hash, int relay_count, DoublyLinkedOnionRelayList* used_relay_list );
DoublyLinkedOnionRelayList* px_get_relays_by_previous_hash( unsigned char* hash, int relay_count, DoublyLinkedOnionRelayList* used_relay_list );
int d_mark_relay_as_guard( unsigned char* identity );
int d_unmark_relay_as_guard( unsigned char* identity );
int d_destroy_all_relays();

#endif
