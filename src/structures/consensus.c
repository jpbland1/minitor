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

#include <stddef.h>

#include "../../include/config.h"
#include "../../h/structures/consensus.h"

MinitorTimer consensus_timer;
MinitorTimer consensus_valid_timer;

// shared state must be protected by mutex
NetworkConsensus network_consensus = {
  .method = 0,
  .valid_after = 0,
  .fresh_until = 0,
  .valid_until = 0,
#ifdef MINITOR_CHUTNEY
  .hsdir_interval = 8,
#else
  .hsdir_interval = HSDIR_INTERVAL_DEFAULT,
#endif
  .hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT,
#ifdef MINITOR_CHUTNEY
  .hsdir_spread_store = 3,
#else
  .hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT,
#endif
};
MinitorMutex network_consensus_mutex;
MinitorMutex crypto_insert_finish;

// add a linked onion relay to a doubly linked list of onion relays
void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list )
{
  node->next = NULL;
  node->previous = NULL;

  // if our length is 0, just set this node as the head and tail
  if ( list->length == 0 )
  {
    list->head = node;
    list->tail = node;
  // otherwise set the new node's previous to the current tail, set the current tail's
  // next to the new node and set the new node as the new tail
  }
  else
  {
    node->previous = list->tail;
    list->tail->next = node;
    list->tail = node;
  }

  // increase the length of the list
  list->length++;
}

void v_pop_relay_from_list_back( DoublyLinkedOnionRelayList* list )
{
  DoublyLinkedOnionRelay* tmp_node;

  if ( list->length == 0 )
  {
    return;
  }

  tmp_node = list->tail;

  if ( list->length > 1 )
  {
    list->tail->previous->next = NULL;
  }

  list->tail = list->tail->previous;

  free( tmp_node->relay );
  free( tmp_node );

  list->length--;
}

DoublyLinkedOnionRelay* px_get_dl_relay_by_index(DoublyLinkedOnionRelayList* list, int index)
{
  int i;
  DoublyLinkedOnionRelay* dl_relay;

  dl_relay = list->head;

  for ( i = 0; i < index; i++ )
  {
    dl_relay = dl_relay->next;
  }

  return dl_relay;
}

OnionRelay* px_get_relay_by_index(DoublyLinkedOnionRelayList* list, int index)
{
  DoublyLinkedOnionRelay* dl_relay;

  dl_relay = px_get_dl_relay_by_index(list, index);

  if (dl_relay == NULL)
    return NULL;

  return dl_relay->relay;
}
