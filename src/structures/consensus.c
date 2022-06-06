#include <stddef.h>

#include "../../include/config.h"
#include "../../h/structures/consensus.h"

TimerHandle_t consensus_timer;
TimerHandle_t consensus_valid_timer;

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
SemaphoreHandle_t network_consensus_mutex;
SemaphoreHandle_t crypto_insert_finish;

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

OnionRelay* px_get_relay_by_index( DoublyLinkedOnionRelayList* list, int index )
{
  int i;
  DoublyLinkedOnionRelay* dl_relay;

  dl_relay = list->head;

  for ( i = 0; i < index; i++ )
  {
    dl_relay = dl_relay->next;
  }

  if ( dl_relay == NULL )
  {
    return NULL;
  }

  return dl_relay->relay;
}
