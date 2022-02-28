#include "../../h/structures/circuit.h"

unsigned int circ_id_counter = 0x80000000;
SemaphoreHandle_t circ_id_mutex;

DoublyLinkedOnionRelayList used_guards = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
SemaphoreHandle_t used_guards_mutex;

DoublyLinkedOnionCircuitList standby_circuits = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
SemaphoreHandle_t standby_circuits_mutex;

DoublyLinkedOnionCircuitList standby_rend_circuits = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
SemaphoreHandle_t standby_rend_circuits_mutex;

void v_add_circuit_to_list( DoublyLinkedOnionCircuit* node, DoublyLinkedOnionCircuitList* list ) {
  node->previous = NULL;
  node->next = NULL;

  if ( list->length == 0 ) {
    list->head = node;
    list->tail = node;
  } else {
    node->previous = list->tail;
    list->tail->next = node;
    list->tail = node;
  }

  list->length++;
}
