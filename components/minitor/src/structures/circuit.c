#include "../../h/structures/circuit.h"

unsigned int circ_id_counter = 0x80000000;
SemaphoreHandle_t circ_id_mutex;

void v_add_circuit_to_list( OnionCircuit* circuit, OnionCircuit** list )
{
  circuit->next = *list;
  circuit->previous = NULL;

  if ( *list != NULL )
  {
    (*list)->previous = circuit;
  }

  *list = circuit;
}

void v_remove_circuit_from_list( OnionCircuit* circuit, OnionCircuit** list )
{
  if ( *list == circuit )
  {
    *list = circuit->next;
  }

  if ( circuit->next != NULL )
  {
    circuit->next->previous = circuit->previous;
  }

  if ( circuit->previous != NULL )
  {
    circuit->previous->next = circuit->next;
  }
}

OnionCircuit* px_get_circuit_by_circ_id( OnionCircuit* list, uint32_t circ_id )
{
  while ( list != NULL )
  {
    if ( circ_id == list->circ_id )
    {
      break;
    }

    list = list->next;
  }

  return list;
}
