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

#include "../../h/structures/circuit.h"

unsigned int circ_id_counter = 0x80000000;
MinitorMutex circ_id_mutex;

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
