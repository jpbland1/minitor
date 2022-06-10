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

#include "../../h/structures/onion_service.h"

void v_add_rendezvous_cookie_to_list( DoublyLinkedRendezvousCookie* node, DoublyLinkedRendezvousCookieList* list ) {
  node->next = NULL;
  node->previous = NULL;

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

void v_add_service_to_list( OnionService* service, OnionService** list )
{
  service->next = *list;
  service->previous = NULL;

  if ( *list != NULL )
  {
    (*list)->previous = service;
  }

  *list = service;
}
