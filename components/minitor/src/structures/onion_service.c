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
