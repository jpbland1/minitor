#include "../../h/structures/or_connection.h"

OrConnectionList or_connections =
{
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
SemaphoreHandle_t or_connections_mutex;

void v_remove_or_connection_from_list( OrConnection* or_connection, OrConnectionList* list )
{
  if ( or_connection == list->head )
  {
    list->head = or_connection->next;
  }

  if ( or_connection == list->tail )
  {
    list->tail = or_connection->previous;
  }

  if ( or_connection->next != NULL )
  {
    or_connection->next->previous = or_connection->previous;
  }

  if ( or_connection->previous != NULL )
  {
    or_connection->previous->next = or_connection->next;
  }

  list->length--;
}

void v_add_or_connection_to_list( OrConnection* or_connection, OrConnectionList* list )
{
  or_connection->previous = NULL;
  or_connection->next = NULL;

  if ( list->length == 0 )
  {
    list->head = or_connection;
    list->tail = or_connection;
  }
  else
  {
    or_connection->previous = list->tail;
    list->tail->next = or_connection;
    list->tail = or_connection;
  }

  list->length++;
}

uint8_t b_verify_or_connection( OrConnection* or_connection, OrConnectionList* list )
{
  int i;
  OrConnection* working_or_connection;

  working_or_connection = list->head;

  for ( i = 0; i < list->length; i++ )
  {
    if ( working_or_connection == or_connection )
    {
      return 1;
    }

    working_or_connection = working_or_connection->next;
  }

  return 0;
}
