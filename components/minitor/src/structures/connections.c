#include "../../h/structures/connections.h"

void v_add_connection_to_list( DlConnection* connection, DlConnection** list )
{
  connection->next = *list;
  connection->previous = NULL;

  if ( *list != NULL )
  {
    (*list)->previous = connection;
  }

  *list = connection;
}

void v_remove_connection_from_list( DlConnection* connection, DlConnection** list )
{
  if ( *list == connection )
  {
    *list = connection->next;
  }

  if ( connection->next != NULL )
  {
    connection->next->previous = connection->previous;
  }

  if ( connection->previous != NULL )
  {
    connection->previous->next = connection->next;
  }
}
