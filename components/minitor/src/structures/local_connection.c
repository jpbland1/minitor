#include "../../h/structures/local_connection.h"

SemaphoreHandle_t local_connections_mutex;

void v_add_local_connection_to_list( DoublyLinkedLocalConnection* db_local_connection, DoublyLinkedLocalConnection** head )
{
  db_local_connection->next = NULL;
  db_local_connection->previous = NULL;

  if ( *head == NULL )
  {
    *head = db_local_connection;
  }
  else
  {
    (*head)->previous = db_local_connection;
    db_local_connection->next = *head;
    *head = db_local_connection;
  }
}

void v_pop_local_connection_from_list( DoublyLinkedLocalConnection* db_local_connection, DoublyLinkedLocalConnection** head )
{
  if ( db_local_connection == *head )
  {
    *head = db_local_connection->next;
  }

  if ( db_local_connection->next != NULL )
  {
    db_local_connection->next->previous = db_local_connection->previous;
  }

  if ( db_local_connection->previous != NULL )
  {
    db_local_connection->previous->next = db_local_connection->next;
  }
}
