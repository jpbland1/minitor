#ifndef MINITOR_STRUCTURES_LOCAL_CONNECTION_H
#define MINITOR_STRUCTURES_LOCAL_CONNECTION_H

#include "user_settings.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

typedef struct LocalConnection
{
  QueueHandle_t forward_queue;
  SemaphoreHandle_t access_mutex;
  uint32_t circ_id;
  uint16_t stream_id;
  int sock_fd;
  int poll_index;
} LocalConnection;

typedef struct DoublyLinkedLocalConnection
{
  struct DoublyLinkedLocalConnection* next;
  struct DoublyLinkedLocalConnection* previous;
  LocalConnection* connection;
} DoublyLinkedLocalConnection;

void v_add_local_connection_to_list( DoublyLinkedLocalConnection* db_local_connection, DoublyLinkedLocalConnection** head );
void v_pop_local_connection_from_list( DoublyLinkedLocalConnection* db_local_connection, DoublyLinkedLocalConnection** head );

#endif
