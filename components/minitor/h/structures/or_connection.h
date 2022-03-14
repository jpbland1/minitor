#ifndef MINITOR_STRUCTURES_OR_CONNECTION_H
#define MINITOR_STRUCTURES_OR_CONNECTION_H

#include "user_settings.h"
#include "wolfssl/ssl.h"

#include "./circuit.h"

typedef struct OrConnection
{
  struct OrConnection* next;
  struct OrConnection* previous;
  uint32_t address;
  uint16_t port;
  WOLFSSL* ssl;
  SemaphoreHandle_t access_mutex;
  DoublyLinkedOnionCircuitList circuits;
  TaskHandle_t task_handle;
} OrConnection;

typedef struct OrConnectionList
{
  OrConnection* head;
  OrConnection* tail;
  uint32_t length;
} OrConnectionList;

extern SemaphoreHandle_t or_connections_mutex;
extern OrConnectionList or_connections;

void v_remove_or_connection_from_list( OrConnection* or_connection, OrConnectionList* list );
void v_add_or_connection_to_list( OrConnection* or_connection, OrConnectionList* list );
uint8_t b_verify_or_connection( OrConnection* or_connection, OrConnectionList* list );

#endif
