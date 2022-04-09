#ifndef MINITOR_LOCAL_CONNECTION_H
#define MINITOR_LOCAL_CONNECTION_H

#include "./structures/local_connection.h"

extern SemaphoreHandle_t local_connections_mutex;

int d_create_local_connection( OnionService* onion_service, uint32_t circ_id, uint16_t stream_id );

#endif
