#ifndef MINITOR_OR_CONNECTION_H
#define MINITOR_OR_CONNECTION_H

#include "./structures/or_connection.h"

void v_cleanup_or_connection( OrConnection* or_connection );
void v_handle_or_connection( void* pv_parameters );
void v_dettach_connection( OnionCircuit* circuit );
int d_attach_connection( uint32_t address, uint16_t port, OnionCircuit* circuit );
OrConnection* px_create_connection( uint32_t address, uint16_t port );

#endif
