#ifndef MINITOR_CONNECTIONS_H
#define MINITOR_CONNECTIONS_H

#include "./structures/circuit.h"
#include "./structures/connections.h"

extern MinitorMutex connections_mutex;
extern MinitorMutex connection_access_mutex[16];
extern DlConnection* connections;
extern MinitorQueue connections_task_queue;
extern MinitorQueue poll_task_queue;

void v_cleanup_connection( DlConnection* dl_connection );
void v_poll_daemon( void* pv_parameters );
void v_connections_daemon( void* pv_parameters );
int d_attach_or_connection( uint32_t address, uint16_t port, OnionCircuit* circuit );
int d_create_local_connection( uint32_t circ_id, uint16_t stream_id, uint16_t port );
int d_forward_to_local_connection( uint32_t circ_id, uint32_t stream_id, uint8_t* data, uint32_t length );
void v_cleanup_local_connection( uint32_t circ_id, uint32_t stream_id );
void v_cleanup_local_connections_by_circ_id( uint32_t circ_id );
bool b_verify_or_connection( uint32_t id );
void v_dettach_connection( DlConnection* or_connection );
DlConnection* px_get_conn_by_id_and_lock( uint32_t id );

#endif
