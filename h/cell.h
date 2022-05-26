#ifndef MINITOR_CELL_H
#define MINITOR_CELL_H

#include "wolfssl/ssl.h"

#include "./structures/cell.h"
#include "./structures/consensus.h"
#include "./structures/circuit.h"
#include "./connections.h"

int d_send_packed_cell_and_free( DlConnection* or_connection, unsigned char* packed_cell );
int d_send_packed_relay_cell_and_free( DlConnection* or_connection, unsigned char* packed_cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto );
//int d_recv_cell( OnionCircuit* circuit, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha, HsCrypto* hs_crypto );
int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length );
int d_decrypt_packed_cell( uint8_t* packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto, int* recv_index );

#endif
