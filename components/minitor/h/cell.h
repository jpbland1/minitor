#ifndef MINITOR_CELL_H
#define MINITOR_CELL_H

#include "wolfssl/ssl.h"

#include "./structures/cell.h"
#include "./structures/consensus.h"
#include "./structures/circuit.h"

int d_send_packed_relay_cell_and_free( WOLFSSL* ssl, unsigned char* packed_cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto );
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha, OnionCircuit* rend_circuit );
int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, OnionCircuit* rend_circuit, int* recv_index );

#endif
