/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
