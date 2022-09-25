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

void v_hostize_variable_short_cell( CellShortVariable* cell );
void v_hostize_variable_cell( CellVariable* cell );
void v_hostize_cell( Cell* cell );
void v_networkize_variable_short_cell( CellShortVariable* cell );
void v_networkize_variable_cell ( CellVariable* cell );
void v_networkize_cell( Cell* cell );

int d_send_cell_and_free( DlConnection* or_connection, Cell* cell );
int d_send_relay_cell_and_free( DlConnection* or_connection, Cell* cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto );
int d_recv_cell( WOLFSSL* ssl, uint8_t** cell, int circ_id_length );
int d_decrypt_cell( Cell* cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto );

#endif
