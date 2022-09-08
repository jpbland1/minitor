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

#ifndef MINITOR_ONION_CLIENT_H
#define MINITOR_ONION_CLIENT_H

#include "./structures/onion_client.h"
#include "./structures/connections.h"
#include "./structures/circuit.h"
#include "./structures/cell.h"

#include "../include/minitor_client.h"

void v_cleanup_client_data( OnionClient* client );
int d_derive_blinded_pubkey( ed25519_key* blinded_key, uint8_t* master_pubkey, int64_t period_number, int64_t period_length, uint8_t* secret, int secret_length );
int d_get_hs_desc( OnionCircuit* circuit, DlConnection* or_connection );
int d_parse_hsdesc( OnionCircuit* circuit, Cell* cell );
int d_decrypt_descriptor_ciphertext( uint8_t* plaintext, uint8_t* ciphertext, int length, uint8_t* onion_pubkey, uint8_t* secret_data, int secret_data_length, char* string_constant, int string_constant_length, uint64_t revision_counter, uint8_t* sub_credential );
int d_client_send_intro( OnionCircuit* circuit, DlConnection* or_connection );
int d_client_establish_rendezvous( OnionCircuit* circuit, DlConnection* or_connection );
int d_client_join_rendezvous( OnionCircuit* circuit, DlConnection* or_connection, Cell* rend_cell );
int d_client_relay_data( OnionCircuit* circuit, Cell* data_cell );
int d_client_relay_end( OnionCircuit* circuit, Cell* end_cell );
int d_client_relay_connected( OnionCircuit* circuit, Cell* connected_cell );
void v_onion_client_handle_cell( OnionCircuit* circuit, DlConnection* or_connection, Cell* cell );

#endif
