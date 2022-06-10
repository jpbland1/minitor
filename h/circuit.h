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

#ifndef MINITOR_CIRCUIT_H
#define MINITOR_CIRCUIT_H

#include "./structures/circuit.h"

#include "./cell.h"

//int d_setup_init_circuits( int circuit_count );
//int d_setup_init_rend_circuits( int circuit_count );
//int d_build_random_onion_circuit( OnionCircuit* circuit, int circuit_length );
//int d_build_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay );
//int d_extend_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay );
int d_prepare_onion_circuit( OnionCircuit* onion_circuit, int length, OnionRelay* start_relay, OnionRelay* destination_relay );
//int d_prepare_random_onion_circuit( OnionCircuit* circuit, int circuit_length, unsigned char* exclude );
int d_get_suitable_relay( DoublyLinkedOnionRelayList* relay_list, int guard, uint8_t* exclude_start, uint8_t* exclude_end );
int d_get_suitable_onion_relays( DoublyLinkedOnionRelayList* relay_list, int desired_length, uint8_t* exclude_start, uint8_t* exclude_end );
//int d_build_onion_circuit( OnionCircuit* circuit );
int d_destroy_onion_circuit( OnionCircuit* circuit );
int d_router_truncate( OnionCircuit* circuit, int new_length );
//void v_handle_circuit( void* pv_parameters );
int d_router_extend2( OnionCircuit* onion_circuit, int node_index );
int d_router_extended2( OnionCircuit* circuit, int node_index, Cell* extended2_cell );
int d_router_create2( OnionCircuit* onion_circuit );
int d_router_created2( OnionCircuit* circuit, Cell* unpacked_cell );
int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key );
int d_ntor_handshake_finish( unsigned char* handshake_data, DoublyLinkedOnionRelay* db_relay, curve25519_key* key );
int d_router_handshake( WOLFSSL* ssl );
int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der );
int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng );
void v_destroy_onion_circuit( int circ_id );
int d_start_v3_handshake( DlConnection* or_connection );
void v_process_versions( DlConnection* or_connection, uint8_t* packed_cell, int length );
int d_process_certs( DlConnection* or_connection, uint8_t* packed_cell, int length );
int d_process_challenge( DlConnection* or_connection, uint8_t* packed_cell, int length );
int d_process_netinfo( DlConnection* or_connection, uint8_t* packed_cell );

#endif
