#ifndef MINITOR_CIRCUIT_H
#define MINITOR_CIRCUIT_H

#include "./structures/circuit.h"

#include "./cell.h"

int d_setup_init_circuits( int circuit_count );
int d_build_random_onion_circuit( OnionCircuit* circuit, int circuit_length );
int d_build_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay );
int d_extend_onion_circuit_to( OnionCircuit* circuit, int circuit_length, OnionRelay* destination_relay );
int d_prepare_random_onion_circuit( OnionCircuit* circuit, int circuit_length, unsigned char* exclude );
int d_get_suitable_onion_relays( DoublyLinkedOnionRelayList* relay_list, int desired_length, unsigned char* exclude );
int d_build_onion_circuit( OnionCircuit* circuit );
int d_destroy_onion_circuit( OnionCircuit* circuit );
int d_truncate_onion_circuit( OnionCircuit* circuit, int new_length );
void v_handle_circuit( void* pv_parameters );
int d_router_extend2( OnionCircuit* onion_circuit, int node_index );
int d_router_create2( OnionCircuit* onion_circuit );
int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key );
int d_ntor_handshake_finish( unsigned char* handshake_data, DoublyLinkedOnionRelay* db_relay, curve25519_key* key );
int d_router_handshake( WOLFSSL* ssl );
int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der );
int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng );
void v_destroy_onion_circuit( int circ_id );
int d_fetch_descriptor_info( OnionCircuit* circuit );

#endif
