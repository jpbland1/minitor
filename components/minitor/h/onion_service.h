#ifndef MINITOR_ONION_SERVICE_H
#define MINITOR_ONION_SERVICE_H

#include "user_settings.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"

#include "./structures/onion_service.h"
#include "./structures/onion_message.h"
#include "./structures/cell.h"

void v_handle_onion_service( void* pv_parameters );
int d_onion_service_handle_local_tcp_data( OnionService* onion_service, ServiceTcpTraffic* tcp_traffic );
int d_onion_service_handle_cell( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_data( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_begin( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_end( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_truncated( OnionService* onion_service, Cell* unpacked_cell );
void v_handle_local( void* pv_parameters );
int d_onion_service_handle_introduce_2( OnionService* onion_service, Cell* unpacked_cell );
int d_router_join_rendezvous( OnionCircuit* rend_circuit, unsigned char* rendezvous_cookie, unsigned char* hs_pub_key, unsigned char* auth_input_mac );
int d_verify_and_decrypt_introduce_2( OnionService* onion_service, Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* client_handshake_key );
int d_hs_ntor_handshake_finish( Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* hs_handshake_key, curve25519_key* client_handshake_key, HsCrypto* hs_crypto, unsigned char* auth_input_mac );
int d_send_descriptors( unsigned char* descriptor_text, int descriptor_length, DoublyLinkedOnionRelayList* target_relays );
int d_post_descriptor( unsigned char* descriptor_text, int descriptor_length, OnionCircuit* publish_circuit );
void v_binary_insert_hsdir_index( HsDirIndexNode* node, HsDirIndexNode** index_array, int index_length );
int d_binary_search_hsdir_index( unsigned char* hash, HsDirIndexNode** index_array, int index_length );
int d_generate_outer_descriptor( unsigned char** outer_layer, unsigned char* ciphertext, int ciphertext_length, ed25519_key* descriptor_signing_key, long int valid_after, ed25519_key* blinded_key, int revision_counter );
int d_generate_first_plaintext( unsigned char** first_layer, unsigned char* ciphertext, int ciphertext_length );
int d_encrypt_descriptor_plaintext( unsigned char** ciphertext, unsigned char* plaintext, int plaintext_length, unsigned char* secret_data, int secret_data_length, const char* string_constant, int string_constant_length, unsigned char* sub_credential, int64_t revision_counter );
int d_generate_second_plaintext( unsigned char** second_layer, DoublyLinkedOnionCircuitList* intro_circuits, long int valid_after, ed25519_key* descriptor_signing_key );
void v_generate_packed_link_specifiers( OnionRelay* relay, unsigned char* packed_link_specifiers );
int d_generate_packed_crosscert( unsigned char* destination, unsigned char* certified_key, ed25519_key* signing_key, unsigned char cert_type, long int valid_after );
void v_ed_pubkey_from_curve_pubkey( unsigned char* output, const unsigned char* input, int sign_bit );
int d_router_establish_intro( OnionCircuit* circuit );
int d_derive_blinded_key( ed25519_key* blinded_key, ed25519_key* master_key, int64_t period_number, int64_t period_length, unsigned char* secret, int secret_length );
int d_generate_hs_keys( OnionService* onion_service, const char* onion_service_directory );
int d_push_hsdir();

#endif
