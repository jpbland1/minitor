#ifndef MINITOR_MINITOR_H
#define MINITOR_MINITOR_H

#include <time.h>
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/ge_operations.h"
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "./config.h"
#include "../h/cell.h"
#include "../h/circuit.h"
#include "../h/consensus.h"

#define HS_ED_BASEPOINT "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
#define HS_ED_BASEPOINT_LENGTH 158
#define HS_DESC_SIG_PREFIX "Tor onion service descriptor sig v3"
#define HS_DESC_SIG_PREFIX_LENGTH 35

typedef struct DoublyLinkedRendezvousCookie DoublyLinkedRendezvousCookie;
typedef struct DoublyLinkedLocalStream DoublyLinkedLocalStream;

struct DoublyLinkedRendezvousCookie {
  unsigned char rendezvous_cookie[20];
  DoublyLinkedRendezvousCookie* next;
  DoublyLinkedRendezvousCookie* previous;
};

typedef struct DoublyLinkedRendezvousCookieList {
  int length;
  DoublyLinkedRendezvousCookie* head;
  DoublyLinkedRendezvousCookie* tail;
} DoublyLinkedRendezvousCookieList;

typedef struct HsDirIndexNode {
  unsigned char hash[WC_SHA3_256_DIGEST_SIZE];
  OnionRelay* relay;
  unsigned char chosen;
} HsDirIndexNode;

struct DoublyLinkedLocalStream {
  int circ_id;
  int stream_id;
  QueueHandle_t rx_queue;
  int sock_fd;
  DoublyLinkedLocalStream* next;
  DoublyLinkedLocalStream* previous;
};

typedef struct DoublyLinkedLocalStreamList {
  int length;
  DoublyLinkedLocalStream* head;
  DoublyLinkedLocalStream* tail;
} DoublyLinkedLocalStreamList;

typedef struct OnionService {
  unsigned short exit_port;
  unsigned short local_port;
  char* onion_service_directory;
  ed25519_key master_key;
  QueueHandle_t rx_queue;
  unsigned char* current_sub_credential;
  unsigned char* previous_sub_credential;
  DoublyLinkedOnionCircuitList intro_circuits;
  DoublyLinkedOnionCircuitList rend_circuits;
  DoublyLinkedRendezvousCookieList rendezvous_cookies;
  DoublyLinkedLocalStreamList local_streams;
} OnionService;

typedef struct ServiceTcpTraffic {
  int circ_id;
  int stream_id;
  int length;
  unsigned char* data;
} ServiceTcpTraffic;

int v_minitor_INIT();
void v_circuit_keepalive( void* pv_parameters );
void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list );
void v_add_rendezvous_cookie_to_list( DoublyLinkedRendezvousCookie* node, DoublyLinkedRendezvousCookieList* list );
void v_add_local_stream_to_list( DoublyLinkedLocalStream* node, DoublyLinkedLocalStreamList* list );
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory );
void v_handle_onion_service( void* pv_parameters );
int d_onion_service_handle_local_tcp_data( OnionService* onion_service, ServiceTcpTraffic* tcp_traffic );
int d_onion_service_handle_cell( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_data( OnionService* onion_service, Cell* unpacked_cell );
int d_onion_service_handle_relay_begin( OnionService* onion_service, Cell* unpacked_cell );
void v_handle_local( void* pv_parameters );
int d_onion_service_handle_introduce_2( OnionService* onion_service, Cell* unpacked_cell );
int d_router_join_rendezvous( OnionCircuit* rend_circuit, unsigned char* rendezvous_cookie, unsigned char* hs_pub_key, unsigned char* auth_input_mac );
int d_verify_and_decrypt_introduce_2( OnionService* onion_service, Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* client_handshake_key );
int d_hs_ntor_handshake_finish( Cell* unpacked_cell, OnionCircuit* intro_circuit, curve25519_key* hs_handshake_key, curve25519_key* client_handshake_key, OnionCircuit* rend_circuit, unsigned char* auth_input_mac );
int d_send_descriptors( unsigned char* descriptor_text, int descriptor_length, unsigned int hsdir_n_replicas, unsigned char* blinded_pub_key, int time_period, unsigned int hsdir_interval, unsigned char* shared_rand, unsigned int hsdir_spread_store );
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

#endif
