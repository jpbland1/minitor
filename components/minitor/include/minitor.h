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
#include "./cell.h"
#include "../h/consensus.h"

// typedef struct ed25519_key ed25519_key;

#define SERVER_STR "Server"
#define SERVER_STR_LENGTH 6

#define PROTOID "ntor-curve25519-sha256-1"
#define PROTOID_LENGTH 24
#define PROTOID_MAC PROTOID ":mac"
#define PROTOID_MAC_LENGTH PROTOID_LENGTH + 4
#define PROTOID_KEY PROTOID ":key_extract"
#define PROTOID_KEY_LENGTH PROTOID_LENGTH + 12
#define PROTOID_VERIFY PROTOID ":verify"
#define PROTOID_VERIFY_LENGTH PROTOID_LENGTH + 7
#define PROTOID_EXPAND PROTOID ":key_expand"
#define PROTOID_EXPAND_LENGTH PROTOID_LENGTH + 11

#define HS_PROTOID "tor-hs-ntor-curve25519-sha3-256-1"
#define HS_PROTOID_LENGTH 33
#define HS_PROTOID_MAC HS_PROTOID ":hs_mac"
#define HS_PROTOID_MAC_LENGTH HS_PROTOID_LENGTH + 7
#define HS_PROTOID_KEY HS_PROTOID ":hs_key_extract"
#define HS_PROTOID_KEY_LENGTH HS_PROTOID_LENGTH + 15
#define HS_PROTOID_VERIFY HS_PROTOID ":hs_verify"
#define HS_PROTOID_VERIFY_LENGTH HS_PROTOID_LENGTH + 10
#define HS_PROTOID_EXPAND HS_PROTOID ":hs_key_expand"
#define HS_PROTOID_EXPAND_LENGTH HS_PROTOID_LENGTH + 14

#define SECRET_INPUT_LENGTH 32 * 5 + ID_LENGTH + PROTOID_LENGTH
#define AUTH_INPUT_LENGTH 32 * 4 + ID_LENGTH + PROTOID_LENGTH + SERVER_STR_LENGTH

#define HS_ED_BASEPOINT "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
#define HS_ED_BASEPOINT_LENGTH 158
#define HS_DESC_SIG_PREFIX "Tor onion service descriptor sig v3"
#define HS_DESC_SIG_PREFIX_LENGTH 35

typedef struct DoublyLinkedOnionCircuit DoublyLinkedOnionCircuit;
typedef struct DoublyLinkedRendezvousCookie DoublyLinkedRendezvousCookie;
typedef struct DoublyLinkedLocalStream DoublyLinkedLocalStream;

typedef enum CircuitStatus {
  CIRCUIT_BUILDING,
  CIRCUIT_STANDBY,
  CIRCUIT_INTRO_POINT,
  CIRCUIT_PUBLISH,
  CIRCUIT_RENDEZVOUS,
} CircuitStatus;

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

typedef struct IntroCrypto {
  ed25519_key auth_key;
  curve25519_key encrypt_key;
} IntroCrypto;

typedef struct HsCrypto {
  Sha3 hs_running_sha_forward;
  Sha3 hs_running_sha_backward;
  Aes hs_aes_forward;
  Aes hs_aes_backward;
} HsCrypto;

typedef struct OnionCircuit {
  int circ_id;
  CircuitStatus status;
  WOLFSSL* ssl;
  QueueHandle_t rx_queue;
  TaskHandle_t task_handle;
  DoublyLinkedOnionRelayList relay_list;
  HsCrypto* hs_crypto;
  IntroCrypto* intro_crypto;
} OnionCircuit;

struct DoublyLinkedOnionCircuit {
  DoublyLinkedOnionCircuit* previous;
  DoublyLinkedOnionCircuit* next;
  OnionCircuit circuit;
};

typedef struct DoublyLinkedOnionCircuitList {
  int length;
  DoublyLinkedOnionCircuit* head;
  DoublyLinkedOnionCircuit* tail;
} DoublyLinkedOnionCircuitList;

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

typedef enum OnionMessageType {
  ONION_CELL,
  SERVICE_TCP_DATA,
  SERVICE_COMMAND,
} OnionMessageType;

typedef enum ServiceCommand {
  SERVICE_COMMAND_STOP,
} ServiceCommand;

typedef struct OnionMessage {
  OnionMessageType type;
  void* data;
} OnionMessage;

typedef struct ServiceTcpTraffic {
  int circ_id;
  int stream_id;
  int length;
  unsigned char* data;
} ServiceTcpTraffic;

int v_minitor_INIT();
void v_circuit_keepalive( void* pv_parameters );
void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list );
void v_add_circuit_to_list( DoublyLinkedOnionCircuit* node, DoublyLinkedOnionCircuitList* list );
void v_add_rendezvous_cookie_to_list( DoublyLinkedRendezvousCookie* node, DoublyLinkedRendezvousCookieList* list );
void v_add_local_stream_to_list( DoublyLinkedLocalStream* node, DoublyLinkedLocalStreamList* list );
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
int d_send_packed_relay_cell_and_free( WOLFSSL* ssl, unsigned char* packed_cell, DoublyLinkedOnionRelayList* relay_list, HsCrypto* hs_crypto );
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha, OnionCircuit* rend_circuit );
int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, OnionCircuit* rend_circuit );
unsigned int ud_get_cert_date( unsigned char* date_buffer, int date_size );
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
