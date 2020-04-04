#ifndef MINITOR_MINITOR_H
#define MINITOR_MINITOR_H

#include <time.h>
#include "freertos/queue.h"

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
#define H_LENGTH 32
#define ID_LENGTH 20
#define G_LENGTH 32
#define DIGEST_LEN 20
#define SECRET_INPUT_LENGTH 32 * 5 + ID_LENGTH + PROTOID_LENGTH
#define AUTH_INPUT_LENGTH 32 * 4 + ID_LENGTH + PROTOID_LENGTH + SERVER_STR_LENGTH

#define HS_ED_BASEPOINT "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
#define HS_ED_BASEPOINT_LENGTH 158
#define HSDIR_INTERVAL_DEFAULT 1440
#define HSDIR_N_REPLICAS_DEFAULT 2
#define HSDIR_SPREAD_STORE_DEFAULT 4

typedef struct DoublyLinkedOnionRelay DoublyLinkedOnionRelay;
typedef struct DoublyLinkedOnionCircuit DoublyLinkedOnionCircuit;

typedef enum CircuitStatus {
  CIRCUIT_BUILDING,
  CIRCUIT_STANDBY,
  CIRCUIT_INTRO_POINT,
  CIRCUIT_RENDEZVOUS,
} CircuitStatus;

typedef struct NetworkConsensus {
  unsigned int method;
  long int valid_after;
  unsigned int fresh_until;
  unsigned int valid_until;
  unsigned char previous_shared_rand[32];
  unsigned char shared_rand[32];
  unsigned int hsdir_interval;
  unsigned int hsdir_n_replicas;
  unsigned int hsdir_spread_store;
} NetworkConsensus;

typedef struct OnionRelay {
  unsigned char identity[ID_LENGTH];
  unsigned char digest[ID_LENGTH];
  unsigned char ntor_onion_key[H_LENGTH];
  Sha running_sha_forward;
  Sha running_sha_backward;
  Aes aes_forward;
  Aes aes_backward;
  unsigned char nonce[DIGEST_LEN];
  unsigned int address;
  short or_port;
  short dir_port;
} OnionRelay;

struct DoublyLinkedOnionRelay {
  DoublyLinkedOnionRelay* previous;
  DoublyLinkedOnionRelay* next;
  OnionRelay* relay;
};

typedef struct DoublyLinkedOnionRelayList {
  int length;
  int built_length;
  DoublyLinkedOnionRelay* head;
  DoublyLinkedOnionRelay* tail;
} DoublyLinkedOnionRelayList;

typedef struct OnionCircuit {
  int circ_id;
  CircuitStatus status;
  WOLFSSL* ssl;
  QueueHandle_t rx_queue;
  TaskHandle_t task_handle;
  ed25519_key auth_key;
  curve25519_key intro_encrypt_key;
  DoublyLinkedOnionRelayList relay_list;
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

typedef struct OnionService {
  unsigned short exit_port;
  unsigned short local_port;
  char* onion_service_directory;
  ed25519_key master_key;
  QueueHandle_t rx_queue;
  DoublyLinkedOnionCircuitList intro_circuits;
  DoublyLinkedOnionCircuitList rend_circuits;
} OnionService;

typedef struct HiddenServiceMessage {
  int circ_id;
  int length;
  unsigned char* data;
} HiddenServiceMessage;

int v_minitor_INIT();
void v_circuit_keepalive( void* pv_parameters );
void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list );
int d_fetch_consensus_info();
int d_parse_date_byte( char byte, int* year, int* year_found, int* month, int* month_found, int* day, int* day_found, int* hour, int* hour_found, int* minute, int* minute_found, int* second, int* second_found, struct tm* temp_time );
void v_base_64_decode_buffer( unsigned char* destination, char* source, int source_length );
void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list );
int d_setup_init_circuits( int circuit_count );
int d_build_onion_circuit( DoublyLinkedOnionCircuit* linked_circuit );
void v_handle_circuit( void* pv_parameters );
int d_router_extend2( OnionCircuit* onion_circuit, int node_index );
int d_router_create2( OnionCircuit* onion_circuit );
int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key );
int d_ntor_handshake_finish( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key );
int d_router_handshake( WOLFSSL* ssl );
int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der );
int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng );
void v_destroy_onion_circuit( int circ_id );
int d_fetch_descriptor_info( DoublyLinkedOnionCircuit* linked_circuit );
int d_send_packed_relay_cell_and_free( unsigned char* packed_cell, OnionCircuit* circuit );
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha );
int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list );
unsigned int ud_get_cert_date( unsigned char* date_buffer, int date_size );
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory );
int d_router_establish_intro( OnionCircuit* circuit );
int d_derive_blinded_keys( unsigned char output_priv_key[ED25519_PRV_KEY_SIZE], ed25519_key* master_key, int64_t period_number, int64_t period_length, unsigned char nonce[32], unsigned char* secret, int secret_length );
int d_generate_hs_keys( OnionService* onion_service, const char* onion_service_directory );

#endif
