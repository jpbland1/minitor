#ifndef MINITOR_MINITOR_H
#define MINITOR_MINITOR_H

#include <time.h>
#include "freertos/queue.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"
#include "./cell.h"
#include "./config.h"

typedef struct ed25519_key ed25519_key;

#define H_LENGTH 32
#define ID_LENGTH 20
#define G_LENGTH 32

typedef struct DoublyLinkedOnionRelay DoublyLinkedOnionRelay;
typedef struct DoublyLinkedOnionCircuit DoublyLinkedOnionCircuit;

typedef enum CircuitStatus {
  CIRCUIT_STANDBY,
} CircuitStatus;

typedef struct NetworkConsensus {
  unsigned int method;
  unsigned int valid_after;
  unsigned int fresh_until;
  unsigned int valid_until;
  unsigned char previous_shared_rand[32];
  unsigned char shared_rand[32];
} NetworkConsensus;

typedef struct OnionRelay {
  unsigned char identity[ID_LENGTH];
  unsigned char digest[ID_LENGTH];
  unsigned char ntor_onion_key[H_LENGTH];
  ed25519_key* ed_identity_key;
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
  DoublyLinkedOnionRelay* head;
  DoublyLinkedOnionRelay* tail;
} DoublyLinkedOnionRelayList;

typedef struct OnionCircuit {
  int circ_id;
  int sock_fd;
  DoublyLinkedOnionRelayList relay_list;
} OnionCircuit;

struct DoublyLinkedOnionCircuit {
  CircuitStatus status;
  QueueHandle_t rx_queue;
  TaskHandle_t task_handle;
  DoublyLinkedOnionCircuit* previous;
  DoublyLinkedOnionCircuit* next;
  OnionCircuit circuit;
};

typedef struct CircuitCommand {
} CircuitCommand;

typedef struct DoublyLinkedOnionCircuitList {
  int length;
  DoublyLinkedOnionCircuit* head;
  DoublyLinkedOnionCircuit* tail;
} DoublyLinkedOnionCircuitList;

typedef struct HiddenService {
  int hidden_service_id;
  int sock_fd;
} HiddenService;

typedef struct HiddenServiceMessage {
  int circ_id;
  int length;
  unsigned char* data;
} HiddenServiceMessage;

int v_minitor_INIT();
int d_fetch_consensus_info();
int d_parse_date_byte( char byte, int* year, int* year_found, int* month, int* month_found, int* day, int* day_found, int* hour, int* hour_found, int* minute, int* minute_found, int* second, int* second_found, struct tm* temp_time );
void v_base_64_decode_buffer( unsigned char* destination, char* source, int source_length );
void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list );
int d_setup_init_circuits();
int d_build_onion_circuit( DoublyLinkedOnionCircuit* linked_circuit );
int d_router_handshake( WOLFSSL* ssl );
int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der );
int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng );
void v_destroy_onion_circuit( int circ_id );
int d_fetch_descriptor_info( DoublyLinkedOnionCircuit* linked_circuit );
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, Sha256* sha );
unsigned int ud_get_cert_date( unsigned char* date_buffer, int date_size );

#endif
