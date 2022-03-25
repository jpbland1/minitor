#ifndef MINITOR_STRUCTURES_CIRCUIT_H
#define MINITOR_STRUCTURES_CIRCUIT_H

#include "user_settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "./consensus.h"

typedef struct OrConnection OrConnection;
typedef struct DoublyLinkedOnionCircuit DoublyLinkedOnionCircuit;

typedef enum CircuitStatus {
  CIRCUIT_BUILDING,
  CIRCUIT_STANDBY,
  CIRCUIT_INTRO_POINT,
  CIRCUIT_PUBLISH,
  CIRCUIT_RENDEZVOUS,
} CircuitStatus;

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
  OrConnection* or_connection;
  QueueHandle_t rx_queue;
  QueueHandle_t forward_queue;
  TaskHandle_t task_handle;
  DoublyLinkedOnionRelayList relay_list;
  HsCrypto* hs_crypto;
  IntroCrypto* intro_crypto;
} OnionCircuit;

struct DoublyLinkedOnionCircuit {
  DoublyLinkedOnionCircuit* previous;
  DoublyLinkedOnionCircuit* next;
  OnionCircuit* circuit;
};

typedef struct DoublyLinkedOnionCircuitList {
  int length;
  DoublyLinkedOnionCircuit* head;
  DoublyLinkedOnionCircuit* tail;
} DoublyLinkedOnionCircuitList;

extern unsigned int circ_id_counter;
extern SemaphoreHandle_t circ_id_mutex;

extern DoublyLinkedOnionCircuitList standby_circuits;
extern SemaphoreHandle_t standby_circuits_mutex;

extern DoublyLinkedOnionCircuitList standby_rend_circuits;
extern SemaphoreHandle_t standby_rend_circuits_mutex;

void v_add_circuit_to_list( DoublyLinkedOnionCircuit* node, DoublyLinkedOnionCircuitList* list );

#include "./or_connection.h"

#endif
