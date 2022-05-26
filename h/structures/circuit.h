#ifndef MINITOR_STRUCTURES_CIRCUIT_H
#define MINITOR_STRUCTURES_CIRCUIT_H

#include "user_settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "./consensus.h"
#include "./cell.h"
#include "./connections.h"
#include "./onion_service.h"

// status tells us what kind of cell the circuit is looking for
// so CIRCUIT_CREATED means it expects to see a CREATED2 cell
typedef enum CircuitStatus
{
  CIRCUIT_CREATE,
  CIRCUIT_CREATED,
  CIRCUIT_EXTENDED,
  CIRCUIT_TRUNCATED,
  CIRCUIT_ESTABLISH_INTRO,
  CIRCUIT_INTRO_ESTABLISHED,
  CIRCUIT_HSDIR_BEGIN_DIR,
  CIRCUIT_HSDIR_CONNECTED,
  CIRCUIT_HSDIR_DATA,
  CIRCUIT_STANDBY,
  CIRCUIT_INTRO_LIVE,
  CIRCUIT_RENDEZVOUS,
} CircuitStatus;

typedef struct IntroCrypto
{
  ed25519_key auth_key;
  curve25519_key encrypt_key;
} IntroCrypto;

typedef struct HsCrypto
{
  Sha3 hs_running_sha_forward;
  Sha3 hs_running_sha_backward;
  Aes hs_aes_forward;
  Aes hs_aes_backward;
  uint8_t rendezvous_cookie[20];
  uint8_t point[PK_PUBKEY_LEN];
  uint8_t auth_input_mac[MAC_LEN];
} HsCrypto;

typedef struct OnionCircuit
{
  struct OnionCircuit* next;
  struct OnionCircuit* previous;
  uint32_t circ_id;
  CircuitStatus status;
  CircuitStatus target_status;
  DlConnection* or_connection;
  curve25519_key create2_handshake_key;
  DoublyLinkedOnionRelayList relay_list;
  HsCrypto* hs_crypto;
  IntroCrypto* intro_crypto;
  OnionService* service;
  int desc_index;
  int target_relay_index;
  int relay_early_count;
} OnionCircuit;

extern unsigned int circ_id_counter;
extern SemaphoreHandle_t circ_id_mutex;

void v_add_circuit_to_list( OnionCircuit* circuit, OnionCircuit** list );
void v_remove_circuit_from_list( OnionCircuit* circuit, OnionCircuit** list );
OnionCircuit* px_get_circuit_by_circ_id( OnionCircuit* list, uint32_t circ_id );

#endif
