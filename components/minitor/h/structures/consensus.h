#ifndef MINITOR_STRUCTURES_CONSENSUS
#define MINITOR_STRUCTURES_CONSENSUS

#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "../constants.h"

typedef struct DoublyLinkedOnionRelay DoublyLinkedOnionRelay;

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
  unsigned int address;
  short or_port;
  short dir_port;
  unsigned char hsdir;
} OnionRelay;

typedef struct RelayCrypto {
  Sha running_sha_forward;
  Sha running_sha_backward;
  Aes aes_forward;
  Aes aes_backward;
  unsigned char nonce[DIGEST_LEN];
} RelayCrypto;

struct DoublyLinkedOnionRelay {
  DoublyLinkedOnionRelay* previous;
  DoublyLinkedOnionRelay* next;
  OnionRelay* relay;
  RelayCrypto* relay_crypto;
};

typedef struct DoublyLinkedOnionRelayList {
  int length;
  int built_length;
  DoublyLinkedOnionRelay* head;
  DoublyLinkedOnionRelay* tail;
} DoublyLinkedOnionRelayList;

void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list );

// shared state must be protected by mutex
extern NetworkConsensus network_consensus;
extern SemaphoreHandle_t network_consensus_mutex;
extern DoublyLinkedOnionRelayList suitable_relays;
extern SemaphoreHandle_t suitable_relays_mutex;
extern DoublyLinkedOnionRelayList hsdir_relays;
extern SemaphoreHandle_t hsdir_relays_mutex;

#endif
