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

#ifndef MINITOR_STRUCTURES_CONSENSUS_H
#define MINITOR_STRUCTURES_CONSENSUS_H

#include "wolfssl/options.h"

#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "../port_types.h"

#include "../constants.h"

#define FAST_RELAY_MAX 100
#define CACHE_RELAY_MAX 100

typedef enum ConsensusStreams
{
  CONSENSUS_STREAM_ID = 1,
  DESCRIPTORS_STREAM_ID = 2,
} ConsensusStreams;

typedef enum ConsensusState
{
  FIND_R,
  FIND_S,
  FIND_PR,
  FIND_W,
} ConsensusState;

typedef enum DescriptorState
{
  REQUEST_DESCRIPTORS,
  FIND_STATUS,
  FIND_ROUTER,
  FIND_MASTER_KEY_ED25519,
  FIND_PROTO,
  FIND_SIGNING_KEY,
  PARSE_SIGNING_RSA_BEGIN,
  PARSE_SIGNING_RSA_END,
  NTOR_ONION_KEY,
} DescriptorState;

typedef struct DoublyLinkedOnionRelay DoublyLinkedOnionRelay;

typedef struct NetworkConsensus {
  unsigned int method;
  time_t valid_after;
  time_t fresh_until;
  time_t valid_until;
  unsigned char previous_shared_rand[32];
  unsigned char shared_rand[32];
  unsigned int hsdir_interval;
  unsigned int hsdir_n_replicas;
  unsigned int hsdir_spread_store;
  int time_period;
} NetworkConsensus;

typedef struct OnionRelay {
  unsigned char identity[ID_LENGTH];
  unsigned char digest[ID_LENGTH];
  unsigned char master_key[H_LENGTH];
  unsigned char ntor_onion_key[H_LENGTH];
  unsigned int address;
  uint16_t or_port;
  uint16_t dir_port;
  unsigned char id_hash[H_LENGTH];
  unsigned char id_hash_previous[H_LENGTH];
  bool fast;
  bool stable;
  bool hsdir;
  bool dir_cache;
  bool guard;
  bool exit;
  int bandwidth;
  int hsdir_seek;
  int cache_seek;
  int fast_seek;
} OnionRelay;

typedef struct RelayCrypto {
  wc_Sha running_sha_forward;
  wc_Sha running_sha_backward;
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
void v_pop_relay_from_list_back( DoublyLinkedOnionRelayList* list );
OnionRelay* px_get_relay_by_index( DoublyLinkedOnionRelayList* list, int index );

// shared state must be protected by mutex
extern NetworkConsensus network_consensus;
extern MinitorMutex network_consensus_mutex;
extern MinitorMutex crypto_insert_finish;
extern MinitorTimer consensus_timer;
extern MinitorTimer consensus_valid_timer;

#endif
