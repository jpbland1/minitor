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

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "../constants.h"

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
  bool suitable;
  bool hsdir;
  bool dir_cache;
  bool can_guard;
  bool can_exit;
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
void v_pop_relay_from_list_back( DoublyLinkedOnionRelayList* list );
OnionRelay* px_get_relay_by_index( DoublyLinkedOnionRelayList* list, int index );

// shared state must be protected by mutex
extern NetworkConsensus network_consensus;
extern SemaphoreHandle_t network_consensus_mutex;
extern SemaphoreHandle_t crypto_insert_finish;
extern TimerHandle_t consensus_timer;
extern TimerHandle_t consensus_valid_timer;

#endif
