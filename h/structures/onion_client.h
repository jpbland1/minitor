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

#ifndef MINITOR_STRUCTURES_ONION_CLIENT_H
#define MINITOR_STRUCTURES_ONION_CLIENT_H

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "./consensus.h"
#include "./circuit.h"

typedef struct OnionClient
{
  ed25519_key blinded_key;
  curve25519_key client_handshake_key;
  uint8_t onion_pubkey[32];
  DoublyLinkedOnionRelayList* target_relays;
  char hostname[63];
  MinitorQueue stream_queues[16];
  struct OnionCircuit* rend_circuit;
  struct OnionCircuit* intro_circuit;
  int hsdesc_header_finish_found;
  int hsdesc_ok_found;
  int hsdesc_content_length;
  int hsdesc_size;
  uint8_t* hsdesc;
  uint8_t sub_credential[WC_SHA3_256_DIGEST_SIZE];
  int num_intro_relays;
  int active_intro_relay;
  OnionRelay* intro_relays[3];
  struct IntroCrypto* intro_cryptos[3];
  bool intro_complete;
  bool intro_built;
  bool rendezvous_ready;
  uint8_t rendezvous_cookie[20];
  uint8_t* read_leftover;
  int read_leftover_offset;
  int read_leftover_length;
} OnionClient;

#endif
