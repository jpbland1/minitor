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

#ifndef MINITOR_STRUCTURES_ONION_MESSAGE_H
#define MINITOR_STRUCTURES_ONION_MESSAGE_H

#include "./onion_service.h"
#include "./circuit.h"

typedef enum OnionMessageType
{
  TOR_CELL,
  SERVICE_TCP_DATA,
  CONN_HANDSHAKE,
  CONN_READY,
  CONN_CLOSE,
  INIT_SERVICE,
  INIT_CIRCUIT,
  TIMER_CONSENSUS,
  TIMER_KEEPALIVE,
  TIMER_HSDIR,
  TIMER_CIRCUIT_TIMEOUT,
  CLIENT_RENDEZVOUS_CIRCUIT_READY,
  CLIENT_RELAY_CONNECTED,
  CLIENT_RELAY_DATA,
  CLIENT_RELAY_END,
  CLIENT_CLOSED,
  CONSENSUS_FETCHED,
} OnionMessageType;

typedef struct OnionMessage
{
  OnionMessageType type;
  int length;
  void* data;
} OnionMessage;

typedef struct ServiceTcpTraffic
{
  int circ_id;
  int stream_id;
  int length;
  unsigned char* data;
} ServiceTcpTraffic;

typedef struct CreateCircuitRequest
{
  int length;
  CircuitStatus target_status;
  OnionService* service;
  OnionClient* client;
  int desc_index;
  int target_relay_index;
  OnionRelay* start_relay;
  OnionRelay* end_relay;
  HsCrypto* hs_crypto;
  IntroCrypto* intro_crypto;
  char* onion_address;
  uint16_t onion_port;
  MinitorQueue client_queue;
} CreateCircuitRequest;

#endif
