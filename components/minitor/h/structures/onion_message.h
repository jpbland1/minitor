#ifndef MINITOR_STRUCTURES_ONION_MESSAGE_H
#define MINITOR_STRUCTURES_ONION_MESSAGE_H

#include "./onion_service.h"
#include "./circuit.h"

typedef enum OnionMessageType
{
  PACKED_CELL,
  SERVICE_TCP_DATA,
  CONN_READY,
  CONN_CLOSE,
  INIT_SERVICE,
  INIT_CIRCUIT,
  TIMER_CONSENSUS,
  TIMER_KEEPALIVE,
  TIMER_HSDIR,
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
  int desc_index;
  int target_relay_index;
  OnionRelay* start_relay;
  OnionRelay* end_relay;
  HsCrypto* hs_crypto;
} CreateCircuitRequest;

#endif
