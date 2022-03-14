#ifndef MINITOR_STRUCTURES_ONION_MESSAGE_H
#define MINITOR_STRUCTURES_ONION_MESSAGE_H

typedef enum OnionMessageType {
  PACKED_CELL,
  ONION_CELL,
  SERVICE_TCP_DATA,
  SERVICE_COMMAND,
} OnionMessageType;

typedef enum ServiceCommand {
  SERVICE_COMMAND_STOP,
} ServiceCommand;

typedef struct OnionMessage {
  OnionMessageType type;
  int length;
  void* data;
} OnionMessage;

typedef struct ServiceTcpTraffic {
  int circ_id;
  int stream_id;
  int length;
  unsigned char* data;
} ServiceTcpTraffic;

#endif
