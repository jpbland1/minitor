typedef enum OnionMessageType {
  ONION_CELL,
  SERVICE_TCP_DATA,
  SERVICE_COMMAND,
} OnionMessageType;

typedef enum ServiceCommand {
  SERVICE_COMMAND_STOP,
} ServiceCommand;

typedef struct OnionMessage {
  OnionMessageType type;
  void* data;
} OnionMessage;
