#include <time.h>
#include "./config.h"

#define ID_LENGTH 20

typedef struct DoublyLinkedOnionRelay DoublyLinkedOnionRelay;

typedef struct NetworkConsensus {
  unsigned int method;
  unsigned int valid_after;
  unsigned int fresh_until;
  unsigned int valid_until;
  unsigned char previous_shared_rand[32];
  unsigned char shared_rand[32];
} NetworkConsensus;

typedef struct OnionRelay {
  unsigned char identity[ID_LENGTH];
  unsigned char digest[ID_LENGTH];
  unsigned int address;
  short or_port;
  short dir_port;
} OnionRelay;

struct DoublyLinkedOnionRelay {
  DoublyLinkedOnionRelay* previous;
  DoublyLinkedOnionRelay* next;
  OnionRelay* relay;
};

typedef struct DoublyLinkedOnionRelayList {
  int length;
  DoublyLinkedOnionRelay* head;
  DoublyLinkedOnionRelay* tail;
} DoublyLinkedOnionRelayList;

typedef struct TorCircuit {
  int circ_id;
  int sock_fd;
} TorCircuit;

typedef struct HiddenService {
  int hidden_service_id;
  int sock_fd;
} HiddenService;

typedef struct HiddenServiceMessage {
  int circ_id;
  int length;
  unsigned char* data;
} HiddenServiceMessage;

int v_minitor_INIT();
int d_fetch_consensus_info();
int d_parse_date_byte( char byte, int* year, int* year_found, int* month, int* month_found, int* day, int* day_found, int* hour, int* hour_found, int* minute, int* minute_found, int* second, int* second_found, struct tm* temp_time );
void v_base_64_decode_buffer( unsigned char* destination, char* source, int source_length );
void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list );
