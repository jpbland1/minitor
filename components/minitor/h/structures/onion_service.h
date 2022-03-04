#ifndef MINITOR_STRUCTURES_ONION_SERVICE_H
#define MINITOR_STRUCTURES_ONION_SERVICE_H

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/ed25519.h"

#include "./consensus.h"
#include "./circuit.h"

typedef struct DoublyLinkedRendezvousCookie DoublyLinkedRendezvousCookie;
typedef struct DoublyLinkedLocalStream DoublyLinkedLocalStream;

struct DoublyLinkedRendezvousCookie {
  unsigned char rendezvous_cookie[20];
  DoublyLinkedRendezvousCookie* next;
  DoublyLinkedRendezvousCookie* previous;
};

typedef struct DoublyLinkedRendezvousCookieList {
  int length;
  DoublyLinkedRendezvousCookie* head;
  DoublyLinkedRendezvousCookie* tail;
} DoublyLinkedRendezvousCookieList;

typedef struct HsDirIndexNode {
  unsigned char hash[WC_SHA3_256_DIGEST_SIZE];
  OnionRelay* relay;
  unsigned char chosen;
} HsDirIndexNode;

struct DoublyLinkedLocalStream {
  int circ_id;
  int stream_id;
  QueueHandle_t rx_queue;
  int sock_fd;
  TaskHandle_t task_handle;
  DoublyLinkedLocalStream* next;
  DoublyLinkedLocalStream* previous;
};

typedef struct DoublyLinkedLocalStreamList {
  int length;
  DoublyLinkedLocalStream* head;
  DoublyLinkedLocalStream* tail;
} DoublyLinkedLocalStreamList;

typedef struct OnionService {
  unsigned short exit_port;
  unsigned short local_port;
  char* onion_service_directory;
  ed25519_key master_key;
  QueueHandle_t rx_queue;
  unsigned char current_sub_credential[WC_SHA3_256_DIGEST_SIZE];
  unsigned char previous_sub_credential[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedOnionCircuitList intro_circuits;
  DoublyLinkedOnionCircuitList rend_circuits;
  DoublyLinkedRendezvousCookieList rendezvous_cookies;
  DoublyLinkedLocalStreamList local_streams;
  unsigned int last_hsdir_update;
  time_t rend_timestamp;
} OnionService;

void v_add_rendezvous_cookie_to_list( DoublyLinkedRendezvousCookie* node, DoublyLinkedRendezvousCookieList* list );
void v_add_local_stream_to_list( DoublyLinkedLocalStream* node, DoublyLinkedLocalStreamList* list );

#endif
