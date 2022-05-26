#ifndef MINITOR_STRUCTURES_ONION_SERVICE_H
#define MINITOR_STRUCTURES_ONION_SERVICE_H

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/ed25519.h"

#include "./consensus.h"

typedef struct DoublyLinkedRendezvousCookie {
  unsigned char rendezvous_cookie[20];
  struct DoublyLinkedRendezvousCookie* next;
  struct DoublyLinkedRendezvousCookie* previous;
} DoublyLinkedRendezvousCookie;

typedef struct DoublyLinkedRendezvousCookieList {
  int length;
  DoublyLinkedRendezvousCookie* head;
  DoublyLinkedRendezvousCookie* tail;
} DoublyLinkedRendezvousCookieList;

typedef struct OnionService
{
  struct OnionService* next;
  struct OnionService* previous;
  unsigned short exit_port;
  unsigned short local_port;
  ed25519_key master_key;
  unsigned char current_sub_credential[WC_SHA3_256_DIGEST_SIZE];
  unsigned char previous_sub_credential[WC_SHA3_256_DIGEST_SIZE];
  DoublyLinkedRendezvousCookieList rendezvous_cookies;
  time_t rend_timestamp;
  TimerHandle_t hsdir_timer;
  int intro_live_count;
  int hsdir_sent;
  int hsdir_to_send;
  DoublyLinkedOnionRelayList* target_relays[2];
  char hostname[63];
  char hs_descs[2][26];
} OnionService;

void v_add_service_to_list( OnionService* service, OnionService** list );
void v_add_rendezvous_cookie_to_list( DoublyLinkedRendezvousCookie* node, DoublyLinkedRendezvousCookieList* list );
//void v_add_local_stream_to_list( DoublyLinkedLocalStream* node, DoublyLinkedLocalStreamList* list );

#endif
