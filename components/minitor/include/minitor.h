#ifndef MINITOR_MINITOR_H
#define MINITOR_MINITOR_H

#include <time.h>
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/ge_operations.h"
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "./config.h"
#include "../h/cell.h"
#include "../h/circuit.h"
#include "../h/consensus.h"
#include "../h/structures/onion_service.h"

int v_minitor_INIT();
void v_circuit_keepalive( void* pv_parameters );
void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list );
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory );

#endif
