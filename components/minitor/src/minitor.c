#include "../include/minitor.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"

WOLFSSL_CTX* xMinitorWolfSSL_Context;

static void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list ) {
  int i;
  Cell padding_cell;
  DoublyLinkedOnionCircuit* node;
  unsigned char* packed_cell;

  padding_cell.command = PADDING;
  padding_cell.payload = NULL;
  node = list->head;

  for ( i = 0; i < list->length; i++ ) {
    padding_cell.circ_id = node->circuit.circ_id;
    packed_cell = pack_and_free( &padding_cell );

    if ( wolfSSL_send( node->circuit.ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send padding cell on circ_id: %d", node->circuit.circ_id );
#endif
    }

    free( packed_cell );
    node = node->next;
  }
}

static void v_circuit_keepalive( void* pv_parameters ) {
  while ( 1 ) {
    xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );
    v_keep_circuitlist_alive( &standby_circuits );
    xSemaphoreGive( standby_circuits_mutex );
    vTaskDelay( 1000 * 60 / portTICK_PERIOD_MS );
  }
}

// intialize tor
int v_minitor_INIT() {
  circ_id_mutex = xSemaphoreCreateMutex();
  network_consensus_mutex = xSemaphoreCreateMutex();
  suitable_relays_mutex = xSemaphoreCreateMutex();
  used_guards_mutex = xSemaphoreCreateMutex();
  hsdir_relays_mutex = xSemaphoreCreateMutex();
  standby_circuits_mutex = xSemaphoreCreateMutex();

  wolfSSL_Init();
  wolfSSL_Debugging_ON();

  if ( ( xMinitorWolfSSL_Context = wolfSSL_CTX_new( wolfTLSv1_2_client_method() ) ) == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't setup wolfssl context" );
#endif

    return -1;
  }

  // fetch network consensus
  if ( d_fetch_consensus_info() < 0 ) {
    return -1;
  }

  xTaskCreatePinnedToCore(
    v_circuit_keepalive,
    "CIRCUIT_KEEPALIVE",
    4096,
    NULL,
    6,
    NULL,
    tskNO_AFFINITY
  );

  return 1;
}

// ONION SERVICES
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory ) {
  int i;
  unsigned int idx;
  int wolf_succ;
  long int valid_after;
  unsigned int hsdir_interval;
  unsigned int hsdir_n_replicas;
  unsigned int hsdir_spread_store;
  int time_period = 0;
  unsigned char previous_shared_rand[32];
  unsigned char shared_rand[32];
  DoublyLinkedOnionCircuit* node;
  int reusable_text_length;
  unsigned char* reusable_plaintext;
  unsigned char* reusable_ciphertext;
  WC_RNG rng;
  ed25519_key blinded_key;
  ed25519_key descriptor_signing_key;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char blinded_pub_key[ED25519_PUB_KEY_SIZE];
  OnionService* onion_service = malloc( sizeof( OnionService ) );

  wc_InitRng( &rng );

  wc_ed25519_init( &blinded_key );
  blinded_key.expanded = 1;

  wc_ed25519_init( &descriptor_signing_key );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  wc_ed25519_make_key( &rng, 32, &descriptor_signing_key );

  wc_FreeRng( &rng );

  onion_service->local_port = local_port;
  onion_service->exit_port = exit_port;
  onion_service->rx_queue = xQueueCreate( 5, sizeof( OnionMessage* ) );
  onion_service->rend_circuits.length = 0;
  onion_service->rend_circuits.head = NULL;
  onion_service->rend_circuits.tail = NULL;
  onion_service->rendezvous_cookies.length = 0;
  onion_service->rendezvous_cookies.head = NULL;
  onion_service->rendezvous_cookies.tail = NULL;
  onion_service->local_streams.length = 0;
  onion_service->local_streams.head = NULL;
  onion_service->local_streams.tail = NULL;

  if ( d_generate_hs_keys( onion_service, onion_service_directory ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate hs keys" );
#endif

    return NULL;
  }

  // setup starting circuits
  if ( d_setup_init_circuits( 3 ) < 3 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to setup init circuits" );
#endif

    return NULL;
  }

  // take two circuits from the standby circuits list
  // BEGIN mutex
  xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

  if ( standby_circuits.length < 3 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Not enough standby circuits to register intro points" );
#endif

    xSemaphoreGive( standby_circuits_mutex );
    // END mutex

    return NULL;
  }

  // set the onion services head to the standby circuit head
  onion_service->intro_circuits.head = standby_circuits.head;
  // set the onion services tail to the second standby circuit
  onion_service->intro_circuits.tail = standby_circuits.head->next->next;

  // if there is a fourth standby circuit, set its previous to NULL
  if ( standby_circuits.length > 3 ) {
    standby_circuits.head->next->next->next->previous = NULL;
  }

  // set the standby circuit head to the thrid, possibly NULL
  standby_circuits.head = standby_circuits.head->next->next->next;
  // disconnect our tail from the other standby circuits
  onion_service->intro_circuits.tail->next = NULL;
  // set our intro length to three
  onion_service->intro_circuits.length = 3;
  // subtract three from the standby_circuits length
  standby_circuits.length -= 3;

  xSemaphoreGive( standby_circuits_mutex );
  // END mutex

  // send establish intro commands to our three circuits
  node = onion_service->intro_circuits.head;

  for ( i = 0; i < onion_service->intro_circuits.length; i++ ) {
    node->circuit.rx_queue = onion_service->rx_queue;

    if ( d_router_establish_intro( &node->circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to establish intro with a circuit" );
#endif

      return NULL;
    }

    node->circuit.status = CIRCUIT_INTRO_POINT;

    node = node->next;
  }

  // BEGIN mutex
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  valid_after = network_consensus.valid_after;
  hsdir_interval = network_consensus.hsdir_interval;
  hsdir_n_replicas = network_consensus.hsdir_n_replicas;
  hsdir_spread_store = network_consensus.hsdir_spread_store;
  memcpy( previous_shared_rand, network_consensus.previous_shared_rand, 32 );
  memcpy( shared_rand, network_consensus.shared_rand, 32 );

  xSemaphoreGive( network_consensus_mutex );
  // END mutex

  time_period = ( valid_after / 60 - 12 * 60 ) / hsdir_interval;

  /* for ( i = 0; i < 2; i++ ) { */
  for ( i = 0; i < 1; i++ ) {
    if ( d_derive_blinded_key( &blinded_key, &onion_service->master_key, time_period, hsdir_interval, NULL, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to derive the blinded key" );
#endif

      return NULL;
    }

    idx = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_public( &blinded_key, blinded_pub_key, &idx );

    if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export blinded public key" );
#endif

      return NULL;
    }


    ESP_LOGE( MINITOR_TAG, "Generating second plaintext" );
    // generate second layer plaintext
    if ( ( reusable_text_length = d_generate_second_plaintext( &reusable_plaintext, &onion_service->intro_circuits, valid_after, &descriptor_signing_key ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate second layer descriptor plaintext" );
#endif

      return NULL;
    }

    ESP_LOGE( MINITOR_TAG, "Creating sub cred" );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"credential", strlen( "credential" ) );
    wc_Sha3_256_Update( &reusable_sha3, onion_service->master_key.p, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"subcredential", strlen( "subcredential" ) );
    wc_Sha3_256_Update( &reusable_sha3, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, blinded_pub_key, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    if ( i == 0 ) {
      ESP_LOGE( MINITOR_TAG, "Storing current sub cred" );
      onion_service->current_sub_credential = malloc( sizeof( unsigned char ) * WC_SHA3_256_DIGEST_SIZE );
      memcpy( onion_service->current_sub_credential, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    } else {
      ESP_LOGE( MINITOR_TAG, "Storing previous sub cred" );
      onion_service->previous_sub_credential = malloc( sizeof( unsigned char ) * WC_SHA3_256_DIGEST_SIZE );
      memcpy( onion_service->previous_sub_credential, reusable_sha3_sum, WC_SHA3_256_DIGEST_SIZE );
    }

    ESP_LOGE( MINITOR_TAG, "Encrypting second plaintext, length %d", reusable_text_length );

    // encrypt second layer plaintext
    if ( (
      reusable_text_length = d_encrypt_descriptor_plaintext(
        &reusable_ciphertext,
        reusable_plaintext,
        reusable_text_length,
        blinded_pub_key,
        ED25519_PUB_KEY_SIZE,
        "hsdir-encrypted-data",
        strlen( "hsdir-encrypted-data" ),
        reusable_sha3_sum, 0 )
      ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt second layer descriptor plaintext" );
#endif

      return NULL;
    }

    free( reusable_plaintext );

    ESP_LOGE( MINITOR_TAG, "Generating first plaintext, length %d", reusable_text_length );
    // create first layer plaintext
    if ( ( reusable_text_length = d_generate_first_plaintext( &reusable_plaintext, reusable_ciphertext, reusable_text_length ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate first layer descriptor plaintext" );
#endif

      return NULL;
    }

    free( reusable_ciphertext );

    ESP_LOGE( MINITOR_TAG, "Encrypting first plaintext, length %d", reusable_text_length );

    // encrypt first layer plaintext
    if ( (
      reusable_text_length = d_encrypt_descriptor_plaintext(
        &reusable_ciphertext,
        reusable_plaintext,
        reusable_text_length,
        blinded_pub_key,
        ED25519_PUB_KEY_SIZE,
        "hsdir-superencrypted-data",
        strlen( "hsdir-superencrypted-data" ),
        reusable_sha3_sum, 0 )
      ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt first layer descriptor plaintext" );
#endif

      return NULL;
    }

    free( reusable_plaintext );

    ESP_LOGE( MINITOR_TAG, "Generating outer plaintext, length %d", reusable_text_length );

    // create outer descriptor wrapper
    if ( ( reusable_text_length = d_generate_outer_descriptor( &reusable_plaintext, reusable_ciphertext, reusable_text_length, &descriptor_signing_key, valid_after, &blinded_key, 0 ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to generate outer descriptor" );
#endif

      return NULL;
    }

    free( reusable_ciphertext );

    ESP_LOGE( MINITOR_TAG, "Sending descriptor length: %d", reusable_text_length );

    // send outer descriptor wrapper to the correct HSDIR nodes
    if ( d_send_descriptors( reusable_plaintext + HS_DESC_SIG_PREFIX_LENGTH, reusable_text_length, hsdir_n_replicas, blinded_pub_key, time_period, hsdir_interval, previous_shared_rand, hsdir_spread_store ) ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send descriptor to hsdir hosts" );
#endif

      return NULL;
    }

    free( reusable_plaintext );

    time_period--;
    memcpy( shared_rand, previous_shared_rand, 32 );
  }

  // create a task to block on the rx_queue
  xTaskCreatePinnedToCore(
    v_handle_onion_service,
    "HANDLE_HS",
    8192,
    (void*)(onion_service),
    6,
    NULL,
    tskNO_AFFINITY
  );

  // return the onion service
  return onion_service;
}
