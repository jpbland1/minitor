#include <stddef.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "../include/config.h"
#include "../include/minitor.h"
#include "../h/models/db.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"
#include "../h/local_connection.h"

#define MINITOR_TIMER_CONSENSUS 0
#define MINITOR_TIMER_CONSENSUS_VALID 1
#define MINITOR_TIMER_KEEPALIVE 2

QueueHandle_t timer_queue;
WOLFSSL_CTX* xMinitorWolfSSL_Context;
TimerHandle_t keepalive_timer;

static void v_timer_trigger_consensus( TimerHandle_t x_timer )
{
  int succ;
  int action = MINITOR_TIMER_CONSENSUS;

  succ = xQueueSendToBack( timer_queue, &action, 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
    xTimerStart( x_timer, portMAX_DELAY );
  }
}

static void v_timer_trigger_consensus_valid( TimerHandle_t x_timer )
{
  int succ;
  int action = MINITOR_TIMER_CONSENSUS_VALID;

  succ = xQueueSendToBack( timer_queue, &action, 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
    xTimerStart( x_timer, portMAX_DELAY );
  }
}

static void v_timer_trigger_keepalive( TimerHandle_t x_timer )
{
  int succ;
  int action = MINITOR_TIMER_KEEPALIVE;

  succ = xQueueSendToBack( timer_queue, &action, 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
    xTimerStart( x_timer, portMAX_DELAY );
  }
}

static void v_timer_trigger_hsdir_update( TimerHandle_t x_timer )
{
  int succ;
  OnionService* onion_service = pvTimerGetTimerID( x_timer );;

  succ = xQueueSendToBack( timer_queue, &onion_service, 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
    xTimerStart( x_timer, portMAX_DELAY );
  }
}

static void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list )
{
  int i;
  int succ;
  Cell padding_cell;
  DoublyLinkedOnionCircuit* node;
  unsigned char* packed_cell;

  padding_cell.command = PADDING;
  padding_cell.payload = NULL;

  node = list->head;

  for ( i = 0; i < list->length; i++ )
  {
    padding_cell.circ_id = node->circuit->circ_id;
    packed_cell = pack_and_free( &padding_cell );

    // MUTEX TAKE
    succ = xSemaphoreTake( node->circuit->or_connection->access_mutex, 500 / portTICK_PERIOD_MS );

    if ( succ == pdFALSE || d_send_packed_cell_and_free( node->circuit->or_connection, packed_cell ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send padding cell on circ_id: %d", node->circuit->circ_id );
#endif
    }

    if ( succ == pdTRUE )
    {
      xSemaphoreGive( node->circuit->or_connection->access_mutex );
      // MUTEX GIVE
    }

    node = node->next;
  }
}

static void v_handle_timed_jobs( void* pv_parameters )
{
  int succ;
  uint32_t action_or_service;

  while ( 1 )
  {
    xQueueReceive( timer_queue, &action_or_service, portMAX_DELAY );

    // This saves us from having a null onion_service later
    if ( action_or_service == MINITOR_TIMER_CONSENSUS )
    {
      if ( d_fetch_consensus_info() < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to fetch consensus" );
#endif

        xTimerChangePeriod( consensus_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
        xTimerStart( consensus_timer, portMAX_DELAY );
      }
    }
    else if ( action_or_service == MINITOR_TIMER_CONSENSUS_VALID )
    {
      if ( d_set_next_consenus() < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to load next consensus" );
#endif

        xTimerChangePeriod( consensus_valid_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
        xTimerStart( consensus_valid_timer, portMAX_DELAY );
      }
    }
    else if ( action_or_service == MINITOR_TIMER_KEEPALIVE )
    {
      xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

      v_keep_circuitlist_alive( &standby_circuits );

      xSemaphoreGive( standby_circuits_mutex );

      ESP_LOGE( MINITOR_TAG, "\nv_circuit_keepalive taking rend mutex" );

      xSemaphoreTake( standby_rend_circuits_mutex, portMAX_DELAY );

      v_keep_circuitlist_alive( &standby_rend_circuits );

      xSemaphoreGive( standby_rend_circuits_mutex );

      ESP_LOGE( MINITOR_TAG, "\nv_circuit_keepalive gave rend mutex" );

      xTimerStart( keepalive_timer, portMAX_DELAY );
    }
    else
    {
      if ( d_push_hsdir( (OnionService*)action_or_service ) < 0 )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to d_push_hsdir for %s", ( (OnionService*)action_or_service )->onion_service_directory );
#endif

        xTimerChangePeriod( ( (OnionService*)action_or_service )->hsdir_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
        xTimerStart( ( (OnionService*)action_or_service )->hsdir_timer, portMAX_DELAY );
      }
    }
  }
}

// intialize tor
int d_minitor_INIT()
{
  circ_id_mutex = xSemaphoreCreateMutex();
  network_consensus_mutex = xSemaphoreCreateMutex();
  standby_circuits_mutex = xSemaphoreCreateMutex();
  standby_rend_circuits_mutex = xSemaphoreCreateMutex();
  or_connections_mutex = xSemaphoreCreateMutex();
  local_connections_mutex = xSemaphoreCreateMutex();
  crypto_insert_finish = xSemaphoreCreateMutex();

  timer_queue = xQueueCreate( 5, sizeof( uint32_t ) );

  xTaskCreatePinnedToCore(
    v_handle_timed_jobs,
    "HANDLE_TIMED_JOBS",
    8192,
    NULL,
    4,
    NULL,
    tskNO_AFFINITY
  );

  consensus_timer = xTimerCreate(
    "CONSENSUS_TIMER",
    1000 * 60 * 60 * 24 / portTICK_PERIOD_MS,
    0,
    NULL,
    v_timer_trigger_consensus
  );
  xTimerStop( consensus_timer, portMAX_DELAY );

  consensus_valid_timer = xTimerCreate(
    "CONSENSUS_VALID_TIMER",
    1000 * 60 * 60 * 24 / portTICK_PERIOD_MS,
    0,
    NULL,
    v_timer_trigger_consensus_valid
  );
  xTimerStop( consensus_valid_timer, portMAX_DELAY );

  keepalive_timer = xTimerCreate(
    "KEEPALIVE_TIMER",
    1000 * 60 * 2,
    0,
    NULL,
    v_timer_trigger_keepalive
  );

  wolfSSL_Init();
  /* wolfSSL_Debugging_ON(); */

  if ( d_initialize_database() < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't setup minitor sqlite3 database" );
#endif

    return -1;
  }

  if ( ( xMinitorWolfSSL_Context = wolfSSL_CTX_new( wolfTLSv1_2_client_method() ) ) == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't setup wolfssl context" );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "Starting fetch" );
  // fetch network consensus
  if ( d_fetch_consensus_info() < 0 )
  {
    return -1;
  }

  return 1;
}

// ONION SERVICES
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory )
{
  int i;
  DoublyLinkedOnionCircuit* node;
  OnionService* onion_service = malloc( sizeof( OnionService ) );

  memset( onion_service, 0, sizeof( OnionService ) );

  onion_service->local_port = local_port;
  onion_service->exit_port = exit_port;
  onion_service->rx_queue = xQueueCreate( 5, sizeof( OnionMessage* ) );
  onion_service->rend_timestamp = 0;

  if ( d_generate_hs_keys( onion_service, onion_service_directory ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate hs keys" );
#endif

    return NULL;
  }

  // setup starting circuits
  if ( d_setup_init_circuits( 3 ) < 3 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to setup init circuits" );
#endif

    return NULL;
  }

  // take two circuits from the standby circuits list
  // BEGIN mutex
  xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

  if ( standby_circuits.length < 3 )
  {
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
  if ( standby_circuits.length > 3 )
  {
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

  for ( i = 0; i < onion_service->intro_circuits.length; i++ )
  {
    node->circuit->forward_queue = onion_service->rx_queue;

    if ( d_router_establish_intro( node->circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to establish intro with a circuit" );
#endif

      return NULL;
    }

    node->circuit->status = CIRCUIT_INTRO_POINT;

    node = node->next;
  }

  onion_service->hsdir_timer = xTimerCreate(
    "HSDIR_TIMER",
    1000 * 60 * 60 * 24 / portTICK_PERIOD_MS,
    0,
    (void*)onion_service,
    v_timer_trigger_hsdir_update
  );
  xTimerStop( onion_service->hsdir_timer, portMAX_DELAY );

  if ( d_push_hsdir( onion_service ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to push hsdir" );
#endif

    return NULL;
  }

  if ( d_setup_init_rend_circuits( 1 ) < 1 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to setup init rend circuits" );
#endif

    return NULL;
  }

  ESP_LOGE( MINITOR_TAG, "starting HANDLE_HS" );

  // create a task to block on the rx_queue
  xTaskCreatePinnedToCore(
    v_handle_onion_service,
    "HANDLE_HS",
    8192,
    (void*)(onion_service),
    8,
    NULL,
    tskNO_AFFINITY
  );

  // return the onion service
  return onion_service;
}
