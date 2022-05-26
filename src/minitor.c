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
#include "../h/connections.h"
#include "../h/core.h"

WOLFSSL_CTX* xMinitorWolfSSL_Context;

static void v_timer_trigger_consensus( TimerHandle_t x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_CONSENSUS;

  succ = xQueueSendToBack( core_task_queue, (void*)(&onion_message), 0 );

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
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_KEEPALIVE;

  succ = xQueueSendToBack( core_task_queue, (void*)(&onion_message), 0 );

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
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_HSDIR;
  onion_message->data = pvTimerGetTimerID( x_timer );

  succ = xQueueSendToBack( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
    xTimerStart( x_timer, portMAX_DELAY );
  }
}

/*
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
*/

/*
// TODO move to services file
inline void* px_get_service_entity_by_circ_id( DlOnionService* dl_service, uint32_t circ_id, int want_circuit )
{
  DlOnionCircuit* dl_circuit

  // loop over all services
  while ( dl_service != NULL )
  {
    dl_circuit = dl_service->onion_circuits;

    // loop over all circuits within the service
    while ( dl_circuit != NULL )
    {
      // if our circuit matches, we found the correct service
      if ( dl_circuit->circuit->circ_id == circ_id )
      {
        break;
      }

      dl_circuit = dl_circuit->next;
    }

    if ( dl_circuit != NULL )
    {
      break;
    }

    dl_service = dl_service->next;
  }

  if ( want_circuit == 1 )
  {
    return dl_circuit;
  }

  return dl_service;
}
*/

/*
DlOnionService* px_get_service_by_circ_id( DlOnionService* dl_service, uint32_t circ_id )
{
  // patsy function handles both service and circuit to save lines
  return (DlOnionService*)px_get_service_entity_by_circ_id( dl_service, circ_id, 0 );
}

DlOnionCircuit* px_get_service_circuit_by_circ_id( DlOnionService* dl_service, uint32_t circ_id )
{
  return (DlOnionCircuit*)px_get_service_entity_by_circ_id( dl_service, circ_id, 1 );
}
*/

// intialize tor
int d_minitor_INIT()
{
  circ_id_mutex = xSemaphoreCreateMutex();
  network_consensus_mutex = xSemaphoreCreateMutex();
  crypto_insert_finish = xSemaphoreCreateMutex();
  connections_mutex = xSemaphoreCreateMutex();
  circuits_mutex = xSemaphoreCreateMutex();

  core_task_queue = xQueueCreate( 25, sizeof( OnionMessage* ) );

  xTaskCreatePinnedToCore(
    v_minitor_daemon,
    "MINITOR_DAEMON",
    8192,
    NULL,
    7,
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
  while ( d_fetch_consensus_info() < 0 )
  {
    ESP_LOGE( MINITOR_TAG, "Fetch failed, retrying" );
  }

  return 0;
}

// ONION SERVICES
int d_setup_onion_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory )
{
  OnionMessage* onion_message;
  OnionService* service = malloc( sizeof( OnionService ) );

  memset( service, 0, sizeof( OnionService ) );

  service->local_port = local_port;
  service->exit_port = exit_port;
  service->rend_timestamp = 0;

  service->hsdir_timer = xTimerCreate(
    "HSDIR_TIMER",
    1000 * 60 * 60 * 24 / portTICK_PERIOD_MS,
    0,
    (void*)service,
    v_timer_trigger_hsdir_update
  );
  xTimerStop( service->hsdir_timer, portMAX_DELAY );

  if ( d_generate_hs_keys( service, onion_service_directory ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate hs keys" );
#endif

    free( service );

    return -1;
  }

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = INIT_SERVICE;
  onion_message->data = service;

  xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );

  return 0;
}
