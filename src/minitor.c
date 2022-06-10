/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stddef.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "../include/config.h"
#include "../include/minitor.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"
#include "../h/connections.h"
#include "../h/core.h"

WOLFSSL_CTX* xMinitorWolfSSL_Context;

static void v_timer_trigger_timeout( TimerHandle_t x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_CIRCUIT_TIMEOUT;

  succ = xQueueSendToBack( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    free( onion_message );
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
  }
}

static void v_timer_trigger_consensus( TimerHandle_t x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_CONSENSUS;

  succ = xQueueSendToBack( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == pdFALSE )
  {
    free( onion_message );
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
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
    free( onion_message );
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
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
    free( onion_message );
    xTimerChangePeriod( x_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
  }
}

// intialize tor
int d_minitor_INIT()
{
  circ_id_mutex = xSemaphoreCreateMutex();
  network_consensus_mutex = xSemaphoreCreateMutex();
  crypto_insert_finish = xSemaphoreCreateMutex();
  connections_mutex = xSemaphoreCreateMutex();
  circuits_mutex = xSemaphoreCreateMutex();
  fastest_cache_mutex = xSemaphoreCreateMutex();

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
    1000 * 60 * 2 / portTICK_PERIOD_MS,
    0,
    NULL,
    v_timer_trigger_keepalive
  );
  xTimerReset( keepalive_timer, portMAX_DELAY );

  timeout_timer = xTimerCreate(
    "TIMEOUT_TIMER",
    1000 * 10 / portTICK_PERIOD_MS,
    0,
    NULL,
    v_timer_trigger_timeout
  );
  xTimerReset( timeout_timer, portMAX_DELAY );

  wolfSSL_Init();
  /* wolfSSL_Debugging_ON(); */

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
