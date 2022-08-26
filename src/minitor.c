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

#include "../include/config.h"
#include "../include/minitor.h"
#include "../h/port.h"

#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"
#include "../h/connections.h"
#include "../h/core.h"

WOLFSSL_CTX* xMinitorWolfSSL_Context;
MinitorTask core_task;

static void v_timer_trigger_timeout( MinitorTimer x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_CIRCUIT_TIMEOUT;

  succ = MINITOR_ENQUEUE_MS( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == false )
  {
    free( onion_message );
    MINITOR_TIMER_SET_MS_BLOCKING( x_timer, 500 );
  }
}

static void v_timer_trigger_consensus( MinitorTimer x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_CONSENSUS;

  succ = MINITOR_ENQUEUE_MS( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == false )
  {
    free( onion_message );
    MINITOR_TIMER_SET_MS_BLOCKING( x_timer, 500 );
  }
}

static void v_timer_trigger_keepalive( MinitorTimer x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_KEEPALIVE;

  succ = MINITOR_ENQUEUE_MS( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == false )
  {
    free( onion_message );
    MINITOR_TIMER_SET_MS_BLOCKING( x_timer, 500 );
  }
}

static void v_timer_trigger_hsdir_update( MinitorTimer x_timer )
{
  int succ;
  OnionMessage* onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = TIMER_HSDIR;
  onion_message->data = MINITOR_TIMER_GET_DATA( x_timer );

  succ = MINITOR_ENQUEUE_MS( core_task_queue, (void*)(&onion_message), 0 );

  // try again in half a second
  if ( succ == false )
  {
    free( onion_message );
    MINITOR_TIMER_SET_MS_BLOCKING( x_timer, 500 );
  }
}

// intialize tor
int d_minitor_INIT()
{
  circ_id_mutex = MINITOR_MUTEX_CREATE();
  network_consensus_mutex = MINITOR_MUTEX_CREATE();
  crypto_insert_finish = MINITOR_MUTEX_CREATE();
  connections_mutex = MINITOR_MUTEX_CREATE();
  circuits_mutex = MINITOR_MUTEX_CREATE();
  fastest_cache_mutex = MINITOR_MUTEX_CREATE();

  core_task_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );
  core_internal_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );
  connections_task_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );
  poll_task_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );

  b_create_core_task( &core_task );

  consensus_timer = MINITOR_TIMER_CREATE_MS(
    "CONSENSUS_TIMER",
    1000 * 60 * 60 * 24,
    0,
    NULL,
    v_timer_trigger_consensus
  );
  MINITOR_TIMER_STOP_BLOCKING( consensus_timer );

  keepalive_timer = MINITOR_TIMER_CREATE_MS(
    "KEEPALIVE_TIMER",
    1000 * 60 * 2,
    0,
    NULL,
    v_timer_trigger_keepalive
  );
  MINITOR_TIMER_RESET_BLOCKING( keepalive_timer );

  timeout_timer = MINITOR_TIMER_CREATE_MS(
    "TIMEOUT_TIMER",
    1000 * 10,
    0,
    NULL,
    v_timer_trigger_timeout
  );
  MINITOR_TIMER_RESET_BLOCKING( timeout_timer );

  wolfSSL_Init();
  //wolfSSL_Debugging_ON();

  //if ( ( xMinitorWolfSSL_Context = wolfSSL_CTX_new( wolfTLSv1_3_client_method() ) ) == NULL )
  if ( ( xMinitorWolfSSL_Context = wolfSSL_CTX_new( wolfTLSv1_2_client_method() ) ) == NULL )
  {
    MINITOR_LOG( MINITOR_TAG, "couldn't setup wolfssl context" );

    return -1;
  }

  MINITOR_LOG( MINITOR_TAG, "Starting fetch" );

  // fetch network consensus
  while ( d_fetch_consensus_info() < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Fetch failed, retrying" );
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

  service->hsdir_timer = MINITOR_TIMER_CREATE_MS(
    "HSDIR_TIMER",
    1000 * 60 * 60 * 24,
    0,
    (void*)service,
    v_timer_trigger_hsdir_update
  );
  MINITOR_TIMER_STOP_BLOCKING( service->hsdir_timer );

  if ( d_generate_hs_keys( service, onion_service_directory ) < 0 )
  {
    MINITOR_LOG( MINITOR_TAG, "Failed to generate hs keys" );

    free( service );

    return -1;
  }

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = INIT_SERVICE;
  onion_message->data = service;

  MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

  return 0;
}
