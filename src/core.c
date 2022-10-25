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
#include "../h/port.h"

#include "../h/core.h"
#include "../h/models/relay.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"
#include "../h/onion_client.h"
#include "../h/connections.h"

static const char* CORE_TAG = "MINITOR DAEMON";

MinitorTimer keepalive_timer;
MinitorTimer timeout_timer;
OnionCircuit* onion_circuits = NULL;
OnionService* onion_services = NULL;
MinitorQueue core_task_queue;
MinitorQueue core_internal_queue;
MinitorMutex circuits_mutex;

static void v_send_init_circuit(
  int length,
  CircuitStatus target_status,
  OnionService* service,
  OnionClient* client,
  int desc_index,
  int target_relay_index,
  OnionRelay* start_relay,
  OnionRelay* end_relay,
  HsCrypto* hs_crypto,
  IntroCrypto* intro_crypto,
  MinitorQueue queue
)
{
  OnionMessage* onion_message;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = INIT_CIRCUIT;
  onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

  ((CreateCircuitRequest*)onion_message->data)->length = length;
  ((CreateCircuitRequest*)onion_message->data)->target_status = target_status;
  ((CreateCircuitRequest*)onion_message->data)->service = service;
  ((CreateCircuitRequest*)onion_message->data)->client = client;
  ((CreateCircuitRequest*)onion_message->data)->desc_index = desc_index;
  ((CreateCircuitRequest*)onion_message->data)->target_relay_index = target_relay_index;
  ((CreateCircuitRequest*)onion_message->data)->start_relay = start_relay;
  ((CreateCircuitRequest*)onion_message->data)->end_relay = end_relay;
  ((CreateCircuitRequest*)onion_message->data)->hs_crypto = hs_crypto;
  ((CreateCircuitRequest*)onion_message->data)->intro_crypto = intro_crypto;

  MINITOR_ENQUEUE_BLOCKING( queue, (void*)(&onion_message) );
}

// called by the core task
void v_send_init_circuit_internal(
  int length,
  CircuitStatus target_status,
  OnionService* service,
  OnionClient* client,
  int desc_index,
  int target_relay_index,
  OnionRelay* start_relay,
  OnionRelay* end_relay,
  HsCrypto* hs_crypto,
  IntroCrypto* intro_crypto
)
{
  v_send_init_circuit(
    length,
    target_status,
    service,
    client,
    desc_index,
    target_relay_index,
    start_relay,
    end_relay,
    hs_crypto,
    intro_crypto,
    core_internal_queue
  );
}

// called by external tasks
void v_send_init_circuit_external(
  int length,
  CircuitStatus target_status,
  OnionService* service,
  OnionClient* client,
  int desc_index,
  int target_relay_index,
  OnionRelay* start_relay,
  OnionRelay* end_relay,
  HsCrypto* hs_crypto,
  IntroCrypto* intro_crypto
)
{
  v_send_init_circuit(
    length,
    target_status,
    service,
    client,
    desc_index,
    target_relay_index,
    start_relay,
    end_relay,
    hs_crypto,
    intro_crypto,
    core_task_queue
  );
}

void v_set_hsdir_timer( MinitorTimer hsdir_timer )
{
  time_t now;
  time_t voting_interval;
  time_t srv_start_time;

#ifdef MINITOR_CHUTNEY
  time( &now );

  voting_interval = network_consensus.fresh_until - network_consensus.valid_after;

  // 24 is SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES
  srv_start_time = network_consensus.valid_after - ( ( ( ( network_consensus.valid_after / voting_interval ) ) % ( SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES ) ) * voting_interval );

  // start the update timer a half second after the consensus update
  if ( now > ( srv_start_time + ( 25 * voting_interval ) ) )
  {
    MINITOR_LOG( CORE_TAG, "Setting hsdir timer to backup time %lu seconds", ( 25 * voting_interval ) );
    MINITOR_TIMER_SET_MS_BLOCKING( hsdir_timer, 1000 * ( 25 * voting_interval ) + 500 );
  }
  else
  {
    MINITOR_LOG( CORE_TAG, "Setting hsdir timer to normal time %lu seconds", ( ( srv_start_time + ( 25 * voting_interval ) ) - now ) );
    MINITOR_TIMER_SET_MS_BLOCKING( hsdir_timer, 1000 * ( ( srv_start_time + ( 25 * voting_interval ) ) - now ) + 500 );
  }
#else
  // start the hsdir_timer at 60-120 minutes, may be too long for clock accurracy
  MINITOR_TIMER_SET_MS_BLOCKING( hsdir_timer, 1000 * 60 * ( MINITOR_RANDOM() % 60 ) + 60 );
#endif
}

int d_get_standby_count()
{
  int count = 0;
  OnionCircuit* circuit;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  circuit = onion_circuits;

  while ( circuit != NULL )
  {
    if ( circuit->status == CIRCUIT_STANDBY )
    {
      count++;
    }

    circuit = circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  return count;
}

static void v_send_init_circuit_fetch( MinitorQueue queue )
{
  OnionMessage* onion_message;

  // check if our consensus is actually out of date
  if ( b_consensus_outdated() == false )
  {
    // if fetch request was from outside the daemon send the done message
    if ( external_want_consensus == true )
    {
      onion_message = malloc( sizeof( OnionMessage ) );

      onion_message->type = CONSENSUS_FETCHED;

      MINITOR_ENQUEUE_BLOCKING( external_consensus_queue, (void*)(&onion_message) );
    }

    return;
  }

  // reset the relay files
  if ( d_reset_relay_files() < 0 )
  {
    MINITOR_LOG( CORE_TAG, "Failed to reset relay files" );

    return;
  }

  // set the tracking globals to false
  have_network_consensus = false;
  have_relay_descriptors = false;

  onion_message = malloc( sizeof( OnionMessage ) );

  onion_message->type = INIT_CIRCUIT;
  onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

  memset( onion_message->data, 0, sizeof( CreateCircuitRequest ) );

  ((CreateCircuitRequest*)onion_message->data)->length = 1;
  ((CreateCircuitRequest*)onion_message->data)->target_status = CIRCUIT_CONSENSUS_FETCH;

  if ( d_get_cache_relay_count() != 0 )
  {
    ((CreateCircuitRequest*)onion_message->data)->end_relay = px_get_random_cache_relay( false );
  }
  else if ( d_get_staging_cache_relay_count() != 0 )
  {
    ((CreateCircuitRequest*)onion_message->data)->end_relay = px_get_random_cache_relay( true );
  }
  else
  {
    ((CreateCircuitRequest*)onion_message->data)->end_relay = px_get_random_backup_cache_relay();
  }

  MINITOR_ENQUEUE_BLOCKING( queue, (void*)(&onion_message) );
}

static void v_send_init_circuit_fetch_internal()
{
  v_send_init_circuit_fetch( core_internal_queue );
}

void v_send_init_circuit_fetch_external()
{
  v_send_init_circuit_fetch( core_task_queue );
}

static void v_send_init_circuit_intro( OnionService* service )
{
  OnionCircuit* circuit;
  OnionMessage* onion_message;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = INIT_CIRCUIT;
  onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

  memset( onion_message->data, 0, sizeof( CreateCircuitRequest ) );

  ((CreateCircuitRequest*)onion_message->data)->length = 3;
  ((CreateCircuitRequest*)onion_message->data)->target_status = CIRCUIT_ESTABLISH_INTRO;
  ((CreateCircuitRequest*)onion_message->data)->service = service;
  ((CreateCircuitRequest*)onion_message->data)->end_relay = NULL;

  do
  {
    ((CreateCircuitRequest*)onion_message->data)->end_relay = px_get_random_fast_relay( 0, NULL, NULL, NULL );

    circuit = onion_circuits;

    while ( circuit != NULL )
    {
      if (
        circuit->target_status == CIRCUIT_ESTABLISH_INTRO &&
        circuit->service == service &&
        memcmp( circuit->relay_list.tail->relay->identity, ((CreateCircuitRequest*)onion_message->data)->end_relay->identity, ID_LENGTH ) == 0
      )
      {
        free( ((CreateCircuitRequest*)onion_message->data)->end_relay );
        ((CreateCircuitRequest*)onion_message->data)->end_relay = NULL;
        break;
      }

      circuit = circuit->next;
    }
  } while ( ((CreateCircuitRequest*)onion_message->data)->end_relay == NULL );

  MINITOR_ENQUEUE_BLOCKING( core_internal_queue, (void*)(&onion_message) );
}

static int d_send_circuit_create( OnionCircuit* circuit, DlConnection* or_connection )
{
  if ( d_router_create2( circuit, or_connection ) < 0 )
  {
    return -1;
  }

  circuit->status = CIRCUIT_CREATED;

  return 0;
}

void v_circuit_rebuild_or_destroy( OnionCircuit* circuit, DlConnection* or_connection )
{
  int i;
  int retry_length;
  OnionRelay* retry_end_relay = NULL;
  OnionRelay* start_relay;
  OnionMessage* onion_message;
  IntroCrypto* intro_crypto = NULL;

  // if a fully built rend circuit is destroyed, it's up to the client to restart
  if ( circuit->status != CIRCUIT_RENDEZVOUS && circuit->status != CIRCUIT_CLIENT_RENDEZVOUS )
  {
    if ( circuit->target_status == CIRCUIT_ESTABLISH_INTRO )
    {
      v_send_init_circuit_intro(
        circuit->service
      );
    }
    else if ( circuit->target_status == CIRCUIT_CONSENSUS_FETCH )
    {
      v_send_init_circuit_fetch_internal();
    }
    else
    {
      if ( circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
      {
        if ( circuit->relay_list.built_length >= 2 )
        {
          circuit->target_relay_index++;
          circuit->service->hsdir_sent++;

          if ( circuit->target_relay_index == circuit->service->target_relays[circuit->desc_index]->length )
          {
            v_cleanup_service_hs_data( circuit->service, circuit->desc_index );

            if ( circuit->service->hsdir_sent != circuit->service->hsdir_to_send )
            {
              start_relay = px_get_random_fast_relay( 1, circuit->service->target_relays[circuit->desc_index + 1], NULL, NULL );

              v_send_init_circuit_internal(
                3,
                CIRCUIT_HSDIR_BEGIN_DIR,
                circuit->service,
                NULL,
                circuit->desc_index + 1,
                0,
                start_relay,
                circuit->service->target_relays[circuit->desc_index + 1]->head->relay,
                NULL,
                NULL
              );
            }

            goto circuit_destroy;
          }

          retry_length = 3;
          retry_end_relay = px_get_relay_by_index( circuit->service->target_relays[circuit->desc_index], circuit->target_relay_index );
        }
        else
        {
          retry_length = 3;
          retry_end_relay = malloc( sizeof( OnionRelay ) );
          memcpy( retry_end_relay, circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
        }
      }
      else if ( circuit->target_status == CIRCUIT_CLIENT_HSDIR )
      {
        if ( circuit->relay_list.built_length >= 2 )
        {
          // use next relay in target list
          circuit->target_relay_index++;

          // if we have exausted all targets send error to api consumer
          if ( circuit->target_relay_index == circuit->client->target_relays->length )
          {
            onion_message = NULL;
            MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[0], &onion_message );
            goto circuit_destroy;
          }

          retry_length = 3;
          retry_end_relay = px_get_relay_by_index( circuit->client->target_relays, circuit->target_relay_index );
        }
        else
        {
          retry_length = 3;
          retry_end_relay = malloc( sizeof( OnionRelay ) );
          memcpy( retry_end_relay, circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
        }
      }
      else if ( circuit->target_status == CIRCUIT_CLIENT_INTRO )
      {
        if ( circuit->relay_list.built_length >= 2 )
        {
          circuit->target_relay_index++;
          circuit->client->active_intro_relay = circuit->target_relay_index;

          if ( circuit->target_relay_index == circuit->client->num_intro_relays )
          {
            onion_message = NULL;
            MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[0], &onion_message );
            goto circuit_destroy;
          }

          retry_length = 3;
          retry_end_relay = circuit->client->intro_relays[circuit->target_relay_index];
          circuit->client->intro_relays[circuit->target_relay_index] = NULL;
          intro_crypto = circuit->client->intro_cryptos[circuit->target_relay_index];
          circuit->client->intro_cryptos[circuit->target_relay_index] = NULL;
        }
        else
        {
          retry_length = 3;
          retry_end_relay = malloc( sizeof( OnionRelay ) );
          memcpy( retry_end_relay, circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
        }
      }
      else if ( circuit->target_status == CIRCUIT_RENDEZVOUS )
      {
        retry_length = 2;
        retry_end_relay = malloc( sizeof( OnionRelay ) );
        memcpy( retry_end_relay, circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
      }
      else
      {
        retry_length = circuit->relay_list.length;
        retry_end_relay = NULL;
      }

      v_send_init_circuit_internal(
        retry_length,
        circuit->target_status,
        circuit->service,
        circuit->client,
        circuit->desc_index,
        circuit->target_relay_index,
        NULL,
        retry_end_relay,
        circuit->hs_crypto,
        circuit->intro_crypto
      );
    }
  }

  if ( circuit->status == CIRCUIT_CLIENT_RENDEZVOUS )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = CLIENT_CLOSED;

    for ( i = 0; i < 16; i++ )
    {
      // the same onion message is used and the first to get it closes down the client
      MINITOR_ENQUEUE_BLOCKING( circuit->client->stream_queues[0], &onion_message );
    }
  }

circuit_destroy:
  v_circuit_remove_destroy( circuit, or_connection );
  // MUTEX GIVE
}

void v_circuit_remove_destroy( OnionCircuit* circuit, DlConnection* or_connection )
{
  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  v_remove_circuit_from_list( circuit, &onion_circuits );

  if ( circuit->client != NULL )
  {
    if ( circuit->client->intro_circuit == circuit )
    {
      circuit->client->intro_circuit = NULL;
    }
    else if ( circuit->client->rend_circuit == circuit )
    {
      circuit->client->rend_circuit = NULL;
    }
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  d_destroy_onion_circuit( circuit, or_connection );
  // MUTEX GIVE

  free( circuit );
}

static void v_handle_tor_cell( uint32_t conn_id )
{
  int ret;
  int recv_index;
  Cell* cell;
  DlConnection* or_connection;
  OnionCircuit* working_circuit;
  OnionCircuit* tmp_circuit;
  OnionService* working_service;
  OnionMessage* onion_message;
  OnionRelay* target_relay;
  OnionRelay* start_relay;
  DoublyLinkedOnionRelay* dl_relay;
  MinitorMutex access_mutex = NULL;

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( conn_id );

  if ( or_connection == NULL )
  {
    return;
  }

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  cell = or_connection->cell_ring_buf[or_connection->cell_ring_start];

  or_connection->cell_ring_buf[or_connection->cell_ring_start] = NULL;

  or_connection->cell_ring_start = ( or_connection->cell_ring_start + 1 ) % RING_BUF_LEN;

  if ( cell == NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    return;
  }

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  working_circuit = px_get_circuit_by_circ_id( onion_circuits, ntohl( cell->circ_id ) );

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  if ( working_circuit == NULL )
  {
    MINITOR_LOG( CORE_TAG, "Discarding circuitless cell %d", cell->circ_id );

    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    free( cell );

    return;
  }

  MINITOR_LOG( CORE_TAG, "status %d target %d", working_circuit->status, working_circuit->target_status );

  time( &(working_circuit->last_action) );

  if ( cell->command == RELAY )
  {
    if ( working_circuit->status == CIRCUIT_RENDEZVOUS || working_circuit->status == CIRCUIT_CLIENT_RENDEZVOUS_LIVE )
    {
      ret = d_decrypt_cell( cell, CIRCID_LEN, &working_circuit->relay_list, working_circuit->hs_crypto );
    }
    else
    {
      ret = d_decrypt_cell( cell, CIRCID_LEN, &working_circuit->relay_list, NULL );
    }

    if ( ret < 0 )
    {
      MINITOR_LOG( CORE_TAG, "Failed to decrypt packed cell, discarding" );

      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      free( cell );

      return;
    }
  }

  // after decryption we need to change from network byte order to our byte order
  v_hostize_cell( cell );

  // discard padding cell
  if ( cell->command == PADDING )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    free( cell );

    return;
  }

  switch ( working_circuit->status )
  {
    case CIRCUIT_CREATED:
      if ( cell->command != CREATED2 )
      {
        goto circuit_rebuild;
      }

      if ( d_router_created2( working_circuit, cell ) < 0 )
      {
        goto circuit_rebuild;
      }

      working_circuit->relay_list.built_length++;

      if ( working_circuit->relay_list.built_length < working_circuit->relay_list.length )
      {
        if ( d_router_extend2( working_circuit, or_connection, working_circuit->relay_list.built_length ) < 0 )
        {
          goto circuit_rebuild;
        }

        working_circuit->status = CIRCUIT_EXTENDED;
      }
      else
      {
        if ( working_circuit->target_status == CIRCUIT_CONSENSUS_FETCH )
        {
          if ( d_router_begin_dir( working_circuit, or_connection, CONSENSUS_STREAM_ID ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_DIR_CONNECTED;
        }
        else
        {
          working_circuit->status = working_circuit->target_status;
        }
      }

      break;
    case CIRCUIT_EXTENDED:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_EXTENDED2 )
      {
        MINITOR_LOG( CORE_TAG, "failed to get extended" );
        MINITOR_LOG( CORE_TAG, "circ_id: %x", working_circuit->circ_id );
        MINITOR_LOG( CORE_TAG, "command: %x relay command: %x", cell->command, cell->payload.relay.relay_command );

        goto circuit_rebuild;
      }

      if ( d_router_extended2( working_circuit, working_circuit->relay_list.built_length, cell ) < 0 )
      {
        MINITOR_LOG( CORE_TAG, "failed to process extended" );

        goto circuit_rebuild;
      }

      working_circuit->relay_list.built_length++;

      if ( working_circuit->relay_list.built_length < working_circuit->relay_list.length )
      {
        if ( d_router_extend2( working_circuit, or_connection, working_circuit->relay_list.built_length ) < 0 )
        {
          goto circuit_rebuild;
        }
      }
      else
      {
        switch ( working_circuit->target_status )
        {
          case CIRCUIT_HSDIR_BEGIN_DIR:
          case CIRCUIT_CLIENT_HSDIR:
            if ( d_begin_hsdir( working_circuit, or_connection ) < 0 )
            {
              goto circuit_rebuild;
            }

            working_circuit->status = CIRCUIT_HSDIR_CONNECTED;

            break;
          case CIRCUIT_ESTABLISH_INTRO:
            if ( d_router_establish_intro( working_circuit, or_connection ) < 0 )
            {
              goto circuit_rebuild;
            }

            working_circuit->status = CIRCUIT_INTRO_ESTABLISHED;

            break;
          case CIRCUIT_RENDEZVOUS:
            if ( d_router_join_rendezvous( working_circuit, or_connection, working_circuit->hs_crypto->rendezvous_cookie, working_circuit->hs_crypto->point, working_circuit->hs_crypto->auth_input_mac ) < 0 )
            {
              MINITOR_LOG( CORE_TAG, "Failed to join rend" );

              goto circuit_rebuild;
            }

            working_circuit->status = CIRCUIT_RENDEZVOUS;

            break;
          case CIRCUIT_CLIENT_INTRO:
            working_circuit->client->intro_built = true;

            if ( working_circuit->client->rendezvous_ready == true )
            {
              if ( d_client_send_intro( working_circuit, or_connection ) < 0 )
              {
                MINITOR_LOG( CORE_TAG, "Failed to send intro" );

                goto circuit_rebuild;
              }

              working_circuit->status = CIRCUIT_CLIENT_INTRO_ACK;
            }

            break;
          case CIRCUIT_CLIENT_RENDEZVOUS:
            if ( d_client_establish_rendezvous( working_circuit, or_connection ) < 0 )
            {
              MINITOR_LOG( CORE_TAG, "Failed to establish rend" );

              goto circuit_rebuild;
            }

            working_circuit->status = CIRCUIT_CILENT_RENDEZVOUS_ESTABLISHED;

            break;
          default:
            break;
        }
      }

      break;
    case CIRCUIT_TRUNCATED:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_TRUNCATED )
      {
        MINITOR_LOG( CORE_TAG, "failed to recv truncated" );
        MINITOR_LOG( CORE_TAG, "command: %d", cell->command );
        MINITOR_LOG( CORE_TAG, "relay command: %d", cell->payload.relay.relay_command );

        goto circuit_rebuild;
      }

      if ( working_circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR || working_circuit->target_status == CIRCUIT_CLIENT_HSDIR )
      {
        if ( working_circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
        {
          target_relay = px_get_relay_by_index( working_circuit->service->target_relays[working_circuit->desc_index], working_circuit->target_relay_index );
        }
        else
        {
          target_relay = px_get_relay_by_index( working_circuit->client->target_relays, working_circuit->target_relay_index );
        }

        dl_relay = working_circuit->relay_list.tail;

        while ( dl_relay != NULL )
        {
          if ( memcmp( dl_relay->relay->identity, target_relay->identity, ID_LENGTH ) == 0 )
          {
            break;
          }

          dl_relay = dl_relay->previous;
        }
      }
      else if ( working_circuit->target_status == CIRCUIT_CLIENT_RENDEZVOUS )
      {
        target_relay = px_get_random_fast_relay( 0, &working_circuit->relay_list, NULL, NULL );

        dl_relay = NULL;
      }

      // one of our relays matches, the target, make new circuit
      if ( dl_relay != NULL )
      {
        v_send_init_circuit_internal(
          3,
          working_circuit->target_status,
          working_circuit->service,
          working_circuit->client,
          working_circuit->desc_index,
          working_circuit->target_relay_index,
          NULL,
          target_relay,
          NULL,
          NULL
        );

        v_circuit_remove_destroy( working_circuit, or_connection );
        // MUTEX GIVE

        access_mutex = NULL;
        working_circuit = NULL;
      }
      else
      {
        dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
        dl_relay->relay = target_relay;

        v_add_relay_to_list( dl_relay, &working_circuit->relay_list );

        if ( d_router_extend2( working_circuit, or_connection, working_circuit->relay_list.built_length ) < 0 )
        {
          goto circuit_rebuild;
        }

        working_circuit->status = CIRCUIT_EXTENDED;
      }

      break;
    case CIRCUIT_DIR_CONNECTED:
      if ( cell->command != RELAY )
      {
        goto circuit_rebuild;
      }

      if ( cell->payload.relay.relay_command != RELAY_CONNECTED )
      {
        goto circuit_rebuild;
      }

      // if we lackk the consensus fetch it
      if ( have_network_consensus == false )
      {
        if ( d_consensus_request( working_circuit, or_connection ) < 0 )
        {
          goto circuit_rebuild;
        }

        working_circuit->status = CIRCUIT_CONSENSUS_FETCH;
      }

      break;
    case CIRCUIT_CONSENSUS_FETCH:
      if (
        cell->command != RELAY ||
        ( cell->payload.relay.relay_command != RELAY_DATA && cell->payload.relay.relay_command != RELAY_END && cell->payload.relay.relay_command != RELAY_CONNECTED )
      )
      {
        goto circuit_rebuild;
      }

      if ( cell->payload.relay.stream_id == CONSENSUS_STREAM_ID )
      {
        // parse this part of the consensus
        ret = d_parse_consensus( working_circuit, or_connection, cell );
      }
      else
      {
        // parse this part of the descriptors
        ret = d_parse_descriptors( working_circuit, or_connection, cell );
      }


      if ( ret == 1 )
      {
        onion_message = malloc( sizeof( OnionMessage ) );

        onion_message->type = EXTERNAL_CONSENSUS_FETCHED;

        // inform the external task that we're done fetching
        MINITOR_ENQUEUE_BLOCKING( external_consensus_queue, (void*)(&onion_message) );

        v_circuit_remove_destroy( working_circuit, or_connection );
        // MUTEX GIVE

        access_mutex = NULL;
        working_circuit = NULL;
      }
      else if ( ret < 0 )
      {
        goto circuit_rebuild;
      }

      break;
    case CIRCUIT_INTRO_ESTABLISHED:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_COMMAND_INTRO_ESTABLISHED )
      {
        goto circuit_rebuild;
      }

      working_circuit->status = CIRCUIT_INTRO_LIVE;

      working_circuit->service->intro_live_count++;

      if ( working_circuit->service->intro_live_count == 3 && working_circuit->service->hsdir_sent == 0 )
      {
        if ( d_push_hsdir( working_circuit->service ) < 0 )
        {
          MINITOR_LOG( CORE_TAG, "Failed to start hsdir push" );
          v_set_hsdir_timer( working_circuit->service->hsdir_timer );
        }
      }

      break;
    case CIRCUIT_HSDIR_CONNECTED:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_CONNECTED )
      {
        goto circuit_rebuild;
      }

      if ( working_circuit->target_status == CIRCUIT_CLIENT_HSDIR )
      {
        if ( d_get_hs_desc( working_circuit, or_connection ) < 0 )
        {
          goto circuit_rebuild;
        }
      }
      else
      {
        if ( d_post_hs_desc( working_circuit, or_connection ) < 0 )
        {
          goto circuit_rebuild;
        }

      }

      working_circuit->status = CIRCUIT_HSDIR_DATA;

      break;
    case CIRCUIT_HSDIR_DATA:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_DATA )
      {
        MINITOR_LOG( CORE_TAG, "failed to recv hsdir data response" );

        goto circuit_rebuild;
      }

      if ( working_circuit->target_status == CIRCUIT_CLIENT_HSDIR )
      {
        MINITOR_LOG( CORE_TAG, "trying parse" );
        ret = d_parse_hsdesc( working_circuit, cell );

        // couldn't parse or desc was invalid
        if ( ret < 0 )
        {
          working_circuit->target_relay_index++;

          if ( working_circuit->target_relay_index == working_circuit->client->target_relays->length )
          {
            goto circuit_rebuild;
          }
        }
        // success, we sent init for the intro circuit
        else if ( ret == 0 )
        {
          working_circuit->client->rend_circuit = working_circuit;

          working_circuit->target_status = CIRCUIT_CLIENT_RENDEZVOUS;
        }

        // parsing but need more cells
        if ( ret != 1 )
        {
          if ( d_router_truncate( working_circuit, or_connection, working_circuit->relay_list.built_length - 1 ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_TRUNCATED;
        }
      }
      else
      {
        // TODO check actual response for success

        working_circuit->service->hsdir_sent++;
        working_circuit->target_relay_index++;

        if ( working_circuit->target_relay_index == working_circuit->service->target_relays[working_circuit->desc_index]->length)
        {
          v_cleanup_service_hs_data( working_circuit->service, working_circuit->desc_index );

          if ( working_circuit->service->hsdir_sent != working_circuit->service->hsdir_to_send )
          {
            start_relay = px_get_random_fast_relay( 1, working_circuit->service->target_relays[working_circuit->desc_index + 1], NULL, NULL );

            v_send_init_circuit_internal(
              3,
              CIRCUIT_HSDIR_BEGIN_DIR,
              working_circuit->service,
              NULL,
              working_circuit->desc_index + 1,
              0,
              start_relay,
              working_circuit->service->target_relays[working_circuit->desc_index + 1]->head->relay,
              NULL,
              NULL
            );
          }

          // TODO need to overhaul circuits to use the same mutexing as connections, this won't be safe if more than one core thread is running
          v_circuit_remove_destroy( working_circuit, or_connection );
          // MUTEX GIVE

          access_mutex = NULL;
          working_circuit = NULL;
        }
        else
        {
          if ( working_circuit->relay_early_count == 6 )
          {
            v_circuit_remove_destroy( working_circuit, or_connection );
            // MUTEX GIVE

            v_send_init_circuit_internal(
              3,
              CIRCUIT_HSDIR_BEGIN_DIR,
              working_circuit->service,
              NULL,
              working_circuit->desc_index,
              working_circuit->target_relay_index,
              NULL,
              px_get_relay_by_index( working_circuit->service->target_relays[working_circuit->desc_index], working_circuit->target_relay_index ),
              NULL,
              NULL
            );

            access_mutex = NULL;
            working_circuit = NULL;
          }
          else
          {
            if ( d_router_truncate( working_circuit, or_connection, working_circuit->relay_list.built_length - 1 ) < 0 )
            {
              goto circuit_rebuild;
            }

            working_circuit->status = CIRCUIT_TRUNCATED;
          }
        }
      }

      break;
    case CIRCUIT_CLIENT_INTRO_ACK:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_COMMAND_INTRODUCE_ACK )
      {
        MINITOR_LOG( CORE_TAG, "Failed to recv RELAY_COMMAND_INTRODUCE_ACK" );

        goto circuit_rebuild;
      }

      if ( cell->payload.relay.intro_ack.status != 0 )
      {
        MINITOR_LOG( CORE_TAG, "Invalid intro ack status %d", cell->payload.relay.intro_ack.status );

        goto circuit_rebuild;
      }

      working_circuit->client->intro_complete = true;
      working_circuit->client->intro_cryptos[working_circuit->client->active_intro_relay] = working_circuit->intro_crypto;

      v_circuit_remove_destroy( working_circuit, or_connection );
      // MUTEX GIVE

      access_mutex = NULL;
      working_circuit = NULL;

      break;
    case CIRCUIT_CILENT_RENDEZVOUS_ESTABLISHED:
      if ( cell->command != RELAY || cell->payload.relay.relay_command != RELAY_COMMAND_RENDEZVOUS_ESTABLISHED )
      {
        MINITOR_LOG( CORE_TAG, "Failed to recv RELAY_COMMAND_RENDEZVOUS_ESTABLISHED" );

        goto circuit_rebuild;
      }

      working_circuit->status = CIRCUIT_CLIENT_RENDEZVOUS;
      working_circuit->client->rendezvous_ready = true;

      if ( working_circuit->client->intro_built == true )
      {
        MINITOR_MUTEX_GIVE( access_mutex );
        // MUTEX GIVE

        working_circuit = working_circuit->client->intro_circuit;

        // MUTEX TAKE
        or_connection = px_get_conn_by_id_and_lock( working_circuit->conn_id );

        access_mutex = connection_access_mutex[or_connection->mutex_index];

        if ( d_client_send_intro( working_circuit, or_connection ) < 0 )
        {
          MINITOR_LOG( CORE_TAG, "Failed to send intro" );

          goto circuit_rebuild;
        }

        working_circuit->status = CIRCUIT_CLIENT_INTRO_ACK;
      }

      break;
    case CIRCUIT_CLIENT_RENDEZVOUS:
    case CIRCUIT_CLIENT_RENDEZVOUS_LIVE:
      v_onion_client_handle_cell( working_circuit, or_connection, cell );

      access_mutex = NULL;

      break;
    case CIRCUIT_INTRO_LIVE:
    case CIRCUIT_RENDEZVOUS:
      // pass the access mutex on so it can be given on a cleanup event
      v_onion_service_handle_cell( working_circuit, or_connection, cell );

      access_mutex = NULL;

      break;
    default:
      MINITOR_LOG( CORE_TAG, "Got an unknown circuit status in v_handle_tor_cell" );

      break;
  }

  if ( working_circuit != NULL )
  {
    if (
      working_circuit->status != CIRCUIT_INTRO_LIVE &&
      working_circuit->status != CIRCUIT_RENDEZVOUS &&
      working_circuit->status != CIRCUIT_STANDBY
    )
    {
      // update the timeout struct to have current step
      working_circuit->want_action = true;
    }
    else
    {
      working_circuit->want_action = false;
    }
  }

  if ( access_mutex != NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE
  }

  free( cell );

  return;

circuit_rebuild:
  // this will give the mutex
  v_circuit_rebuild_or_destroy( working_circuit, or_connection );
  // MUTEX GIVE

  free( cell );
}

static void v_handle_service_tcp_data( ServiceTcpTraffic* tcp_traffic )
{
  OnionCircuit* rend_circuit;
  DlConnection* or_connection;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  // get the service that uses this circ_id
  rend_circuit = px_get_circuit_by_circ_id( onion_circuits, tcp_traffic->circ_id );

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  if ( rend_circuit != NULL )
  {
    // MUTEX TAKE
    or_connection = px_get_conn_by_id_and_lock( rend_circuit->conn_id );

    v_onion_service_handle_local_tcp_data( rend_circuit, or_connection, tcp_traffic );

    MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
    // MUTEX GIVE
  }
  else if ( tcp_traffic->length > 0 )
  {
    free( tcp_traffic->data );
  }

  free( tcp_traffic );
}

// TODO had a failure to restart an hsdir upload circuit
// this function seems to have been called but no subsequent
// circuit init showed in the log
static void v_handle_conn_close( uint32_t conn_id )
{
  int i = 0;
  OnionCircuit* closed_circuits[20];
  OnionCircuit* closed_circuit;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  closed_circuit = onion_circuits;

  while ( closed_circuit != NULL )
  {
    if ( closed_circuit->conn_id == conn_id )
    {
      closed_circuits[i] = closed_circuit;
      i++;
    }

    closed_circuit = closed_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  for ( i = i - 1; i >= 0; i-- )
  {
    MINITOR_LOG( CORE_TAG, "conn closed status: %d target_status: %d", closed_circuits[i]->status, closed_circuits[i]->target_status );
    v_circuit_rebuild_or_destroy( closed_circuits[i], NULL );
  }
}

static void v_init_circuit( CreateCircuitRequest* create_request )
{
  int succ;
  OnionCircuit* new_circuit;
  OnionRelay* start_relay;
  OnionRelay* end_relay;
  DlConnection* or_connection = NULL;

  new_circuit = malloc( sizeof( OnionCircuit ) );

  memset( new_circuit, 0, sizeof( OnionCircuit ) );

  new_circuit->status = CIRCUIT_CREATE;
  new_circuit->target_status = create_request->target_status;
  new_circuit->service = create_request->service;
  new_circuit->client = create_request->client;
  new_circuit->desc_index = create_request->desc_index;
  new_circuit->target_relay_index = create_request->target_relay_index;
  new_circuit->hs_crypto = create_request->hs_crypto;
  new_circuit->intro_crypto = create_request->intro_crypto;
  new_circuit->want_action = false;

  if ( new_circuit->client != NULL )
  {
    if ( new_circuit->target_status == CIRCUIT_CLIENT_INTRO )
    {
      new_circuit->client->intro_circuit = new_circuit;
    }
    else if ( new_circuit->target_status == CIRCUIT_CLIENT_RENDEZVOUS )
    {
      new_circuit->client->rend_circuit = new_circuit;
    }
  }

  if ( d_prepare_onion_circuit( new_circuit, create_request->length, create_request->start_relay, create_request->end_relay ) < 0 )
  {
    goto fail;
  }

  succ = d_attach_or_connection( new_circuit->relay_list.head->relay->address, new_circuit->relay_list.head->relay->or_port, new_circuit );

  if ( succ < 0 )
  {
    goto fail;
  }

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( new_circuit->conn_id );

  // connection is live, start create
  if ( succ == 1 )
  {
    if ( d_send_circuit_create( new_circuit, or_connection ) < 0 )
    {
      goto fail;
    }

    new_circuit->status = CIRCUIT_CREATED;
    new_circuit->want_action = true;
    time( &(new_circuit->last_action) );
  }

  MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
  // MUTEX GIVE

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  // add to both master list and this service's list
  v_add_circuit_to_list( new_circuit, &onion_circuits );

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  free( create_request );

  return;

// try to make the circuit again
fail:
  start_relay = NULL;
  end_relay = NULL;

  // the prepare function frees these but they will still be non NULL
  if ( create_request->start_relay != NULL )
  {
    start_relay = malloc( sizeof( OnionRelay ) );
    memcpy( start_relay, new_circuit->relay_list.head->relay, sizeof( OnionRelay ) );
  }

  if ( create_request->end_relay != NULL )
  {
    end_relay = malloc( sizeof( OnionRelay ) );
    memcpy( end_relay, new_circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
  }

  d_destroy_onion_circuit( new_circuit, or_connection );
  // MUTEX GIVE

  v_send_init_circuit_internal(
    create_request->length,
    create_request->target_status,
    create_request->service,
    create_request->client,
    create_request->desc_index,
    create_request->target_relay_index,
    start_relay,
    end_relay,
    create_request->hs_crypto,
    create_request->intro_crypto
  );

  free( create_request );
  free( new_circuit );
}

static void v_handle_conn_ready( uint32_t conn_id )
{
  int i = 0;
  int f = 0;
  OnionCircuit* ready_circuit;
  OnionCircuit* ready_circuits[20];
  OnionRelay* end_relay;
  DlConnection* or_connection;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  ready_circuit = onion_circuits;

  while ( ready_circuit != NULL )
  {
    if ( ready_circuit->conn_id == conn_id )
    {
      ready_circuits[i] = ready_circuit;
      i++;
    }

    ready_circuit = ready_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  // we shouldn't need to reaquire the lock every circuit
  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( conn_id );

  if ( or_connection == NULL )
  {
    // destroy all our ready circuits
    for ( i = i - 1; i >= 0; i-- )
    {
      v_circuit_rebuild_or_destroy( ready_circuits[i], NULL );
    }

    return;
  }

  for ( f = i, i = i - 1; i >= 0; i-- )
  {
    ready_circuits[i]->want_action = true;
    time( &(ready_circuits[i]->last_action) );

    if ( ready_circuits[i]->status == CIRCUIT_CREATE && d_send_circuit_create( ready_circuits[i], or_connection ) < 0 )
    {
      f--;

      // don't pass in the or_connection, keeps our lock
      v_circuit_rebuild_or_destroy( ready_circuits[i], NULL );
    }
  }

  MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
  // MUTEX GIVE

  if ( f == 0 )
  {
    v_cleanup_connection( or_connection );
  }
}

static void v_handle_scheduled_consensus()
{
  v_send_init_circuit_fetch_internal();
}

static void v_keep_circuitlist_alive()
{
  Cell* padding_cell;
  DlConnection* or_connection;
  OnionCircuit* working_circuit;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  working_circuit = onion_circuits;

  while ( working_circuit != NULL )
  {
    // MUTEX TAKE
    or_connection = px_get_conn_by_id_and_lock( working_circuit->conn_id );

    if ( or_connection == NULL )
    {
      working_circuit = working_circuit->next;

      continue;
    }

    padding_cell = malloc( MINITOR_CELL_LEN );

    padding_cell->command = PADDING;
    padding_cell->circ_id = working_circuit->circ_id;
    padding_cell->length = FIXED_CELL_HEADER_SIZE;

    if ( d_send_cell_and_free( or_connection, padding_cell ) < 0 )
    {
      MINITOR_LOG( CORE_TAG, "Failed to send padding cell on circ_id: %d", working_circuit->circ_id );
    }

    MINITOR_MUTEX_GIVE( connection_access_mutex[or_connection->mutex_index] );
    // MUTEX GIVE

    working_circuit = working_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  MINITOR_TIMER_RESET_BLOCKING( keepalive_timer );
}

static void v_handle_scheduled_hsdir( OnionService* service )
{
  if ( d_push_hsdir( service ) < 0 )
  {
    MINITOR_LOG( CORE_TAG, "Failed to push hsdir for service on port: %d", service->local_port );

    MINITOR_TIMER_RESET_BLOCKING( service->hsdir_timer );
  }
}

static void v_init_service( OnionService* service )
{
  int i;
  int j;
  OnionMessage* onion_message;
  OnionRelay* start_relay;
  uint8_t final_identities[2][ID_LENGTH];
  int duplicate;

  service->intro_live_count = 0;

  v_add_service_to_list( service, &onion_services );

  start_relay = px_get_random_fast_relay( 1, NULL, NULL, NULL );

  if ( start_relay == NULL )
  {
    return;
  }

  i = d_get_standby_count();

  for ( ; i < 2; i++ )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = INIT_CIRCUIT;
    onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

    memset( onion_message->data, 0, sizeof( CreateCircuitRequest ) );

    ((CreateCircuitRequest*)onion_message->data)->length = 1;
    ((CreateCircuitRequest*)onion_message->data)->target_status = CIRCUIT_STANDBY;
    ((CreateCircuitRequest*)onion_message->data)->service = service;

    MINITOR_ENQUEUE_BLOCKING( core_internal_queue, (void*)(&onion_message) );
  }

  for ( i = 0; i < 3; i++ )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = INIT_CIRCUIT;
    onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

    memset( onion_message->data, 0, sizeof( CreateCircuitRequest ) );

    ((CreateCircuitRequest*)onion_message->data)->length = 3;
    ((CreateCircuitRequest*)onion_message->data)->target_status = CIRCUIT_ESTABLISH_INTRO;
    ((CreateCircuitRequest*)onion_message->data)->service = service;

    if ( i == 2 )
    {
      ((CreateCircuitRequest*)onion_message->data)->start_relay = start_relay;
    }
    else
    {
      ((CreateCircuitRequest*)onion_message->data)->start_relay = malloc( sizeof( OnionRelay ) );
      memcpy( ((CreateCircuitRequest*)onion_message->data)->start_relay, start_relay, sizeof( OnionRelay ) );
    }

    do
    {
      ((CreateCircuitRequest*)onion_message->data)->end_relay = px_get_random_fast_relay( 0, NULL, start_relay->identity, NULL );;

      duplicate = 0;

      for ( j = 0; j < i; j++ )
      {
        if ( memcmp( final_identities[j], ((CreateCircuitRequest*)onion_message->data)->end_relay->identity, ID_LENGTH ) == 0 )
        {
          free( ((CreateCircuitRequest*)onion_message->data)->end_relay );
          duplicate = 1;
          break;
        }
      }
    } while ( duplicate == 1 );

    if ( i < 2 )
    {
      memcpy( final_identities[i], ((CreateCircuitRequest*)onion_message->data)->end_relay->identity, ID_LENGTH );
    }

    MINITOR_ENQUEUE_BLOCKING( core_internal_queue, (void*)(&onion_message) );
  }
}

void v_handle_circuit_timeout()
{
  /*
  struct CircIdStreamId
  {
    uint32_t circ_id;
    uint16_t stream_id;
  };
  */

  int i = 0;
  time_t now;
  time_t elapsed;
  time_t min_left = 30;
  OnionCircuit* circuit;
  OnionCircuit* timed_out_circuits[20];
  DlConnection* dl_connection;
  /*
  struct CircIdStreamId timed_out_local[20];
  OnionMessage* onion_message;
  */

  // first get all the circuits protected by the mutex
  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  time( &now );

  circuit = onion_circuits;

  while ( circuit != NULL )
  {
    if ( circuit->want_action == true )
    {
      elapsed = now - circuit->last_action;

      if ( elapsed >= WATCHDOG_TIMEOUT_PERIOD )
      {
        MINITOR_LOG( CORE_TAG, "timeout status: %d target_status: %d", circuit->status, circuit->target_status );

        timed_out_circuits[i] = circuit;
        i++;
      }
      else
      {
        if ( WATCHDOG_TIMEOUT_PERIOD - elapsed < min_left )
        {
          min_left = WATCHDOG_TIMEOUT_PERIOD - elapsed;
        }
      }
    }

    circuit = circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  // now rebuild the timed out circuits found out of the mutex
  for ( i = i - 1; i >= 0; i-- )
  {
    // MUTEX TAKE
    dl_connection = px_get_conn_by_id_and_lock( timed_out_circuits[i]->conn_id );

    if ( dl_connection == NULL )
    {
      continue;
    }

    v_circuit_rebuild_or_destroy( timed_out_circuits[i], dl_connection );
    // MUTEX GIVE
  }

  /*
  i = 0;

  // now check local connections to see if they've timed out
  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  time( &now );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->is_or == 0 )
    {
      elapsed = now - dl_connection->last_action;

      if ( elapsed >= WATCHDOG_TIMEOUT_PERIOD )
      {
        timed_out_local[i].circ_id = dl_connection->circ_id;
        timed_out_local[i].stream_id = dl_connection->stream_id;
        i++;
      }
      else
      {
        if ( WATCHDOG_TIMEOUT_PERIOD - elapsed < min_left )
        {
          min_left = WATCHDOG_TIMEOUT_PERIOD - elapsed;
        }
      }
    }

    dl_connection = dl_connection->next;
  }

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  // now queue the relay end and cleanup the local connection
  for ( i = i - 1; i >= 0; i-- )
  {
    // send a 0 length tcp message
    onion_message = malloc( sizeof( OnionMessage ) );

    onion_message->type = SERVICE_TCP_DATA;
    onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );

    ( (ServiceTcpTraffic*)onion_message->data )->length = 0;
    ( (ServiceTcpTraffic*)onion_message->data )->circ_id = timed_out_local[i].circ_id;
    ( (ServiceTcpTraffic*)onion_message->data )->stream_id = timed_out_local[i].stream_id;

    // use internal queue
    MINITOR_ENQUEUE_BLOCKING( core_internal_queue, &onion_message );

    // cleanup the local connection
    v_cleanup_local_connection( timed_out_local[i].circ_id, timed_out_local[i].stream_id );
  }
  */

  // this should also start the timer
  MINITOR_TIMER_SET_MS_BLOCKING( timeout_timer, 1000 * min_left );
}

void v_handle_conn_handshake( uint32_t conn_id, uint32_t length )
{
  Cell* cell;
  DlConnection* or_connection;
  MinitorMutex access_mutex = NULL;

  // MUTEX TAKE
  or_connection = px_get_conn_by_id_and_lock( conn_id );

  if ( or_connection == NULL )
  {
    return;
  }

  access_mutex = connection_access_mutex[or_connection->mutex_index];

  cell = or_connection->cell_ring_buf[or_connection->cell_ring_start];

  or_connection->cell_ring_buf[or_connection->cell_ring_start] = NULL;

  or_connection->cell_ring_start = ( or_connection->cell_ring_start + 1 ) % RING_BUF_LEN;

  if ( cell == NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE

    return;
  }

  switch ( or_connection->status )
  {
    case CONNECTION_WANT_VERSIONS:
      if ( ((CellShortVariable*)cell)->command != VERSIONS )
      {
        goto fail;
      }

      v_process_versions( or_connection, cell, length );

      or_connection->status = CONNECTION_WANT_CERTS;

      break;
    case CONNECTION_WANT_CERTS:
      if 
      (
        ((CellVariable*)cell)->command != CERTS ||
        d_process_certs( or_connection, cell, length ) < 0
      )
      {
        goto fail;
      }

      or_connection->status = CONNECTION_WANT_CHALLENGE;

      break;
    case CONNECTION_WANT_CHALLENGE:
      if
      (
        ((CellVariable*)cell)->command != AUTH_CHALLENGE ||
        d_process_challenge( or_connection, cell, length ) < 0
      )
      {
        goto fail;
      }

      or_connection->status = CONNECTION_WANT_NETINFO;

      break;
    case CONNECTION_WANT_NETINFO:
      if
      (
        cell->command != NETINFO ||
        d_process_netinfo( or_connection, cell ) < 0
      )
      {
        goto fail;
      }

      or_connection->status = CONNECTION_LIVE;

      MINITOR_MUTEX_GIVE( access_mutex );
      // MUTEX GIVE

      access_mutex = NULL;

      v_handle_conn_ready( or_connection->conn_id );

      break;
    case CONNECTION_LIVE:
    default:
      MINITOR_LOG( CORE_TAG, "Got an unknown connection status %d", or_connection->status );

      break;
  }

  if ( access_mutex != NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE
  }

  free( cell );

  return;

fail:
  if ( access_mutex != NULL )
  {
    MINITOR_MUTEX_GIVE( access_mutex );
    // MUTEX GIVE
  }

  free( cell );

  v_cleanup_connection( or_connection );
}

void v_minitor_daemon( void* pv_parameters )
{
  OnionMessage* onion_message;

  core_internal_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );

  MINITOR_LOG( CORE_TAG, "Starting core" );

  while ( 1 )
  {
    // if we didn't get an internal message
    if ( MINITOR_DEQUEUE_NONBLOCKING( core_internal_queue, &onion_message ) == false )
    {
      // try the external queue
      if ( MINITOR_DEQUEUE_BLOCKING( core_task_queue, &onion_message ) == false )
      {
        continue;
      }
    }

    // got a null, time to shutdown
    if ( onion_message == NULL )
    {
      MINITOR_LOG( CORE_TAG, "Minitor Shutdown" );
      MINITOR_TASK_DELETE( NULL );
    }

    //MINITOR_LOG( CORE_TAG, "Heap check %d, command: %d", xPortGetFreeHeapSize(), onion_message->type );
    MINITOR_LOG( CORE_TAG, "command: %d", onion_message->type );

    switch ( onion_message->type )
    {
      case TIMER_CONSENSUS:
        v_handle_scheduled_consensus();
        break;
      case TIMER_KEEPALIVE:
        v_keep_circuitlist_alive();
        break;
      case TIMER_HSDIR:
        v_handle_scheduled_hsdir( onion_message->data );
        break;
      case TIMER_CIRCUIT_TIMEOUT:
        v_handle_circuit_timeout();
        break;
      case INIT_SERVICE:
        v_init_service( onion_message->data );
        break;
      case INIT_CIRCUIT:
        v_init_circuit( onion_message->data );
        break;
      case TOR_CELL:
        v_handle_tor_cell( onion_message->data );
        break;
      case SERVICE_TCP_DATA:
        v_handle_service_tcp_data( onion_message->data );
        break;
      case CONN_HANDSHAKE:
        v_handle_conn_handshake( onion_message->data, onion_message->length );
        break;
      case CONN_READY:
        v_handle_conn_ready( onion_message->data );
        break;
      case CONN_CLOSE:
        v_handle_conn_close( onion_message->data );
        break;
      default:
#ifdef DEBUG_MINITOR
        MINITOR_LOG( CORE_TAG, "Got an unknown onion message %d", onion_message->type );
#endif
        break;
    }

    free( onion_message );
    
    MINITOR_LOG( CORE_TAG, "message processed" );
  }
}
