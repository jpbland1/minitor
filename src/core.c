#include <stddef.h>
#include <stdlib.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "../include/config.h"
#include "../h/core.h"
#include "../h/models/db.h"
#include "../h/models/relay.h"
#include "../h/consensus.h"
#include "../h/circuit.h"
#include "../h/onion_service.h"
#include "../h/connections.h"

static const char* CORE_TAG = "MINITOR DAEMON";

TimerHandle_t keepalive_timer;
TimerHandle_t timeout_timer;
OnionCircuit* onion_circuits = NULL;
OnionService* onion_services = NULL;
QueueHandle_t core_task_queue;
SemaphoreHandle_t circuits_mutex;

void v_send_init_circuit( int length, CircuitStatus target_status, OnionService* service, int desc_index, int target_relay_index, OnionRelay* start_relay, OnionRelay* end_relay, HsCrypto* hs_crypto )
{
  OnionMessage* onion_message;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->type = INIT_CIRCUIT;
  onion_message->data = malloc( sizeof( CreateCircuitRequest ) );

  ((CreateCircuitRequest*)onion_message->data)->length = length;
  ((CreateCircuitRequest*)onion_message->data)->target_status = target_status;
  ((CreateCircuitRequest*)onion_message->data)->service = service;
  ((CreateCircuitRequest*)onion_message->data)->desc_index = desc_index;
  ((CreateCircuitRequest*)onion_message->data)->target_relay_index = target_relay_index;
  ((CreateCircuitRequest*)onion_message->data)->start_relay = start_relay;
  ((CreateCircuitRequest*)onion_message->data)->end_relay = end_relay;
  ((CreateCircuitRequest*)onion_message->data)->hs_crypto = hs_crypto;

  xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
}

void v_set_hsdir_timer( TimerHandle_t hsdir_timer )
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
    ESP_LOGE( CORE_TAG, "Setting hsdir timer to backup time %lu seconds", ( 25 * voting_interval ) );
    xTimerChangePeriod( hsdir_timer, ( 1000 * ( 25 * voting_interval ) + 500 ) / portTICK_PERIOD_MS, portMAX_DELAY );
  }
  else
  {
    ESP_LOGE( CORE_TAG, "Setting hsdir timer to normal time %lu seconds", ( ( srv_start_time + ( 25 * voting_interval ) ) - now ) );
    xTimerChangePeriod( hsdir_timer, ( 1000 * ( ( srv_start_time + ( 25 * voting_interval ) ) - now ) + 500 ) / portTICK_PERIOD_MS, portMAX_DELAY );
  }

#else
  // start the hsdir_timer at 60-120 minutes, may be too long for clock accurracy
  xTimerChangePeriod( hsdir_timer, 1000 * 60 * ( ( esp_random() % 60 ) + 60 ) / portTICK_PERIOD_MS, portMAX_DELAY );
#endif
}

int d_get_standby_count()
{
  int count = 0;
  OnionCircuit* circuit;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  circuit = onion_circuits;

  while ( circuit != NULL )
  {
    if ( circuit->status == CIRCUIT_STANDBY )
    {
      count++;
    }

    circuit = circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  return count;
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

  xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
}

static int d_send_circuit_create( OnionCircuit* circuit )
{
  if ( d_router_create2( circuit ) < 0 )
  {
    return -1;
  }

  circuit->status = CIRCUIT_CREATED;

  return 0;
}

static void v_circuit_rebuild_or_destroy( OnionCircuit* circuit )
{
  int retry_length;
  OnionRelay* retry_end_relay = NULL;

  // if a fully built rend circuit is destroyed, it's up to the client to restart
  if ( circuit->status != CIRCUIT_RENDEZVOUS )
  {
    if ( circuit->target_status == CIRCUIT_ESTABLISH_INTRO )
    {
      v_send_init_circuit_intro(
        circuit->service
      );
    }
    else
    {
      if ( circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
      {
#ifdef DEBUG_MINITOR
        ESP_LOGE( CORE_TAG, "hsdir begin rebuild" );
#endif

        if ( circuit->relay_list.built_length >= 2 )
        {
          circuit->target_relay_index++;
          circuit->service->hsdir_sent++;

          if (
            circuit->service->hsdir_sent == circuit->service->hsdir_to_send ||
            circuit->target_relay_index == circuit->service->target_relays[circuit->desc_index]->length
          )
          {
            v_cleanup_service_hs_data( circuit->service, circuit->desc_index );
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

      v_send_init_circuit(
        retry_length,
        circuit->target_status,
        circuit->service,
        circuit->desc_index,
        circuit->target_relay_index,
        NULL,
        retry_end_relay,
        circuit->hs_crypto
      );
    }
  }

circuit_destroy:
  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  v_remove_circuit_from_list( circuit, &onion_circuits );

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  d_destroy_onion_circuit( circuit );

  free( circuit );
}

static void v_handle_packed_cell( uint8_t* packed_cell )
{
  int succ;
  uint32_t circ_id;
  Cell unpacked_cell;
  OnionCircuit* working_circuit;
  OnionCircuit* tmp_circuit;
  OnionService* working_service;
  OnionMessage* onion_message;
  OnionRelay* target_relay;
  DoublyLinkedOnionRelay* dl_relay;

  circ_id = ((uint32_t)packed_cell[0]) << 24;
  circ_id |= ((uint32_t)packed_cell[1]) << 16;
  circ_id |= ((uint32_t)packed_cell[2]) << 8;
  circ_id |= (packed_cell[3]);

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  working_circuit = px_get_circuit_by_circ_id( onion_circuits, circ_id );

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  if ( working_circuit == NULL )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CORE_TAG, "Discarding circuitless cell %d", circ_id );
#endif

    free( packed_cell );

    return;
  }

  time( &(working_circuit->last_action) );

  // in manual mode, another task will handle the packed cell
  if ( working_circuit->status == CIRCUIT_RENDEZVOUS )
  {
    succ = d_decrypt_packed_cell( packed_cell, CIRCID_LEN, &working_circuit->relay_list, working_circuit->hs_crypto, &unpacked_cell.recv_index );
  }
  else
  {
    succ = d_decrypt_packed_cell( packed_cell, CIRCID_LEN, &working_circuit->relay_list, NULL, &unpacked_cell.recv_index );
  }

  if ( succ < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CORE_TAG, "Failed to decrypt packed cell" );
#endif

    free( packed_cell );

    return;
  }

  // packed cell is freed here
  unpack_and_free( &unpacked_cell, packed_cell, CIRCID_LEN );

  // discard padding cell
  if ( unpacked_cell.command == PADDING )
  {
    free_cell( &unpacked_cell );

    return;
  }

  switch ( working_circuit->status )
  {
    case CIRCUIT_CREATED:
      ESP_LOGE( CORE_TAG, "in created" );
      if ( unpacked_cell.command != CREATED2 )
      {
        goto circuit_rebuild;
      }

      if ( d_router_created2( working_circuit, &unpacked_cell ) < 0 )
      {
        goto circuit_rebuild;
      }

      working_circuit->relay_list.built_length++;

      if ( working_circuit->relay_list.built_length < working_circuit->relay_list.length )
      {
        if ( d_router_extend2( working_circuit, working_circuit->relay_list.built_length ) < 0 )
        {
          goto circuit_rebuild;
        }

        working_circuit->status = CIRCUIT_EXTENDED;
      }
      else
      {
        working_circuit->status = working_circuit->target_status;

        if ( working_circuit->status == CIRCUIT_STANDBY )
        {
          ESP_LOGE( CORE_TAG, "Standby Created" );
        }
      }

      break;
    case CIRCUIT_EXTENDED:
      ESP_LOGE( CORE_TAG, "in extended" );
      if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_EXTENDED2 )
      {
        ESP_LOGE( CORE_TAG, "failed to get extended" );
        ESP_LOGE( CORE_TAG, "circ_id: %x", working_circuit->circ_id );
        ESP_LOGE( CORE_TAG, "circuit: %d %d %d", working_circuit->relay_list.head->relay->or_port, working_circuit->relay_list.head->next->relay->or_port, working_circuit->relay_list.tail->relay->or_port );
        goto circuit_rebuild;
      }

      if ( d_router_extended2( working_circuit, working_circuit->relay_list.built_length, &unpacked_cell ) < 0 )
      {
        ESP_LOGE( CORE_TAG, "failed to process extended" );
        goto circuit_rebuild;
      }

      working_circuit->relay_list.built_length++;

      if ( working_circuit->relay_list.built_length < working_circuit->relay_list.length )
      {
        if ( d_router_extend2( working_circuit, working_circuit->relay_list.built_length ) < 0 )
        {
          goto circuit_rebuild;
        }
      }
      else
      {
        if ( working_circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
        {
          if ( d_begin_hsdir( working_circuit ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_HSDIR_CONNECTED;
        }
        else if ( working_circuit->target_status == CIRCUIT_ESTABLISH_INTRO )
        {
          if ( d_router_establish_intro( working_circuit ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_INTRO_ESTABLISHED;
        }
        else if ( working_circuit->target_status == CIRCUIT_RENDEZVOUS )
        {
          if ( d_router_join_rendezvous( working_circuit, working_circuit->hs_crypto->rendezvous_cookie, working_circuit->hs_crypto->point, working_circuit->hs_crypto->auth_input_mac ) < 0 )
          {
            ESP_LOGE( CORE_TAG, "Failed to join rend" );
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_RENDEZVOUS;
        }
      }

      break;
    case CIRCUIT_TRUNCATED:
      ESP_LOGE( CORE_TAG, "in truncated" );
      if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_TRUNCATED )
      {
        ESP_LOGE( CORE_TAG, "failed to recv truncated" );
        ESP_LOGE( CORE_TAG, "command: %d", unpacked_cell.command );
        ESP_LOGE( CORE_TAG, "command: %d", ( (PayloadRelay*)unpacked_cell.payload )->command );
        goto circuit_rebuild;
      }

      if ( working_circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
      {
        target_relay = px_get_relay_by_index( working_circuit->service->target_relays[working_circuit->desc_index], working_circuit->target_relay_index );

        dl_relay = working_circuit->relay_list.tail;

        while ( dl_relay != NULL )
        {
          if ( memcmp( dl_relay->relay->identity, target_relay->identity, ID_LENGTH ) == 0 )
          {
            break;
          }

          dl_relay = dl_relay->previous;
        }

        // one of our relays matches, the target, make new circuit
        if ( dl_relay != NULL )
        {
          // MUTEX TAKE
          xSemaphoreTake( circuits_mutex, portMAX_DELAY );

          v_remove_circuit_from_list( working_circuit, &onion_circuits );

          xSemaphoreGive( circuits_mutex );
          // MUTEX GIVE

          d_destroy_onion_circuit( working_circuit );

          v_send_init_circuit(
            3,
            CIRCUIT_HSDIR_BEGIN_DIR,
            working_circuit->service,
            working_circuit->desc_index,
            working_circuit->target_relay_index,
            NULL,
            target_relay,
            NULL
          );

          free( working_circuit );
        }
        else
        {
          dl_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
          dl_relay->relay = target_relay;

          v_add_relay_to_list( dl_relay, &working_circuit->relay_list );

          if ( d_router_extend2( working_circuit, working_circuit->relay_list.built_length ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_EXTENDED;
        }
      }

      break;
    case CIRCUIT_INTRO_ESTABLISHED:
      ESP_LOGE( CORE_TAG, "in intro established" );
      if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_COMMAND_INTRO_ESTABLISHED )
      {
        goto circuit_rebuild;
      }

      working_circuit->status = CIRCUIT_INTRO_LIVE;

      working_circuit->service->intro_live_count++;

      if ( working_circuit->service->intro_live_count == 3 && working_circuit->service->hsdir_sent == 0 )
      {
        if ( d_push_hsdir( working_circuit->service ) < 0 )
        {
          ESP_LOGE( CORE_TAG, "Failed to start hsdir push" );
          v_set_hsdir_timer( working_circuit->service->hsdir_timer );
        }
      }

      break;
    case CIRCUIT_HSDIR_CONNECTED:
      ESP_LOGE( CORE_TAG, "in hsdir connected" );
      if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_CONNECTED )
      {
        goto circuit_rebuild;
      }

      if ( d_post_hs_desc( working_circuit ) < 0 )
      {
        goto circuit_rebuild;
      }

      working_circuit->status = CIRCUIT_HSDIR_DATA;

      break;
    case CIRCUIT_HSDIR_DATA:
      ESP_LOGE( CORE_TAG, "in hsdir data" );
      if ( unpacked_cell.command != RELAY || ( (PayloadRelay*)unpacked_cell.payload )->command != RELAY_DATA )
      {
        ESP_LOGE( CORE_TAG, "failed to recv hsdir data response" );
        goto circuit_rebuild;
      }

      // TODO check actual response for success

      ESP_LOGE( CORE_TAG, "%.*s\n", ( (PayloadRelay*)unpacked_cell.payload )->length, ( (RelayPayloadData*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->payload );

      working_circuit->service->hsdir_sent++;
      working_circuit->target_relay_index++;

      if
      (
        working_circuit->service->hsdir_sent == working_circuit->service->hsdir_to_send ||
        working_circuit->target_relay_index == working_circuit->service->target_relays[working_circuit->desc_index]->length
      )
      {
        v_cleanup_service_hs_data( working_circuit->service, working_circuit->desc_index );

        // MUTEX TAKE
        xSemaphoreTake( circuits_mutex, portMAX_DELAY );

        v_remove_circuit_from_list( working_circuit, &onion_circuits );

        xSemaphoreGive( circuits_mutex );
        // MUTEX GIVE

        d_destroy_onion_circuit( working_circuit );

        free( working_circuit );

        working_circuit = NULL;
      }
      else
      {
        if ( working_circuit->relay_early_count == 6 )
        {
          // MUTEX TAKE
          xSemaphoreTake( circuits_mutex, portMAX_DELAY );

          v_remove_circuit_from_list( working_circuit, &onion_circuits );

          xSemaphoreGive( circuits_mutex );
          // MUTEX GIVE

          d_destroy_onion_circuit( working_circuit );

          v_send_init_circuit(
            3,
            CIRCUIT_HSDIR_BEGIN_DIR,
            working_circuit->service,
            working_circuit->desc_index,
            working_circuit->target_relay_index,
            NULL,
            px_get_relay_by_index( working_circuit->service->target_relays[working_circuit->desc_index], working_circuit->target_relay_index ),
            NULL
          );

          free( working_circuit );

          working_circuit = NULL;
        }
        else
        {
          if ( d_router_truncate( working_circuit, working_circuit->relay_list.built_length - 1 ) < 0 )
          {
            goto circuit_rebuild;
          }

          working_circuit->status = CIRCUIT_TRUNCATED;
        }
      }

      break;
    case CIRCUIT_INTRO_LIVE:
    case CIRCUIT_RENDEZVOUS:
      ESP_LOGE( CORE_TAG, "Got a service cell" );
      v_onion_service_handle_cell( working_circuit, &unpacked_cell );

      break;
    default:
#ifdef DEBUG_MINITOR
      ESP_LOGE( CORE_TAG, "Got an unknown circuit status in v_handle_packed_cell" );
#endif
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


  free_cell( &unpacked_cell );

  return;

circuit_rebuild:
  free_cell( &unpacked_cell );

  v_circuit_rebuild_or_destroy( working_circuit );
}

static void v_handle_service_tcp_data( ServiceTcpTraffic* tcp_traffic )
{
  Cell unpacked_cell;
  OnionCircuit* rend_circuit;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  // get the service that uses this circ_id
  rend_circuit = px_get_circuit_by_circ_id( onion_circuits, tcp_traffic->circ_id );

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  if ( rend_circuit != NULL )
  {
    v_onion_service_handle_local_tcp_data( rend_circuit, tcp_traffic );
  }

  free( tcp_traffic );
}

// TODO had a failure to restart an hsdir upload circuit
// this function seems to have been called but no subsequent
// circuit init showed in the log
static void v_handle_conn_close( DlConnection* or_connection )
{
  int i = 0;
  OnionCircuit* closed_circuits[20];
  OnionCircuit* closed_circuit;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  closed_circuit = onion_circuits;

  while ( closed_circuit != NULL )
  {
    if ( closed_circuit->or_connection == or_connection )
    {
      closed_circuits[i] = closed_circuit;
      i++;
    }

    closed_circuit = closed_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  for ( i = i - 1; i >= 0; i-- )
  {
    v_circuit_rebuild_or_destroy( closed_circuits[i] );
  }
}

static void v_init_circuit( CreateCircuitRequest* create_request )
{
  int succ;
  OnionCircuit* new_circuit;
  OnionRelay* start_relay;
  OnionRelay* end_relay;

  new_circuit = malloc( sizeof( OnionCircuit ) );

  memset( new_circuit, 0, sizeof( OnionCircuit ) );

  new_circuit->status = CIRCUIT_CREATE;
  new_circuit->target_status = create_request->target_status;
  new_circuit->service = create_request->service;
  new_circuit->desc_index = create_request->desc_index;
  new_circuit->target_relay_index = create_request->target_relay_index;
  new_circuit->hs_crypto = create_request->hs_crypto;
  new_circuit->want_action = false;

  if ( d_prepare_onion_circuit( new_circuit, create_request->length, create_request->start_relay, create_request->end_relay ) < 0 )
  {
    goto fail;
  }

  succ = d_attach_or_connection( new_circuit->relay_list.head->relay->address, new_circuit->relay_list.head->relay->or_port, new_circuit );

  if ( succ < 0 )
  {
    goto fail;
  }
  // connection is live, start create
  else if ( succ == 1 )
  {
    if ( d_send_circuit_create( new_circuit ) < 0 )
    {
      goto fail;
    }

    new_circuit->status = CIRCUIT_CREATED;
    new_circuit->want_action = true;
    time( &(new_circuit->last_action) );
  }


  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  // add to both master list and this service's list
  v_add_circuit_to_list( new_circuit, &onion_circuits );

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  free( create_request );

  return;

// try to make the circuit again
fail:
  start_relay = NULL;
  end_relay = NULL;

  if ( create_request->start_relay != NULL )
  {
    start_relay = malloc( sizeof( OnionRelay ) );
    memcpy( start_relay, create_request->start_relay, sizeof( OnionRelay ) );
  }

  if ( create_request->end_relay != NULL )
  {
    end_relay = malloc( sizeof( OnionRelay ) );
    memcpy( end_relay, create_request->end_relay, sizeof( OnionRelay ) );
  }

  v_send_init_circuit(
    create_request->length,
    create_request->target_status,
    create_request->service,
    create_request->desc_index,
    create_request->target_relay_index,
    start_relay,
    end_relay,
    create_request->hs_crypto
  );

  d_destroy_onion_circuit( new_circuit );

  free( create_request );
  free( new_circuit );
}

static void v_handle_conn_ready( DlConnection* or_connection )
{
  OnionCircuit* ready_circuit;
  OnionCircuit* next_circuit;
  OnionRelay* end_relay;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  ready_circuit = onion_circuits;

  while ( ready_circuit != NULL )
  {
    next_circuit = ready_circuit->next;

    if ( ready_circuit->or_connection == or_connection )
    {
      if ( ready_circuit->status == CIRCUIT_CREATE && d_send_circuit_create( ready_circuit ) < 0 )
      {
        if ( ready_circuit->target_status == CIRCUIT_RENDEZVOUS || ready_circuit->target_status == CIRCUIT_HSDIR_BEGIN_DIR )
        {
          end_relay = malloc( sizeof( OnionRelay ) );
          memcpy( end_relay, ready_circuit->relay_list.tail->relay, sizeof( OnionRelay ) );
        }
        else
        {
          end_relay = NULL;
        }

        v_send_init_circuit(
          ready_circuit->relay_list.length,
          ready_circuit->target_status,
          ready_circuit->service,
          ready_circuit->desc_index,
          ready_circuit->target_relay_index,
          NULL,
          end_relay,
          ready_circuit->hs_crypto
        );

        v_remove_circuit_from_list( ready_circuit, &onion_circuits );

        d_destroy_onion_circuit( ready_circuit );
        free( ready_circuit );
      }
    }

    ready_circuit = next_circuit;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE
}

static void v_handle_scheduled_consensus()
{
  if ( d_fetch_consensus_info() < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CORE_TAG, "Failed to fetch consensus" );
#endif

    xTimerChangePeriod( consensus_timer, 500 / portTICK_PERIOD_MS, portMAX_DELAY );
  }
}

static void v_keep_circuitlist_alive()
{
  int succ;
  Cell padding_cell;
  OnionCircuit* working_circuit;
  unsigned char* packed_cell;

  padding_cell.command = PADDING;
  padding_cell.payload = NULL;

  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  working_circuit = onion_circuits;

  while ( working_circuit != NULL )
  {
    padding_cell.circ_id = working_circuit->circ_id;
    packed_cell = pack_and_free( &padding_cell );

    if ( d_send_packed_cell_and_free( working_circuit->or_connection, packed_cell ) < 0 )
    {
#ifdef DEBUG_MINITOR
      ESP_LOGE( CORE_TAG, "Failed to send padding cell on circ_id: %d", working_circuit->circ_id );
#endif
    }

    working_circuit = working_circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  xTimerReset( keepalive_timer, portMAX_DELAY );
}

static void v_handle_scheduled_hsdir( OnionService* service )
{
  if ( d_push_hsdir( service ) < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( CORE_TAG, "Failed to push hsdir for service on port: %d", service->local_port );
#endif

    xTimerStart( service->hsdir_timer, portMAX_DELAY );
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

    xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
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

    xQueueSendToBack( core_task_queue, (void*)(&onion_message), portMAX_DELAY );
  }
}

void v_handle_circuit_timeout()
{
  int i = 0;
  time_t now;
  time_t elapsed;
  time_t min_left = 30;
  OnionCircuit* circuit;
  OnionCircuit* timed_out[20];

  // first get all the circuits protected by the mutex
  // MUTEX TAKE
  xSemaphoreTake( circuits_mutex, portMAX_DELAY );

  time( &now );

  circuit = onion_circuits;

  while ( circuit != NULL )
  {
    if ( circuit->want_action == true )
    {
      elapsed = now - circuit->last_action;

      if ( elapsed >= 30 )
      {
        ESP_LOGE( CORE_TAG, "timeout status: %d target_status: %d", circuit->status, circuit->target_status );
        timed_out[i] = circuit;
        i++;
      }
      else
      {
        if ( 30 - elapsed < min_left )
        {
          min_left = 30 - elapsed;
        }
      }
    }

    circuit = circuit->next;
  }

  xSemaphoreGive( circuits_mutex );
  // MUTEX GIVE

  // now rebuild the timed out circuits found out of the mutex
  for ( i = i - 1; i >= 0; i-- )
  {
    v_circuit_rebuild_or_destroy( timed_out[i] );
  }


  // this should also start the timer
  xTimerChangePeriod( timeout_timer, 1000 * min_left / portTICK_PERIOD_MS, portMAX_DELAY );
}

void v_minitor_daemon( void* pv_parameters )
{
  OnionMessage* onion_message;

  while ( xQueueReceive( core_task_queue, &onion_message, portMAX_DELAY ) )
  {
    // got a null, time to shutdown
    if ( onion_message == NULL )
    {
      ESP_LOGE( CORE_TAG, "Minitor Shutdown" );
      vTaskDelete( NULL );
    }

    //ESP_LOGE( MINITOR_TAG, "Heap check %d, command: %d", xPortGetFreeHeapSize(), onion_message->type );

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
      case PACKED_CELL:
        v_handle_packed_cell( onion_message->data );
        break;
      case SERVICE_TCP_DATA:
        v_handle_service_tcp_data( onion_message->data );
        break;
      case CONN_READY:
        v_handle_conn_ready( onion_message->data );
        break;
      case CONN_CLOSE:
        v_handle_conn_close( onion_message->data );
        break;
      default:
#ifdef DEBUG_MINITOR
        ESP_LOGE( CORE_TAG, "Got an unknown onion message %d", onion_message->type );
#endif
        break;
    }

    free( onion_message );
  }
}
