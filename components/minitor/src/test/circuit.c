#include "esp_log.h"
#include "../../include/config.h"
#include "../../include/test/circuit.h"
#include "../../h/constants.h"
#include "../../h/circuit.h"

int d_test_circuit_memory_leak( int iterations ) {
  int i;
  int free_before;
  int free_after;
  OnionCircuit test_circuit = {
    .task_handle = NULL,
  };

  /* heap_trace_init_standalone( trace_record, 100 ); */

  for ( i = 0; i < iterations; i++ ) {
    free_before = heap_caps_get_free_size( MALLOC_CAP_8BIT );

    switch ( d_build_random_onion_circuit( &test_circuit, 3 ) ) {
      case 0:
        d_destroy_onion_circuit( &test_circuit );
        break;
      case -1:
        ESP_LOGE( MINITOR_TAG, "Failed to build" );
        break;
      case -2:
        ESP_LOGE( MINITOR_TAG, "Unable to reasonably make a circuit" );
        return -1;
        break;
    }

    free_after = heap_caps_get_free_size( MALLOC_CAP_8BIT );

    ESP_LOGE( MINITOR_TAG, "free before %d", free_before );
    ESP_LOGE( MINITOR_TAG, "free after %d", free_after );
    ESP_LOGE( MINITOR_TAG, "free diff %d", free_before - free_after );
  }

  return 0;
}

int d_test_circuit_memory_leak_truncate( int iterations ) {
  int i;
  int free_before;
  int free_after;
  OnionCircuit test_circuit = {
    .task_handle = NULL,
  };

  /* heap_trace_init_standalone( trace_record, 100 ); */

  for ( i = 0; i < iterations; i++ ) {
    free_before = heap_caps_get_free_size( MALLOC_CAP_8BIT );

    switch ( d_build_random_onion_circuit( &test_circuit, 3 ) ) {
      case 0:
        if ( test_circuit.relay_list.built_length == 3 ) {
          d_truncate_onion_circuit( &test_circuit, 2 );
        }

        if ( test_circuit.relay_list.built_length == 2 ) {
          d_truncate_onion_circuit( &test_circuit, 1 );
        }

        d_destroy_onion_circuit( &test_circuit );
        break;
      case -1:
        ESP_LOGE( MINITOR_TAG, "Failed to build" );
        break;
      case -2:
        ESP_LOGE( MINITOR_TAG, "Unable to reasonably make a circuit" );
        return -1;
        break;
    }

    free_after = heap_caps_get_free_size( MALLOC_CAP_8BIT );

    ESP_LOGE( MINITOR_TAG, "free before %d", free_before );
    ESP_LOGE( MINITOR_TAG, "free after %d", free_after );
    ESP_LOGE( MINITOR_TAG, "free diff %d", free_before - free_after );
  }

  return 0;
}
