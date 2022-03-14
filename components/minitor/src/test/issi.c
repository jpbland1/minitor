#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/consensus.h"
#include "../../h/models/relay.h"

#define NODE_COUNT 50

void v_test_setup_issi()
{
  if ( d_reset_hsdir_relay_tree() != 0 )
  {
    ESP_LOGE( MINITOR_TAG, "Failed to reset hsdir relay tree" );

    while ( 1 )
    {
    }
  }
}

void v_test_d_traverse_hsdir_relays_in_order()
{
  int i;
  int j;
  int next_addr;
  int previous_addr;
  uint8_t last_id_hash[H_LENGTH];
  binary_relay* b_relay;
  OnionRelay relay;

  b_relay = heap_caps_malloc( sizeof( binary_relay ), MALLOC_CAP_DMA );

  memset( &relay, 0, sizeof( OnionRelay ) );

  ESP_LOGE( MINITOR_TAG, "start test" );

  for ( i = 0; i < NODE_COUNT; i++ )
  {
    ESP_LOGE( MINITOR_TAG, "i: %d", i );

    for ( j = 0; j < H_LENGTH; j++ )
    {
      relay.id_hash[j] = esp_random() % 256;
    }

    d_create_hsdir_relay( &relay );
  }

  next_addr = hsdir_root_addr;
  previous_addr = hsdir_root_addr;

  ESP_LOGE( MINITOR_TAG, "Iterate 1 at a time" );

  // test 1 item at a time
  for ( i = 0; i < NODE_COUNT; i++ )
  {
    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, 1 );

    if ( next_addr < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to traverse to next relay FAIL" );

      while ( 1 )
      {
      }
    }

    if ( i > 0 )
    {
      if ( memcmp( b_relay->relay.id_hash, last_id_hash, H_LENGTH ) < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Relay misorder: %d FAIL", i );

        while ( 1 )
        {
        }
      }
    }

    memcpy( last_id_hash, b_relay->relay.id_hash, H_LENGTH );
  }

  ESP_LOGE( MINITOR_TAG, "Iterate from root" );

  // test iterating from root
  for ( i = NODE_COUNT - 1; i >= 0; i-- )
  {
    ESP_LOGE( MINITOR_TAG, "%d", i );

    next_addr = hsdir_root_addr;
    previous_addr = hsdir_root_addr;

    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, i + 1 );

    if ( next_addr < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to traverse to next relay FAIL" );

      while ( 1 )
      {
      }
    }

    if ( i < NODE_COUNT - 1 )
    {
      if ( memcmp( b_relay->relay.id_hash, last_id_hash, H_LENGTH ) >= 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Relay misorder: %d FAIL", i );

        while ( 1 )
        {
        }
      }
    }

    memcpy( last_id_hash, b_relay->relay.id_hash, H_LENGTH );
  }

  ESP_LOGE( MINITOR_TAG, "PASS" );

  return;
}
