#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/consensus.h"
#include "../../h/models/relay.h"

#define NODE_COUNT 1000

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
  uint8_t last[H_LENGTH];
  BinaryRelay* b_relay;
  OnionRelay relay;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  memset( &relay, 0, sizeof( OnionRelay ) );

  ESP_LOGE( MINITOR_TAG, "start insert" );
  uint64_t start = esp_timer_get_time();

  for ( i = 0; i < NODE_COUNT; i++ )
  {
    for ( j = 0; j < H_LENGTH; j++ )
    {
      if ( j < ID_LENGTH )
      {
        relay.identity[j] = esp_random() % 256;
      }

      relay.id_hash[j] = esp_random() % 256;
      relay.id_hash_previous[j] = esp_random() % 256;
      //relay.id_hash[j] = i;
      //relay.id_hash_previous[j] = i;
    }

    d_create_hsdir_relay( &relay );
  }
  ESP_LOGE( MINITOR_TAG, "Insert time: %lld", esp_timer_get_time() - start );

  ESP_LOGE( MINITOR_TAG, "Iterate over identity" );

  next_addr = avl_roots[0];
  previous_addr = avl_roots[0];

  // test 1 item at a time
  for ( i = 0; i < NODE_COUNT; i++ )
  {
    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, 1, 0 );

    if ( next_addr < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to traverse to next relay FAIL" );

      while ( 1 )
      {
      }
    }

    if ( i > 0 )
    {
      if ( memcmp( b_relay->relay.identity, last, ID_LENGTH ) < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Relay misorder by identity: %d FAIL", i );

        while ( 1 )
        {
        }
      }
    }

    memcpy( last, b_relay->relay.identity, ID_LENGTH );
  }

  ESP_LOGE( MINITOR_TAG, "Iterate over id_hash" );

  next_addr = avl_roots[1];
  previous_addr = avl_roots[1];

  // test 1 item at a time
  for ( i = 0; i < NODE_COUNT; i++ )
  {
    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, 1, 1 );

    if ( next_addr < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to traverse to next relay FAIL" );

      while ( 1 )
      {
      }
    }

    if ( i > 0 )
    {
      if ( memcmp( b_relay->relay.id_hash, last, H_LENGTH ) < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Relay misorder by identity: %d FAIL", i );

        while ( 1 )
        {
        }
      }
    }

    memcpy( last, b_relay->relay.id_hash, H_LENGTH );
  }

  ESP_LOGE( MINITOR_TAG, "Iterate over id_hash_previous" );

  next_addr = avl_roots[2];
  previous_addr = avl_roots[2];

  // test 1 item at a time
  for ( i = 0; i < NODE_COUNT; i++ )
  {
    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, 1, 2 );

    if ( next_addr < 0 )
    {
      ESP_LOGE( MINITOR_TAG, "Failed to traverse to next relay FAIL" );

      while ( 1 )
      {
      }
    }

    if ( i > 0 )
    {
      if ( memcmp( b_relay->relay.id_hash_previous, last, H_LENGTH ) < 0 )
      {
        ESP_LOGE( MINITOR_TAG, "Relay misorder by identity: %d FAIL", i );

        while ( 1 )
        {
        }
      }
    }

    memcpy( last, b_relay->relay.id_hash_previous, H_LENGTH );
  }

  ESP_LOGE( MINITOR_TAG, "PASS" );

  return;
}
