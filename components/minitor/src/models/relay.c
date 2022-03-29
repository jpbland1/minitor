#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "esp_log.h"
#include "user_settings.h"
#include "driver/spi_master.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/consensus.h"
#include "../../h/models/issi.h"
#include "../../h/models/relay.h"

uint32_t hsdir_relay_count = 0;
uint32_t file_hsdir_relay_count = 0;
uint32_t random_offset_count = 1;

int file_avl_roots[3] = { HSDIR_TREE_ROOT };
int avl_roots[3] = { HSDIR_TREE_ROOT };

static int d_get_relay_from_issi( BinaryRelay* b_relay, int addr )
{
  int err;

  err = spi_device_acquire_bus( issi_spi, portMAX_DELAY );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to aquire the spi bus" );

    return -1;
  }

  spi_transaction_ext_t t;

  t.base.cmd = ISSI_READ;
  t.base.addr = ( addr & 0xffffff );
  t.base.length = 0;
  t.base.tx_buffer = NULL;
  t.base.rxlength = 8 * sizeof( BinaryRelay );
  t.base.rx_buffer = b_relay;
  t.base.flags = SPI_TRANS_VARIABLE_DUMMY;
  t.dummy_bits = 9;

  err = spi_device_polling_transmit( issi_spi, &t );

  spi_device_release_bus( issi_spi );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to transmit the spi transaction" );

    return -1;
  }

  // ensure dma memory is stable, sort of a hack
  vTaskDelay( 1 );

  return err;
}

static int d_get_relay_from_file( BinaryRelay* b_relay, int addr )
{
  int fd;
  int read_ret;
  int err;

  fd = open( "/sdcard/hsdir_relay_tree", O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  err = lseek( fd, addr + sizeof( int ) * 4, SEEK_SET );

  if ( err < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to lseek /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    close( fd );

    return -1;
  }

  read_ret = read( fd, b_relay, sizeof( BinaryRelay ) );

  close( fd );

  if ( read_ret != sizeof( BinaryRelay ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  return 0;
}

static int d_get_relay_at_address( BinaryRelay* b_relay, int addr, int file )
{
  if ( file == 1 )
  {
    return d_get_relay_from_file( b_relay, addr );
  }
  else
  {
    return d_get_relay_from_issi( b_relay, addr );
  }
}

static int d_store_relay_to_issi( BinaryRelay* b_relay, int addr )
{
  int err;

  err = spi_device_acquire_bus( issi_spi, portMAX_DELAY );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to aquire the spi bus" );

    return -1;
  }

  spi_transaction_ext_t t;

  t.base.cmd = ISSI_WRITE;
  t.base.addr = ( addr & 0xffffff );
  t.base.length = 8 * sizeof( BinaryRelay );
  t.base.tx_buffer = b_relay;
  t.base.rxlength = 0;
  t.base.rx_buffer = NULL;
  t.base.flags = 0;

  err = spi_device_polling_transmit( issi_spi, &t );

  spi_device_release_bus( issi_spi );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to transmit the spi transaction" );

    return -1;
  }

  // ensure dma memory is stable, sort of a hack
  vTaskDelay( 1 );

  return err;
}

static int d_store_relay_to_file( BinaryRelay* b_relay, int addr )
{
  int fd;
  int write_ret;
  int err;

  fd = open( "/sdcard/hsdir_relay_tree", O_WRONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  err = lseek( fd, addr + sizeof( int ) * 4, SEEK_SET );

  if ( err < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to lseek /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    close( fd );

    return -1;
  }

  write_ret = write( fd, b_relay, sizeof( BinaryRelay ) );

  close( fd );

  if ( write_ret != sizeof( BinaryRelay ) )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  return 0;
}

static int d_store_relay_at_address( BinaryRelay* b_relay, int addr, int file )
{
  if ( file == 1 )
  {
    return d_store_relay_to_file( b_relay, addr );
  }
  else
  {
    return d_store_relay_to_issi( b_relay, addr );
  }
}

int d_reset_hsdir_relay_tree()
{
  BinaryRelay* b_relay;

  avl_roots[0] = HSDIR_TREE_ROOT;
  avl_roots[1] = HSDIR_TREE_ROOT;
  avl_roots[2] = HSDIR_TREE_ROOT;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  memset( b_relay, 0xff, sizeof( BinaryRelay ) );

  if ( d_store_relay_to_issi( b_relay, avl_roots[0] ) != 0 )
  {
    return -1;
  }

  hsdir_relay_count = 0;

  free( b_relay );

  return 0;
}

static int d_rebalance_relays( int parent_addr, int child_addr, int avl_index, int file )
{
  int ret = 0;
  int tmp_addr;
  int root_addr;
  BinaryRelay* parent_relay;
  BinaryRelay* child_relay;
  BinaryRelay* tmp_relay;

  parent_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );
  child_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );
  tmp_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  if ( file == 1 )
  {
    root_addr = file_avl_roots[avl_index];
  }
  else
  {
    root_addr = avl_roots[avl_index];
  }

  while ( child_addr != root_addr )
  {
    if ( d_get_relay_at_address( parent_relay, parent_addr, file ) != 0 )
    {
      ret = -1;
      goto finish;
    }

    if ( parent_relay->avl_blocks[avl_index].right_addr == child_addr )
    {
      parent_relay->avl_blocks[avl_index].balance++;

      if ( parent_relay->avl_blocks[avl_index].balance > 1 )
      {
        if ( d_get_relay_at_address( child_relay, child_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        // rotate left
        if ( child_relay->avl_blocks[avl_index].balance > 0 )
        {
          if ( parent_addr == root_addr )
          {
            if ( file == 1 )
            {
              file_avl_roots[avl_index] = child_addr;
            }
            else
            {
              avl_roots[avl_index] = child_addr;
            }
          }
          else
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            if ( tmp_relay->avl_blocks[avl_index].right_addr == parent_addr )
            {
              tmp_relay->avl_blocks[avl_index].right_addr = child_addr;
            }
            else
            {
              tmp_relay->avl_blocks[avl_index].left_addr = child_addr;
            }

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          child_relay->avl_blocks[avl_index].parent_addr = parent_relay->avl_blocks[avl_index].parent_addr;
          parent_relay->avl_blocks[avl_index].parent_addr = child_addr;
          parent_relay->avl_blocks[avl_index].right_addr = child_relay->avl_blocks[avl_index].left_addr;
          child_relay->avl_blocks[avl_index].left_addr = parent_addr;

          if ( parent_relay->avl_blocks[avl_index].right_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = parent_addr;

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          parent_relay->avl_blocks[avl_index].balance = 0;
          child_relay->avl_blocks[avl_index].balance = 0;
        }
        // rotate right left
        else if ( child_relay->avl_blocks[avl_index].balance < 0 )
        {
          tmp_addr = child_relay->avl_blocks[avl_index].left_addr;

          if ( parent_addr == root_addr )
          {
            if ( file == 1 )
            {
              file_avl_roots[avl_index] = tmp_addr;
            }
            else
            {
              avl_roots[avl_index] = tmp_addr;
            }
          }
          else
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            if ( tmp_relay->avl_blocks[avl_index].right_addr == parent_addr )
            {
              tmp_relay->avl_blocks[avl_index].right_addr = tmp_addr;
            }
            else
            {
              tmp_relay->avl_blocks[avl_index].left_addr = tmp_addr;
            }

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          if ( d_get_relay_at_address( tmp_relay, tmp_addr, file ) != 0 )
          {
            ret = -1;
            goto finish;
          }

          tmp_relay->avl_blocks[avl_index].parent_addr = parent_relay->avl_blocks[avl_index].parent_addr;
          parent_relay->avl_blocks[avl_index].right_addr = tmp_relay->avl_blocks[avl_index].left_addr;
          tmp_relay->avl_blocks[avl_index].left_addr = parent_addr;
          child_relay->avl_blocks[avl_index].left_addr = tmp_relay->avl_blocks[avl_index].right_addr;
          tmp_relay->avl_blocks[avl_index].right_addr = child_addr;
          child_relay->avl_blocks[avl_index].parent_addr = tmp_addr;
          parent_relay->avl_blocks[avl_index].parent_addr = tmp_addr;

          if ( tmp_relay->avl_blocks[avl_index].balance > 0 )
          {
            parent_relay->avl_blocks[avl_index].balance = -1;
            child_relay->avl_blocks[avl_index].balance = 0;
          }
          else if ( tmp_relay->avl_blocks[avl_index].balance < 0 )
          {
            parent_relay->avl_blocks[avl_index].balance = 0;
            child_relay->avl_blocks[avl_index].balance = 1;
          }
          else
          {
            parent_relay->avl_blocks[avl_index].balance = 0;
            child_relay->avl_blocks[avl_index].balance = 0;
          }

          tmp_relay->avl_blocks[avl_index].balance = 0;

          if ( d_store_relay_at_address( tmp_relay, tmp_addr, file ) != 0 )
          {
            ret = -1;
            goto finish;
          }

          if ( parent_relay->avl_blocks[avl_index].right_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = parent_addr;

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          if ( child_relay->avl_blocks[avl_index].left_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, child_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = child_addr;

            if ( d_store_relay_at_address( tmp_relay, child_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }
        }

        if ( d_store_relay_at_address( child_relay, child_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        if ( d_store_relay_at_address( parent_relay, parent_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        // balance restored, now exit
        break;
      }
    }
    else if ( parent_relay->avl_blocks[avl_index].left_addr == child_addr )
    {
      parent_relay->avl_blocks[avl_index].balance--;

      if ( parent_relay->avl_blocks[avl_index].balance < -1 )
      {
        if ( d_get_relay_at_address( child_relay, child_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        // rotate right
        if ( child_relay->avl_blocks[avl_index].balance < 0 )
        {
          if ( parent_addr == root_addr )
          {
            if ( file == 1 )
            {
              file_avl_roots[avl_index] = child_addr;
            }
            else
            {
              avl_roots[avl_index] = child_addr;
            }
          }
          else
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            if ( tmp_relay->avl_blocks[avl_index].right_addr == parent_addr )
            {
              tmp_relay->avl_blocks[avl_index].right_addr = child_addr;
            }
            else
            {
              tmp_relay->avl_blocks[avl_index].left_addr = child_addr;
            }

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          child_relay->avl_blocks[avl_index].parent_addr = parent_relay->avl_blocks[avl_index].parent_addr;
          parent_relay->avl_blocks[avl_index].parent_addr = child_addr;
          parent_relay->avl_blocks[avl_index].left_addr = child_relay->avl_blocks[avl_index].right_addr;
          child_relay->avl_blocks[avl_index].right_addr = parent_addr;

          if ( parent_relay->avl_blocks[avl_index].left_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = parent_addr;

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          parent_relay->avl_blocks[avl_index].balance = 0;
          child_relay->avl_blocks[avl_index].balance = 0;
        }
        // rotate left right
        else if ( child_relay->avl_blocks[avl_index].balance > 0 )
        {
          tmp_addr = child_relay->avl_blocks[avl_index].right_addr;

          if ( parent_addr == root_addr )
          {
            if ( file == 1 )
            {
              file_avl_roots[avl_index] = tmp_addr;
            }
            else
            {
              avl_roots[avl_index] = tmp_addr;
            }
          }
          else
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            if ( tmp_relay->avl_blocks[avl_index].right_addr == parent_addr )
            {
              tmp_relay->avl_blocks[avl_index].right_addr = tmp_addr;
            }
            else
            {
              tmp_relay->avl_blocks[avl_index].left_addr = tmp_addr;
            }

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].parent_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          if ( d_get_relay_at_address( tmp_relay, tmp_addr, file ) != 0 )
          {
            ret = -1;
            goto finish;
          }

          tmp_relay->avl_blocks[avl_index].parent_addr = parent_relay->avl_blocks[avl_index].parent_addr;
          parent_relay->avl_blocks[avl_index].left_addr = tmp_relay->avl_blocks[avl_index].right_addr;
          tmp_relay->avl_blocks[avl_index].right_addr = parent_addr;
          child_relay->avl_blocks[avl_index].right_addr = tmp_relay->avl_blocks[avl_index].left_addr;
          tmp_relay->avl_blocks[avl_index].left_addr = child_addr;
          child_relay->avl_blocks[avl_index].parent_addr = tmp_addr;
          parent_relay->avl_blocks[avl_index].parent_addr = tmp_addr;

          if ( tmp_relay->avl_blocks[avl_index].balance > 0 )
          {
            child_relay->avl_blocks[avl_index].balance = -1;
            parent_relay->avl_blocks[avl_index].balance = 0;
          }
          else if ( tmp_relay->avl_blocks[avl_index].balance < 0 )
          {
            parent_relay->avl_blocks[avl_index].balance = 1;
            child_relay->avl_blocks[avl_index].balance = 0;
          }
          else
          {
            parent_relay->avl_blocks[avl_index].balance = 0;
            child_relay->avl_blocks[avl_index].balance = 0;
          }

          tmp_relay->avl_blocks[avl_index].balance = 0;

          if ( d_store_relay_at_address( tmp_relay, tmp_addr, file ) != 0 )
          {
            ret = -1;
            goto finish;
          }

          if ( parent_relay->avl_blocks[avl_index].left_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = parent_addr;

            if ( d_store_relay_at_address( tmp_relay, parent_relay->avl_blocks[avl_index].left_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }

          if ( child_relay->avl_blocks[avl_index].right_addr != -1 )
          {
            if ( d_get_relay_at_address( tmp_relay, child_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }

            tmp_relay->avl_blocks[avl_index].parent_addr = child_addr;

            if ( d_store_relay_at_address( tmp_relay, child_relay->avl_blocks[avl_index].right_addr, file ) != 0 )
            {
              ret = -1;
              goto finish;
            }
          }
        }

        if ( d_store_relay_at_address( child_relay, child_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        if ( d_store_relay_at_address( parent_relay, parent_addr, file ) != 0 )
        {
          ret = -1;
          goto finish;
        }

        // balance restored, now exit
        break;
      }
    }

    if ( d_store_relay_at_address( parent_relay, parent_addr, file ) != 0 )
    {
      ret = -1;
      goto finish;
    }

    // our addition balanced the subtree, no need to continue up
    if ( parent_relay->avl_blocks[avl_index].balance == 0 )
    {
      break;
    }

    child_addr = parent_addr;
    parent_addr = parent_relay->avl_blocks[avl_index].parent_addr;
  }

finish:
  free( parent_relay );
  free( child_relay );
  free( tmp_relay );

  return ret;
}

static int d_compare_relays_by_avl( OnionRelay* a, OnionRelay* b, int avl_index )
{
  switch ( avl_index )
  {
    case 0:
      return memcmp( a->identity, b->identity, ID_LENGTH );
    case 1:
      return memcmp( a->id_hash, b->id_hash, H_LENGTH );
    case 2:
      return memcmp( a->id_hash_previous, b->id_hash_previous, H_LENGTH );
    default:
      return 0;
  }
}

static int d_create_hsdir_relay_by_options( OnionRelay* onion_relay, int avl_index, int write_addr, int file )
{
  int ret;
  int next_addr;
  int root_addr;
  BinaryRelay* b_relay;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  if ( file == 1 )
  {
    root_addr = file_avl_roots[avl_index];
  }
  else
  {
    root_addr = avl_roots[avl_index];
  }

  next_addr = root_addr;

  while ( 1 )
  {
    if ( d_get_relay_at_address( b_relay, next_addr, file ) != 0 )
    {
      goto fail;
    }

    if ( next_addr == root_addr )
    {
      if ( b_relay->avl_blocks[avl_index].parent_addr == 0xffffffff )
      {
        b_relay->avl_blocks[avl_index].parent_addr = root_addr + sizeof( BinaryRelay );
        b_relay->avl_blocks[avl_index].left_addr = -1;
        b_relay->avl_blocks[avl_index].right_addr = -1;
        b_relay->avl_blocks[avl_index].balance = 0;

        memcpy( &b_relay->relay, onion_relay, sizeof( OnionRelay ) );

        if ( d_store_relay_at_address( b_relay, root_addr, file ) != 0 )
        {
          goto fail;
        }

        if ( avl_index == 0 )
        {
          if ( file == 1 )
          {
            file_hsdir_relay_count++;
          }
          else
          {
            hsdir_relay_count++;
          }
        }

        free( b_relay );

        return root_addr;
      }

      if ( avl_index == 0 )
      {
        write_addr = b_relay->avl_blocks[avl_index].parent_addr;
      }
    }

    ret = d_compare_relays_by_avl( onion_relay, &b_relay->relay, avl_index );

    if ( ret < 0 )
    {
      if ( b_relay->avl_blocks[avl_index].left_addr == -1 )
      {
        b_relay->avl_blocks[avl_index].left_addr = write_addr;

        break;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].left_addr;
      }
    }
    else
    {
      if ( b_relay->avl_blocks[avl_index].right_addr == -1 )
      {
        b_relay->avl_blocks[avl_index].right_addr = write_addr;

        break;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].right_addr;
      }
    }
  }

  if ( d_store_relay_at_address( b_relay, next_addr, file ) != 0 )
  {
    goto fail;
  }

  if ( avl_index == 0 )
  {
    memset( b_relay, 0xff, sizeof( BinaryRelay ) );

    memcpy( &b_relay->relay, onion_relay, sizeof( OnionRelay ) );
  }
  else
  {
    if ( d_get_relay_at_address( b_relay, write_addr, file ) != 0 )
    {
      goto fail;
    }
  }

  b_relay->avl_blocks[avl_index].parent_addr = next_addr;
  b_relay->avl_blocks[avl_index].left_addr = -1;
  b_relay->avl_blocks[avl_index].right_addr = -1;
  b_relay->avl_blocks[avl_index].balance = 0;

  if ( d_store_relay_at_address( b_relay, write_addr, file ) != 0 )
  {
    goto fail;
  }

  if ( avl_index == 0 )
  {
    if ( d_get_relay_at_address( b_relay, root_addr, file ) != 0 )
    {
      goto fail;
    }

    b_relay->avl_blocks[avl_index].parent_addr = write_addr + sizeof( BinaryRelay );

    if ( d_store_relay_at_address( b_relay, root_addr, file ) != 0 )
    {
      goto fail;
    }
  }

  if ( d_rebalance_relays( next_addr, write_addr, avl_index, file ) != 0 )
  {
    goto fail;
  }

  if ( avl_index == 0 )
  {
    if ( file == 1 )
    {
      file_hsdir_relay_count++;
    }
    else
    {
      hsdir_relay_count++;
    }
  }

  free( b_relay );

  return write_addr;

fail:
  free( b_relay );

  return -1;
}

int d_create_hsdir_relay( OnionRelay* onion_relay )
{
  int write_addr;

  // avl index 0 for identity
  write_addr = d_create_hsdir_relay_by_options( onion_relay, 0, -1, 0 );

  if ( write_addr < 0 )
  {
    return -1;
  }

  // avl index 1 for current
  write_addr = d_create_hsdir_relay_by_options( onion_relay, 1, write_addr, 0 );

  if ( write_addr < 0 )
  {
    return -1;
  }

  // avl index 2 for previous
  return d_create_hsdir_relay_by_options( onion_relay, 2, write_addr, 0 );
}

int d_traverse_hsdir_relays_in_order( BinaryRelay* b_relay, int next_addr, int* previous_addr, int offset, int avl_index )
{
  int i;
  int root_addr;

  root_addr = avl_roots[avl_index];

  // traverse to the next node offset times
  for ( i = 0; i < offset; i++ )
  {
    if ( hsdir_relay_count == 1 )
    {
      if ( d_get_relay_at_address( b_relay, root_addr, 0 ) != 0 )
      {
        return -1;
      }

      return 0;
    }

    if ( d_get_relay_at_address( b_relay, next_addr, 0 ) != 0 )
    {
      return -1;
    }

    if ( next_addr == root_addr && b_relay->avl_blocks[avl_index].parent_addr == 0xffffffff )
    {
      return -1;
    }

    // if we moved up and left, don't count it as next
    if ( *previous_addr == b_relay->avl_blocks[avl_index].right_addr )
    {
      i--;
      *previous_addr = next_addr;

      // at root, start traversing down to first node
      if ( next_addr == root_addr )
      {
        next_addr = b_relay->avl_blocks[avl_index].left_addr;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].parent_addr;
      }
    }
    else if ( *previous_addr == b_relay->avl_blocks[avl_index].left_addr )
    {
      *previous_addr = next_addr;

      if ( b_relay->avl_blocks[avl_index].right_addr == -1 )
      {
        next_addr = b_relay->avl_blocks[avl_index].parent_addr;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].right_addr;
      }
    }
    // if we traversed down or we just started at the root node
    else if ( *previous_addr == b_relay->avl_blocks[avl_index].parent_addr || ( *previous_addr == root_addr && next_addr == root_addr ) )
    {
      *previous_addr = next_addr;

      if ( b_relay->avl_blocks[avl_index].left_addr == -1 )
      {
        if ( b_relay->avl_blocks[avl_index].right_addr == -1 )
        {
          next_addr = b_relay->avl_blocks[avl_index].parent_addr;
        }
        else
        {
          next_addr = b_relay->avl_blocks[avl_index].right_addr;
        }
      }
      else
      {
        i--;
        next_addr = b_relay->avl_blocks[avl_index].left_addr;
      }
    }
  }

  return next_addr;
}

OnionRelay* px_get_hsdir_relay_by_identity( uint8_t* identity )
{
  int ret;
  int next_addr;
  BinaryRelay* b_relay;
  OnionRelay* onion_relay;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  next_addr = avl_roots[0];

  while ( 1 )
  {
    if ( d_get_relay_at_address( b_relay, next_addr, 0 ) != 0 )
    {
      goto fail;
    }

    if ( next_addr == avl_roots[0] )
    {
      if ( b_relay->avl_blocks[0].parent_addr == 0xffffffff )
      {
        goto fail;
      }
    }

    ret = memcmp( identity, b_relay->relay.identity, ID_LENGTH );

    if ( ret < 0 )
    {
      if ( b_relay->avl_blocks[0].left_addr == -1 )
      {
        goto fail;
      }
      else
      {
        next_addr = b_relay->avl_blocks[0].left_addr;
      }
    }
    else if ( ret > 0 )
    {
      if ( b_relay->avl_blocks[0].right_addr == -1 )
      {
        goto fail;
      }
      else
      {
        next_addr = b_relay->avl_blocks[0].right_addr;
      }
    }
    else
    {
      break;
    }
  }

  onion_relay = malloc( sizeof( OnionRelay ) );
  memcpy( onion_relay, &b_relay->relay, sizeof( OnionRelay ) );
  free( b_relay );

  return onion_relay;

fail:
  free( b_relay );

  return NULL;
}

OnionRelay* px_get_hsdir_relay_by_id_hash( uint8_t* id_hash, int offset, DoublyLinkedOnionRelayList* used_relays, int current )
{
  int i;
  int ret;
  int next_addr;
  int previous_addr;
  int root_addr;
  int avl_index;
  BinaryRelay* b_relay;
  DoublyLinkedOnionRelay* used_relay;
  OnionRelay* onion_relay;

  if ( current == 1 )
  {
    avl_index = 1;
  }
  else
  {
    avl_index = 2;
  }

  root_addr = avl_roots[avl_index];

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  next_addr = root_addr;

  while ( 1 )
  {
    if ( d_get_relay_at_address( b_relay, next_addr, 0 ) != 0 )
    {
      goto fail;
    }

    if ( next_addr == root_addr )
    {
      if ( b_relay->avl_blocks[avl_index].parent_addr == 0xffffffff )
      {
        goto fail;
      }
    }

    if ( current == 1 )
    {
      ret = memcmp( id_hash, b_relay->relay.id_hash, H_LENGTH );
    }
    else
    {
      ret = memcmp( id_hash, b_relay->relay.id_hash_previous, H_LENGTH );
    }

    if ( ret < 0 )
    {
      if ( b_relay->avl_blocks[avl_index].left_addr == -1 )
      {
        previous_addr = next_addr;

        if ( b_relay->avl_blocks[avl_index].right_addr != -1 )
        {
          next_addr = b_relay->avl_blocks[avl_index].right_addr;
        }
        else
        {
          next_addr = b_relay->avl_blocks[avl_index].parent_addr;
        }

        break;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].left_addr;
      }
    }
    else if ( ret > 0 )
    {
      // we have stopped at a node that is less than us
      // we need to traverse to the next node in order
      // since that will be larger than us or will be the
      // first node
      if ( b_relay->avl_blocks[avl_index].right_addr == -1 )
      {
        offset++;
        previous_addr = next_addr;
        next_addr = b_relay->avl_blocks[avl_index].parent_addr;

        break;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].right_addr;
      }
    }
    else
    {
      previous_addr = next_addr;

      if ( b_relay->avl_blocks[avl_index].right_addr == -1 )
      {
        next_addr = b_relay->avl_blocks[avl_index].parent_addr;
      }
      else
      {
        next_addr = b_relay->avl_blocks[avl_index].right_addr;
      }

      break;
    }
  }

  if ( offset == 0 && used_relays != NULL )
  {
    used_relay = used_relays->head;

    for ( i = 0; i < used_relays->length; i++ )
    {
      if ( memcmp( b_relay->relay.identity, used_relay->relay->identity, ID_LENGTH ) == 0 )
      {
        offset = 1;

        break;
      }

      used_relay = used_relay->next;
    }
  }

  while ( offset != 0 )
  {
    next_addr = d_traverse_hsdir_relays_in_order( b_relay, next_addr, &previous_addr, offset, avl_index );

    if ( next_addr < 0 )
    {
      goto fail;
    }

    offset = 0;

    used_relay = used_relays->head;

    for ( i = 0; i < used_relays->length; i++ )
    {
      if ( memcmp( b_relay->relay.identity, used_relay->relay->identity, ID_LENGTH ) == 0 )
      {
        offset = 1;

        break;
      }

      used_relay = used_relay->next;
    }
  }

  onion_relay = malloc( sizeof( OnionRelay ) );
  memcpy( onion_relay, &b_relay->relay, sizeof( OnionRelay ) );
  free( b_relay );

  return onion_relay;

fail:
  free( b_relay );

  return NULL;
}

OnionRelay* px_get_random_hsdir_relay( int want_guard, DoublyLinkedOnionRelayList* relay_list, uint8_t* exclude )
{
  int i;
  int start_addr;
  int previous_addr;
  int offset;
  BinaryRelay* b_relay;
  OnionRelay* onion_relay;
  DoublyLinkedOnionRelay* db_onion_relay;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  start_addr = avl_roots[0];
  previous_addr = avl_roots[0];
  offset = ( esp_random() % hsdir_relay_count ) + 1;
  //offset = random_offset_count;
  //random_offset_count++;

  //if ( random_offset_count > hsdir_relay_count )
  //{
    //ESP_LOGE( MINITOR_TAG, "reset random_offset_count: %d, %d", random_offset_count, hsdir_relay_count );
    //random_offset_count = 1;
  //}

  do
  {
    start_addr = d_traverse_hsdir_relays_in_order( b_relay, start_addr, &previous_addr, offset, 0 );

    if ( start_addr < 0 )
    {
      goto fail;
    }

    offset = 0;

    if ( relay_list != NULL )
    {
      db_onion_relay = relay_list->head;

      for ( i = 0; i < relay_list->length; i++ )
      {
        if ( memcmp( db_onion_relay->relay->identity, b_relay->relay.identity, ID_LENGTH ) == 0 )
        {
          break;
        }

        db_onion_relay = db_onion_relay->next;
      }

      if ( i != relay_list->length )
      {
        offset = 1;
      }
    }

    if ( want_guard == 1 && ( b_relay->relay.can_guard == 0 || b_relay->relay.is_guard == 1 ) )
    {
      offset = 1;
    }

    if ( exclude != NULL && memcmp( exclude, b_relay->relay.identity, ID_LENGTH ) == 0 )
    {
      offset = 1;
    }
  } while ( offset != 0 );

  onion_relay = malloc( sizeof( OnionRelay ) );
  memcpy( onion_relay, &b_relay->relay, sizeof( OnionRelay ) );
  free( b_relay );

  return onion_relay;

fail:
  free( b_relay );

  return NULL;
}

int d_get_hsdir_count()
{
  return hsdir_relay_count;
}

static int d_update_relay_guard( uint8_t* identity, int guard )
{
  int ret;
  int next_addr;
  BinaryRelay* b_relay;

  b_relay = heap_caps_malloc( sizeof( BinaryRelay ), MALLOC_CAP_DMA );

  next_addr = avl_roots[0];

  while ( 1 )
  {
    if ( d_get_relay_at_address( b_relay, next_addr, 0 ) != 0 )
    {
      goto fail;
    }

    if ( next_addr == avl_roots[0] )
    {
      if ( b_relay->avl_blocks[0].parent_addr == 0xffffffff )
      {
        goto fail;
      }
    }

    ret = memcmp( identity, b_relay->relay.identity, ID_LENGTH );

    if ( ret < 0 )
    {
      if ( b_relay->avl_blocks[0].left_addr == -1 )
      {
        goto fail;
      }
      else
      {
        next_addr = b_relay->avl_blocks[0].left_addr;
      }
    }
    else if ( ret > 0 )
    {
      if ( b_relay->avl_blocks[0].right_addr == -1 )
      {
        goto fail;
      }
      else
      {
        next_addr = b_relay->avl_blocks[0].right_addr;
      }
    }
    else
    {
      b_relay->relay.is_guard = guard;

      if ( d_store_relay_at_address( b_relay, next_addr, 0 ) != 0 )
      {
        goto fail;
      }

      break;
    }
  }

  free( b_relay );

  return 0;

fail:
  free( b_relay );

  return -1;
}

int d_mark_hsdir_relay_as_guard( uint8_t* identity )
{
  return d_update_relay_guard( identity, 1 );
}

int d_unmark_hsdir_relay_as_guard( uint8_t* identity )
{
  return d_update_relay_guard( identity, 0 );
}

int d_reset_hsdir_relay_tree_file()
{
  int fd;
  int i;
  uint8_t byte = 0xff;

  fd = open( "/sdcard/hsdir_relay_tree", O_CREAT | O_WRONLY | O_TRUNC );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  for ( i = 0; i < sizeof( BinaryRelay ) + sizeof( int ) * 4; i++ )
  {
    if ( write( fd, &byte, 1 ) < 0 )
    {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

        close( fd );
        return -1;
    }
  }

  file_hsdir_relay_count = 0;
  file_avl_roots[0] = HSDIR_TREE_ROOT;
  file_avl_roots[1] = HSDIR_TREE_ROOT;
  file_avl_roots[2] = HSDIR_TREE_ROOT;

  close( fd );
  return 0;
}

int d_finalize_hsdir_relays_file()
{
  int fd;
  int tree_header[4];

  tree_header[0] = file_hsdir_relay_count;
  tree_header[1] = file_avl_roots[0];
  tree_header[2] = file_avl_roots[1];
  tree_header[3] = file_avl_roots[2];

  fd = open( "/sdcard/hsdir_relay_tree", O_WRONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  if ( write( fd, tree_header, sizeof( int ) * 4 ) != sizeof( int ) * 4 )
  {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

      close( fd );
      return -1;
  }

  close( fd );
  return 0;
}

int d_load_hsdir_relays_from_file()
{
  int ret = 0;
  int tree_header[4];
  int err = 0;
  int fd;
  int read_ret;
  int addr = HSDIR_TREE_ROOT;
  uint8_t* tree_scoop;

  fd = open( "/sdcard/hsdir_relay_tree", O_RDONLY );

  if ( fd < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    return -1;
  }

  read_ret = read( fd, tree_header, sizeof( int ) * 4 );

  if ( read_ret < 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/hsdir_relay_tree, errno: %d", errno );
#endif

    close( fd );
    return -1;
  }

  if ( tree_header[0] <= 0 )
  {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "hsdir_relay_tree file not complete" );
#endif

    close( fd );
    return -1;
  }

  hsdir_relay_count = tree_header[0];
  avl_roots[0] = tree_header[1];
  avl_roots[1] = tree_header[2];
  avl_roots[2] = tree_header[3];

  tree_scoop = heap_caps_malloc( 4092, MALLOC_CAP_DMA );

  do
  {
    read_ret = read( fd, tree_scoop, 4092 );

    if ( read_ret < 0 )
    {
  #ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/hsdir_relay_tree, errno: %d", errno );
  #endif

      ret = -1;
      goto finish;
    }

    err = spi_device_acquire_bus( issi_spi, portMAX_DELAY );

    if ( err != 0 ) {
      ESP_LOGE( MINITOR_TAG, "Failed to aquire the spi bus" );

      ret = -1;
      goto finish;
    }

    spi_transaction_ext_t t;

    t.base.cmd = ISSI_WRITE;
    t.base.addr = ( addr & 0xffffff );
    t.base.length = 8 * read_ret;
    t.base.tx_buffer = tree_scoop;
    t.base.rxlength = 0;
    t.base.rx_buffer = NULL;
    t.base.flags = 0;

    err = spi_device_polling_transmit( issi_spi, &t );

    spi_device_release_bus( issi_spi );

    if ( err != 0 ) {
      ESP_LOGE( MINITOR_TAG, "Failed to transmit the spi transaction" );

      ret = -1;
      goto finish;
    }

    // ensure dma memory is stable, sort of a hack
    vTaskDelay( 1 );

    addr += read_ret;
  } while ( read_ret == 4092 );

finish:
  close( fd );
  free( tree_scoop );

  return ret;
}

int d_create_hsdir_relay_in_file( OnionRelay* onion_relay )
{
  int write_addr;

  // avl index 0 for current
  write_addr = d_create_hsdir_relay_by_options( onion_relay, 0, -1, 1 );

  if ( write_addr < 0 )
  {
    return -1;
  }

  write_addr = d_create_hsdir_relay_by_options( onion_relay, 1, write_addr, 1 );

  if ( write_addr < 0 )
  {
    return -1;
  }

  return d_create_hsdir_relay_by_options( onion_relay, 2, write_addr, 1 );
}
