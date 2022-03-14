#include "esp_log.h"
#include "driver/spi_master.h"
#include "driver/sdspi_host.h"

#include "../../include/config.h"
#include "../../h/constants.h"
#include "../../h/models/issi.h"

spi_device_handle_t issi_spi;

int d_issi_INIT()
{
  int err;

  // register the spi device
  spi_device_interface_config_t dev_cfg = {
    .command_bits = 8,
    .address_bits = 24,
    .dummy_bits = 0,
    .clock_speed_hz = 45000000,
    .mode = 0,          //SPI mode 0
    .spics_io_num = ISSI_CS,
    .queue_size = 1,
    .flags = SPI_DEVICE_HALFDUPLEX,
  };

  err = spi_bus_add_device( SDSPI_DEFAULT_HOST, &dev_cfg, &issi_spi );

  if ( err != 0 )
  {
    ESP_LOGE( MINITOR_TAG, "Failed to add the spi device to the bus" );

    return -1;
  }

  err = spi_device_acquire_bus( issi_spi, portMAX_DELAY );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to aquire the spi bus" );
    return -1;
  }

  spi_transaction_ext_t t;

  t.base.cmd = ISSI_WRMR;
  t.base.length = 8;
  t.base.tx_data[0] = 0b01000000;
  t.base.rxlength = 0;
  t.base.rx_buffer = NULL;
  t.base.flags = SPI_TRANS_VARIABLE_ADDR | SPI_TRANS_USE_TXDATA;
  t.address_bits = 0;

  err = spi_device_polling_transmit( issi_spi, &t );

  spi_device_release_bus( issi_spi );

  if ( err != 0 ) {
    ESP_LOGE( MINITOR_TAG, "Failed to transmit the spi transaction" );
    return -1;
  }

  return 0;
}
