#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/apps/sntp.h"

#include "wifi_connect.h"
#include "minitor.h"

#define WEB_SERVER "www.howsmyssl.com"
#define WEB_PORT 443
#define WEB_URL "https://www.howsmyssl.com/a/check"

static const char* TAG = "MAIN";

#define SPI_DMA_CHAN 1
#define PIN_NUM_MISO 4
#define PIN_NUM_MOSI 15
#define PIN_NUM_CLK  14
#define PIN_NUM_CS   13

void app_main()
{
  time_t now = 0;
  struct tm time_info = { 0 };
  int err;
  esp_err_t ret;

  esp_vfs_fat_sdmmc_mount_config_t mount_config = {
    .format_if_mount_failed = true,
    .max_files = 5,
    .allocation_unit_size = 16 * 1024
  };

  /* sdmmc_card_t* card; */

  // SPI
  sdmmc_host_t host = SDSPI_HOST_DEFAULT();

  spi_bus_config_t bus_cfg = {
    .mosi_io_num = PIN_NUM_MOSI,
    .miso_io_num = PIN_NUM_MISO,
    .sclk_io_num = PIN_NUM_CLK,
    .quadwp_io_num = -1,
    .quadhd_io_num = -1,
    .max_transfer_sz = 4000,
  };

  ret = spi_bus_initialize( host.slot, &bus_cfg, SPI_DMA_CHAN );

  if ( ret != ESP_OK ) {
    ESP_LOGE( TAG, "Failed to initialize bus." );
    return;
  }

  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = host.slot;

  /* ret = esp_vfs_fat_sdspi_mount( "/sdcard", &host, &slot_config, &mount_config, &card ); */
  ret = esp_vfs_fat_sdspi_mount( "/sdcard", &host, &slot_config, &mount_config, NULL );

  if (ret != ESP_OK) {
    if (ret == ESP_FAIL) {
      ESP_LOGE(TAG, "Failed to mount filesystem. "
        "If you want the card to be formatted, set format_if_mount_failed = true.");
    } else {
      ESP_LOGE(TAG, "Failed to initialize the card (%s). "
        "Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
    }

    return;
  }

  /* sdmmc_card_print_info( stdout, card ); */

  wifi_init_sta();

  sntp_setoperatingmode( SNTP_OPMODE_POLL );
  sntp_setservername( 0, "pool.ntp.org" );
  sntp_init();

  do {
    vTaskDelay( pdMS_TO_TICKS( 1000 ) );
    time( &now );
    localtime_r( &now, &time_info );
  } while ( time_info.tm_year < (2016 - 1900) );


  v_minitor_INIT();

  OnionService* test_service = px_setup_hidden_service( 8080, 80, "/sdcard/test_service" );
}
