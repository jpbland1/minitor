# Minitor
Minitor is an embedded implementation of Tor that allows a Tor onion service to run on a microcontroller, though it does require an sd card or some form of filesystem.  
To get a minitor capable devboard, visit shop.3layer.dev [click here](https://shop.3layer.dev).  

# Installation
Install on Linux or else.  
Minitor currently only runs on the esp32 and requires the esp-idf to be installed. It uses freeRTOS to run concurrently and requires wolfSSL to handle the cryptography.  
First, install and setup the esp-idf [click here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).  
Once you have sourced the export script from the esp-idf `. ./esp-idf/export.sh` clone this repository into your components folder `git clone https://github.com/jpbland1/Minitor`.  
Do the same for the wolfSSL component `git clone https://github.com/jpbland1/wolfssl`.  
Minitor requires a filesystem and an up to date time system, in this snippet we use an sdcard and ntp client provided by the esp-idf:  
```
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"

#define SPI_DMA_CHAN 1
#define PIN_NUM_CS   4
#define PIN_NUM_CLK  18
#define PIN_NUM_MOSI 23
#define PIN_NUM_MISO 19
...
#include "lwip/apps/sntp.h"
...
  // setup file system
  esp_vfs_fat_sdmmc_mount_config_t mount_config = {
    .format_if_mount_failed = true,
    .max_files = 20,
    .allocation_unit_size = 16 * 1024
  };

  // SPI
  sdmmc_host_t host = SDSPI_HOST_DEFAULT();

  spi_bus_config_t bus_cfg = {
    .mosi_io_num = PIN_NUM_MOSI,
    .miso_io_num = PIN_NUM_MISO,
    .sclk_io_num = PIN_NUM_CLK,
    .quadwp_io_num = -1,
    .quadhd_io_num = -1,
    .max_transfer_sz = 4092,
  };

  ret = spi_bus_initialize( host.slot, &bus_cfg, SPI_DMA_CHAN );

  if ( ret != ESP_OK ) {
    ESP_LOGE( TAG, "Failed to initialize bus." );
    return;
  }

  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = host.slot;

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
...
  // setup the ntp client
  sntp_setoperatingmode( SNTP_OPMODE_POLL );
  sntp_setservername( 0, "pool.ntp.org" );
  sntp_init();

  do {
    vTaskDelay( pdMS_TO_TICKS( 1000 ) );
    time( &now );
    localtime_r( &now, &time_info );
  } while ( time_info.tm_year < (2016 - 1900) );
```
The path you mounted the sdcard to the filesystem, `/sdcard/` in this snippet MUST match `FILESYSTEM_PREFIX` in `minitor/include.h`  
```
#define FILESYSTEM_PREFIX "/sdcard/"
```
Finally, include Minitor in your main task and call these functions 
```
#include "minitor.h"
...
  if ( d_minitor_INIT() < 0 )
  {
    ESP_LOGE( TAG, "Failed to init" );

    // while loop is fine since we want to hang to inspect our error
    while ( 1 )
    {
    }
  }

  if ( d_setup_onion_service( 8080, 80, "/sdcard/test_service" ) < 0 )
  {
    ESP_LOGE( TAG, "Failed to setup hidden service" );
  }
```
When `d\_minitor\_INIT()` is called, all the necessary global variables, queues, semaphores and files will be created to run minitor, and the Tor network consensus documents will be fetched.  
The fetch process usually takes around 300 seconds but can vary based on the number of Tor nodes online.  
Once Minitor has the consensus documents, they are saved on the file system and don't need to be re-fetched until they expire, meaning you can restart the esp32 without having to wait again.  
When `d_setup_onion_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory )` is called, Minitor will then setup the hidden service and run in the background, the main task may continue on but the onion service won't be ready to connect until it has finished sending its hidden service descriptors, which typically takes a few minutes.  
When finished, an onion service will be setup and will proxy a web server running on the esp32 on localhost port `local_port` to port `exit_port` of the onion service.  
It will print the address of the onion service to the console but if you miss it or are running headless the onion address will be saved to the sdcard at `/sdcard/test_service/hostname`.  
This example assumes your sd card is mounted at /sdcard/ and a web server is running on localhost 8080 but you can adjust the parameters as you need.  
If you want an example project that already has the sdcard and web server, run `git clone --recurse-submodules https://github.com/jpbland1/code-me-not` which clones the code-me-not project. code-me-not is a program that lets you control the esp32's pins from a web interface without writing any code and by default it runs an onion service.  

# Running with Chutney
If you are contribuing to Minitor (<3) you will need to run Chutney [click here](https://github.com/torproject/chutney).  
Chutney is a simulated test Tor network that runs several Tor nodes on 1 computer, which allows us to do local testing and debugging without using the real Tor network.  
Once it's cloned, copy the file `minitor/chutney/mini_net` into `chutney/networks`.  
Run `export CHUTNEY_LISTEN_ADDRESS=<your local ip address>`.  
Run `./chutney configure networks/mini_net` and `./chutney start networks/mini_net` to start Chutney.  
Then in Minitor, update `MINITOR_CHUTNEY_ADDRESS_STR` and `MINITOR_CHUTNEY_ADDRESS` in `minitor/include/config.h` to match your ip address. Use a hex converter to change your address into hex, note that it needs to be in little endian (it needs to be in opposite order of the string so 0xc0 = 192 needs to be last and 0x76 = 118 needs to be first).  
You also need to un-comment `#define MINITOR_CHUTNEY` to enable chutney.  
```
#define MINITOR_CHUTNEY
#define MINITOR_CHUTNEY_ADDRESS 0x7602a8c0
#define MINITOR_CHUTNEY_ADDRESS_STR "192.168.2.118"
```
Then flash and run the esp32, it will now connect to your chutney network instead of real Tor.  
