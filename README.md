# Minitor
Minitor is an embedded implementation of Tor that allows an application to easily run or connect to Tor Onion Services. Minitor was written to be much smaller than mainline Tor, allowing cheap microcontrollers with little memory to host their own Onion Service. To get a minitor capable devboard, visit shop.3layer.dev [click here](https://shop.3layer.dev).  

# Installation

## Installation on Linux
Minitor requires that wolfSSL is installed separately on linux [click here](https://github.com/wolfSSL/wolfssl).  
Then the linux port can be installed:
```
git checkout linux
./autogen.sh
./configure
make
sudo make install
```

## Installation on ESP-32
Currently the only microcontroller Minitor supports is the esp32, which requires the esp-idf to be installed.  
First, install and setup the esp-idf [click here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).  
Once you have sourced the export script from the esp-idf `. ./esp-idf/export.sh` clone this repository into your components folder `git clone https://github.com/jpbland1/minitor`.  
Do the same for the wolfSSL component `git clone https://github.com/jpbland1/wolfssl`.  
Checkout the esp32 branch of Minitor `cd components/minitor && git checkout esp32`
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

The path you mounted the sdcard to the filesystem, `/sdcard/` in this snippet MUST match `FILESYSTEM_PREFIX`

# Using Minitor

Before using minitor we need to set the `FILESYSTEM_PREFIX` definition in `minitor/include/config.h` to where you want Minitor to store consensus data and keys.

```
#define FILESYSTEM_PREFIX "./local_data/"
```

Now we can include Minitor in our application and use it to either host an Onion Service or connect to one.

## Hosting an Onion Service

```
#include <minitor.h>
#include <minitor_service.h>
...
  if ( d_minitor_INIT() < 0 )
  {
    printf( "Failed to d_minitor_INIT" );

    // while loop is fine since we want to hang to inspect our error
    while ( 1 )
    {
    }
  }

  if ( d_setup_onion_service( 8080, 80, "./local_data/test_service" ) < 0 )
  {
    printf( "Failed to setup hidden service" );
  }
```

When `d_minitor_INIT()` is called, the Tor network consensus and relay descriptors are fetched and the core daemon is started.
The fetch process usually takes around 300 seconds but can vary based on the number of Tor nodes online.
Once Minitor has the consensus documents, they are saved on the file system and don't need to be re-fetched until they expire, meaning you can restart the process without having to wait again.
When `d_setup_onion_service( 8080, 80, "./local_data/test_service" )` is called, a message is sent to the Minitor core daemon to setup and start the Onion Service.
Starting the Onion Service may take several minutes on the esp32, but since the core task is handling everything the main task can continue on without waiting.
When finished, an Onion Service will be setup and will proxy a web server on localhost port `8080` to port `80` of the onion service.  
Minitor will print the address of the onion service to the console but if you miss it or are running headless the onion address will be saved to the filesystem at `./local_data/test_service`.  

## Connecting to an Onion Service

```
#include <minitor.h>
#include <minitor_client.h>

const char* REQUEST =
"GET / HTTP/1.0\r\n"
"Host: 127.0.0.1\r\n"
"User-Agent: esp-idf/1.0 esp3266\r\n"
"Content-Type: text/plain\r\n"
"\r\n\r\n";

int i;
OnionClient* client;
int stream;
int ret;
char read_buf[512];

if ( d_minitor_INIT() < 0 )
{
  printf( "Failed to init" );

  while ( 1 )
  {
  }
}

// create a rendezvous circuit with the service
client = px_create_onion_client( "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion" );

if ( client == NULL )
{
  while ( 1 )
  {
    printf( "Failed to create client\n" );
    sleep( 1 );
  }
}

// create a stream on the circuit
stream = d_connect_onion_client( client, 80 )

if ( stream < 0 )
{
  while ( 1 )
  {
    printf( "Failed to connect client\n" );
    sleep( 1 );
  }
}

// write to the http request to the stream
if ( d_write_onion_client( client, stream, REQUEST, strlen( REQUEST ) ) != strlen( REQUEST ) )
{
  while ( 1 )
  {
    printf( "Failed to write client\n" );
    sleep( 1 );
  }
}

do
{
  ret = d_read_onion_client( client, stream, read_buf, sizeof( read_buf ) );

  if ( ret < 0 )
  {
    printf( "Failed to read on stream\n" );
    break;
  }

  printf( "ret %d\n", ret );

  for ( i = 0; i < ret; i++ )
  {
    printf( "read_buf[%d] %c\n", i, read_buf[i] );
  }
} while ( ret == sizeof( read_buf ) );
```

This example connects to the duckduckgo hidden service and prints out each byte of the homepage.
`d_minitor_INIT` is called to fetch the consensus and start the core daemon.
`px_create_onion_client` creates a rendezvous circuit to the onion service address passed in, it will block until the circuit is ready or fails to create.
`d_connect_onion_client` creates a relay stream on the rendezvous circuit to the specified port.
`d_write_onion_client` takes the client and stream and allows the stream to be written to just like a socket file descriptor
`d_read_onion_client` takes the client and stream and allows the stream to be read from just like a socket file descriptor

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
