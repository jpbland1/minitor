# Minitor
Minitor is an embedded implementation of Tor that allows a Tor onion service to run on a microcontroller, though it does require an sd card or some form of filesystem.
To get a minitor capable devboard, visit shop.3layer.dev [click here](https://shop.3layer.dev).

# Installation
Install on Linux or else.
Minitor currently only runs on the esp32 and requires the esp-idf to be installed. It uses freeRTOS to run concurrently and requires wolfSSL to handle the cryptography.
First, install and setup the esp-idf [click here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).
Once you have run the export command from esp-idf `. ./esp-idf/export.sh` clone this repository into your components folder `git clone https://git.triplelayerdevelopment.com/minitor.git/`.
Do the same for the wolfSSL component `git clone https://git.triplelayerdevelopment.com/wolfssl.git/`.
Finally, include Minitor and run these commands in your main application:
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
And presto, an onion service will be setup and will proxy a web server running on the esp32 on localhost port 8080 to port 80 of the onion service.
It will print the address of the onion service to the console but if you miss it or are running headless the onion address will be saved to the sdcard at `/sdcard/test_service/hostname`.
This example assumes your sd card is mounted at /sdcard/ and a web server is running on localhost 8080 but you can adjust the parameters as you need.
If you want an example project that already has the sdcard and web server, run `git clone --recurse-submodules https://git.triplelayerdevelopment.com/code-me-not.git/` which clones the code-me-not project. code-me-not is a program that lets you control the esp32's pins from a web interface without writing any code and by default it runs a hidden service.

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
