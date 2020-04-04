# Minitor
## Instalation
### Linux Only Fools
## esp-idf
The esp-idf is like a library that helps compile and link esp32 projects and also holds the core components like the wifi drivers, tcp stack etc
Clone and install the esp-idf from the github link and instructions, it may require an up to date version of python and other make tools
[esp-idf](https://github.com/espressif/esp-idf)
Plug your esp32 dev board into your computer via usb
Flash and run the getting started example to make sure everything is configured correctly
```bash
cd $IDF_PATH/examples/get-started/hello_world/
idf.py -p /dev/ttyUSB0 flash monitor
```
The correct dev device may not be `ttyUSB0`, you may need to use a different port
## Wolfssl
Clone the wolfssl repo, outside of the `$IDF_PATH`
[Wolfssl](https://github.com/wolfSSL/wolfssl)
Now we need to run the install script to add wolfssl as an esp-idf component
Make sure your `$IDF_PATH` environment variable is still set, you can run the `export.sh` to set it
```bash
cd wolfssl/IDE/Espressif/ESP-IDF/
./setup.sh
```
The esp-idf port of wolfssl has some problems with generating certificates and some of the hardware execeleration doesn't work so we need to make a few modifications
```bash
cd $ESP_IDF/components/wolfssl
```
change the `include/user_settings.h` to look like this:
```c
/* user_settings.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048

/* TLS 1.3                                 */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define HAVE_HKDF
#define HAVE_AEAD
#define HAVE_SUPPORTED_CURVES

/* when you want to use SINGLE THREAD */
/* #define SINGLE_THREADED */
#define NO_FILESYSTEM

#define HAVE_AESGCM
/* when you want to use SHA384 */
/* #define WOLFSSL_SHA384 */
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHA3_SMALL
#define HAVE_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519
#define ED25519_SMALL
#define HAVE_DH
#define HAVE_FFDHE_2048
#define HAVE_RSA
#define HAVE_SHA
#define HAVE_AES_CBC
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_DES3
#define WOLFSSL_ALLOW_SSLV3

#define KEEP_PEER_CERT
#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_GEN
#define SHOW_SECRETS

#define WOLFSSL_ESPWROOM32

/* esp32-wroom-32se specific definition */
#if defined(WOLFSSL_ESPWROOM32SE)
    #define WOLFSSL_ATECC508A
    #define HAVE_PK_CALLBACKS
    /* when you want to use a custom slot allocation for ATECC608A */
    /* unless your configuration is unusual, you can use default   */
    /* implementation.                                             */
    /* #define CUSTOM_SLOT_ALLOCATION                              */
#endif

/* rsa primitive specific definition */
#if defined(WOLFSSL_ESPWROOM32) || defined(WOLFSSL_ESPWROOM32SE)
    /* Define USE_FAST_MATH and SMALL_STACK                        */
    #define ESP32_USE_RSA_PRIMITIVE
    /* threshold for performance adjustment for hw primitive use   */
    /* X bits of G^X mod P greater than                            */ 
    #define EPS_RSA_EXPT_XBTIS           36
    /* X and Y of X * Y mod P greater than                         */
    #define ESP_RSA_MULM_BITS            2000
#endif

/* debug options */
#define DEBUG_WOLFSSL
/* #define WOLFSSL_ESP32WROOM32_CRYPT_DEBUG */
/* #define WOLFSSL_ATECC508A_DEBUG          */

/* date/time                               */
/* if it cannot adjust time in the device, */
/* enable macro below                      */
/* #define NO_ASN_TIME */
/* #define XTIME time */

/* when you want not to use HW acceleration */
/* #define NO_ESP32WROOM32_CRYPT */
// #define NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH
#define NO_WOLFSSL_ESP32WROOM32_CRYPT_AES
/* #define NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI */
```
The `#define WOLFSSL_ESPWROOM32` will make it define the correct properties below and the `#define NO_WOLFSSL_ESP32WROOM32_CRYPT_AES` will disable the use of hardware excelerated aes
Next, edit the `wolfssl/wolfcrypt/settings.h` uncomment the following lines:
```c
/* Uncomment next line if building for using ESP-IDF */
#define WOLFSSL_ESPIDF

/* Uncomment next line if using Espressif ESP32-WROOM-32 */
#define WOLFSSL_ESPWROOM32
```
Now, due to a bug with this port, we need to comment out the use of fast math, I honestly have no idea why but I got all kinds of bugs when this line wasn't commented out
Find the following block and comment out `#define USE_FAST_MATH`:
```c
#if defined(WOLFSSL_ESPWROOM32) || defined(WOLFSSL_ESPWROOM32SE)
   #ifndef NO_ESP32WROOM32_CRYPT
        #define WOLFSSL_ESP32WROOM32_CRYPT
        #if defined(ESP32_USE_RSA_PRIMITIVE) && \
            !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI)
            #define WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI
            // #define USE_FAST_MATH
            #define WOLFSSL_SMALL_STACK
        #endif
   #endif
#endif
#endif /* WOLFSSL_ESPIDF */
```
Lastly, there is a bug with key and certificate generation. Wolfssl has openssl compatability extensions that it uses to generate keys and certificates. These extensions are not included in the esp32 port but for some reason when you try to enable key and cert generation, it tries to include those files. I commented out the openssl extension it tires to include and everything worked:
Edit the file `src/ssl.c` and comment out `#include <wolfssl/openssl/evp.h>` in the following block
```c
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
        defined(HAVE_WEBSERVER) || defined(WOLFSSL_KEY_GEN)
    /* #include <wolfssl/openssl/evp.h> */
    /* openssl headers end, wolfssl internal headers next */
#endif
```
## Tor
You will need to install tor iteself on your test machine in order to run a test tor network. This can be done through any package manager
If you are debugging something it is sometimes super helpful to compile tor with print statements that give hits whats going wrong or print the value of a shared secret to confirm you're generating it corectly. To do this you need to compile your own tor build and link chutney to use it
Clone tor outside of other project folders from the clone link listed at:
[Tor](https://gitweb.torproject.org/tor.git/)
Follow the instructions found in INSTALL, BUT if you want to have tor installed to a specific directory other than `/usr/local`, as to not interfere with your package manager version, you need to run the configure script with `--prefix=/my/custom/directory`, more information can be found by running ./configure --help
## Chutney
Chutney is a tool used for running test tor networks, we use it as a local tor network that we can verify and debug Minitor against
Clone chutney outside of other project folders from the clone link listed at:
[Chutney](https://gitweb.torproject.org/chutney.git)
Set `$CHUTNEY_TOR` and `$CHUTNEY_TOR_GENCERT` to point to the correct binaries, might be the binaries from you package manager or the custom ones you compiled for debugging
Set `$CHUTNEY_LISTEN_ADDRESS` to your network ip, eg `192.168.1.2`, this is necessary for making circuits with more than 1 hop, otherwise it will run on `127.0.0.1` and will git confused when our client trys to extend to a network ip
Next, create the file `networks/no_clients` with the following conetents:
```
# By default, Authorities are not configured as exits
Authority = Node(tag="a", authority=1, relay=1, torrc="authority.tmpl")
ExitRelay = Node(tag="r", relay=1, exit=1, torrc="relay.tmpl")
# Client = Node(tag="c", client=1, torrc="client.tmpl")

NODES = Authority.getN(3) + ExitRelay.getN(11)

ConfigureNodes(NODES)
```
This is the config file for a network with 3 authorities, 11 relays and no clients
Now run:
```
./chutney configure networks/no_clients
./chutney start networks/no_clients
```
When you want to stop the network, run `./chutney stop networks/no_clients`
## Minitor
Now we're ready to set Minitor level settings, edit `components/wifi_connect/include/wifi_connect.h` and change the ssid and password to your wifi router's:
```c
#define EXAMPLE_ESP_WIFI_SSID      "feff"
#define EXAMPLE_ESP_WIFI_PASS      "feff"
```
Now edit `components/minitor/include/config.h` and change `MINITOR_CHUTNEY_ADDRESS` to be your ip address as a small endian integer. The ip stack lwip uses small endian integers for address while tor uses big endian integers for its addresses, keep this in mind when encoding addresses:
As an example, if your address is `192.168.1.2`, you would set `#define MINITOR_CHUTNEY_ADDRESS 0x0201a8c0` where `0xc0` is `192`, `0xa8` is `168`, `0x01` is `1` and `0x02` is `2`
Now we need to insure our sd card breakout is setup correctly, I've included two images, setup1.jpg and setup2.jpg, that show how to connect the breakout to the esp. The cs pin connects to D13, the DI pin connects to D15, the DO pin connects to D4 and the CLK pin connects to D14
Additionally you must connect the 3v pin to the 3v3 on the esp32 and the GND pin to the GND pin. You must also attatch a 10K-OHM resistor, connecting the DO pin and the 3v3 pin. This will pull the DO pin up which is required
With all of that out of the way, you should be able to run `./run` to flash and run the project. At the time of writing, it should get to the point of creating hidden service keys on the sd card and register the introduction points correctly, The next step is to create the hidden service descriptors and send them to the correct HSDir relays
If you have any questions or problems setting up, contact me at jpbland@mtu.edu
