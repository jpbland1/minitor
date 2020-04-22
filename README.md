# Minitor
## Installation
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
Now edit `components/minitor/include/config.h` and change `MINITOR_CHUTNEY_ADDRESS` to be your ip address as a small endian integer and `MINITOR_CHUTNEY_ADDRESS_STR` to be the ipv4 string of that address. The ip stack lwip uses small endian integers for addresses while tor uses big endian integers for its addresses, keep this in mind when encoding addresses:
As an example, if your address is `192.168.1.2`, you would set `#define MINITOR_CHUTNEY_ADDRESS 0x0201a8c0` where `0xc0` is `192`, `0xa8` is `168`, `0x01` is `1` and `0x02` is `2`
Now we need to insure our sd card breakout is setup correctly, I've included two images, setup1.jpg and setup2.jpg, that show how to connect the breakout to the esp. The cs pin connects to D13, the DI pin connects to D15, the DO pin connects to D4 and the CLK pin connects to D14
Additionally you must connect the 3v pin to the 3v3 on the esp32 and the GND pin to the GND pin. You must also attatch a 10K-OHM resistor, connecting the DO pin and the 3v3 pin. This will pull the DO pin up which is required
With all of that out of the way, you should be able to run `./run` to flash and run the project. At the time of writing, it should get to the point of creating hidden service keys on the sd card and register the introduction points correctly, The next step is to create the hidden service descriptors and send them to the correct HSDir relays
If you have any questions or problems setting up, contact me at jpbland@mtu.edu
