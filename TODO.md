#Minitor, a minimal Tor implementation to run on embedded devices, specifically the esp32
## List of tasks that need to be completed for the various stages of Minitor Release
[x] Principle reasearch on tor and high level understanding of how it and onion services work
[x] Creation of basic data structures and methods for working with tor cells
[x] Setup of tor experimentation network via chutney
[x] Connection to tor directory servers, fetching and parsing of network consensus
[X] Building of a tor circuit
  [x] Connection to tor directory servers, fetching and parsing of individual router descriptors
  [x] Tls connection to first onion relay
  [x] Tor "in protocol" handshake, aka handshake v3
    [x] Exchange of VERSIONS cells, currently Minitor is using tor version 4
    [x] Receive, parse and validate tor CERTS cell
    [x] Receive and generate answer to AUTH_CHALLENGE cell
    [x] Send answer in tor AUTHENTICATE cell
    [x] Exchange of NETINFO cells
  [X] Send CREATE2 cell to onion relay
  [X] Receive CREATED2 cell from onion relay, derive shared key for RELAY cells from handshake
  [X] Send EXTEND2 cell to extend the circuit to next onion relay
  [X] Receive EXTENDED2 cell from first relay, derive shared key for RELAY cells from handshake
  [X] Repeat previous two steps to extend to third router
[X] Setup fat filesystem on esp32, required to reasonably host onion services
[] Register a tor onion service
  [X] Generate onion service master identity keypair
  [?] Generate dirivative blinded keys from the identity keypair
  [X] Generate descriptor signing key
  [X] Generate descriptor encryption key
  [?] Generate and encrypt the descriptors
  [?] Calculate the position in the hash ring to upload the descriptors to
  [X] Generate introduction point authentication key
  [] Generate introduction point encryption key
  [X] Send a RELAY_COMMAND_ESTABLISH_INTRO cell to existing tor circuit to turn it into an introduction point
  [X] Receive a RELAY_COMMAND_INTRO_ESTABLISHED cell to confirm that introduction has been established
  [] Receive a RELAY_COMMAND_INTRODUCE2 cell from our introduction point
  [] Connect to rendezvous point recieved from previous cell, send a RELAY_COMMAND_RENDEZVOUS1 cell to connect to our client
[] Operate a tor onion service
  [] Receive RELAY_BEGIN cells from rendezvous-ed circuit
  [] Create a TCP socket to on-system web service
  [] Receive RELAY_DATA cells from rendezvous-ed circuit
  [] Forward RELAY_DATA contents to on-system web services
  [] Receive TCP data from the socket, package it into RELAY_DATA cells and send them over tor to the client
At this point in development, we have a working demo/prototype and I would be confident integrating this into a physical thermostat unit and advertising the product for investment or preferably, just pre orders. I don't think we need to take on investers when costs can be kept low and crowd funding/pre orders can be used instead
[] Refactor consensus fetching to cache all information in the filesystem so we don't have to fetch the consensus every time we start the system
[] Modularize each step (handshaking, cell creating, intro establishment, etc) into separate functions or even files, rename functions with prefixes to avoid name collisions with other libraries
[] Setup test infrastructure for automated testing, probably using a raspberry pi to program the esp32 with test functions that will run over a long period of time
[] Move demo to live tor network and deal with any integration hurdles that arise, this step may be very complicated since the real tor network is more diverse than the chutney tests
At this point in development, I would consider Minitor stable and suitable for use in live products, from this point we could integrate it into a smart thermostat, self grow unit, smart plug, smart butt plug etc and we will have acheived an infustructure cost an order of magnitude lower than large competitors and a level of privacy that larger companies refuse to sell
These next steps are speculative but hopefully Minitor is a big success and many developers/companies want to use it
[] Release Minitor for sale at a price of around $20
[] Setup support system, probably private forum, where Minitor customers can receive support. This would be the incentive to buy the Libre software.
[] Add additional support options like porting Minitor to other platforms and possibly onsite consulting
After this point main development tasks will be bug fixing and keeping up to date with changes to the tor protocol, tor moves relatively slow and all the documents are open so I don't see this being a huge problem
Since this system relies on a functioning tor network, a significant portion of Minitor specific profits should be reinvested into the tor network, specifically setting up more relays and funding relay related bug fixes in the mainline tor project. We don't really care about bugs in the tor client but bugs in the relays and the number of available relays are a major concern to the health of not only Minitor but any products that integrate it
