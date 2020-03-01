#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"


#include "../include/config.h"
#include "../include/minitor.h"
#include "../include/cell.h"

#define WEB_SERVER "192.168.1.138"
#define WEB_PORT 7001
#define WEB_URL "/tor/status-vote/current/consensus"

static const char* TAG = "MINITOR: ";

static const char *REQUEST = "GET " WEB_URL " HTTP/1.0\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp3266\r\n"
    "\r\n";

static NetworkConsensus network_consensus = {
  .method = 0,
  .valid_after = 0,
  .fresh_until = 0,
  .valid_until = 0,
};

static DoublyLinkedOnionRelayList suitable_relays = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};

static const char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// intialize tor
int v_minitor_INIT() {
  // fetch network consensus
  if ( d_fetch_consensus_info() < 0 ) {
    return -1;
  }
  // TODO setup starting circuits

  return 1;
}

// create a tor circuit
/* TorCircuit* x_build_circuit( QueueHandle_t rx_queue ) { */
  // TODO find 3 suitable circuits from our directory information
  // TODO make the first create cell and  send it to the first hop
  // TODO make an extend cell and send it to the second hop
  // TODO make an extend cell and send it to the thrid hop
  // TODO register a tx_queue
  // TODO spawn a task to block on the tx_queue and cells from the queue to the tls buffer
  // TODO spawn a task to block on the tls buffer and put the data into the rx_queue
  // TODO return the circ_id and tx_queue back to the caller
/* } */

// destroy a tor circuit
/* void v_destroy_circuit( int circ_id ) { */
  // TODO send a destroy cell to the first hop
  // TODO clean up the rx,tx queues
  // TODO clean up the tls socket
  // TODO clean up any circuit specific data
/* } */

// register a hidden service
/* HiddenService x_setup_hidden_service( char* onion_address, unsigned char* private_key, QueueHandle_t rx_queue ) { */
  // TODO create two circuits that are available as introduction points
  // TODO setup introduction points with these relays
  // TODO create a two hop circuit that will be available to extend to any rendezvous requests we get
  // TODO spawn a task to block on each introduction point and when an introduction arrives, extend the two hop circuit to rendezvous with the client,
  // spawn another task to block on that tcp buffer, forward relay data's to the rx_queue
  // TODO spawn a task to block on the tx_queue and send any outgoing data to the correct circuit
  // TODO return the hidden service id and tx queue to the caller
/* } */

// shut down a hidden service
/* void v_stop_hidden_service( int hidden_service_id ) { */
  // TODO send destroy's to all hidden service associated circuits; introduction points and client rendezvous
  // TODO clean up the tls socket
  // TODO clean up the rx,tx queues
  // TODO clean up any hidden service specific data
/* } */

// perform a first time handshake with a guard cell
/* int v_relay_handshake(  ) { */

/* } */

// send a cell to a circuit
/* void v_send_cell( int circ_id, unsigned char* packed_cell ) { */

/* } */

int d_fetch_consensus_info() {
  // we will have multiple threads trying to read the network consensus so we can't
  // edit the global one outside of a critical section. We want to keep our critical
  // sections short so we're going to store everything in a local variable and then
  // transfer it over
  NetworkConsensus result_network_consensus = {
    .method = 0,
    .valid_after = 0,
    .fresh_until = 0,
    .valid_until = 0,
  };

  // in order to find the strings we need, we just compare each byte to the string
  // and every time we get a match we increment how many we've found. If we don't
  // get a match we reset the count to 0. once the count is equal to the length of
  // the string we know we've found that string in the document and can start parsing
  // its value
  const char* consensus_method = "consensus-method ";
  int consensus_method_found = 0;
  const char* valid_after = "valid-after ";
  int valid_after_found = 0;
  const char* fresh_until = "fresh-until ";
  int fresh_until_found = 0;
  const char* valid_until = "valid-until ";
  int valid_until_found = 0;
  // the * is used to match any character since the number will vary
  const char* previous_shared_rand = "shared-rand-previous-value * ";
  int previous_shared_rand_found = 0;
  // TODO possibly better to make this a constant instead of a magic number
  char previous_shared_rand_64[43] = {0};
  int previous_shared_rand_length = 0;
  const char* shared_rand = "shared-rand-current-value * ";
  int shared_rand_found = 0;
  char shared_rand_64[43] = {0};
  int shared_rand_length = 0;
  // create a time object so we can easily convert to the epoch
  struct tm temp_time = {
    .tm_year = -1,
    .tm_mon = -1,
    .tm_mday = -1,
    .tm_hour = -1,
    .tm_min = -1,
    .tm_sec = -1,
  };
  // temp variables for finding and sotring date values, same concept as
  // string matching
  int year = 0;
  int year_found = 0;
  int month = 0;
  int month_found = 0;
  int day = 0;
  int day_found = 0;
  int hour = 0;
  int hour_found = 0;
  int minute = 0;
  int minute_found = 0;
  int second = 0;
  int second_found = 0;

  // variable for string a canidate relay. because we parse one byte at
  // a time we need to store data on a relay before we know if its actuall
  // suitable
  DoublyLinkedOnionRelay* canidate_relay = NULL;
  // since many threads may be accessing the suitable relay list we need
  // to use a temp variable to keep our critical section short
  DoublyLinkedOnionRelayList result_suitable_relays = {
    .head = NULL,
    .tail = NULL,
    .length = 0,
  };
  // string matching variables for relays and tags
  const char* relay = "\nr ";
  int relay_found = 0;
  const char* tag = "\ns ";
  int tag_found = 0;
  // counts the current element of the relay we're on since they are in
  // a set order
  int relay_element_num = -1;
  // holds the base64 encoded value of the relay's identity
  char identity[27] = {0};
  int identity_length = 0;
  // holds the base64 encoded value of the relay's digest
  char digest[27] = {0};
  int digest_length = 0;
  // holds one octect of an ipv4 address
  unsigned char address_byte = 0;
  // offsset to shift the octect
  int address_offset = 24;
  // string matching variables for possible tags
  const char* fast = "Fast";
  int fast_found = 0;
  const char* running = "Running";
  int running_found = 0;
  const char* stable = "Stable";
  int stable_found = 0;
  const char* valid = "Valid";
  int valid_found = 0;

  // information for connecting to the directory server
  int i;
  int rx_length;
  int sock_fd;
  char end_header = 0;
  // buffer thath holds data returned from the socket
  char rx_buffer[512];
  char addr_str[128];
  struct sockaddr_in dest_addr;

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "192.168.1.138" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( WEB_PORT );
  inet_ntoa_r( dest_addr.sin_addr, addr_str, sizeof( addr_str ) - 1 );

  // create a socket to access the consensus
  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( TAG, "couldn't create a socket to http server\n" );
#endif

    return -1;
  }

  // connect the socket to the dir server address
  int err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( err != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( TAG, "couldn't connect to http server" );
#endif

    return -1;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGI( TAG, "connected to http socket" );
#endif

  // send the http request to the dir server
  err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( TAG, "couldn't send to http server" );
#endif

    return -1;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGI( TAG, "sent to http socket" );
#endif

  // keep reading forever, we will break inside when the transfer is over
  while ( 1 ) {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( TAG, "couldn't recv http server" );
#endif

      return -1;
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    } else if ( rx_length == 0 ) {
      break;
    }

#ifdef DEBUG_MINITOR
    ESP_LOGI( TAG, "recved from http socket" );
#endif

    // iterate over each byte we got back from the socket recv
    // NOTE that we can't rely on all the data being there, we
    // have to treat each byte as though we only have that byte
    for ( i = 0; i < rx_length; i++ ) {
      // skip over the http header, when we get two \r\n s in a row we
      // know we're at the end
      if ( end_header < 4 ) {
        // increment end_header whenever we get part of a carrage retrun
        if ( rx_buffer[i] == '\r' || rx_buffer[i] == '\n' ) {
          end_header++;
        // otherwise reset the count
        } else {
          end_header = 0;
        }
      // if we have 4 end_header we're onto the actual data
      } else {
        // if we haven't already parsed the consensus method
        if ( result_network_consensus.method == 0 || consensus_method_found != 0 ) {
          // if we've found the consensus method string and we haven't hit a newline, start parsing the value
          if ( consensus_method_found == strlen( consensus_method ) && rx_buffer[i] != '\n' ) {
            result_network_consensus.method *= 10;
            result_network_consensus.method += rx_buffer[i] - 48;
          // otherwise if we match a a caracter, increment found
          } else if ( result_network_consensus.method == 0 && rx_buffer[i] == consensus_method[consensus_method_found] ) {
            consensus_method_found++;
          // lastly if we don't match the string or we've hit the newline, reset the found
          // if we've hit the newline, this will set the entry check to false so we don't
          // keep trying to parse this value if we've already got it
          } else {
            consensus_method_found = 0;
          }
        }

        // if we don't already have a valid after value
        if ( result_network_consensus.valid_after == 0 ) {
          // if we've already matched the string and we haven't hit a newline parse the date
          if ( valid_after_found == strlen( valid_after ) && rx_buffer[i] != '\n' ) {
            // parse the date for this one byte, if we've reached the end of the date
            // fill the result network consensus with the epoch
            if ( d_parse_date_byte( rx_buffer[i], &year, &year_found, &month, &month_found, &day, &day_found, &hour, &hour_found, &minute, &minute_found, &second, &second_found, &temp_time ) == 1 ) {
              result_network_consensus.valid_after = mktime( &temp_time );
            }
          // otherwise if we match a a caracter, increment found
          } else if ( result_network_consensus.valid_after == 0 && rx_buffer[i] == valid_after[valid_after_found] ) {
            valid_after_found++;
          // lastly if we don't match the string or we've hit the newline, reset the found
          // if we've hit the newline
          } else {
            valid_after_found = 0;
          }
        }

        // comments are excluded here due to similarity with the valid after
        // logic, same thing applies here just for the fresh until value
        if ( result_network_consensus.fresh_until == 0 ) {
          if ( fresh_until_found == strlen( fresh_until ) && rx_buffer[i] != '\n' ) {
            if ( d_parse_date_byte( rx_buffer[i], &year, &year_found, &month, &month_found, &day, &day_found, &hour, &hour_found, &minute, &minute_found, &second, &second_found, &temp_time ) == 1 ) {
              result_network_consensus.fresh_until = mktime( &temp_time );
            }
          } else if ( result_network_consensus.fresh_until == 0 && rx_buffer[i] == fresh_until[fresh_until_found] ) {
            fresh_until_found++;
          } else {
            fresh_until_found = 0;
          }
        }

        // comments are excluded here due to similarity with the valid after
        // logic, same thing applies here just for the valid until value
        if ( result_network_consensus.valid_until == 0 ) {
          if ( valid_until_found == strlen( valid_until ) && rx_buffer[i] != '\n' ) {
            if ( d_parse_date_byte( rx_buffer[i], &year, &year_found, &month, &month_found, &day, &day_found, &hour, &hour_found, &minute, &minute_found, &second, &second_found, &temp_time ) == 1 ) {
              result_network_consensus.valid_until = mktime( &temp_time );
            }
          } else if ( result_network_consensus.valid_until == 0 && rx_buffer[i] == valid_until[valid_until_found] ) {
            valid_until_found++;
          } else {
            valid_until_found = 0;
          }
        }

        // -1 marks the previous_shared_rand as alrady having been parsed
        // if we've already parsed it stop trying
        if ( previous_shared_rand_found != -1 ) {
          // if we've already matched the string start recording the base64 value
          if ( previous_shared_rand_found == strlen( previous_shared_rand ) ) {
            // if we've got 43 characters of the base64 value, decode it and
            // copy it into the unsigned char array
            if ( previous_shared_rand_length == 43 ) {
              v_base_64_decode_buffer( result_network_consensus.previous_shared_rand, previous_shared_rand_64, previous_shared_rand_length );
              previous_shared_rand_found = -1;
            // otherwise keep copying the base64 characters into the array
            } else {
              previous_shared_rand_64[previous_shared_rand_length] = rx_buffer[i];
              previous_shared_rand_length++;
            }
          // if the string matches, increment the found
          /* } else if ( previous_shared_rand_found < strlen( previous_shared_rand ) && ( rx_buffer[i] == previous_shared_rand[previous_shared_rand_found] || previous_shared_rand[previous_shared_rand_found] == '*' ) ) { */
          } else if ( rx_buffer[i] == previous_shared_rand[previous_shared_rand_found] || previous_shared_rand[previous_shared_rand_found] == '*' ) {
            previous_shared_rand_found++;
          // if we don't match reset the found
          } else {
            previous_shared_rand_found = 0;
          }
        }

        // comments excluded due to similarity with previous shared value parsing
        if ( shared_rand_found != -1 ) {
          if ( shared_rand_found == strlen( shared_rand ) ) {
            if ( shared_rand_length == 43 ) {
              v_base_64_decode_buffer( result_network_consensus.shared_rand, shared_rand_64, shared_rand_length );
              shared_rand_found = -1;
            } else {
              shared_rand_64[shared_rand_length] = rx_buffer[i];
              shared_rand_length++;
            }
          } else if ( rx_buffer[i] == shared_rand[shared_rand_found] || shared_rand[shared_rand_found] == '*' ) {
            shared_rand_found++;
          } else {
            shared_rand_found = 0;
          }
        }

        // if we've found a relay tag
        if ( relay_found == strlen( relay ) ) {
          // if we don't already have a canidate relay the we just hit the tag
          // create the relay node and set the necessary variables
          if ( canidate_relay == NULL ) {
            canidate_relay = malloc( sizeof( DoublyLinkedOnionRelay ) );
            canidate_relay->next = NULL;
            canidate_relay->previous = NULL;
            canidate_relay->relay = malloc( sizeof( OnionRelay ) );
            canidate_relay->relay->address = 0;
            canidate_relay->relay->or_port = 0;
            canidate_relay->relay->dir_port = 0;
            // reset relay element num from -1 to 0
            relay_element_num = 0;
          }

          // if we haven't finished parsing all the relay elements
          if ( relay_element_num != -1 ) {
            // if we hit a space
            if ( rx_buffer[i] == ' ' ) {
              // if we're on element 5 we need to update the address
              if ( relay_element_num == 5 ) {
                canidate_relay->relay->address |= ( (int)address_byte ) << address_offset;
                // reset the address byte and offset for next relay
                address_byte = 0;
                address_offset = 24;

#ifdef MINITOR_CHUTNEY
                // override the address if we're using chutney
                canidate_relay->relay->address = MINITOR_CHUTNEY_ADDRESS;
#endif
              }

              // move on to the next relay element
              relay_element_num++;
            // otherwise if we hit a newline
            } else if ( rx_buffer[i] == '\n' ) {
              // mark the element num as ended
              relay_element_num = -1;

              // if we've matched the tag then increment found, since \n is part of the tag
              if ( rx_buffer[i] == tag[tag_found] ) {
                tag_found++;
              }
            // otherwise if we haven't hit a newline or a space we need to parse an element
            } else {
              // handle the possible relay elements based on the num since they're in order
              switch ( relay_element_num ) {
                // identity
                case 1:
                  // put the base64 character into the identity array
                  identity[identity_length] = rx_buffer[i];
                  identity_length++;

                  // if we hit 27 decode the base64 string into the char array for the relay
                  if ( identity_length == 27 ) {
                    v_base_64_decode_buffer( canidate_relay->relay->identity, identity, identity_length );;
                  }

                  break;
                // digest
                case 2:
                  // same as with the identity
                  digest[digest_length] = rx_buffer[i];
                  digest_length++;

                  if ( digest_length == 27 ) {
                    v_base_64_decode_buffer( canidate_relay->relay->digest, digest, digest_length );;
                  }

                  break;
                // address
                case 5:
                  // if we hit a period we ned to store that byte of the address
                  if ( rx_buffer[i] == '.' ) {
                    // add the address to the byte at the correct offset
                    canidate_relay->relay->address |= ( (int)address_byte ) << address_offset;
                    // move the offset and reset the byte
                    address_offset -= 8;
                    address_byte = 0;
                  // otherwise add the character to the byte
                  } else {
                    address_byte *= 10;
                    address_byte += rx_buffer[i] - 48;
                  }

                  break;
                // onion port
                case 6:
                  // add the character to the short
                  canidate_relay->relay->or_port *= 10;
                  canidate_relay->relay->or_port += rx_buffer[i] - 48;

                  break;
                // dir port
                case 7:
                  // add the character to the short
                  canidate_relay->relay->dir_port *= 10;
                  canidate_relay->relay->dir_port += rx_buffer[i] - 48;

                  break;
                // for all other elements we don't need to parse them
                default:
                  break;
              }
            }
          // otherwise we're done parsing the relay line and we need to parse the tags
          } else {
            // if we've already matched the tag string
            if ( tag_found == strlen( tag ) ) {
              // if we hit a newline we're done parsing the tags and need to add it to
              // the array lists
              if ( rx_buffer[i] == '\n' ) {
                // if the relay is fast, running, stable and valid then we want to use it
                if ( fast_found == strlen( fast ) && running_found == strlen( running ) && stable_found == strlen( stable ) && valid_found == strlen( valid ) ) {
                  v_add_relay_to_list( canidate_relay, &result_suitable_relays );
                // otherwise its not suiteable and wee need to free the canidate
                } else {
                  free( canidate_relay->relay );
                  free( canidate_relay );
                }

                // clean up the associated string matching variables and
                // reset the canidate relay to null
                canidate_relay = NULL;
                relay_found = 0;
                identity_length = 0;
                digest_length = 0;
                tag_found = 0;
                fast_found = 0;
                running_found = 0;
                stable_found = 0;
                valid_found = 0;
              // otherwise we need to match the tags
              } else {
                // if the found is less than the length of the string
                if ( fast_found < strlen( fast ) ) {
                  // if the character matches
                  if ( fast[fast_found] == rx_buffer[i] ) {
                    fast_found++;
                  // otherwise reset the count
                  } else {
                    fast_found = 0;
                  }
                }
                // NOTE the other tag matching sections have
                // the same logic so  comments are excluded

                if ( running_found < strlen( running ) ) {
                  if ( running[running_found] == rx_buffer[i] ) {
                    running_found++;
                  } else {
                    running_found = 0;
                  }
                }

                if ( stable_found < strlen( stable ) ) {
                  if ( stable[stable_found] == rx_buffer[i] ) {
                    stable_found++;
                  } else {
                    stable_found = 0;
                  }
                }

                if ( valid_found < strlen( valid ) ) {
                  if ( valid[valid_found] == rx_buffer[i] ) {
                    valid_found++;
                  } else {
                    valid_found = 0;
                  }
                }
              }
            // if we match the tag string increment the found
            } else if ( rx_buffer[i] == tag[tag_found] ) {
              tag_found++;
            // otherwise reset the found
            } else {
              tag_found = 0;
            }
          }
        // if we've matched part of the tag increment found
        } else if ( rx_buffer[i] == relay[relay_found] ) {
          relay_found++;
        // otherwise reset the found
        } else {
          relay_found = 0;
        }
      }
    }
  }

  // TODO some kind of mutex for when this is run as a task
  network_consensus.method = result_network_consensus.method;
  network_consensus.valid_after = result_network_consensus.valid_after;
  network_consensus.fresh_until = result_network_consensus.fresh_until;
  network_consensus.valid_until = result_network_consensus.valid_until;

  for ( i = 0; i < 32; i++ ) {
    network_consensus.previous_shared_rand[i] = result_network_consensus.previous_shared_rand[i];
    network_consensus.shared_rand[i] = result_network_consensus.shared_rand[i];
  }

  suitable_relays.length = result_suitable_relays.length;
  suitable_relays.head = result_suitable_relays.head;
  suitable_relays.tail = result_suitable_relays.tail;

#ifdef DEBUG_MINITOR
  // print all the info we got from the directory server
  DoublyLinkedOnionRelay* node;
  ESP_LOGI( TAG, "Consensus method: %d", network_consensus.method );
  ESP_LOGI( TAG, "Consensus valid after: %u", network_consensus.valid_after );
  ESP_LOGI( TAG, "Consensus fresh until: %u", network_consensus.fresh_until );
  ESP_LOGI( TAG, "Consensus valid until: %u", network_consensus.valid_until );

  ESP_LOGI( TAG, "Previous shared random value:" );

  for ( i = 0; i < 32; i++ ) {
    ESP_LOGI( TAG, "%x", network_consensus.previous_shared_rand[i] );
  }

  ESP_LOGI( TAG, "Shared random value:" );

  for ( i = 0; i < 32; i++ ) {
    ESP_LOGI( TAG, "%x", network_consensus.shared_rand[i] );
  }

  ESP_LOGI( TAG, "Found %d suitable relays:", suitable_relays.length );
  node = suitable_relays.head;

  while ( node != NULL ) {
    ESP_LOGI( TAG, "address: %u, or_port: %d, dir_port: %d", node->relay->address, node->relay->or_port, node->relay->dir_port );
    ESP_LOGI( TAG, "identity:" );

    for ( i = 0; i < ID_LENGTH; i++ ) {
      ESP_LOGI( TAG, "%x", node->relay->identity[i] );
    }

    ESP_LOGI( TAG, "digest:" );

    for ( i = 0; i < ID_LENGTH; i++ ) {
      ESP_LOGI( TAG, "%x", node->relay->digest[i] );
    }

    node = node->next;
  }
#endif

  // we're done reading data from the directory server, shutdown and close the socket
  shutdown( sock_fd, 0 );
  close( sock_fd );

  // return 0 for no errors
  return 0;
}

// parse the date using a single byte, relies on other variables to determine how far
// in the date we are
int d_parse_date_byte( char byte, int* year, int* year_found, int* month, int* month_found, int* day, int* day_found, int* hour, int* hour_found, int* minute, int* minute_found, int* second, int* second_found, struct tm* temp_time ) {
  // if we haven't hit a dilimeter
  if ( byte != '-' && byte != ' ' && byte != ':' ) {
    // if we haven't already parsed the year
    if ( *year_found < 4 ) {
      // add this byte to the year
      *year *= 10;
      *year += byte - 48;
      (*year_found)++;
      // NOTE parsing for other date elements are extremeley similar so comments are
      // excluded
    } else if ( *month_found < 2 ) {
      *month *= 10;
      *month += byte - 48;
      (*month_found)++;
    } else if ( *day_found < 2 ) {
      *day *= 10;
      *day += byte - 48;
      (*day_found)++;
    } else if ( *hour_found < 2 ) {
      *hour *= 10;
      *hour += byte - 48;
      (*hour_found)++;
    } else if ( *minute_found < 2 ) {
      *minute *= 10;
      *minute += byte - 48;
      (*minute_found)++;
    } else if ( *second_found < 2 ) {
      *second *= 10;
      *second += byte - 48;
      (*second_found)++;

      // if we've found both seconds we're done parsing the date and need to clean up
      if ( *second_found == 2 ) {
        // set the time time fields to the values parsed from the bytes
        // year has to have 1900 subtracted from it
        temp_time->tm_year = *year - 1900;
        // month is base 0 so we need to subtract 1
        temp_time->tm_mon = *month - 1;
        temp_time->tm_mday = *day;
        temp_time->tm_hour = *hour;
        temp_time->tm_min = *minute;
        temp_time->tm_sec = *second;
        // reset all the temp fields
        *year = 0;
        *year_found = 0;
        *month = 0;
        *month_found = 0;
        *day = 0;
        *day_found = 0;
        *hour = 0;
        *hour_found = 0;
        *minute = 0;
        *minute_found = 0;
        *second = 0;
        *second_found = 0;

        // return 1 to mark that this byte was the final byte in the date
        return 1;
      }
    }
  }

  return 0;
}

// decode a base64 string and put it into the destination byte buffer
// NOTE it is up to the coller to make sure the destination can fit the
// bytes being put into it
void v_base_64_decode_buffer( unsigned char* destination, char* source, int source_length ) {
  // index variables
  int i;
  int j;
  // byte to store the value between characters
  unsigned char tmp_byte = 0;
  // how many bits of the tmp_byte are full
  int tmp_byte_length = 0;
  // the src byte which always has the last 6 bits filled
  unsigned char src_byte = 0;

  // for each character in the base64 string
  for ( i = 0; i < source_length; i++ ) {
    // find the value of the base64 character by matching it to the table, the index
    // of the table is the value of that character
    for ( j = 0; j < 64; j++ ) {
      if ( base64_table[j] == source[i] ) {
        src_byte = (unsigned char)j;
        break;
      }
    }

    // if we have a fresh byte, just move the src byte over 2, store it set the length
    // to 6
    if ( tmp_byte_length == 0 ) {
      tmp_byte = src_byte << 2;
      tmp_byte_length = 6;
    // if our length is 6
    } else if ( tmp_byte_length == 6 ) {
      // we only want the first two bits of the src byte, shift the last 4 off and
      // add the first two to the temp_byte
      tmp_byte |= src_byte >> 4;
      // the tmp byte is full, add it to the destination buffer
      *destination = tmp_byte;
      destination++;
      // store the last 4 bits of the src_byte into the tmp byte and set the length
      // to 4
      tmp_byte = src_byte << 4;
      tmp_byte_length = 4;
    // if our length is 4
    } else if ( tmp_byte_length == 4 ) {
      // we only want the first four bits of the src byte, shift the last 2 off and
      // add the first 4 to the tmp_byte
      tmp_byte |= src_byte >> 2;
      // the tmp byte is full, add it to the destination buffer
      *destination = tmp_byte;
      destination++;
      // store the last 2 bits of the src_byte into the tmp byte and set the length
      // to 2
      tmp_byte = src_byte << 6;
      tmp_byte_length = 2;
    // if our length is 2
    } else if ( tmp_byte_length == 2 ) {
      // we can just add 6 bits of our src byte to the tmp byte and add that to the
      // destination buffer, we now have a fresh temp byte so set length to 0
      tmp_byte |= src_byte;
      *destination = tmp_byte;
      destination++;
      tmp_byte_length = 0;
    }
  }
}

// add a linked onion relay to a doubly linked list of onion relays
void v_add_relay_to_list( DoublyLinkedOnionRelay* node, DoublyLinkedOnionRelayList* list ) {
  // if our length is 0, just set this node as the head and tail
  if ( list->length == 0 ) {
    list->head = node;
    list->tail = node;
  // otherwise set the new node's previous to the current tail, set the current tail's
  // next to the new node and set the new node as the new tail
  } else {
    node->previous = list->tail;
    list->tail->next = node;
    list->tail = node;
  }

  // increase the length of the list
  list->length++;
}
