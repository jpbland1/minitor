#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

#include "minitor.h"

#define WEB_SERVER "192.168.1.138"
#define WEB_PORT 7001
#define WEB_URL "/tor/status-vote/current/consensus"

WOLFSSL_CTX* xMinitorWolfSSL_Context;

static const char* MINITOR_TAG = "MINITOR: ";

// TODO shared state must be protected by mutex
static unsigned int circ_id_counter = 0x80000000;
static SemaphoreHandle_t circ_id_mutex;

static NetworkConsensus network_consensus = {
  .method = 0,
  .valid_after = 0,
  .fresh_until = 0,
  .valid_until = 0,
  .hsdir_interval = HSDIR_INTERVAL_DEFAULT,
  .hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT,
  .hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT,
};
static SemaphoreHandle_t network_consensus_mutex;

static DoublyLinkedOnionRelayList suitable_relays = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
static SemaphoreHandle_t suitable_relays_mutex;

static DoublyLinkedOnionCircuitList standby_circuits = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
static SemaphoreHandle_t standby_circuits_mutex;

static DoublyLinkedOnionCircuitList intro_circuits = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
static SemaphoreHandle_t intro_circuits_mutex;

static DoublyLinkedOnionCircuitList rend_circuits = {
  .length = 0,
  .head = NULL,
  .tail = NULL,
};
static SemaphoreHandle_t rend_circuits_mutex;

static const char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* base32_table = "abcdefghijklmnopqrstuvwxyz234567";

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store ) {
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }
  ESP_LOGE( MINITOR_TAG, "SSL callback error %d", store->error );

#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't connect to relay, wolfssl error code: %d", store->error );
#endif

  return 0;
}

// intialize tor
int v_minitor_INIT() {
  circ_id_mutex = xSemaphoreCreateMutex();
  network_consensus_mutex = xSemaphoreCreateMutex();
  suitable_relays_mutex = xSemaphoreCreateMutex();
  standby_circuits_mutex = xSemaphoreCreateMutex();
  intro_circuits_mutex = xSemaphoreCreateMutex();
  rend_circuits_mutex = xSemaphoreCreateMutex();

  wolfSSL_Init();
  wolfSSL_Debugging_ON();

  if ( ( xMinitorWolfSSL_Context = wolfSSL_CTX_new( wolfTLSv1_2_client_method() ) ) == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't setup wolfssl context" );
#endif

    return -1;
  }

  // fetch network consensus
  if ( d_fetch_consensus_info() < 0 ) {
    return -1;
  }

  xTaskCreatePinnedToCore(
      v_circuit_keepalive,
      "CIRCUIT_KEEPALIVE",
      4096,
      NULL,
      6,
      NULL,
      tskNO_AFFINITY
    );

  return 1;
}

void v_circuit_keepalive( void* pv_parameters ) {
  while ( 1 ) {
    xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );
    v_keep_circuitlist_alive( &standby_circuits );
    xSemaphoreGive( standby_circuits_mutex );
    vTaskDelay( 1000 * 60 / portTICK_PERIOD_MS );

    xSemaphoreTake( intro_circuits_mutex, portMAX_DELAY );
    v_keep_circuitlist_alive( &intro_circuits );
    xSemaphoreGive( intro_circuits_mutex );
    vTaskDelay( 1000 * 60 / portTICK_PERIOD_MS );

    xSemaphoreTake( rend_circuits_mutex, portMAX_DELAY );
    v_keep_circuitlist_alive( &rend_circuits );
    xSemaphoreGive( rend_circuits_mutex );
    vTaskDelay( 1000 * 60 / portTICK_PERIOD_MS );
  }
}

void v_keep_circuitlist_alive( DoublyLinkedOnionCircuitList* list ) {
  int i;
  Cell padding_cell;
  DoublyLinkedOnionCircuit* node;
  unsigned char* packed_cell;

  padding_cell.command = PADDING;
  padding_cell.payload = NULL;
  node = list->head;

  for ( i = 0; i < list->length; i++ ) {
    padding_cell.circ_id = node->circuit.circ_id;
    packed_cell = pack_and_free( &padding_cell );

    if ( wolfSSL_send( node->circuit.ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to send padding cell on circ_id: %d", node->circuit.circ_id );
#endif
    }

    free( packed_cell );
    node = node->next;
  }
}

// send a cell to a circuit
/* void v_send_cell( int circ_id, unsigned char* packed_cell ) { */

/* } */

// fetch the network consensus so we can correctly create circuits
int d_fetch_consensus_info() {
  const char* REQUEST = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n"
      /* "Host: 192.168.1.138\r\n" */
      "Host: 192.168.1.16\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
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
  int address_offset = 0;
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
  struct sockaddr_in dest_addr;

  // set the address of the directory server
  /* dest_addr.sin_addr.s_addr = inet_addr( "192.168.1.138" ); */
  dest_addr.sin_addr.s_addr = inet_addr( "192.168.1.16" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( 7000 );

  // create a socket to access the consensus
  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server\n" );
#endif

    return -1;
  }

  // connect the socket to the dir server address
  int err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( err != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

    return -1;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "connected to http socket" );
#endif

  // send the http request to the dir server
  err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

  if ( err < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

    return -1;
  }

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "sent to http socket" );
#endif

  // keep reading forever, we will break inside when the transfer is over
  while ( 1 ) {
    // recv data from the destination and fill the rx_buffer with the data
    rx_length = recv( sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

    // if we got less than 0 we encoutered an error
    if ( rx_length < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

      return -1;
    // we got 0 bytes back then the connection closed and we're done getting
    // consensus data
    } else if ( rx_length == 0 ) {
      break;
    }

#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "recved from http socket" );
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
                address_offset = 0;
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
                    address_offset += 8;
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

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  network_consensus.method = result_network_consensus.method;
  network_consensus.valid_after = result_network_consensus.valid_after;
  network_consensus.fresh_until = result_network_consensus.fresh_until;
  network_consensus.valid_until = result_network_consensus.valid_until;

  for ( i = 0; i < 32; i++ ) {
    network_consensus.previous_shared_rand[i] = result_network_consensus.previous_shared_rand[i];
    network_consensus.shared_rand[i] = result_network_consensus.shared_rand[i];
  }

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus

  // BEGIN mutex for suitable relays
  xSemaphoreTake( suitable_relays_mutex, portMAX_DELAY );

  suitable_relays.length = result_suitable_relays.length;
  suitable_relays.head = result_suitable_relays.head;
  suitable_relays.tail = result_suitable_relays.tail;

#ifdef DEBUG_MINITOR
  // print all the info we got from the directory server
  DoublyLinkedOnionRelay* node;
  /* ESP_LOGE( MINITOR_TAG, "Consensus method: %d", network_consensus.method ); */
  /* ESP_LOGE( MINITOR_TAG, "Consensus valid after: %u", network_consensus.valid_after ); */
  /* ESP_LOGE( MINITOR_TAG, "Consensus fresh until: %u", network_consensus.fresh_until ); */
  /* ESP_LOGE( MINITOR_TAG, "Consensus valid until: %u", network_consensus.valid_until ); */

  /* ESP_LOGE( MINITOR_TAG, "Previous shared random value:" ); */

  /* for ( i = 0; i < 32; i++ ) { */
    /* ESP_LOGE( MINITOR_TAG, "%x", network_consensus.previous_shared_rand[i] ); */
  /* } */

  /* ESP_LOGE( MINITOR_TAG, "Shared random value:" ); */

  /* for ( i = 0; i < 32; i++ ) { */
    /* ESP_LOGE( MINITOR_TAG, "%x", network_consensus.shared_rand[i] ); */
  /* } */

  /* ESP_LOGE( MINITOR_TAG, "Found %d suitable relays:", suitable_relays.length ); */
  node = suitable_relays.head;

  while ( node != NULL ) {
    /* ESP_LOGE( MINITOR_TAG, "address: %x, or_port: %d, dir_port: %d", node->relay->address, node->relay->or_port, node->relay->dir_port ); */
#ifdef MINITOR_CHUTNEY
    // override the address if we're using chutney
    node->relay->address = MINITOR_CHUTNEY_ADDRESS;
#endif
    /* ESP_LOGE( MINITOR_TAG, "identity:" ); */

    /* for ( i = 0; i < ID_LENGTH; i++ ) { */
      /* ESP_LOGE( MINITOR_TAG, "%x", node->relay->identity[i] ); */
    /* } */

    /* ESP_LOGE( MINITOR_TAG, "digest:" ); */

    /* for ( i = 0; i < ID_LENGTH; i++ ) { */
      /* ESP_LOGE( MINITOR_TAG, "%x", node->relay->digest[i] ); */
    /* } */

    node = node->next;
  }
#endif

  xSemaphoreGive( suitable_relays_mutex );
  // END mutex for suitable relays

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

void v_base_32_encode( char* destination, unsigned char* source, int source_length ) {
  int i;
  unsigned char tmp_byte = 0;
  int tmp_byte_length = 0;

  for ( i = 0; i < source_length; i++ ) {
    if ( tmp_byte_length == 0 ) {
      *destination = base32_table[(int)( source[i] >> 3 )];
      destination++;
      tmp_byte = ( source[i] & 0x07 ) << 2;
      tmp_byte_length = 3;
    } else if ( tmp_byte_length == 3 ) {
      tmp_byte |= source[i] >> 6;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( ( source[i] & 0x3f ) >> 1 )];
      destination++;
      tmp_byte = ( source[i] & 0x01 ) << 4;
      tmp_byte_length = 1;
    } else if ( tmp_byte_length == 1 ) {
      tmp_byte |= source[i] >> 4;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      tmp_byte = ( source[i] & 0x0f ) << 1;
      tmp_byte_length = 4;
    } else if ( tmp_byte_length == 4 ) {
      tmp_byte |= source[i] >> 7;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( ( source[i] & 0x7f ) >> 2 )];
      destination++;
      tmp_byte = ( source[i] & 0x03 ) << 3;
      tmp_byte_length = 2;
    } else if ( tmp_byte_length == 2 ) {
      tmp_byte |= source[i] >> 5;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( source[i] & 0x1f )];
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

void v_add_circuit_to_list( DoublyLinkedOnionCircuit* node, DoublyLinkedOnionCircuitList* list ) {
  if ( list->length == 0 ) {
    list->head = node;
    list->tail = node;
  } else {
    node->previous = list->tail;
    list->tail->next = node;
    list->tail = node;
  }

  list->length++;
}

// create three hop circuits that can quickly be turned into introduction points
int d_setup_init_circuits( int circuit_count ) {
  int i;
  DoublyLinkedOnionCircuitList result_standby_circuits = {
    .length = 0,
    .head = NULL,
    .tail = NULL,
  };
  DoublyLinkedOnionCircuit* node;

  for ( i = 0; i < circuit_count; i++ ) {
    node = malloc( sizeof( DoublyLinkedOnionCircuit ) );

    switch ( d_build_onion_circuit( node ) ) {
      case -1:
        i--;
        free( node );
        ESP_LOGE( MINITOR_TAG, "single fail" );
        break;
      case -2:
        i = circuit_count;
        free( node );
        ESP_LOGE( MINITOR_TAG, "total fail" );
        break;
      case 0:
        v_add_circuit_to_list( node, &result_standby_circuits );
        ESP_LOGE( MINITOR_TAG, "no fail" );
        break;
      default:
        break;
    }
  }

  // BEGIN mutex for standby circuits
  xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

  node = result_standby_circuits.head;

  for ( i = 0; i < result_standby_circuits.length; i++ ) {
    v_add_circuit_to_list( node, &standby_circuits );
    node = node->next;
  }

  xSemaphoreGive( standby_circuits_mutex );
  // END mutex for standby circuits

  return result_standby_circuits.length;
}

// create a tor circuit
int d_build_onion_circuit( DoublyLinkedOnionCircuit* linked_circuit ) {
  struct sockaddr_in dest_addr;
  int sock_fd;
  WOLFSSL* ssl;

  // find 3 suitable relays from our directory information
  linked_circuit->circuit.status = CIRCUIT_BUILDING;
  linked_circuit->circuit.rx_queue = NULL;

  // BEGIN mutex for circ_id
  xSemaphoreTake( circ_id_mutex, portMAX_DELAY );

  linked_circuit->circuit.circ_id = ++circ_id_counter;

  xSemaphoreGive( circ_id_mutex );
  // END mutex for circ_id

  // BEGIN mutex for suitable relays
  xSemaphoreTake( suitable_relays_mutex, portMAX_DELAY );

  if ( suitable_relays.length < 3 ) {
    return -2;
  }

  // set the head node of the suitable relays as our head node
  linked_circuit->circuit.relay_list.head = suitable_relays.head;
  // set the 3rd node of the suitable relays as our tail node
  linked_circuit->circuit.relay_list.tail = suitable_relays.head->next->next;

  // set the fourth node of the suiteable relays previous node to NULL
  if ( suitable_relays.length > 3 ) {
    suitable_relays.head->next->next->next->previous = NULL;
  }

  // set the head of the suitable relays to the fourth node
  suitable_relays.head = suitable_relays.head->next->next->next;
  // set the tail of our lists next node to NULL
  linked_circuit->circuit.relay_list.tail->next = NULL;
  // set our length to 3
  linked_circuit->circuit.relay_list.length = 3;
  linked_circuit->circuit.relay_list.built_length = 0;
  // set the suitable relays length to -= 3
  suitable_relays.length -= 3;

  xSemaphoreGive( suitable_relays_mutex );
  // END mutex for suitable relays

  // get the relay's ntor onion keys
  if ( d_fetch_descriptor_info( linked_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to fetch descriptors" );
#endif

    return -1;
  }

  // connect to the relay over ssl
  dest_addr.sin_addr.s_addr = linked_circuit->circuit.relay_list.head->relay->address;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( linked_circuit->circuit.relay_list.head->relay->or_port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create socket" );
#endif

    return -1;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to connect socket" );
#endif

    return -1;
  }

  if ( ( ssl = wolfSSL_new( xMinitorWolfSSL_Context ) ) == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );
#endif

    return -1;
  }

  wolfSSL_set_verify( ssl, SSL_VERIFY_PEER, d_ignore_ca_callback );
  wolfSSL_KeepArrays( ssl );

  ESP_LOGE( MINITOR_TAG, "Setting sock_fd" );
  if ( wolfSSL_set_fd( ssl, sock_fd ) != SSL_SUCCESS ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to set ssl fd" );
#endif

    return -1;
  }

  if ( wolfSSL_connect( ssl ) != SSL_SUCCESS ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to wolfssl_connect" );
#endif

    return -1;
  }

  // attach the ssl object to the circuit
  linked_circuit->circuit.ssl = ssl;

  if ( d_router_handshake( linked_circuit->circuit.ssl ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to handshake with first relay" );
#endif

    return -1;
  }

  if ( d_router_create2( &linked_circuit->circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to CREATE2 with first relay" );
#endif

    return -1;
  }

  linked_circuit->circuit.relay_list.built_length++;

  // make an extend cell and send it to the second hop
  if ( d_router_extend2( &linked_circuit->circuit, 1 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to EXTEND2 with second relay" );
#endif

    return -1;
  }

  linked_circuit->circuit.relay_list.built_length++;

  // make an extend cell and send it to the thrid hop
  if ( d_router_extend2( &linked_circuit->circuit, 2 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to EXTEND2 with third relay" );
#endif

    return -1;
  }

  linked_circuit->circuit.relay_list.built_length++;

  linked_circuit->circuit.status = CIRCUIT_STANDBY;

  // spawn a task to block on the tls buffer and put the data into the rx_queue
  xTaskCreatePinnedToCore(
      v_handle_circuit,
      "HANDLE_CIRCUIT",
      4096,
      (void*)(&linked_circuit->circuit),
      6,
      &linked_circuit->circuit.task_handle,
      tskNO_AFFINITY
    );

  return 0;
}

void v_handle_circuit( void* pv_parameters ) {
  int succ;
  OnionCircuit* onion_circuit = (OnionCircuit*)pv_parameters;
  Cell* unpacked_cell = malloc( sizeof( Cell ) );

  while ( 1 ) {
    succ = d_recv_cell( onion_circuit->ssl, unpacked_cell, CIRCID_LEN, &onion_circuit->relay_list, NULL );

    if ( succ < 0 ) {
      ESP_LOGE( MINITOR_TAG, "Circuit %.8x received error code: %d waiting for a cell", onion_circuit->circ_id, succ );
      continue;
    }

    // TODO should determine if we need to destroy the circuit on a NULL queue
    if ( unpacked_cell->command == PADDING || onion_circuit->rx_queue == NULL ) {
      free_cell( unpacked_cell );
    } else {
      xQueueSendToBack( onion_circuit->rx_queue, (void*)(&unpacked_cell), portMAX_DELAY );
    }
  }
}

int d_router_extend2( OnionCircuit* onion_circuit, int node_index ) {
  int i;
  int wolf_succ;
  WC_RNG rng;
  DoublyLinkedOnionRelay* relay;
  DoublyLinkedOnionRelay* target_relay;
  Cell unpacked_cell;
  unsigned char* packed_cell;
  curve25519_key extend2_handshake_key;
  /* unsigned char temp_digest[WC_SHA_DIGEST_SIZE]; */
  curve25519_key extended2_handshake_public_key;
  curve25519_key ntor_onion_key;

  wc_curve25519_init( &extend2_handshake_key );
  wc_curve25519_init( &extended2_handshake_public_key );
  wc_curve25519_init( &ntor_onion_key );
  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &extend2_handshake_key );

  wc_FreeRng( &rng );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make extend2_handshake_key, error code %d", wolf_succ );
#endif

    return -1;
  }

  relay = onion_circuit->relay_list.head;

  for ( i = 0; i < node_index; i++ ) {
    relay = relay->next;
  }

  target_relay = relay;

  // TODO construct link specifiers
  unpacked_cell.circ_id = onion_circuit->circ_id;
  unpacked_cell.command = RELAY_EARLY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_EXTEND2;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 35 + ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadExtend2 ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->specifier_count = 2;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers = malloc( sizeof( LinkSpecifier* ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->specifier_count );

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0] = malloc( sizeof( LinkSpecifier ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->type = IPv4Link;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->length = 6;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->length );

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[3] = (unsigned char)( target_relay->relay->address >> 24 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[2] = (unsigned char)( target_relay->relay->address >> 16 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[1] = (unsigned char)( target_relay->relay->address >> 8 );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[0] = (unsigned char)target_relay->relay->address;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[4] = (unsigned char)target_relay->relay->or_port >> 8;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[0]->specifier[5] = (unsigned char)target_relay->relay->or_port;

  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1] = malloc( sizeof( LinkSpecifier ) );
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->type = LEGACYLink;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->length = ID_LENGTH;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->specifier = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->length );

  memcpy( ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->link_specifiers[1]->specifier, target_relay->relay->identity, ID_LENGTH );

  // construct our side of the handshake
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_type = NTOR;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data = malloc( sizeof( unsigned char ) * ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_length );

  if ( d_ntor_handshake_start( ( (RelayPayloadExtend2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data, target_relay->relay, &extend2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    return -1;
  }

  packed_cell = pack_and_free( &unpacked_cell );

  /* // update the running digest */
  /* relay = target_relay->previous; */

  /* wc_ShaUpdate( &relay->relay->running_sha_forward, packed_cell + 5, PAYLOAD_LEN ); */
  /* wc_ShaGetHash( &relay->relay->running_sha_forward, temp_digest ); */

  /* memcpy( packed_cell + 10, temp_digest, 4 ); */

  /* // encrypt the RELAY_EARLY cell's payload from R_(node_index-1) to R_0 */
  /* for ( i = node_index - 1; i >= 0; i-- ) { */
    /* wolf_succ = wc_AesCtrEncrypt( &relay->relay->aes_forward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN ); */

    /* if ( wolf_succ < 0 ) { */
/* #ifdef DEBUG_MINITOR */
      /* ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY_EARLY payload, error code: %d", wolf_succ ); */
/* #endif */

      /* return -1; */
    /* } */

    /* relay = relay->previous; */
  /* } */

  /* // send the RELAY_EARLY to the first node in the circuit */
  /* if ( wolfSSL_send( onion_circuit->ssl, packed_cell, CELL_LEN, 0 ) < 0 ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_EXTEND2 cell" ); */
/* #endif */

    /* return -1; */
  /* } */

  /* free( packed_cell ); */

  // send the EXTEND2 cell
  if ( d_send_packed_relay_cell_and_free( packed_cell, onion_circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_EXTEND2 cell" );
#endif
  }

  // recv EXTENDED2 cell and perform the second half of the handshake
  if ( d_recv_cell( onion_circuit->ssl, &unpacked_cell, CIRCID_LEN, &onion_circuit->relay_list, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv RELAY_EXTENDED2 cell" );
#endif

    return -1;
  }

  if ( d_ntor_handshake_finish( ( (PayloadCreated2*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->handshake_data, target_relay->relay, &extend2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute handshake_data for extend" );
#endif

    return -1;
  }

  free_cell( &unpacked_cell );

  return 0;
}

int d_router_create2( OnionCircuit* onion_circuit ) {
  int wolf_succ;
  WC_RNG rng;
  Cell unpacked_cell;
  unsigned char* packed_cell;
  curve25519_key create2_handshake_key;

  wc_curve25519_init( &create2_handshake_key );
  wc_InitRng( &rng );

  wolf_succ = wc_curve25519_make_key( &rng, 32, &create2_handshake_key );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make create2_handshake_key, error code %d", wolf_succ );
#endif

    return -1;
  }

  // make a create2 cell
  unpacked_cell.circ_id = onion_circuit->circ_id;
  unpacked_cell.command = CREATE2;
  unpacked_cell.payload = malloc( sizeof( PayloadCreate2 ) );

  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_type = NTOR;
  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_length = ID_LENGTH + H_LENGTH + G_LENGTH;
  ( (PayloadCreate2*)unpacked_cell.payload )->handshake_data = malloc( sizeof( unsigned char ) * ( (PayloadCreate2*)unpacked_cell.payload )->handshake_length );

  if ( d_ntor_handshake_start( ( (PayloadCreate2*)unpacked_cell.payload )->handshake_data, onion_circuit->relay_list.head->relay, &create2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export create2_handshake_key into unpacked_cell" );
#endif

    return -1;
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( wolfSSL_send( onion_circuit->ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send CREATE2 cell" );
#endif

    return -1;
  }

  free( packed_cell );

  if ( d_recv_cell( onion_circuit->ssl, &unpacked_cell, CIRCID_LEN, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv CREATED2 cell" );
#endif

    return -1;
  }

  if ( d_ntor_handshake_finish( ( (PayloadCreated2*)unpacked_cell.payload )->handshake_data, onion_circuit->relay_list.head->relay, &create2_handshake_key ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to finish CREATED2 handshake" );
#endif

    return -1;
  }

  wc_FreeRng( &rng );

  free_cell( &unpacked_cell );

  return 0;
}

int d_ntor_handshake_start( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key ) {
  int wolf_succ;
  unsigned int idx;

  memcpy( handshake_data, relay->identity, ID_LENGTH );
  memcpy( handshake_data + ID_LENGTH, relay->ntor_onion_key, H_LENGTH );

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, handshake_data + ID_LENGTH + H_LENGTH, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export curve25519_key into handshake_data, error code: %d", wolf_succ );
#endif

    return -1;
  }

  return 0;
}

int d_ntor_handshake_finish( unsigned char* handshake_data, OnionRelay* relay, curve25519_key* key ) {
  int wolf_succ;
  unsigned int idx;
  curve25519_key responder_handshake_public_key;
  curve25519_key ntor_onion_key;
  unsigned char* secret_input = malloc( sizeof( unsigned char ) * SECRET_INPUT_LENGTH );
  unsigned char* working_secret_input = secret_input;
  unsigned char* auth_input = malloc( sizeof( unsigned char ) * AUTH_INPUT_LENGTH );
  unsigned char* working_auth_input = auth_input;
  Hmac reusable_hmac;
  unsigned char reusable_hmac_digest[WC_SHA256_DIGEST_SIZE];
  unsigned char reusable_aes_key[KEY_LEN];
  unsigned char aes_iv[16] = { 0 };
  unsigned char key_seed[WC_SHA256_DIGEST_SIZE];
  unsigned char expand_i;
  int bytes_written;
  int bytes_remaining;

  wc_curve25519_init( &responder_handshake_public_key );
  wc_curve25519_init( &ntor_onion_key );
  wc_InitSha( &relay->running_sha_forward );
  wc_InitSha( &relay->running_sha_backward );
  wc_AesInit( &relay->aes_forward, NULL, INVALID_DEVID );
  wc_AesInit( &relay->aes_backward, NULL, INVALID_DEVID );

  wolf_succ = wc_curve25519_import_public_ex( handshake_data, G_LENGTH, &responder_handshake_public_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import responder public key, error code %d", wolf_succ );
#endif

    return -1;
  }

  wolf_succ = wc_curve25519_import_public_ex( relay->ntor_onion_key, H_LENGTH, &ntor_onion_key, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to import ntor onion public key, error code %d", wolf_succ );
#endif

    return -1;
  }

  // create secret_input
  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &responder_handshake_public_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(Y,x), error code %d", wolf_succ );
#endif

    return -1;
  }

  working_secret_input += 32;

  idx = 32;
  wolf_succ = wc_curve25519_shared_secret_ex( key, &ntor_onion_key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ < 0 || idx != 32 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to compute EXP(B,x), error code %d", wolf_succ );
#endif

    return -1;
  }

  working_secret_input += 32;

  memcpy( working_secret_input, relay->identity, ID_LENGTH );
  working_secret_input += ID_LENGTH;

  memcpy( working_secret_input, relay->ntor_onion_key, H_LENGTH );
  working_secret_input += H_LENGTH;

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, working_secret_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_secret_input, error code: %d", wolf_succ );
#endif

    return -1;
  }

  working_secret_input += 32;

  memcpy( working_secret_input, handshake_data, G_LENGTH );
  working_secret_input += G_LENGTH;

  memcpy( working_secret_input, PROTOID, PROTOID_LENGTH );

  // create auth_input
  wc_HmacSetKey( &reusable_hmac, SHA256, (unsigned char*)PROTOID_VERIFY, PROTOID_VERIFY_LENGTH );
  wc_HmacUpdate( &reusable_hmac, secret_input, SECRET_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, working_auth_input );
  working_auth_input += WC_SHA256_DIGEST_SIZE;

  memcpy( working_auth_input, relay->identity, ID_LENGTH );
  working_auth_input += ID_LENGTH;

  memcpy( working_auth_input, relay->ntor_onion_key, H_LENGTH );
  working_auth_input += H_LENGTH;

  memcpy( working_auth_input, handshake_data, G_LENGTH );
  working_auth_input += G_LENGTH;

  idx = 32;
  wolf_succ = wc_curve25519_export_public_ex( key, working_auth_input, &idx, EC25519_LITTLE_ENDIAN );

  if ( wolf_succ != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export handshake key into working_auth_input, error code: %d", wolf_succ );
#endif

    return -1;
  }

  working_auth_input += 32;

  memcpy( working_auth_input, PROTOID, PROTOID_LENGTH );
  working_auth_input += PROTOID_LENGTH;

  memcpy( working_auth_input, SERVER_STR, SERVER_STR_LENGTH );

  wc_HmacSetKey( &reusable_hmac, SHA256, (unsigned char*)PROTOID_MAC, PROTOID_MAC_LENGTH );
  wc_HmacUpdate( &reusable_hmac, auth_input, AUTH_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );

  if ( memcmp( reusable_hmac_digest, handshake_data + G_LENGTH, WC_SHA256_DIGEST_SIZE ) != 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to match AUTH with our own digest" );
#endif

    return -1;
  }

  // create the key seed
  wc_HmacSetKey( &reusable_hmac, SHA256, (unsigned char*)PROTOID_KEY, PROTOID_KEY_LENGTH );
  wc_HmacUpdate( &reusable_hmac, secret_input, SECRET_INPUT_LENGTH );
  wc_HmacFinal( &reusable_hmac, key_seed );

  // generate the first 32 bytes
  wc_HmacSetKey( &reusable_hmac, SHA256, key_seed, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 1;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );

  // seed the forward sha
  wc_ShaUpdate( &relay->running_sha_forward, reusable_hmac_digest, HASH_LEN );
  // seed the first 16 bytes of backwards sha
  wc_ShaUpdate( &relay->running_sha_backward, reusable_hmac_digest + HASH_LEN, WC_SHA256_DIGEST_SIZE - HASH_LEN );
  // mark how many bytes we've written to the backwards sha and how many remain
  bytes_written = WC_SHA256_DIGEST_SIZE - HASH_LEN;
  bytes_remaining = HASH_LEN - bytes_written;

  // generate the second 32 bytes
  wc_HmacUpdate( &reusable_hmac, reusable_hmac_digest, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 2;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );

  // seed the last 8 bytes of backward sha
  wc_ShaUpdate( &relay->running_sha_backward, reusable_hmac_digest, bytes_remaining );
  // set the forward aes key
  memcpy( reusable_aes_key, reusable_hmac_digest + bytes_remaining, KEY_LEN );
  wc_AesSetKeyDirect( &relay->aes_forward, reusable_aes_key, KEY_LEN, aes_iv, AES_ENCRYPTION );
  // copy the first part of the backward key into the buffer
  memcpy( reusable_aes_key, reusable_hmac_digest + bytes_remaining + KEY_LEN, WC_SHA256_DIGEST_SIZE - bytes_remaining - KEY_LEN );
  // mark how many bytes we've written to the backwards key and how many remain
  bytes_written = WC_SHA256_DIGEST_SIZE - bytes_remaining - KEY_LEN;
  bytes_remaining = KEY_LEN - bytes_written;

  // generate the third 32 bytes
  wc_HmacUpdate( &reusable_hmac, reusable_hmac_digest, WC_SHA256_DIGEST_SIZE );
  wc_HmacUpdate( &reusable_hmac, (unsigned char*)PROTOID_EXPAND, PROTOID_EXPAND_LENGTH );
  expand_i = 3;
  wc_HmacUpdate( &reusable_hmac, &expand_i, 1 );
  wc_HmacFinal( &reusable_hmac, reusable_hmac_digest );

  // copy the last part of the key into the buffer and initialize the key
  memcpy( reusable_aes_key + bytes_written, reusable_hmac_digest, bytes_remaining );
  wc_AesSetKeyDirect( &relay->aes_backward, reusable_aes_key, KEY_LEN, aes_iv, AES_ENCRYPTION );

  // copy the nonce
  memcpy( relay->nonce, reusable_hmac_digest + bytes_remaining, DIGEST_LEN );

  // free all the heap resources
  wc_curve25519_free( key );
  wc_curve25519_free( &responder_handshake_public_key );
  wc_curve25519_free( &ntor_onion_key );

  free( secret_input );
  free( auth_input );

  return 0;
}

int d_router_handshake( WOLFSSL* ssl ) {
  int i;
  int wolf_succ;
  WOLFSSL_X509* peer_cert;
  Sha256 reusable_sha;
  unsigned char reusable_sha_sum[WC_SHA256_DIGEST_SIZE];
  Hmac tls_secrets_hmac;
  unsigned char tls_secrets_digest[WC_SHA256_DIGEST_SIZE];
  Cell unpacked_cell;
  unsigned char* packed_cell;
  Sha256 initiator_sha;
  unsigned char initiator_sha_sum[WC_SHA256_DIGEST_SIZE];
  Sha256 responder_sha;
  unsigned char responder_sha_sum[WC_SHA256_DIGEST_SIZE];
  unsigned char* responder_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );
  int responder_rsa_identity_key_der_size;
  unsigned char* initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_identity_key_der_size;
  unsigned char* initiator_rsa_identity_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_identity_cert_der_size;
  RsaKey initiator_rsa_auth_key;
  unsigned char* initiator_rsa_auth_cert_der = malloc( sizeof( unsigned char ) * 2048 );
  int initiator_rsa_auth_cert_der_size;
  WC_RNG rng;
  unsigned char my_address_length;
  unsigned char* my_address;
  unsigned char other_address_length;
  unsigned char* other_address;

  wc_InitSha256( &reusable_sha );
  wc_InitSha256( &initiator_sha );
  wc_InitSha256( &responder_sha );

  wc_InitRng( &rng );

  // get the peer cert
  peer_cert = wolfSSL_get_peer_certificate( ssl );

  if ( peer_cert == NULL ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed get peer cert" );
#endif

    return -1;
  }

  // set the hmac key to the master secret that was negotiated
  wc_HmacSetKey( &tls_secrets_hmac, SHA256, ssl->arrays->masterSecret, SECRET_LEN );
  // update the hmac
  wc_HmacUpdate( &tls_secrets_hmac, ssl->arrays->clientRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, ssl->arrays->serverRandom, RAN_LEN );
  wc_HmacUpdate( &tls_secrets_hmac, (unsigned char*)"Tor V3 handshake TLS cross-certification", strlen( "Tor V3 handshake TLS cross-certification" ) + 1 );
  // finalize the hmac
  wc_HmacFinal( &tls_secrets_hmac, tls_secrets_digest );
  // free the temporary arrays
  wolfSSL_FreeArrays( ssl );

  // make a versions cell
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = VERSIONS;
  unpacked_cell.length = 4;
  unpacked_cell.payload = malloc( sizeof( PayloadVersions ) );

  ( (PayloadVersions*)unpacked_cell.payload )->versions = malloc( sizeof( unsigned short ) * 2 );
  ( (PayloadVersions*)unpacked_cell.payload )->versions[0] = 3;
  ( (PayloadVersions*)unpacked_cell.payload )->versions[1] = 4;

  packed_cell = pack_and_free( &unpacked_cell );

  wc_Sha256Update( &initiator_sha, packed_cell, LEGACY_CIRCID_LEN + 3 + unpacked_cell.length );

  // send the versions cell
  ESP_LOGE( MINITOR_TAG, "sending versions cell" );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, LEGACY_CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send versions cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  // reset the packed cell
  free( packed_cell );

  ESP_LOGE( MINITOR_TAG, "recving versions cell" );

  // recv and unpack the versions cell
  if ( d_recv_cell( ssl, &unpacked_cell, LEGACY_CIRCID_LEN, NULL, &responder_sha ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv versions cell" );
#endif

    return -1;
  }

  for ( i = 0; i < unpacked_cell.length / 2; i++ ) {
    ESP_LOGE( MINITOR_TAG, "Relay Version: %d", ( (PayloadVersions*)unpacked_cell.payload )->versions[i] );
  }

  // free the unpacked cell
  free_cell( &unpacked_cell );

  ESP_LOGE( MINITOR_TAG, "recving certs cell" );

  // recv and unpack the certs cell
  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, &responder_sha ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv certs cell" );
#endif

    return -1;
  }

  // verify certs
  if ( d_verify_certs( &unpacked_cell, peer_cert, &responder_rsa_identity_key_der_size, responder_rsa_identity_key_der ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to verify certs" );
#endif

    return -1;
  }

  // recv and unpack the auth challenge cell
  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, &responder_sha ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv auth challenge cell" );
#endif

    return -1;
  }

  // free the unpacked cell
  free_cell( &unpacked_cell );

  // generate certs for certs cell
  if ( d_generate_certs( &initiator_rsa_identity_key_der_size, initiator_rsa_identity_key_der, initiator_rsa_identity_cert_der, &initiator_rsa_identity_cert_der_size, initiator_rsa_auth_cert_der, &initiator_rsa_auth_cert_der_size, &initiator_rsa_auth_key, &rng ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate rsa certificates" );
#endif

    return -1;
  }

  // generate a certs cell of our own
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = CERTS;
  unpacked_cell.length = 7 + initiator_rsa_auth_cert_der_size + initiator_rsa_identity_cert_der_size;
  unpacked_cell.payload = malloc( sizeof( PayloadCerts ) );

  ( (PayloadCerts*)unpacked_cell.payload )->cert_count = 2;
  ( (PayloadCerts*)unpacked_cell.payload )->certs = malloc( sizeof( MinitorCert* ) * 2 );

  for ( i = 0; i < ( (PayloadCerts*)unpacked_cell.payload )->cert_count; i++ ) {
    ( (PayloadCerts*)unpacked_cell.payload )->certs[i] = malloc( sizeof( MinitorCert ) );
  }

  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_type = IDENTITY_CERT;
  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_length = initiator_rsa_identity_cert_der_size;

  ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert = malloc( sizeof( unsigned char ) * initiator_rsa_identity_cert_der_size );

  memcpy( ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert, initiator_rsa_identity_cert_der, ( (PayloadCerts*)unpacked_cell.payload )->certs[0]->cert_length );

  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_type = RSA_AUTH_CERT;
  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_length = initiator_rsa_auth_cert_der_size;

  ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert = malloc( sizeof( unsigned char ) * initiator_rsa_auth_cert_der_size );

  memcpy( ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert, initiator_rsa_auth_cert_der, ( (PayloadCerts*)unpacked_cell.payload )->certs[1]->cert_length );

  free( initiator_rsa_identity_cert_der );
  free( initiator_rsa_auth_cert_der );

  packed_cell = pack_and_free( &unpacked_cell );
  wc_Sha256Update( &initiator_sha, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send certs cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  // generate answer for auth challenge
  unpacked_cell.circ_id = 0;
  unpacked_cell.command = AUTHENTICATE;
  unpacked_cell.length = 4 + 352;
  unpacked_cell.payload = malloc( sizeof( PayloadAuthenticate ) );

  ( (PayloadAuthenticate*)unpacked_cell.payload )->auth_type = AUTH_ONE;
  ( (PayloadAuthenticate*)unpacked_cell.payload )->auth_length = 352;
  ( (PayloadAuthenticate*)unpacked_cell.payload )->authentication = malloc( sizeof( AuthenticationOne ) );

  // fill in type
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->type, "AUTH0001", 8 );
  // create the hash of the clients identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, initiator_rsa_identity_key_der, initiator_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_id, reusable_sha_sum, 32 );
  // create the hash of the server's identity key and fill the authenticate cell with it
  wc_Sha256Update( &reusable_sha, responder_rsa_identity_key_der, responder_rsa_identity_key_der_size );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_id, reusable_sha_sum, 32 );
  // create the hash of all server cells so far and fill the authenticate cell with it
  wc_Sha256Final( &responder_sha, responder_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_log, responder_sha_sum, 32 );
  // create the hash of all cilent cells so far and fill the authenticate cell with it
  wc_Sha256Final( &initiator_sha, initiator_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_log, initiator_sha_sum, 32 );
  // create a sha hash of the tls cert and copy it in
  wc_Sha256Update( &reusable_sha, peer_cert->derCert->buffer, peer_cert->derCert->length );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_cert, reusable_sha_sum, 32 );
  // copy the tls secrets digest in
  memcpy( ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->tls_secrets, tls_secrets_digest, 32 );
  // fill the rand array
  wc_RNG_GenerateBlock( &rng, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->rand, 24 );
  // create the signature
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->type, 8 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_id, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_id, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_log, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->client_log, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->server_cert, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->tls_secrets, 32 );
  wc_Sha256Update( &reusable_sha, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->rand, 24 );
  wc_Sha256Final( &reusable_sha, reusable_sha_sum );

  wolf_succ = wc_RsaSSL_Sign( reusable_sha_sum, 32, ( (AuthenticationOne*)( (PayloadAuthenticate*)unpacked_cell.payload )->authentication )->signature, 128, &initiator_rsa_auth_key, &rng );

  free( responder_rsa_identity_key_der );;
  free( initiator_rsa_identity_key_der );;
  wc_FreeRng( &rng );

  if (wolf_succ  < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign authenticate cell, error code: %d", wolf_succ );
#endif
  }

  packed_cell = pack_and_free( &unpacked_cell );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CIRCID_LEN + 3 + unpacked_cell.length, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send authenticate cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  free( packed_cell );

  if ( d_recv_cell( ssl, &unpacked_cell, CIRCID_LEN, NULL, NULL ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to recv netinfo cell" );
#endif

    return -1;
  }

  my_address_length = ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->length;
  my_address = malloc( sizeof( unsigned char ) * my_address_length );
  memcpy( my_address, ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address, my_address_length );

  other_address_length = ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->length;
  other_address = malloc( sizeof( unsigned char ) * other_address_length );
  memcpy( other_address, ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address, other_address_length );

  free_cell( &unpacked_cell );

  unpacked_cell.circ_id = 0;
  unpacked_cell.command = NETINFO;
  unpacked_cell.payload = malloc( sizeof( PayloadNetInfo ) );

  time( &( (PayloadNetInfo*)unpacked_cell.payload )->time );
  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address = malloc( sizeof( Address ) );

  if ( other_address_length == 4 ) {
    ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address_type = IPv4;
  } else {
    ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address_type = IPv6;
  }

  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->length = other_address_length;
  ( (PayloadNetInfo*)unpacked_cell.payload )->other_address->address = other_address;

  ( (PayloadNetInfo*)unpacked_cell.payload )->address_count = 1;
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses = malloc( sizeof( Address* ) );
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0] = malloc( sizeof( Address ) );

  if ( my_address_length == 4 ) {
    ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address_type = IPv4;
  } else {
    ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address_type = IPv6;
  }

  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->length = my_address_length;
  ( (PayloadNetInfo*)unpacked_cell.payload )->my_addresses[0]->address = my_address;

  // this will also free my_address and other_address
  packed_cell = pack_and_free( &unpacked_cell );

  if ( ( wolf_succ = wolfSSL_send( ssl, packed_cell, CELL_LEN, 0 ) ) <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send NETINFO cell, error code: %d", wolfSSL_get_error( ssl, wolf_succ ) );
#endif

    return -1;
  }

  free( packed_cell );

  return 0;
}

int d_verify_certs( Cell* certs_cell, WOLFSSL_X509* peer_cert, int* responder_rsa_identity_key_der_size, unsigned char* responder_rsa_identity_key_der ) {
  int i;
  time_t now;
  WOLFSSL_X509* certificate = NULL;
  WOLFSSL_X509* link_key_certificate = NULL;
  unsigned int cert_date;
  int link_key_count = 0;
  int identity_count = 0;
  unsigned int idx;
  int wolf_succ;
  RsaKey responder_rsa_identity_key;
  unsigned char* temp_array;

  wc_InitRsaKey( &responder_rsa_identity_key, NULL );

  // verify the certs
  time( &now );

  for ( i = 0; i < ( (PayloadCerts*)certs_cell->payload )->cert_count; i++ ) {
    if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type > IDENTITY_CERT ) {
      break;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert,
      ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_length,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid certificate" );
#endif

      return -1;
    }

    cert_date = ud_get_cert_date( certificate->notBefore.data, certificate->notBefore.length );

    if ( cert_date == 0 || cert_date > now ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not before time" );
#endif

      return -1;
    }

    cert_date = ud_get_cert_date( certificate->notAfter.data, certificate->notAfter.length );

    if ( cert_date == 0 || cert_date < now ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid not after time" );
#endif

      return -1;
    }

    if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type == LINK_KEY ) {
      link_key_certificate = certificate;
      link_key_count++;

      if ( link_key_count > 1 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many LINK_KEYs" );
#endif

        return -1;
      }

      if ( memcmp( certificate->pubKey.buffer, peer_cert->pubKey.buffer, certificate->pubKey.length ) != 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to match LINK_KEY with tls key" );
#endif

        return -1;
      }
    } else if ( ( (PayloadCerts*)certs_cell->payload )->certs[i]->cert_type == IDENTITY_CERT ) {
      identity_count++;

      if ( identity_count > 1 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Too many IDENTITY_CERTs" );
#endif

        return -1;
      }

      idx = 0;
      wolf_succ = wc_RsaPublicKeyDecode( certificate->pubKey.buffer, &idx, &responder_rsa_identity_key, certificate->pubKey.length );
      if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to parse IDENTITY_CERT, error code: %d", wolf_succ );
#endif

        return -1;
      }

      memcpy( responder_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
      *responder_rsa_identity_key_der_size = certificate->pubKey.length;

      temp_array = malloc( sizeof( unsigned char ) * 128 );

      // verify the signatures on the keys
      wolf_succ = wc_RsaSSL_Verify(
        link_key_certificate->sig.buffer,
        link_key_certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify LINK_KEY signature, error code: %d", wolf_succ );
#endif

          return -1;
      }

      wolf_succ = wc_RsaSSL_Verify(
        certificate->sig.buffer,
        certificate->sig.length,
        temp_array,
        128,
        &responder_rsa_identity_key
      );

      free( temp_array );

      if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to verify IDENTITY_CERT signature, error code: %d", wolf_succ );
#endif

          return -1;
      }
    }

  }

  if ( link_key_count == 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No LINK_KEYs" );
#endif

    return -1;
  }

  if ( identity_count == 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "No IDENTITY_CERTs" );
#endif

    return -1;
  }

  wolfSSL_X509_free( certificate );
  wolfSSL_X509_free( link_key_certificate );

  return 0;
}

int d_generate_certs( int* initiator_rsa_identity_key_der_size, unsigned char* initiator_rsa_identity_key_der, unsigned char* initiator_rsa_identity_cert_der, int* initiator_rsa_identity_cert_der_size, unsigned char* initiator_rsa_auth_cert_der, int* initiator_rsa_auth_cert_der_size, RsaKey* initiator_rsa_auth_key, WC_RNG* rng ) {
  struct stat st;
  int fd;
  int wolf_succ;
  unsigned int idx;
  RsaKey initiator_rsa_identity_key;
  unsigned char* tmp_initiator_rsa_identity_key_der = malloc( sizeof( unsigned char ) * 1024 );
  Cert initiator_rsa_identity_cert;
  Cert initiator_rsa_auth_cert;
  WOLFSSL_X509* certificate = NULL;

  // init the rsa keys
  wc_InitRsaKey( &initiator_rsa_identity_key, NULL );
  wc_InitRsaKey( initiator_rsa_auth_key, NULL );

  // rsa identity key doesn't exist, create it and save it
  if ( stat( "/sdcard/identity_rsa_key", &st ) == -1 ) {
    // make and save the identity key to the file system
    wolf_succ = wc_MakeRsaKey( &initiator_rsa_identity_key, 1024, 65537, rng );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key, error code: %d", wolf_succ );
#endif

      return -1;
    }

    wolf_succ = wc_RsaKeyToDer( &initiator_rsa_identity_key, tmp_initiator_rsa_identity_key_der, 1024 );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity key der, error code: %d", wolf_succ );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_key", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }
  // rsa identity key exists, load it from the file system
  } else {
    if ( ( fd = open( "/sdcard/identity_rsa_key", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( read( fd, tmp_initiator_rsa_identity_key_der, sizeof( unsigned char ) * 1024 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key, errno: %d", errno );
#endif

      return -1;
    }

    idx = 0;
    wolf_succ = wc_RsaPrivateKeyDecode( tmp_initiator_rsa_identity_key_der, &idx, &initiator_rsa_identity_key, 1024 );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to load rsa identity private key der, error code: %d", wolf_succ );
#endif

      return -1;
    }
  }

  free( tmp_initiator_rsa_identity_key_der );

  // TODO figure out if we can just use one of these and save it to the file system
  // make and export the auth key
  wolf_succ = wc_MakeRsaKey( initiator_rsa_auth_key, 1024, 65537, rng );

  if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wc_InitCert( &initiator_rsa_identity_cert );

  // rsa identity cert doesn't exist, create it and save it
  if ( stat( "/sdcard/identity_rsa_cert_der", &st ) == -1 ) {
    // TODO randomize these
    strncpy( initiator_rsa_identity_cert.subject.country, "US", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.state, "OR", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.locality, "Portland", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.org, "yaSSL", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.unit, "Development", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE );
    strncpy( initiator_rsa_identity_cert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE );

    *initiator_rsa_identity_cert_der_size = wc_MakeSelfCert( &initiator_rsa_identity_cert, initiator_rsa_identity_cert_der, 2048, &initiator_rsa_identity_key, rng );

    if ( *initiator_rsa_identity_cert_der_size <= 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to make rsa identity cert der, error code: %d", *initiator_rsa_identity_cert_der_size );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_cert_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_cert_der_size ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    certificate = wolfSSL_X509_load_certificate_buffer(
      initiator_rsa_identity_cert_der,
      *initiator_rsa_identity_cert_der_size,
      WOLFSSL_FILETYPE_ASN1 );

    if ( certificate == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Invalid identity certificate" );
#endif

      return -1;
    }

    memcpy( initiator_rsa_identity_key_der, certificate->pubKey.buffer, certificate->pubKey.length );
    *initiator_rsa_identity_key_der_size = certificate->pubKey.length;

    wolfSSL_X509_free( certificate );

    if ( ( fd = open( "/sdcard/identity_rsa_key_der", O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( write( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * ( *initiator_rsa_identity_key_der_size ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }
  // rsa identity cert exists, load it from the file system
  } else {
    if ( ( fd = open( "/sdcard/identity_rsa_cert_der", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( *initiator_rsa_identity_cert_der_size = read( fd, initiator_rsa_identity_cert_der, sizeof( unsigned char ) * 2048 ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_cert_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( fd = open( "/sdcard/identity_rsa_key_der", O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( ( *initiator_rsa_identity_key_der_size = read( fd, initiator_rsa_identity_key_der, sizeof( unsigned char ) * 2048 ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close /sdcard/identity_rsa_key_der, errno: %d", errno );
#endif

      return -1;
    }
  }

  // TODO figure out if we can just use one of these and save it to the file system
  wc_InitCert( &initiator_rsa_auth_cert );

  // TODO randomize these
  strncpy( initiator_rsa_auth_cert.subject.country, "US", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.state, "OR", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.locality, "Portland", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.org, "yaSSL", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.unit, "Development", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE );
  strncpy( initiator_rsa_auth_cert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE );

  wc_SetIssuerBuffer( &initiator_rsa_auth_cert, initiator_rsa_identity_cert_der, *initiator_rsa_identity_cert_der_size );

  *initiator_rsa_auth_cert_der_size = wc_MakeCert( &initiator_rsa_auth_cert, initiator_rsa_auth_cert_der, 2048, initiator_rsa_auth_key, NULL, rng );

  if ( *initiator_rsa_auth_cert_der_size <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to make rsa auth cert der, error code: %d", *initiator_rsa_auth_cert_der_size );
#endif

    return -1;
  }

  wolf_succ = wc_SignCert( *initiator_rsa_auth_cert_der_size, initiator_rsa_auth_cert.sigType, initiator_rsa_auth_cert_der, 2048, &initiator_rsa_identity_key, NULL, rng );

  if ( wolf_succ <= 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to sign rsa auth cert der, error code: %d", wolf_succ );
#endif

    return -1;
  }

  *initiator_rsa_auth_cert_der_size = wolf_succ;

  return 0;
}

// destroy a tor circuit
void v_destroy_onion_circuit( int circ_id ) {
  // TODO send a destroy cell to the first hop
  // TODO clean up the rx,tx queues
  // TODO clean up the tls socket
  // TODO clean up any circuit specific data
}

// fetch the descriptor info for the list of relays
int d_fetch_descriptor_info( DoublyLinkedOnionCircuit* linked_circuit ) {
  const char* REQUEST_CONST = "GET /tor/server/d/**************************************** HTTP/1.0\r\n"
      /* "Host: 192.168.1.138\r\n" */
      "Host: 192.168.1.16\r\n"
      "User-Agent: esp-idf/1.0 esp3266\r\n"
      "\r\n";
  char REQUEST[126];

  const char* ntor_onion_key = "\nntor-onion-key ";
  int ntor_onion_key_found = 0;
  char ntor_onion_key_64[43] = { 0 };
  int ntor_onion_key_64_length = 0;

  int i;
  int retries;
  int rx_length;
  int sock_fd;
  int err;
  char end_header = 0;
  // buffer thath holds data returned from the socket
  char rx_buffer[512];
  struct sockaddr_in dest_addr;

  // copy the string into editable memory
  strcpy( REQUEST, REQUEST_CONST );

  // set the address of the directory server
  /* dest_addr.sin_addr.s_addr = inet_addr( "192.168.1.138" ); */
  dest_addr.sin_addr.s_addr = inet_addr( "192.168.1.16" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( 7000 );

  DoublyLinkedOnionRelay* node = linked_circuit->circuit.relay_list.head;

  while ( node != NULL ) {
    retries = 0;
    end_header = 0;
    ntor_onion_key_found = 0;
    ntor_onion_key_64_length = 0;

    while ( retries < 3 ) {
      // create a socket to access the descriptor
      sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

      if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server" );
#endif

        return -1;
      }

      // connect the socket to the dir server address
      err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

      if ( err != 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't connect to http server" );
#endif

        shutdown( sock_fd, 0 );
        close( sock_fd );

        if ( retries >= 2 ) {
          return -1;
        } else {
          retries++;
        }
      } else {
        retries = 3;
      }
    }

#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "connected to http socket" );
#endif

    for ( i = 0; i < 20; i++ ) {
      if ( node->relay->digest[i] >> 4 < 10 ) {
        REQUEST[18 + 2 * i] = 48 + ( node->relay->digest[i] >> 4 );
      } else {
        REQUEST[18 + 2 * i] = 65 + ( ( node->relay->digest[i] >> 4 ) - 10 );
      }

      if ( ( node->relay->digest[i] & 0x0f ) < 10  ) {
        REQUEST[18 + 2 * i + 1] = 48 + ( node->relay->digest[i] & 0x0f );
      } else {
        REQUEST[18 + 2 * i + 1] = 65 + ( ( node->relay->digest[i] & 0x0f ) - 10 );
      }
    }

    // send the http request to the dir server
    err = send( sock_fd, REQUEST, strlen( REQUEST ), 0 );

    if ( err < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "couldn't send to http server" );
#endif

      return -1;
    }

#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "sent to http socket" );
#endif

    // keep reading forever, we will break inside when the transfer is over
    while ( 1 ) {
      // recv data from the destination and fill the rx_buffer with the data
      rx_length = recv( sock_fd, rx_buffer, sizeof( rx_buffer ), 0 );

      // if we got less than 0 we encoutered an error
      if ( rx_length < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "couldn't recv http server" );
#endif

        return -1;
      // we got 0 bytes back then the connection closed and we're done getting
      // consensus data
      } else if ( rx_length == 0 ) {
        break;
      }

#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "recved from http socket" );
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
          if ( ntor_onion_key_found != -1 ) {
            if ( ntor_onion_key_found == strlen( ntor_onion_key ) ) {
              ntor_onion_key_64[ntor_onion_key_64_length] = rx_buffer[i];
              ntor_onion_key_64_length++;

              if ( ntor_onion_key_64_length == 43 ) {
                v_base_64_decode_buffer( node->relay->ntor_onion_key, ntor_onion_key_64, 43 );
                ntor_onion_key_found = -1;
              }
            } else if ( rx_buffer[i] == ntor_onion_key[ntor_onion_key_found] ) {
              ntor_onion_key_found++;
            } else {
              ntor_onion_key_found = 0;
            }
          }
        }
      }
    }

    node = node->next;
    shutdown( sock_fd, 0 );
    close( sock_fd );
  }


  return 0;
}

int d_send_packed_relay_cell_and_free( unsigned char* packed_cell, OnionCircuit* circuit ) {
  int i;
  int wolf_succ;
  unsigned char temp_digest[WC_SHA_DIGEST_SIZE];
  DoublyLinkedOnionRelay* relay = circuit->relay_list.head;

  for ( i = 0; i < circuit->relay_list.built_length - 1; i++ ) {
    relay = relay->next;
  }

  wc_ShaUpdate( &relay->relay->running_sha_forward, packed_cell + 5, PAYLOAD_LEN );
  wc_ShaGetHash( &relay->relay->running_sha_forward, temp_digest );

  memcpy( packed_cell + 10, temp_digest, 4 );

  // encrypt the RELAY_EARLY cell's payload from R_(node_index-1) to R_0
  for ( i = circuit->relay_list.built_length - 1; i >= 0; i-- ) {
    wolf_succ = wc_AesCtrEncrypt( &relay->relay->aes_forward, packed_cell + 5, packed_cell + 5, PAYLOAD_LEN );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to encrypt RELAY payload, error code: %d", wolf_succ );
#endif

      return -1;
    }

    relay = relay->previous;
  }

  // send the RELAY_EARLY to the first node in the circuit
  if ( wolfSSL_send( circuit->ssl, packed_cell, CELL_LEN, 0 ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY cell" );
#endif

    return -1;
  }

  free( packed_cell );

  return 0;
}

// recv a cell from our ssl connection
int d_recv_cell( WOLFSSL* ssl, Cell* unpacked_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list, Sha256* sha ) {
  int rx_limit;
  unsigned char* packed_cell;

  rx_limit = d_recv_packed_cell( ssl, &packed_cell, circ_id_length, relay_list );

  if ( rx_limit < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't recv packed cell" );
#endif

    return -1;
  }

  if ( sha != NULL ) {
    wc_Sha256Update( sha, packed_cell, rx_limit );
  }

  // set the unpacked cell and return success
  return unpack_and_free( unpacked_cell, packed_cell, circ_id_length );
}

int d_recv_packed_cell( WOLFSSL* ssl, unsigned char** packed_cell, int circ_id_length, DoublyLinkedOnionRelayList* relay_list ) {
  int i;
  int wolf_succ;
  int rx_length;
  int rx_length_total = 0;
  // length of the header may change if we run into a variable length cell
  int header_length = circ_id_length + 1;
  // limit will change
  int rx_limit = header_length;
  // we want to make it big enough for an entire cell to fit
  unsigned char rx_buffer[CELL_LEN];
  // variable length of the cell if there is one
  unsigned short length = 0;
  Sha tmp_sha;
  DoublyLinkedOnionRelay* relay;
  unsigned char zeros[4] = { 0 };
  unsigned char temp_digest[WC_SHA_DIGEST_SIZE];
  int fully_recognized = 0;

  // initially just make the packed cell big enough for a standard header,
  // we'll realloc it later
  *packed_cell = malloc( sizeof( unsigned char ) * header_length );

  while ( 1 ) {
    // read in at most rx_length, rx_length will be either the length of
    // the cell or the length of the header
    if ( rx_limit - rx_length_total > CELL_LEN ) {
      rx_length = wolfSSL_recv( ssl, rx_buffer, CELL_LEN, 0 );
    } else {
      rx_length = wolfSSL_recv( ssl, rx_buffer, rx_limit - rx_length_total, 0 );
    }

    // if rx_length is 0 then we've hit an error and should return -1
    if ( rx_length <= 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "error code: %d", wolfSSL_get_error( ssl, rx_length ) );
#endif

      free( *packed_cell );
      return -1;
    }

    // put the contents of the rx_buffer into the packed cell and increment the
    // rx_length_total
    for ( i = 0; i < rx_length; i++ ) {
      (*packed_cell)[rx_length_total] = rx_buffer[i];
      rx_length_total++;
    }

    // if the total number of bytes we've read in is the fixed header length,
    // check for a versions variable length cell, if we have one, extend the
    // header length to include the length field
    if ( rx_length_total == circ_id_length + 1 ) {
      if ( (*packed_cell)[circ_id_length] == VERSIONS || (*packed_cell)[circ_id_length] >= VPADDING ) {
        header_length = circ_id_length + 3;
        rx_limit = header_length;
        *packed_cell = realloc( *packed_cell, header_length );
      }
    }

    // if we've reached the header we're ready to realloc and move the rx_limit
    // to the length of the cell
    if ( rx_length_total == header_length ) {
      // set the rx_limit to the length of the cell
      if ( (*packed_cell)[circ_id_length] == VERSIONS || (*packed_cell)[circ_id_length] >= VPADDING ) {
        length = ( (unsigned short)(*packed_cell)[circ_id_length + 1] ) << 8;
        length |= (unsigned short)(*packed_cell)[circ_id_length + 2];
        rx_limit = header_length + length;
      } else {
        rx_limit = CELL_LEN;
      }

      // realloc the cell to the correct size
      *packed_cell = realloc( *packed_cell, rx_limit );
    }

    // if we've hit the rx_limit then we're done recv-ing the packed cell,
    // the rx_limit will increase after we've recv-ed the header so we
    // won't hit this prematurely
    if ( rx_length_total == rx_limit ) {
      break;
    }
  }

  if ( (*packed_cell)[circ_id_length] == RELAY ) {
    if ( relay_list == NULL ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, relay list was null" );
#endif

      return -1;
    }

    relay = relay_list->head;
    wc_InitSha( &tmp_sha );

    for ( i = 0; i < relay_list->built_length; i++ ) {
      wolf_succ = wc_AesCtrEncrypt( &relay->relay->aes_backward, *packed_cell + 5, *packed_cell + 5, PAYLOAD_LEN );

      if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
        ESP_LOGE( MINITOR_TAG, "Failed to decrypt RELAY payload, error code: %d", wolf_succ );
#endif

        return -1;
      }

      if ( (*packed_cell)[6] == 0 && (*packed_cell)[7] == 0 ) {
        wc_ShaCopy( &relay->relay->running_sha_backward, &tmp_sha );

        wc_ShaUpdate( &tmp_sha, *packed_cell + 5, 5 );
        wc_ShaUpdate( &tmp_sha, zeros, 4 );
        wc_ShaUpdate( &tmp_sha, *packed_cell + 14, PAYLOAD_LEN - 9 );
        wc_ShaGetHash( &tmp_sha, temp_digest );

        if ( memcmp( temp_digest, *packed_cell + 10, 4 ) == 0 ) {
          wc_ShaCopy( &tmp_sha, &relay->relay->running_sha_backward );
          fully_recognized = 1;
          break;
        }
      }

      relay = relay->next;
    }

    if ( !fully_recognized ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Relay recognized cell was not set to 0" );
#endif

      return -1;
    }
  }

  return rx_limit;
}

unsigned int ud_get_cert_date( unsigned char* date_buffer, int date_size ) {
  int i = 0;
  struct tm temp_time;
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;

  for ( i = 0; i < date_size; i++ ) {
    if ( i < 2 ) {
      year *= 10;
      year += date_buffer[i] & 0x0f;
    } else if ( i < 4 ) {
      month *= 10;
      month += date_buffer[i] & 0x0f;
    } else if ( i < 6 ) {
      day *= 10;
      day += date_buffer[i] & 0x0f;
    } else if ( i < 8 ) {
      hour *= 10;
      hour += date_buffer[i] & 0x0f;
    } else if ( i < 10 ) {
      minute *= 10;
      minute += date_buffer[i] & 0x0f;
    } else if ( i < 12 ) {
      second *= 10;
      second += date_buffer[i] & 0x0f;
    } else {
      temp_time.tm_year = ( year + 100 );
      temp_time.tm_mon = month - 1;
      temp_time.tm_mday = day;
      temp_time.tm_hour = hour;
      temp_time.tm_min = minute;
      temp_time.tm_sec = second;

      return mktime( &temp_time );
    }
  }

  return 0;
}

// ONION SERVICES
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory ) {
  int i;
  long int valid_after;
  unsigned int hsdir_interval;
  int time_period = 0;
  DoublyLinkedOnionCircuit* node;
  unsigned char* second_layer;
  unsigned char* first_layer;
  unsigned char* descriptor_outer;
  OnionService* onion_service = malloc( sizeof( OnionService ) );

  onion_service->local_port = local_port;
  onion_service->exit_port = exit_port;
  onion_service->rx_queue = xQueueCreate( 5, sizeof( Cell* ) );

  if ( d_generate_hs_keys( onion_service, onion_service_directory ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate hs keys" );
#endif

    return NULL;
  }

  // setup starting circuits
  if ( d_setup_init_circuits( 3 ) < 3 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to setup init circuits" );
#endif

    return NULL;
  }

  // take two circuits from the standby circuits list
  // BEGIN mutex
  xSemaphoreTake( standby_circuits_mutex, portMAX_DELAY );

  if ( standby_circuits.length < 3 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Not enough standby circuits to register intro points" );
#endif

    xSemaphoreGive( standby_circuits_mutex );
    // END mutex

    return NULL;
  }

  // set the onion services head to the standby circuit head
  onion_service->intro_circuits.head = standby_circuits.head;
  // set the onion services tail to the second standby circuit
  onion_service->intro_circuits.tail = standby_circuits.head->next->next;

  // if there is a third standby circuit, set its previous to NULL
  if ( standby_circuits.length > 3 ) {
    standby_circuits.head->next->next->next->previous = NULL;
  }

  // set the standby circuit head to the thrid, possibly NULL
  standby_circuits.head = standby_circuits.head->next->next->next;
  // disconnect our tail from the other standby circuits
  onion_service->intro_circuits.tail->next = NULL;
  // set our intro length to 2
  onion_service->intro_circuits.length = 3;
  // subtract two from the standby_circuits length
  standby_circuits.length -= 3;

  xSemaphoreGive( standby_circuits_mutex );
  // END mutex

  // TODO send establish intro commands to our three circuits
  node = onion_service->intro_circuits.head;

  for ( i = 0; i < onion_service->intro_circuits.length; i++ ) {
    node->circuit.rx_queue = onion_service->rx_queue;

    if ( d_router_establish_intro( &node->circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to establish intro with a circuit" );
#endif

      return NULL;
    }

    node = node->next;
  }

  // BEGIN mutex
  /* xSemaphoreTake( network_consensus_mutex, portMAX_DELAY ); */

  valid_after = network_consensus.valid_after;
  hsdir_interval = network_consensus.hsdir_interval;

  xSemaphoreGive( network_consensus_mutex );
  // END mutex

  time_period = ( valid_after / 60 - 12 * 60 ) / hsdir_interval;

  // TODO generate second layer plaintext
  /* if ( d_generate_second_plaintext( &second_layer, &onion_service->intro_circuits, valid_after ) < 0 ) { */
/* #ifdef DEBUG_MINITOR */
      /* ESP_LOGE( MINITOR_TAG, "Failed to generate second layer descriptor plaintext" ); */
/* #endif */

      /* return NULL; */
  /* } */
  // TODO encrypt second layer plaintext
  // TODO create first layer plaintext
  // TODO encrypt first layer plaintext
  // TODO create outer descriptor wrapper
  // TODO send outer descriptor wrapper to the correct HSDIR nodes
  // TODO create a task to block on the rx_queue

  // return the onion service
  return onion_service;
}

void v_handle_onion_service( void* pv_parameters ) {
  // TODO block on rx_queue
  // TODO when an intro request comes in, respond to it
  // TODO when a relay_begin comes in, create a task to block on the local tcp stream
  // TODO when a relay_data comes in, send the data to the local tcp stream
  // TODO when a destroy comes in close and clean the circuit and local tcp stream
}

/* int d_generate_second_plaintext( unsigned char** second_layer, DoublyLinkedOnionCircuitList* intro_circuits, long int valid_after, ed25519_key* descriptor_signing_key ) { */
  /* int i; */
  /* int idx; */
  /* unsigned char* working_second_layer; */
  /* unsigned char packed_link_specifiers[1 + 4 + 6 + ID_LENGTH]; */
  /* unsigned char tmp_pub_key[CURVE25519_KEYSIZE]; */
  /* DoublyLinkedOnionCircuit* node; */

  /* const char* second_layer_template = */
    /* "create2-formats 2\n" */
    /* ; */
  /* const char* introduction_point_template = */
    /* "introduction-point ******************************************\n" */
    /* "onion-key ntor ******************************************\n" */
    /* "auth-key\n" */
    /* // TODO this is a crosscert with the descriptor signing key as the main key and the intoduction point authentication key as the mandatory extension */
    /* "-----BEGIN ED25519 CERT-----********************************************************************************************************************************************-----END ED25519 CERT-----\n" */
    /* // TODO this is the public cruve25519 key used to encrypt the introduction request */
    /* "enc-key ntor ******************************************\n" */
    /* "enc-key-cert\n" */
    /* // TODO this is a crosscert with the descriptor signing key as the main key and the the ed25519 equivilent of the above key used as the mandatory extension */
    /* "-----BEGIN ED25519 CERT-----********************************************************************************************************************************************-----END ED25519 CERT-----\n" */
    /* ; */

  /* *second_layer = malloc( sizeof( unsigned char ) * ( strlen( second_layer_template ) + strlen( introduction_point_template ) * intro_circuits.length ) ); */

  /* working_second_layer = *second_layer; */

  /* memcpy( working_second_layer, second_layer_template, strlen( second_layer_template ) ); */
  /* working_second_layer += strlen( second_layer_template ); */

  /* node = intro_circuits.head; */

  /* for ( i = 0; i < intro_circuits.length; i++ ) { */
    /* memcpy( working_second_layer, introduction_point_template, strlen( introduction_point_template ) ); */
    /* // skip past the intordouction-point header */
    /* working_second_layer += 19; */
    /* v_generate_packed_link_specifiers( node->circuit.relay_list->tail->relay, packed_link_specifiers ); */
    /* v_base_64_encode( working_second_layer, packed_link_specifiers, sizeof( packed_link_specifiers ) ); */
    /* // skip past the link specifiers and \nonion-key ntor */
    /* working_second_layer += 42 + 16; */
    /* v_base_64_encode( working_second_layer, node->circuit.relay_list->tail->relay->ntor_onion_key, H_LENGTH ); */
    /* // skip past the onion key and next header */
    /* working_second_layer += 42 + 38; */

    /* if ( d_generate_packed_ed_crosscert( working_second_layer, descriptor_signing_key, &node->circuit.auth_key, 0x09, valid_after ) < 0 ) { */
/* #ifdef DEBUG_MINITOR */
      /* ESP_LOGE( MINITOR_TAG, "Failed to generate the auth_key cross cert" ); */
/* #endif */
    /* } */

    /* // skip past the cert and next header */
    /* working_second_layer += 140 + 40; */

    /* idx = CURVE25519_KEYSIZE; */
    /* wolf_succ = wc_curve25519_export_public_ex( &node->circuit.intro_encrypt_key, tmp_pub_key, &idx, EC25519_LITTLE_ENDIAN ); */

    /* if ( wolf_succ != 0 ) { */
/* #ifdef DEBUG_MINITOR */
      /* ESP_LOGE( MINITOR_TAG, "Failed to export intro encrypt key, error code: %d", wolf_succ ); */
/* #endif */

      /* return -1; */
    /* } */

    /* v_base_64_encode( working_second_layer, tmp_pub_key, CURVE25519_KEYSIZE ); */
    /* // skip past the enc key and next header */
    /* working_second_layer += 42 + 42; */

    /* // TODO create the derived key by converting our intro_encrypt_key into an ed25519 key */
    /* if ( d_generate_packed_ed_crosscert( working_second_layer, descriptor_signing_key, &derived_key, 0x0B, valid_after ) < 0 ) { */
/* #ifdef DEBUG_MINITOR */
      /* ESP_LOGE( MINITOR_TAG, "Failed to generate the enc-key cross cert" ); */
/* #endif */
    /* } */

    /* node = node->next; */
  /* } */
/* } */

/* void v_generate_packed_link_specifiers( OnionRelay* relay, unsigned char* packed_link_specifiers ) { */
  /* // set the specifier count */
  /* packed_link_specifiers[0] = 2; */

  /* // IPv4 specifier */
  /* // set the type */
  /* packed_link_specifiers[1] = IPv4Link; */
  /* // set the length */
  /* packed_link_specifiers[2] = 6; */
  /* // set the address and port */
  /* packed_link_specifiers[6] = (unsigned char)( relay->address >> 24 ); */
  /* packed_link_specifiers[5] = (unsigned char)( relay->address >> 16 ); */
  /* packed_link_specifiers[4] = (unsigned char)( relay->address >> 8 ); */
  /* packed_link_specifiers[3] = (unsigned char)relay->address; */
  /* packed_link_specifiers[7] = (unsigned char)relay->or_port >> 8; */
  /* packed_link_specifiers[8] = (unsigned char)relay->or_port; */

  /* // LEGACYLink specifier */
  /* // set the type */
  /* packed_link_specifiers[9] = LEGACYLink; */
  /* // set the length */
  /* packed_link_specifiers[10] = ID_LENGTH; */
  /* // copy the identity in */
  /* memcpy( *packed_link_specifiers + 10, relay->identity, ID_LENGTH ); */
/* } */

/* int d_generate_packed_ed_crosscert( unsigned char* destination, ed25519_key* main_key, ed25519_key* signing_key, unsigned char cert_type, long int valid_after ) { */
  /* unsigned int idx; */
  /* int wolf_succ; */
  /* // set epoch hours to current epoch hours plus three hours later */
  /* int epoch_hours = valid_after / 60 / 60 + 3; */

  /* // set the version */
  /* destination[0] = 0x01; */
  /* // set the cert type */
  /* destination[1] = cert_type; */
  /* // set the expiration date, four bytes */
  /* destination[2] = (unsigned char)( epoch_hours >> 24 ); */
  /* destination[3] = (unsigned char)( epoch_hours >> 16 ); */
  /* destination[4] = (unsigned char)( epoch_hours >> 8 ); */
  /* destination[5] = (unsigned char)epoch_hours; */
  /* // set the cert key type, same a cert type */
  /* destination[6] = cert_type; */
  /* // copy the main key */
  /* idx = ED25519_PUB_KEY_SIZE; */
  /* wolf_succ = wc_ed25519_export_public( &main_key, destination + 7, &idx ); */

  /* if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ ); */
/* #endif */

    /* return -1; */
  /* } */

  /* // set n extensions to 1 */
  /* destination[39] = 1; */
  /* // set the ext length to key size */
  /* destination[40] = 0; */
  /* destination[41] = ED25519_PUB_KEY_SIZE; */
  /* // set the ext type to 0x04 */
  /* destination[42] = 0x04; */
  /* // set ext flag to 1 */
  /* destination[43] = 0x01; */
  /* // copy the signing key */
  /* idx = ED25519_PUB_KEY_SIZE; */
  /* wolf_succ = wc_ed25519_export_public( &signing_key, destination + 44, &idx ); */

  /* if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ ); */
/* #endif */

    /* return -1; */
  /* } */

  /* idx = 64; */
  /* wolf_succ = wc_ed25519_sign_msg( destination, 74, destination + 76, &idx, signing_key ); */

  /* if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( MINITOR_TAG, "Failed to sign the ed crosscert, error code: %d", wolf_succ ); */
/* #endif */

    /* return -1; */
  /* } */

  /* return 0; */
/* } */

int d_router_establish_intro( OnionCircuit* circuit ) {
  int wolf_succ;
  unsigned int idx;
  int64_t ordered_digest_length = (int64_t)DIGEST_LEN;
  unsigned char ordered_digest_length_buffer[8];
  WC_RNG rng;
  Sha3 reusable_sha3;
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  Cell unpacked_cell;
  Cell* recv_unpacked_cell = NULL;
  unsigned char* packed_cell;
  unsigned char* prefixed_cell;
  const char* prefix_str = "Tor establish-intro cell v1";

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  wc_InitRng( &rng );
  wc_ed25519_init( &circuit->auth_key );

  wc_ed25519_make_key( &rng, 32, &circuit->auth_key );

  wc_FreeRng( &rng );

  idx = ED25519_PUB_KEY_SIZE;
  wolf_succ = wc_ed25519_export_public( &circuit->auth_key, tmp_pub_key, &idx );

  if ( wolf_succ < 0 || idx != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export public auth_key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  unpacked_cell.circ_id = circuit->circ_id;
  unpacked_cell.command = RELAY;
  unpacked_cell.payload = malloc( sizeof( PayloadRelay ) );

  ( (PayloadRelay*)unpacked_cell.payload )->command = RELAY_COMMAND_ESTABLISH_INTRO;
  ( (PayloadRelay*)unpacked_cell.payload )->recognized = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->stream_id = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->digest = 0;
  ( (PayloadRelay*)unpacked_cell.payload )->length = 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN + 2 + ED25519_SIG_SIZE;
  ( (PayloadRelay*)unpacked_cell.payload )->relay_payload = malloc( sizeof( RelayPayloadEstablishIntro ) );

  ( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->type = ESTABLISH_INTRO_CURRENT;
  ( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro = malloc( sizeof( EstablishIntroCurrent ) );

  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key_type = EDSHA3;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key_length = ED25519_PUB_KEY_SIZE;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key = malloc( sizeof( unsigned char ) * ED25519_PUB_KEY_SIZE );
  memcpy( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->auth_key, tmp_pub_key, ED25519_PUB_KEY_SIZE );
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->extension_count = 0;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->signature_length = ED25519_SIG_SIZE;
  ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)( (PayloadRelay*)unpacked_cell.payload )->relay_payload )->establish_intro )->signature = NULL;

  packed_cell = pack_and_free( &unpacked_cell );

  ESP_LOGE( MINITOR_TAG, "%lld", ordered_digest_length );
  ESP_LOGE( MINITOR_TAG, "%lld", (int64_t)DIGEST_LEN );

  ordered_digest_length_buffer[0] = (unsigned char)( ordered_digest_length >> 56 );
  ordered_digest_length_buffer[1] = (unsigned char)( ordered_digest_length >> 48 );
  ordered_digest_length_buffer[2] = (unsigned char)( ordered_digest_length >> 40 );
  ordered_digest_length_buffer[3] = (unsigned char)( ordered_digest_length >> 32 );
  ordered_digest_length_buffer[4] = (unsigned char)( ordered_digest_length >> 24 );
  ordered_digest_length_buffer[5] = (unsigned char)( ordered_digest_length >> 16 );
  ordered_digest_length_buffer[6] = (unsigned char)( ordered_digest_length >> 8 );
  ordered_digest_length_buffer[7] = (unsigned char)ordered_digest_length;

  /* wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)&ordered_digest_length, 8 ); */
  wc_Sha3_256_Update( &reusable_sha3, ordered_digest_length_buffer, sizeof( ordered_digest_length_buffer ) );
  wc_Sha3_256_Update( &reusable_sha3, circuit->relay_list.tail->relay->nonce, DIGEST_LEN );
  wc_Sha3_256_Update( &reusable_sha3, packed_cell + 5 + 11, 3 + ED25519_PUB_KEY_SIZE + 1 );
  wc_Sha3_256_Final( &reusable_sha3, packed_cell + 5 + 11 + 3 + ED25519_PUB_KEY_SIZE + 1 );

  prefixed_cell = malloc( sizeof( unsigned char ) * ( strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN ) );
  memcpy( prefixed_cell, prefix_str, strlen( prefix_str ) );
  memcpy( prefixed_cell + strlen( prefix_str ), packed_cell + 5 + 11, 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN );

  idx = ED25519_SIG_SIZE;
  wolf_succ = wc_ed25519_sign_msg(
    prefixed_cell,
    strlen( prefix_str ) + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN,
    packed_cell + 5 + 11 + 3 + ED25519_PUB_KEY_SIZE + 1 + MAC_LEN + 2,
    &idx,
    &circuit->auth_key
  );

  free( prefixed_cell );

  if ( wolf_succ < 0 || idx != ED25519_SIG_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to generate establish intro signature, error code: %d", wolf_succ );
#endif

    return -1;
  }

  ESP_LOGE( MINITOR_TAG, "Sending establish intro to %d", circuit->relay_list.tail->relay->or_port );

  if ( d_send_packed_relay_cell_and_free( packed_cell, circuit ) < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to send RELAY_COMMAND_ESTABLISH_INTRO cell" );
#endif
  }

  while ( 1 ) {
    ESP_LOGE( MINITOR_TAG, "Waiting for intro response" );
    xQueueReceive( circuit->rx_queue, &recv_unpacked_cell, portMAX_DELAY );

    if ( recv_unpacked_cell->circ_id != circuit->circ_id ) {
      xQueueSendToBack( circuit->rx_queue, (void*)(&recv_unpacked_cell), portMAX_DELAY );
    } else {
      break;
    }
  }

  ESP_LOGE( MINITOR_TAG, "got cell command %d", recv_unpacked_cell->command );

  if ( recv_unpacked_cell->command != RELAY ) {
    return -1;
  }

  if ( recv_unpacked_cell->command == RELAY ) {
    ESP_LOGE( MINITOR_TAG, "got relay command %d", ( (PayloadRelay*)recv_unpacked_cell->payload )->command );
  }

  free_cell( recv_unpacked_cell );
  free( recv_unpacked_cell );

  return 0;
}

int d_derive_blinded_keys( unsigned char output_priv_key[ED25519_PRV_KEY_SIZE], ed25519_key* master_key, int64_t period_number, int64_t period_length, unsigned char nonce[32], unsigned char* secret, int secret_length ) {
  int wolf_succ;
  unsigned int idx;
  unsigned int idy;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  Sha512 reusable_sha512;
  unsigned char reusable_sha512_sum[WC_SHA512_DIGEST_SIZE];
  ge_p3 expanded_secret_key;
  /* ge_p3 expanded_secret_key, expanded_hash; */
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  unsigned char tmp_priv_key[ED25519_PRV_KEY_SIZE];

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );
  wc_InitSha512( &reusable_sha512 );

  idx = ED25519_PRV_KEY_SIZE;
  idy = ED25519_PUB_KEY_SIZE;
  wolf_succ = wc_ed25519_export_key( master_key, tmp_priv_key, &idx, tmp_pub_key, &idy );

  if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to export master key, error code: %d", wolf_succ );
#endif

    return -1;
  }

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"Derive temporary signing key", strlen( "Derive temporary signing key" ) + 1 );
  wc_Sha3_256_Update( &reusable_sha3, tmp_pub_key, ED25519_PUB_KEY_SIZE );

  if ( secret != NULL ) {
    wc_Sha3_256_Update( &reusable_sha3, secret, secret_length );
  }

  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)HS_ED_BASEPOINT, HS_ED_BASEPOINT_LENGTH );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"key-blind", strlen( "key-blind" ) );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)&period_number, 8 );
  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)&period_length, 8 );
  wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

  reusable_sha3_sum[0] &= 248;
  reusable_sha3_sum[31] &= 63;
  reusable_sha3_sum[31] |= 64;

  /* ge_frombytes_vartime( &expanded_hash, reusable_sha3_sum ); */
  ge_frombytes_vartime( &expanded_secret_key, tmp_priv_key );
  // TODO this may not be the correct a' = h a mod 1 operation, the actual tor implementation does something different
  // will need to verify this produces the correct key
  ed25519_smult( &expanded_secret_key, &expanded_secret_key, reusable_sha3_sum );

  ge_p3_tobytes( output_priv_key, &expanded_secret_key );

  wc_Sha512Update( &reusable_sha512, (unsigned char*)"Derive temporary signing key hash input", strlen( "Derive temporary signing key hash input" ) );
  wc_Sha512Update( &reusable_sha512, tmp_priv_key + 32, 32 );
  wc_Sha512Final( &reusable_sha512, reusable_sha512_sum );

  memcpy( output_priv_key + 32, reusable_sha512_sum, 32 );

  return 0;
}

int d_generate_hs_keys( OnionService* onion_service, const char* onion_service_directory ) {
  int fd;
  int wolf_succ;
  unsigned int idx;
  unsigned int idy;
  unsigned char version = 0x03;
  struct stat st;
  WC_RNG rng;
  Sha3 reusable_sha3;
  unsigned char reusable_sha3_sum[WC_SHA3_256_DIGEST_SIZE];
  unsigned char tmp_pub_key[ED25519_PUB_KEY_SIZE];
  unsigned char tmp_priv_key[ED25519_PRV_KEY_SIZE];
  unsigned char raw_onion_address[ED25519_PUB_KEY_SIZE + 2 + 1];
  char onion_address[63] = { 0 };
  char working_file[256];

  strcpy( onion_address + 56, ".onion" );

  wc_InitRng( &rng );
  wc_ed25519_init( &onion_service->master_key );
  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  /* rmdir( onion_service_directory ); */

  // directory doesn't exist, create the keys
  if ( stat( onion_service_directory, &st ) == -1 ) {
    if ( mkdir( onion_service_directory, 0755 ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to create %s for onion service, errno: %d", onion_service_directory, errno );
#endif

      return -1;
    }

    wc_ed25519_make_key( &rng, 32, &onion_service->master_key );

    wc_FreeRng( &rng );

    idx = ED25519_PRV_KEY_SIZE;
    idy = ED25519_PUB_KEY_SIZE;
    wolf_succ = wc_ed25519_export_key( &onion_service->master_key, tmp_priv_key, &idx, tmp_pub_key, &idy );

    if ( wolf_succ < 0 || idx != ED25519_PRV_KEY_SIZE || idy != ED25519_PUB_KEY_SIZE ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to export ed25519 key, error code: %d", wolf_succ );
#endif

      return -1;
    }

    wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)".onion checksum", strlen( ".onion checksum" ) );
    wc_Sha3_256_Update( &reusable_sha3, tmp_pub_key, ED25519_PUB_KEY_SIZE );
    wc_Sha3_256_Update( &reusable_sha3, &version, 1 );
    wc_Sha3_256_Final( &reusable_sha3, reusable_sha3_sum );

    memcpy( raw_onion_address, tmp_pub_key, ED25519_PUB_KEY_SIZE );
    memcpy( raw_onion_address + ED25519_PUB_KEY_SIZE, reusable_sha3_sum, 2 );
    raw_onion_address[ED25519_PUB_KEY_SIZE + 2] = version;

    v_base_32_encode( onion_address, raw_onion_address, sizeof( raw_onion_address ) );

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/hostname" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, onion_address, sizeof( char ) * strlen( onion_address ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_pub_key, ED25519_PUB_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_CREAT | O_WRONLY | O_TRUNC ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( write( fd, tmp_priv_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to write %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }
  // directory exists, load the keys
  } else {
    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/private_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( read( fd, tmp_priv_key, sizeof( char ) * ED25519_PUB_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    strcpy( working_file, onion_service_directory );
    strcat( working_file, "/public_key_ed25519" );

    if ( ( fd = open( working_file, O_RDONLY ) ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to open %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }


    if ( read( fd, tmp_pub_key, sizeof( char ) * ED25519_PRV_KEY_SIZE ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to read %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    if ( close( fd ) < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to close %s for onion service, errno: %d", working_file, errno );
#endif

      return -1;
    }

    wolf_succ = wc_ed25519_import_private_key( tmp_priv_key, ED25519_PRV_KEY_SIZE, tmp_pub_key, ED25519_PUB_KEY_SIZE, &onion_service->master_key );

    if ( wolf_succ < 0 ) {
#ifdef DEBUG_MINITOR
      ESP_LOGE( MINITOR_TAG, "Failed to import ed25519 key, error code: %d", wolf_succ );
#endif

      return -1;
    }
  }

  return 0;
}

// shut down a hidden service
/* void v_stop_hidden_service( int hidden_service_id ) { */
  // TODO send destroy's to all hidden service associated circuits; introduction points and client rendezvous
  // TODO clean up the tls socket
  // TODO clean up the rx,tx queues
  // TODO clean up any hidden service specific data
/* } */
