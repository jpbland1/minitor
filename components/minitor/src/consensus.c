#include <stdlib.h>
#include <time.h>

#include "esp_log.h"
#include "lwip/sockets.h"

#include "user_settings.h"
#include "wolfssl/wolfcrypt/sha3.h"

#include "../include/config.h"
#include "../h/constants.h"
#include "../h/consensus.h"
#include "../h/encoding.h"
#include "../h/models/relay.h"

// parse the date using a single byte, relies on other variables to determine how far
// in the date we are
static int d_parse_date_byte( char byte, int* year, int* year_found, int* month, int* month_found, int* day, int* day_found, int* hour, int* hour_found, int* minute, int* minute_found, int* second, int* second_found, struct tm* temp_time ) {
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

// fetch the network consensus so we can correctly create circuits
int d_fetch_consensus_info() {
  const char* REQUEST = "GET /tor/status-vote/current/consensus HTTP/1.0\r\n"
      "Host: "MINITOR_CHUTNEY_ADDRESS_STR"\r\n"
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
    .hsdir_interval = HSDIR_INTERVAL_DEFAULT,
    .hsdir_n_replicas = HSDIR_N_REPLICAS_DEFAULT,
    .hsdir_spread_store = HSDIR_SPREAD_STORE_DEFAULT,
  };
  int time_period = 0;
  unsigned char tmp_64_buffer[8];

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
  OnionRelay canidate_relay = {
    .address = 0,
    .or_port = 0,
    .dir_port = 0,
    .hsdir = 0,
    .suitable = 0,
  };
  Sha3 reusable_sha3;
  // string matching variables for relays and tags
  const char* relay = "\nr ";
  int relay_found = 0;
  const char* s_tag = "\ns ";
  int s_tag_found = 0;
  const char* pr_tag = "\npr ";
  int pr_tag_found = 0;
  // counts the current element of the relay we're on since they are in
  // a set order
  int relay_element_num = 0;
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
  const char* hsdir = "HSDir=1-2";
  int hsdir_found = 0;

  // information for connecting to the directory server
  int i;
  int rx_length;
  int sock_fd;
  char end_header = 0;
  // buffer thath holds data returned from the socket
  char rx_buffer[512];
  struct sockaddr_in dest_addr;

  wc_InitSha3_256( &reusable_sha3, NULL, INVALID_DEVID );

  if ( d_destroy_all_relays() < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "Failed to clear old relays out of the database" );
#endif

    return -1;
  }

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = MINITOR_CHUTNEY_ADDRESS;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( 7000 );

  // create a socket to access the consensus
  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 ) {
#ifdef DEBUG_MINITOR
    ESP_LOGE( MINITOR_TAG, "couldn't create a socket to http server" );
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

              time_period = ( result_network_consensus.valid_after / 60 - 12 * 60 ) / result_network_consensus.hsdir_interval;
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
              v_base_64_decode( result_network_consensus.previous_shared_rand, previous_shared_rand_64, previous_shared_rand_length );
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
              v_base_64_decode( result_network_consensus.shared_rand, shared_rand_64, shared_rand_length );
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
          // if we haven't finished parsing all the relay elements
          if ( relay_element_num != -1 ) {
            // if we hit a space
            if ( rx_buffer[i] == ' ' ) {
              // if we're on element 5 we need to update the address
              if ( relay_element_num == 5 ) {
                canidate_relay.address |= ( (int)address_byte ) << address_offset;
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
              if ( rx_buffer[i] == s_tag[s_tag_found] ) {
                s_tag_found++;
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
                    v_base_64_decode( canidate_relay.identity, identity, identity_length );;
                  }

                  break;
                // digest
                case 2:
                  // same as with the identity
                  digest[digest_length] = rx_buffer[i];
                  digest_length++;

                  if ( digest_length == 27 ) {
                    v_base_64_decode( canidate_relay.digest, digest, digest_length );;
                  }

                  break;
                // address
                case 5:
                  // if we hit a period we ned to store that byte of the address
                  if ( rx_buffer[i] == '.' ) {
                    // add the address to the byte at the correct offset
                    canidate_relay.address |= ( (int)address_byte ) << address_offset;
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
                  canidate_relay.or_port *= 10;
                  canidate_relay.or_port += rx_buffer[i] - 48;

                  break;
                // dir port
                case 7:
                  // add the character to the short
                  canidate_relay.dir_port *= 10;
                  canidate_relay.dir_port += rx_buffer[i] - 48;

                  break;
                // for all other elements we don't need to parse them
                default:
                  break;
              }
            }
          // otherwise we're done parsing the relay line and we need to parse the tags
          } else if ( s_tag_found != -1 ) {
            // if we've already matched the tag string
            if ( s_tag_found == strlen( s_tag ) ) {
              // if we hit a newline we're done parsing the tags and need to add it to
              // the array lists
              if ( rx_buffer[i] == '\n' ) {
                // mark the s_tag found as ended
                s_tag_found = -1;

                // if we've matched the pr_tag then increment found, since \n is part of the tag
                if ( rx_buffer[i] == pr_tag[pr_tag_found] ) {
                  pr_tag_found++;
                }
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
            } else if ( rx_buffer[i] == s_tag[s_tag_found] ) {
              s_tag_found++;
            // otherwise reset the found
            } else {
              s_tag_found = 0;
            }
          } else {
            if ( pr_tag_found == strlen( pr_tag ) ) {
              if ( rx_buffer[i] == '\n' ) {
                if ( hsdir_found == strlen( hsdir ) ) {
                  canidate_relay.hsdir = 1;

                  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"node-idx", strlen( "node-idx" ) );
                  wc_Sha3_256_Update( &reusable_sha3, canidate_relay.identity, ID_LENGTH );
                  wc_Sha3_256_Update( &reusable_sha3, result_network_consensus.previous_shared_rand, 32 );

                  tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 56 );
                  tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 48 );
                  tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 40 );
                  tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 32 );
                  tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 24 );
                  tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 16 );
                  tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( time_period - 1 ) ) >> 8 );
                  tmp_64_buffer[7] = (unsigned char)( (int64_t)( time_period - 1 ) );

                  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

                  tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 56 );
                  tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 48 );
                  tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 40 );
                  tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 32 );
                  tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 24 );
                  tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 16 );
                  tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 8 );
                  tmp_64_buffer[7] = (unsigned char)( (int64_t)( result_network_consensus.hsdir_interval ) );

                  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

                  wc_Sha3_256_Final( &reusable_sha3, canidate_relay.previous_hash );

                  wc_Sha3_256_Update( &reusable_sha3, (unsigned char*)"node-idx", strlen( "node-idx" ) );
                  wc_Sha3_256_Update( &reusable_sha3, canidate_relay.identity, ID_LENGTH );
                  wc_Sha3_256_Update( &reusable_sha3, result_network_consensus.shared_rand, 32 );

                  tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( time_period ) ) >> 56 );
                  tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( time_period ) ) >> 48 );
                  tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( time_period ) ) >> 40 );
                  tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( time_period ) ) >> 32 );
                  tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( time_period ) ) >> 24 );
                  tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( time_period ) ) >> 16 );
                  tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( time_period ) ) >> 8 );
                  tmp_64_buffer[7] = (unsigned char)( (int64_t)( time_period ) );

                  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

                  tmp_64_buffer[0] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 56 );
                  tmp_64_buffer[1] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 48 );
                  tmp_64_buffer[2] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 40 );
                  tmp_64_buffer[3] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 32 );
                  tmp_64_buffer[4] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 24 );
                  tmp_64_buffer[5] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 16 );
                  tmp_64_buffer[6] = (unsigned char)( ( (int64_t)( result_network_consensus.hsdir_interval ) ) >> 8 );
                  tmp_64_buffer[7] = (unsigned char)( (int64_t)( result_network_consensus.hsdir_interval ) );

                  wc_Sha3_256_Update( &reusable_sha3, tmp_64_buffer, 8 );

                  wc_Sha3_256_Final( &reusable_sha3, canidate_relay.current_hash );
                }

                // if the relay is fast, running, stable and valid then we want to use it
                if ( fast_found == strlen( fast ) && running_found == strlen( running ) && stable_found == strlen( stable ) && valid_found == strlen( valid ) ) {
                  canidate_relay.suitable = 1;
                // otherwise its not suiteable and wee need to free the canidate
                }

                if ( canidate_relay.hsdir || canidate_relay.suitable ) {
                  if ( d_create_relay( &canidate_relay ) < 0 ) {
#ifdef DEBUG_MINITOR
                    ESP_LOGE( MINITOR_TAG, "Failed to create canidate relay in the database" );
#endif

                    return -1;
                  }
                }

                // clean up the associated string matching variables and
                // reset the canidate relay to null
                relay_found = 0;
                identity_length = 0;
                digest_length = 0;
                s_tag_found = 0;
                fast_found = 0;
                running_found = 0;
                stable_found = 0;
                valid_found = 0;
                pr_tag_found = 0;
                hsdir_found = 0;
                relay_element_num = 0;

                canidate_relay.address = 0;
                canidate_relay.or_port = 0;
                canidate_relay.dir_port = 0;
                canidate_relay.hsdir = 0;
                canidate_relay.suitable = 0;
              } else {
                if ( hsdir_found < strlen( hsdir ) ) {
                  if ( hsdir[hsdir_found] == rx_buffer[i] ) {
                    hsdir_found++;
                  } else {
                    hsdir_found = 0;
                  }
                }
              }
            } else if ( rx_buffer[i] == pr_tag[pr_tag_found] ) {
              pr_tag_found++;
            } else {
              pr_tag_found = 0;
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

  wc_Sha3_256_Free( &reusable_sha3 );

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "finished recving" );
#endif

  // BEGIN mutex for the network consensus
  xSemaphoreTake( network_consensus_mutex, portMAX_DELAY );

  network_consensus.method = result_network_consensus.method;
  network_consensus.valid_after = result_network_consensus.valid_after;
  network_consensus.fresh_until = result_network_consensus.fresh_until;
  network_consensus.valid_until = result_network_consensus.valid_until;

  memcpy( network_consensus.previous_shared_rand, result_network_consensus.previous_shared_rand, 32 );
  memcpy( network_consensus.shared_rand, result_network_consensus.shared_rand, 32 );

  xSemaphoreGive( network_consensus_mutex );
  // END mutex for the network consensus

#ifdef DEBUG_MINITOR
  ESP_LOGE( MINITOR_TAG, "finished setting consensus" );
#endif

  // we're done reading data from the directory server, shutdown and close the socket
  shutdown( sock_fd, 0 );
  close( sock_fd );

  // return 0 for no errors
  return 0;
}
