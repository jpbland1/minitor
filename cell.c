// TODO change all functions to use a moving pointer
#include "./cell.h"
#include <stdlib.h>

unsigned char* pack_and_free( Cell* unpacked_cell, unsigned char command ) {
  unsigned char* packed_cell = malloc( sizeof( unsigned char ) * CELL_LEN );

  // TODO pack the cell

  free( unpacked_cell );
  return packed_cell;
}

Cell* unpack_and_free( unsigned char* packed_cell ) {
  int i;
  unsigned char* packed_cell_start = packed_cell;
  Cell* unpacked_cell = malloc( sizeof( Cell ) );

  // get the circ_id out of the packed cell, circ_id is 0th - 3rd byte
  unpacked_cell->circ_id = unpack_four_bytes( &packed_cell );

  // get the command out of the packed cell, 4th byte
  unpacked_cell->command = *packed_cell;
  packed_cell += 1;

  // get the length out of the packed cell, 5th and 6th byte
  // unsigned short:
  // 0x00 0x00
  // unsigned char:
  // 0x00
  unpacked_cell->length = unpack_two_bytes( &packed_cell );

  // assign the payload based on what the command was
  // payloads start at byte 7
  switch ( unpacked_cell->command ) {
    // TODO padding payload is just placeholder, may lower footprint to ignore it
    case PADDING:
      unpacked_cell->payload = malloc( sizeof( PayloadPadding ) );

      break;
    // TODO we shouldn't need to unpack a create cell because we aren't running a relay
    case CREATE:
      break;
    case CREATED:
      unpacked_cell->payload = malloc( sizeof( PayloadCreated ) );
      // create the buffer for the handshake data
      ( (PayloadCreated*) unpacked_cell->payload )->handshake_data = malloc( sizeof( unsigned char ) * TAP_S_HANDSHAKE_LEN );
      // unpack the handshake data into the struct
      unpack_buffer(
        ( (PayloadCreated*) unpacked_cell->payload )->handshake_data,
        TAP_S_HANDSHAKE_LEN,
        &packed_cell
        );

      break;
    // create a relay object from the packed cell
    case RELAY:
      unpacked_cell->payload = malloc( sizeof( PayloadRelay ) );

      // get the relay command out of the packed cell, 7th byte
      ( (PayloadRelay*) unpacked_cell->payload )->command = *packed_cell;
      packed_cell += 1;

      // get the recognized out of the packed cell, 8th and 9th bytes
      ( (PayloadRelay*) unpacked_cell->payload )->recognized = unpack_two_bytes( &packed_cell );

      // get the stream_id out of the packed cell, 10th and 11th bytes
      ( (PayloadRelay*) unpacked_cell->payload )->stream_id = unpack_two_bytes( &packed_cell );

      // get the digest out of the packed cell, 12th - 15th bytes
      ( (PayloadRelay*) unpacked_cell->payload )->digest = unpack_four_bytes( &packed_cell );

      // get the length out of the packed cell, 16th and 17th bytes
      ( (PayloadRelay*) unpacked_cell->payload )->length = unpack_two_bytes( &packed_cell );

      // now we need to unpack the relay_payload, nested operation :(
      // TODO possibly need to decrypt the relay payload before unpacking it
      ( (PayloadRelay*) unpacked_cell->payload )->relay_payload =
        unpack_relay_payload(
          packed_cell,
          ( (PayloadRelay*) unpacked_cell->payload )->command,
          ( (PayloadRelay*) unpacked_cell->payload )->length
        );

      break;
    case DESTROY:
      unpacked_cell->payload = malloc( sizeof( PayloadDestroy ) );
      // unpack the byte with the destroy code
      ( (PayloadDestroy*)unpacked_cell->payload )->destroy_code = *packed_cell;
      packed_cell += 1;

      break;
    case CREATE_FAST:
      unpacked_cell->payload = malloc( sizeof( PayloadCreateFast ) );
      // unpack the key material
      unpack_buffer(
        ( (PayloadCreateFast*)unpacked_cell->payload )->key_material,
        HASH_LEN,
        &packed_cell
        );

      break;
    case CREATED_FAST:
      unpacked_cell->payload = malloc( sizeof( PayloadCreatedFast ) );
      // unpack the key material
      unpack_buffer(
        ( (PayloadCreatedFast*)unpacked_cell->payload )->key_material,
        HASH_LEN,
        &packed_cell
        );
      // unpack the derivative_key_data
      unpack_buffer(
        ( (PayloadCreatedFast*)unpacked_cell->payload )->derivative_key_data,
        HASH_LEN,
        &packed_cell
        );

      break;
    case VERSIONS:
      unpacked_cell->payload = malloc( sizeof( PayloadVersions ) );
      // create the buffer for the versions array
      ( (PayloadVersions*)unpacked_cell->payload )-> versions = malloc( sizeof( unsigned char ) * unpacked_cell->length  );
      // unpack the versions array
      unpack_buffer_short(
        ( (PayloadVersions*)unpacked_cell->payload )-> versions,
        unpacked_cell->length,
        &packed_cell
        );

      break;
    case NETINFO:
      unpacked_cell->payload = malloc( sizeof( PayloadNetInfo ) );
      // get the 4 byte time
      ( (PayloadNetInfo*)unpacked_cell->payload )->time = unpack_four_bytes( &packed_cell );
      // create a buffer for the other address
      ( (PayloadNetInfo*)unpacked_cell->payload )->other_address = malloc( sizeof( Address ) );
      // unpack the other addresses type
      ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address_type = *packed_cell;
      packed_cell += 1;
      // unpack the address length
      ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->length = *packed_cell;
      packed_cell += 1;
      // create a buffer for the address
      ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address = malloc( sizeof( unsigned char ) * ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->length );
      // unpack the actual address
      unpack_buffer(
        ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address,
        ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->length,
        &packed_cell
        );
      ( (PayloadNetInfo*)unpacked_cell->payload )->address_count = *packed_cell;
      packed_cell += 1;
      // create a buffer for the other addresses
      ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses = malloc( sizeof( Address* ) * ( (PayloadNetInfo*)unpacked_cell->payload )->address_count );


      // unpack all of our addresses
      for ( i = 0; i < ( (PayloadNetInfo*)unpacked_cell->payload )->address_count; i++ ) {
        // create a buffer for the address
        ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i] = malloc( sizeof( Address ) );
        // unpack the type
        ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->address_type = *packed_cell;
        packed_cell += 1;
        // unpack the length
        ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->length = *packed_cell;
        packed_cell += 1;
        // create a buffer with the specified length
        ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->address = malloc( sizeof( unsigned char ) * ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->length );
        // unpack the address
        unpack_buffer(
          ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->address,
          ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->length,
          &packed_cell
          );
      }

      break;
    // TODO we shouldn't need to unpack a relay early cell because we aren't running a relay
    case RELAY_EARLY:
      break;
    // TODO we shouldn't need to unpack a create2 cell because we aren't running a relay
    case CREATE2:
      break;
    case CREATED2:
      unpacked_cell->payload = malloc( sizeof( PayloadCreated2 ) );
      // unpack the length of the handshake
      ( (PayloadCreated2*)unpacked_cell->payload )->handshake_length = unpack_two_bytes( &packed_cell );
      // create the buffer for the handshake with the specified length
      ( (PayloadCreated2*)unpacked_cell->payload )->handshake_data = malloc( sizeof( unsigned char ) * ( (PayloadCreated2*)unpacked_cell->payload )->handshake_length );
      // unpack the handshake
      unpack_buffer(
        ( (PayloadCreated2*)unpacked_cell->payload )->handshake_data,
        ( (PayloadCreated2*)unpacked_cell->payload )->handshake_length,
        &packed_cell
        );

      break;
    case PADDING_NEGOTIATE:
      unpacked_cell->payload = malloc( sizeof( PayloadPaddingNegotiate ) );
      // unpack the version
      ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->version = *packed_cell;
      packed_cell += 1;
      // unpack the command
      ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->command = *packed_cell;
      packed_cell += 1;
      ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->timeout_low_ms = unpack_two_bytes( &packed_cell );
      ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->timeout_high_ms = unpack_two_bytes( &packed_cell );

      break;
    // TODO v padding payload is just placeholder, may lower footprint to ignore it
    case VPADDING:
      unpacked_cell->payload = malloc( sizeof( PayloadVpadding ) );

      break;
    case CERTS:
      unpacked_cell->payload = malloc( sizeof( PayloadCerts ) );
      // unpack the cert count
      ( (PayloadCerts*)unpacked_cell->payload )->cert_count = *packed_cell;
      packed_cell += 1;
      // create buffer for certs array
      ( (PayloadCerts*)unpacked_cell->payload )->certs = malloc( sizeof( Cert* ) * ( (PayloadCerts*)unpacked_cell->payload )->cert_count );

      // unpack all the certs
      for ( i = 0; i < ( (PayloadCerts*)unpacked_cell->payload )->cert_count; i++ ) {
        // create a buffer to hold the cert
        ( (PayloadCerts*)unpacked_cell->payload )->certs[i] = malloc( sizeof( Cert ) );
        // unpack the cert type
        ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_type = *packed_cell;
        packed_cell += 1;
        // unpack the cert length
        ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_length = unpack_two_bytes( &packed_cell );
        // create a buffer for the cert with appropriate length
        ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert = malloc( sizeof( unsigned char ) * ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_length );
        // unpack the cert
        unpack_buffer(
          ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert,
          ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_length,
          &packed_cell
          );
      }

      break;
    case AUTH_CHALLENGE:
      unpacked_cell->payload = malloc( sizeof( PayloadAuthChallenge ) );
      // unpack the challenge, its size is static so we don't need to malloc it
      unpack_buffer(
        ( (PayloadAuthChallenge*)unpacked_cell->payload )->challenge,
        32,
        &packed_cell
        );
      // unpack the number of methods
      ( (PayloadAuthChallenge*)unpacked_cell->payload )->n_methods = unpack_two_bytes( &packed_cell );
      // create a buffer of the appropriate length to hold the methods accepted by the responder
      ( (PayloadAuthChallenge*)unpacked_cell->payload )->methods = malloc( sizeof( unsigned short ) * ( (PayloadAuthChallenge*)unpacked_cell->payload )->n_methods );
      // unpack the methods
      unpack_buffer_short(
        ( (PayloadAuthChallenge*)unpacked_cell->payload )->methods,
        ( (PayloadAuthChallenge*)unpacked_cell->payload )->n_methods * 2,
        &packed_cell
        );

      break;
    // TODO we shouldn't need to unpack a authenticate cell because we aren't running a relay
    case AUTHENTICATE:
      break;
    // TODO cell type reserved but not implemented
    case AUTHORIZE:
      break;
    default:
      break;
  }

  free( packed_cell_start );
  return unpacked_cell;
}

void* unpack_relay_payload( unsigned char* packed_cell, unsigned char command, unsigned short payload_length ) {
  int i;
  void* result;
  unsigned char* packed_cell_relay_end = packed_cell + payload_length;

  // unpack the correct relay struct based on the command
  // relay payloads start at byte 17
  switch( command ) {
    // TODO we shouldn't need to unpack a relay begin because this isn't a router
    case RELAY_BEGIN:
      break;
    case RELAY_DATA:
      result = malloc( sizeof( RelayPayloadData ) );
      ( (RelayPayloadData*)result )->payload = malloc( sizeof( unsigned char ) * ( payload_length ) );
      unpack_buffer(
        ( (RelayPayloadData*)result )->payload,
        payload_length,
        &packed_cell
        );

      break;
    case RELAY_END:
      // get the reason the relay end cell was sent
      result = malloc( sizeof( RelayPayloadEnd ) );
      ( (RelayPayloadEnd*)result )->reason = *packed_cell;
      packed_cell += 1;

      break;
    case RELAY_CONNECTED:
      result = malloc( sizeof( RelayPayloadConnected ) );

      // check if we have an IPv4 connected or IPv6
      // IPv6 will have 4 zero bytes and a 6 at the start of the payload
      if (
        *packed_cell == 0 &&
        *( packed_cell + 1 ) == 0 &&
        *( packed_cell + 2 ) == 0 &&
        *( packed_cell + 3 ) == 0 &&
        *( packed_cell + 4 ) == 6
      ) {
        // make the address 16 chars to hold the IPv6 address
        ( (RelayPayloadConnected*)result )->address = malloc( sizeof( unsigned char ) * 16 );
        // unpack the contents of the address
        unpack_buffer(
          ( (RelayPayloadConnected*)result )->address,
          16,
          &packed_cell
          );
        // set the time to live and address_type so its obvious to
        // anyone using the structure what kind of address it is
        ( (RelayPayloadConnected*)result )->time_to_live = unpack_four_bytes( &packed_cell );
        ( (RelayPayloadConnected*)result )->address_type = IPv6;
      // otherwise we're dealing with an IPv4 address
      } else {
        // make the address 4 chars the hold the IPv4 address
        ( (RelayPayloadConnected*)result )->address = malloc( sizeof( unsigned char ) * 4 );

        // unpack the contents of the address
        unpack_buffer(
          ( (RelayPayloadConnected*)result )->address,
          4,
          &packed_cell
          );

        // set the time to live and address type
        ( (RelayPayloadConnected*)result )->time_to_live = unpack_four_bytes( &packed_cell );
        ( (RelayPayloadConnected*)result )->address_type = IPv4;
      }

      break;
    case RELAY_SENDME:
      result = malloc( sizeof( RelayPayloadSendMe ) );
      // unpack the version
      ( (RelayPayloadSendMe*)result )->version = *packed_cell;
      packed_cell += 1;
      // unpack the data length
      ( (RelayPayloadSendMe*)result )->data_length = unpack_two_bytes( &packed_cell );
      // create the data buffer
      ( (RelayPayloadSendMe*)result )->data = malloc( sizeof( unsigned char ) * ( (RelayPayloadSendMe*)result )->data_length );
      // unpack the data buffer into the struct
      unpack_buffer(
        ( (RelayPayloadSendMe*)result )->data,
        ( (RelayPayloadSendMe*)result )->data_length,
        &packed_cell
        );

      break;
    // TODO we shouldn't need to unpack a relay extend because this isn't a router
    case RELAY_EXTEND:
      break;
    case RELAY_EXTENDED:
      result = malloc( sizeof( PayloadCreated ) );
      // create the buffer for the handshake data
      ( (PayloadCreated*)result )->handshake_data = malloc( sizeof( unsigned char ) * TAP_S_HANDSHAKE_LEN );
      // unpack the handshake data into the buffer
      unpack_buffer(
        ( (PayloadCreated*)result )->handshake_data,
        TAP_S_HANDSHAKE_LEN,
        &packed_cell
        );

      break;
    // TODO we shouldn't need to unpack a relay truncate because this isn't a router
    case RELAY_TRUNCATE:
      break;
    case RELAY_TRUNCATED:
      result = malloc( sizeof( PayloadDestroy ) );
      // unpack the destroycode into the struct
      ( (PayloadDestroy*)result )->destroy_code = *packed_cell;
      packed_cell += 1;

      break;
      // long range dummy, cell is dropped
    case RELAY_DROP:
      break;
    // TODO we shouldn't need to unpack a relay resolve because this isn't a router
    case RELAY_RESOLVE:
      break;
    case RELAY_RESOLVED:
      result = malloc( sizeof( RelayPayloadResolved ) );
      // unpack the type of address
      ( (RelayPayloadResolved*)result )->type = *packed_cell;
      packed_cell += 1;
      // unpack the length of the value
      ( (RelayPayloadResolved*)result )->length = *packed_cell;
      packed_cell += 1;
      // create a buffer for the value
      ( (RelayPayloadResolved*)result )->value = malloc( sizeof( unsigned char ) * ( (RelayPayloadResolved*)result )->length );
      // unpack the value buffer into the struct
      unpack_buffer(
        ( (RelayPayloadResolved*)result )->value,
        ( (RelayPayloadResolved*)result )->length,
        &packed_cell
        );
      // unpack the time to live
      ( (RelayPayloadResolved*)result )->time_to_live = unpack_four_bytes( &packed_cell );

      break;
    // TODO we shouldn't need to unpack a relay begin dir because this isn't a router
    case RELAY_BEGIN_DIR:
      break;
    // TODO we shouldn't need to unpack a relay extend2 because this isn't a router
    case RELAY_EXTEND2:
      break;
    case RELAY_EXTENDED2:
      result = malloc( sizeof( PayloadCreated2 ) );
      // unpack the handshake length into the struct
      ( (PayloadCreated2*)result )->handshake_length = unpack_two_bytes( &packed_cell );
      // create buffer for the handshake data
      ( (PayloadCreated2*)result )->handshake_data = malloc( sizeof( unsigned char ) * ( (PayloadCreated2*)result )->handshake_length );
      // unpack the handshake data buffer into the struct
      unpack_buffer(
        ( (PayloadCreated2*)result )->handshake_data,
        ( (PayloadCreated2*)result )->handshake_length,
        &packed_cell
        );

      break;
    // TODO we shouldn't need to unpack a relay establish intro because this isn't an introduction point
    case RELAY_COMMAND_ESTABLISH_INTRO:
      break;
    // TODO we shouldn't need to unpack a relay establish intro because this isn't an rendezvous point
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      break;
    // TODO we shouldn't need to unpack a relay establish intro because this isn't an introduction point
    case RELAY_COMMAND_INTRODUCE1:
      break;
    case RELAY_COMMAND_INTRODUCE2:
      // introduce 1 and 2 both use the same struct
      result = malloc( sizeof( RelayPayloadIntroduce1 ) );
      // unpack the legacy_key_id into the struct
      unpack_buffer(
        ( (RelayPayloadIntroduce1*)result )->legacy_key_id,
        20,
        &packed_cell
        );
      // unpack the auth key type into the struct
      ( (RelayPayloadIntroduce1*)result )->auth_key_type = *packed_cell;
      packed_cell += 1;
      // unpack the auth_key_length
      ( (RelayPayloadIntroduce1*)result )->auth_key_length = unpack_two_bytes( &packed_cell );
      // create a buffer for the auth key
      ( (RelayPayloadIntroduce1*)result )->auth_key = malloc( sizeof( unsigned char ) * ( (RelayPayloadIntroduce1*)result )->auth_key_length );
      // copy the auth key from the packed cell to the auth key buffer
      unpack_buffer(
        ( (RelayPayloadIntroduce1*)result )->auth_key,
        ( (RelayPayloadIntroduce1*)result )->auth_key_length,
        &packed_cell
        );
      // unpack the extensions count
      ( (RelayPayloadIntroduce1*)result )->extension_count = *packed_cell;
      packed_cell += 1;
      // create a buffer of buffers for the extensions
      ( (RelayPayloadIntroduce1*)result )->extensions = malloc( sizeof( IntroExtension* ) * ( (RelayPayloadIntroduce1*)result )->extension_count );
      // set the packed cell pointer to the current position since from here on we can't keep proper track of our position

      for ( i = 0; i < ( (RelayPayloadIntroduce1*)result )->extension_count; i++ ) {
        // create a buffer for each extension
        ( (RelayPayloadIntroduce1*)result )->extensions[i] = malloc( sizeof( IntroExtension ) );
        // read the type and increment the pointer
        ( (RelayPayloadIntroduce1*)result )->extensions[i]->type = *packed_cell;
        packed_cell += 1;
        // read the length and increment
        ( (RelayPayloadIntroduce1*)result )->extensions[i]->length = *packed_cell;
        packed_cell += 1;

        // check which type of extension we're dealing with
        switch( ( (RelayPayloadIntroduce1*)result )->extensions[i]->type ) {
          case Ed25519:
            // create a buffer for the extension
            ( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field = malloc( sizeof( IntroExtensionFieldEd25519 ) );
            // unpack the the nonce and move the buffer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->nonce,
              16,
              &packed_cell
              );
            // unpack the pubkey and move the pointer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->pubkey,
              32,
              &packed_cell
              );
            // unpack the signature and move the pointer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->signature,
              64,
              &packed_cell
              );
            
            break;
        }

        // TODO check if pointer arithmatic actually returns the difference
        // create buffer to hold the encrypted data
        ( (RelayPayloadIntroduce1*)result )->encrypted = malloc( sizeof( unsigned char ) * ( packed_cell_relay_end - packed_cell ) );
        // unpack the encryped data into the buffer
        unpack_buffer(
          ( (RelayPayloadIntroduce1*)result )->encrypted,
          packed_cell_relay_end - packed_cell,
          &packed_cell
          );
      }

      break;
    // TODO we shouldn't need to unpack a relay rendezvous 1 because this isn't an introduction point
    case RELAY_COMMAND_RENDEZVOUS1:
      break;
    // TODO we shouldn't need to unpack a relay rendezvous 2 because this isn't a client
    case RELAY_COMMAND_RENDEZVOUS2:
      break;
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      result = malloc( sizeof( RelayPayloadIntroEstablished ) );
      // unpack the extension count and increment pointer
      ( (RelayPayloadIntroEstablished*)result )->extension_count = *packed_cell;
      packed_cell += 1;
      // create a buffer for the extensions
      ( (RelayPayloadIntroEstablished*)result )->extensions = malloc( sizeof( IntroExtension* ) * ( (RelayPayloadIntroEstablished*)result )->extension_count );

      for ( i = 0; i < ( (RelayPayloadIntroEstablished*)result )->extension_count; i++ ) {
        // create a buffer for the extension
        ( (RelayPayloadIntroEstablished*)result )->extensions[i] = malloc( sizeof( IntroExtension ) );
        // unpack the type and increment pointer
        ( (RelayPayloadIntroEstablished*)result )->extensions[i]->type = *packed_cell;
        packed_cell += 1;
        ( (RelayPayloadIntroEstablished*)result )->extensions[i]->length = *packed_cell;
        packed_cell += 1;

        // check which type of extension we're dealing with
        switch( ( (RelayPayloadIntroduce1*)result )->extensions[i]->type ) {
          case Ed25519:
            // create a buffer for the extension
            ( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field = malloc( sizeof( IntroExtensionFieldEd25519 ) );
            // unpack the the nonce and move the buffer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->nonce,
              16,
              &packed_cell
              );
            // unpack the pubkey and move the pointer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->pubkey,
              32,
              &packed_cell
              );
            // unpack the signature and move the pointer
            unpack_buffer( 
              ( (IntroExtensionFieldEd25519*)( (RelayPayloadIntroduce1*)result )->extensions[i]->intro_extension_field )->signature,
              64,
              &packed_cell
              );
            
            break;
        }
      }

      break;
    // TODO we shouldn't need to unpack a relay rendezvous established because this isn't a client
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      break;
    // TODO we shouldn't need to unpack a relay introduce acknowledgement because this isn't a client
    case RELAY_COMMAND_INTRODUCE_ACK:
      break;
  }

  return result;
}

// take four bytes out of the byte array and turn it into an unsigned int
unsigned int unpack_four_bytes( unsigned char** packed_cell ) {
  // unsigned int:
  // 0x00 0x00 0x00 0x00
  // unsigned char:
  // 0x00
  // ints are big endian so we need to move the first byte up 3 positions and so on
  unsigned int result = ( (unsigned int) **packed_cell ) << 24;
  *packed_cell += 1;
  result |= ( (unsigned int) **packed_cell ) << 16;
  *packed_cell += 1;
  result |= ( (unsigned int) **packed_cell ) << 8;
  *packed_cell += 1;
  result |= (unsigned int) **packed_cell;
  *packed_cell += 1;

  return result;
}

// take two bytes out of the byte array and turn it into an unsigned short
unsigned short unpack_two_bytes( unsigned char** packed_cell ) {
  // unsigned short:
  // 0x00 0x00
  // unsigned char:
  // 0x00
  // shorts are small endian so need to move the first byte up one position and the second can just be ored
  unsigned short result = ( (unsigned short) **packed_cell ) << 8;
  *packed_cell += 1;
  result |= (unsigned int) **packed_cell;
  *packed_cell += 1;

  return result;
}

// copy the contents of the packed cell into the target buffer
void unpack_buffer( unsigned char* buffer, int length, unsigned char** packed_cell ) {
  int i;

  // loop over the length of the target buffer and put the bytes
  // from start to start + length into the target buffer
  for ( i = 0; i < length; i++ ) {
    buffer[i] = **packed_cell;
    *packed_cell += 1;
  }
}

// copy the contents of the packed cell into the target buffer of unsigned short type
// the length is the length in chars, not length in shorts
void unpack_buffer_short( unsigned short* buffer, int length, unsigned char** packed_cell ) {
  int i;

  // loop over the length of the target buffer and put the bytes, two at a time
  // from start to start + length into the target buffer
  for ( i = 0; i < length / 2; i++ ) {
    buffer[i] = unpack_two_bytes( packed_cell );
  }
}
