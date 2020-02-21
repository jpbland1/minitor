#include <stdlib.h>
#include "./cell.h"

//
// PACK CELL
//
unsigned char* pack_and_free( Cell* unpacked_cell ) {
  int i;
  // create a buffer for the packed cell
  unsigned char* packed_cell;
  unsigned char* packed_cell_start;

  if ( unpacked_cell->command == VERSIONS || unpacked_cell->command >= VPADDING ) {
    // TODO cells must calculate their length before we get to this point
    // its easier to  keep track of the length as the cell is constructed
    // than to calculate it at the end
    packed_cell = malloc( sizeof( unsigned char ) * ( CIRCID_LEN + 3 + unpacked_cell->length ) );
  } else {
    packed_cell = malloc( sizeof( unsigned char ) * CELL_LEN );
  }

  // mark the start so we can return it
  packed_cell_start = packed_cell;
  // pack the circ_id
  pack_four_bytes( &packed_cell, unpacked_cell->circ_id );
  // pack the command
  *packed_cell = unpacked_cell->command;
  packed_cell += 1;


  // if the cell is veriable length, pack the length
  if ( unpacked_cell->command == VERSIONS || unpacked_cell->command >= VPADDING ) {
    pack_two_bytes( &packed_cell, unpacked_cell->length );
  }

  switch( unpacked_cell->command ) {
    // TODO may not need to do anything here
    case PADDING:
      break;
    case CREATE:
      // pack the handshake tag
      pack_buffer(
        &packed_cell,
        ( unsigned char* )( (PayloadCreate*)unpacked_cell->payload )->handshake_tag,
        16
        );
      // pack the handshake data
      pack_buffer(
        &packed_cell,
        ( unsigned char* )( (PayloadCreate*)unpacked_cell->payload )->handshake_data,
        TAP_C_HANDSHAKE_LEN - 16
        );

      break;
    // TODO we shouldn't need to pack a created cell since this isn't a relay
    case CREATED:
      break;
    case RELAY_EARLY:
    case RELAY:
      // pack the relay command
      *packed_cell = ( (PayloadRelay*)unpacked_cell->payload )->command;
      packed_cell += 1;
      // pack the recognized value
      pack_two_bytes( &packed_cell, ( (PayloadRelay*)unpacked_cell->payload )->recognized );
      // pack the stream id
      pack_two_bytes( &packed_cell, ( (PayloadRelay*)unpacked_cell->payload )->stream_id );
      // pack the digest
      pack_four_bytes( &packed_cell, ( (PayloadRelay*)unpacked_cell->payload )->digest );
      // pack the length
      pack_two_bytes( &packed_cell, ( (PayloadRelay*)unpacked_cell->payload )->length );
      // pack relay payload
      pack_relay_payload(
        &packed_cell,
        unpacked_cell->payload,
        ( (PayloadRelay*)unpacked_cell->payload )->command,
        ( (PayloadRelay*)unpacked_cell->payload )->length
        );
      // TODO may need to encrypt after packing relay payload

      break;
    case DESTROY:
      // pack the destroy code
      *packed_cell = ( (PayloadDestroy*)unpacked_cell->payload )->destroy_code;
      packed_cell += 1;

      break;
    case CREATE_FAST:
      // pack the key material
      pack_buffer(
        &packed_cell,
        ( (PayloadCreateFast*)unpacked_cell->payload )->key_material,
        HASH_LEN
        );

      break;
    // TODO we shouldn't need to pack a created fast cell since we're not running a relay
    case CREATED_FAST:
      break;
    case VERSIONS:
      // pack the versions
      pack_buffer_short(
        &packed_cell,
        ( (PayloadVersions*)unpacked_cell->payload )->versions,
        unpacked_cell->length
        );

      break;
    case NETINFO:
      // pack the time
      pack_four_bytes( &packed_cell, ( (PayloadNetInfo*)unpacked_cell->payload )->time );
      // pack the other address type
      *packed_cell = ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address_type;
      packed_cell += 1;
      // pack the address length
      *packed_cell = ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->length;
      packed_cell += 1;
      // pack the address with the appropriate length
      pack_buffer(
        &packed_cell,
        ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address,
        ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->length
        );
      // pack the address count
      *packed_cell = ( (PayloadNetInfo*)unpacked_cell->payload )->address_count;
      packed_cell += 1;

      // pack each address into the cell
      for ( i = 0; i < ( (PayloadNetInfo*)unpacked_cell->payload )->address_count; i++ ) {
        // pack the address type
        *packed_cell = ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->address_type;
        packed_cell += 1;
        // pack the address length
        *packed_cell = ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->length;
        packed_cell += 1;
        // pack the address with the appropriate length
        pack_buffer(
          &packed_cell,
          ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->address,
          ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[i]->length
          );
      }

      break;
    case CREATE2:
      // pack the handshake type
      pack_two_bytes(
        &packed_cell,
        ( (PayloadCreate2*)unpacked_cell->payload )->handshake_type
        );
      // pack the handshake length
      pack_two_bytes(
        &packed_cell,
        ( (PayloadCreate2*)unpacked_cell->payload )->handshake_length
        );
      // pack the handshake data
      pack_buffer(
        &packed_cell,
        ( (PayloadCreate2*)unpacked_cell->payload )->handshake_data,
        ( (PayloadCreate2*)unpacked_cell->payload )->handshake_length
        );

      break;
    // TODO we shouldn't need to pack a created 2 since we're not running a relay
    case CREATED2:
      break;
    case PADDING_NEGOTIATE:
      // pack the version
      *packed_cell = ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->version;
      packed_cell += 1;
      // pack the command
      *packed_cell = ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->command;
      packed_cell += 1;
      // pack the timeout lower limit
      pack_two_bytes(
        &packed_cell,
        ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->timeout_low_ms
        );
      // pack the timeout upper limit
      pack_two_bytes(
        &packed_cell,
        ( (PayloadPaddingNegotiate*)unpacked_cell->payload )->timeout_high_ms
        );

      break;
    case VPADDING:
      // fill the payload to length with nul bytes
      for ( i = 0; i < unpacked_cell->length; i++ ) {
        *packed_cell = 0;
        packed_cell += 1;
      }

      break;
    case CERTS:
      // pack the cert_count
      *packed_cell = ( (PayloadCerts*)unpacked_cell->payload )->cert_count;
      packed_cell += 1;

      // pack each certificate into the cell
      for ( i = 0; i < ( (PayloadCerts*)unpacked_cell->payload )->cert_count; i++ ) {
        // pack the cert type
        *packed_cell = ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_type;
        packed_cell += 1;
        // pack the cert length
        pack_two_bytes(
          &packed_cell,
          ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_length
          );
        // pack the cert
        pack_buffer(
          &packed_cell,
          ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert,
          ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert_length
          );
      }

      break;
    // TODO we shouldn't need to pack an auth challenge since we're not running a relay
    case AUTH_CHALLENGE:
      break;
    case AUTHENTICATE:
      // pack the auth type
      pack_two_bytes(
        &packed_cell,
        ( (PayloadAuthenticate*)unpacked_cell->payload )->auth_type
        );
      // pack the auth length
      pack_two_bytes(
        &packed_cell,
        ( (PayloadAuthenticate*)unpacked_cell->payload )->auth_length
        );
      // pack the authentication buffer with the correct length
      pack_buffer(
        &packed_cell,
        ( (PayloadAuthenticate*)unpacked_cell->payload )->authentication,
        ( (PayloadAuthenticate*)unpacked_cell->payload )->auth_length
        );

      break;
    // TODO reserved for later use
    case AUTHORIZE:
      break;
  }

  // if we arent dealing with a variable length cell, padd the cell to the length
  // TODO  make sure pointer math works this way
  if ( unpacked_cell->command != VERSIONS && unpacked_cell->command < VPADDING ) {
    // relay and relay early cells need random padding
    if ( unpacked_cell->command == RELAY || unpacked_cell->command == RELAY_EARLY ) {
      while ( ( packed_cell - packed_cell_start ) > CELL_LEN ) {
        *packed_cell = (unsigned char)rand();
        packed_cell += 1;
      }
    } else {
      while ( ( packed_cell - packed_cell_start ) > CELL_LEN ) {
        *packed_cell = (unsigned char)0;
        packed_cell += 1;
      }
    }
  }

  free_cell( unpacked_cell );
  return packed_cell_start;
}

// TODO pack the relay payload
void pack_relay_payload( unsigned char** packed_cell, void* payload, unsigned char command, unsigned short payload_length ) {
  int i;

  switch( command ) {
    case RELAY_BEGIN:
      i = 0;

      // TODO possibly better to preprocess this so its easier to deal with
      // pack all of the characters from address and port into the cell
      while ( ( (RelayPayloadBegin*)payload )->address_and_port[i] != '\0' ) {
        **packed_cell = (unsigned char)( (RelayPayloadBegin*)payload )->address_and_port[i];
        *packed_cell += 1;
        i += 1;
      }

      // TODO I'm pretty sure this works and our pointer position will be valid but make sure
      // pack the flags
      pack_four_bytes(
        packed_cell,
        ( (RelayPayloadBegin*)payload )->flags
        );

      break;
    case RELAY_DATA:
      // pack the buffer
      pack_buffer(
        packed_cell,
        ( (RelayPayloadData*)payload )->payload,
        payload_length
        );

      break;
    case RELAY_END:
      // pack the reason into the cell
      **packed_cell = ( (RelayPayloadEnd*)payload )->reason;
      *packed_cell += 1;

      break;
    // TODO we shouldn't need to pack a relay connected cell since we're not running a relay
    case RELAY_CONNECTED:
      break;
    case RELAY_SENDME:
      // pack the version into the cell
      **packed_cell = ( (RelayPayloadSendMe*)payload )->version,
      *packed_cell += 1;
      // pack the length into the cell
      pack_two_bytes( packed_cell, ( (RelayPayloadSendMe*)payload )->data_length );
      // TODO might be a good idea to leave the data empty for
      // versions without authentication and load zeros here instead,
      // might save on memory
      //
      // pack the data into the cell
      pack_buffer(
        packed_cell,
        ( (RelayPayloadSendMe*)payload )->data,
        ( (RelayPayloadSendMe*)payload )->data_length
        );

      break;
    case RELAY_EXTEND:
      // pack the addresss in the cell
      pack_four_bytes(
        packed_cell,
        ( (RelayPayloadExtend*)payload )->address
        );
      // pack the port number into the payload
      pack_two_bytes(
        packed_cell,
        ( (RelayPayloadExtend*)payload )->port
        );
      // pack the onion skin
      pack_buffer(
        packed_cell,
        ( (RelayPayloadExtend*)payload )->onion_skin,
        TAP_C_HANDSHAKE_LEN
        );
      // pack the identity fingerprint
      pack_buffer(
        packed_cell,
        ( (RelayPayloadExtend*)payload )->identity_fingerprint,
        HASH_LEN
        );

      break;
    // TODO we shouldn't need to pack a relay extended cell since we're not running a relay
    case RELAY_EXTENDED:
      break;
    // relay truncate doesn't have a body its just a straight command
    case RELAY_TRUNCATE:
      break;
    // TODO we shouldn't need to pack a relay truncated cell since we're not running a relay
    case RELAY_TRUNCATED:
      break;
    // relay drop doesn't have a body the cell will just be dropped
    case RELAY_DROP:
      break;
    case RELAY_RESOLVE:
      i = 0;

      // until we hit a nul terminator, pack the hostname into the cell
      // one byte at a time
      while ( ( (RelayPayloadResolve*)payload )->hostname[i] != '\0' ) {
        **packed_cell = (unsigned char)( (RelayPayloadResolve*)payload )->hostname[i];
        *packed_cell += 1;
        i += 1;
      }

      break;
    // TODO we shouldn't need to pack a relay resolved cell since we're not running a relay
    case RELAY_RESOLVED:
      break;
    // cell is all zeros, nothing to pack
    case RELAY_BEGIN_DIR:
      break;
    case RELAY_EXTEND2:
      // pack the specifier count
      **packed_cell = ( (RelayPayloadExtend2*)payload )->specifier_count;
      *packed_cell += 1;

      // pack each link_specifier
      for ( i = 0; i < ( (RelayPayloadExtend2*)payload )->specifier_count; i++ ) {
        // pack the specifier type
        **packed_cell = ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->type;
        *packed_cell += 1;
        // pack the specifier length
        **packed_cell = ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->length;
        *packed_cell += 1;
        // pack the specifier to the correct length
        pack_buffer(
          packed_cell,
          ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->specifier,
          ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->length
          );
      }

      // pack the handshake type
      pack_two_bytes( packed_cell, ( (RelayPayloadExtend2*)payload )->handshake_type );
      // pack the handshake length
      pack_two_bytes( packed_cell, ( (RelayPayloadExtend2*)payload )->handshake_length );
      // pack the handshake data to the appropriate length
      pack_buffer(
        packed_cell,
        ( (RelayPayloadExtend2*)payload )->handshake_data,
        ( (RelayPayloadExtend2*)payload )->handshake_length
        );


      break;
    // TODO we shouldn't need to pack a relay extended 2 cell since we're not running a relay
    case RELAY_EXTENDED2:
      break;
    case RELAY_COMMAND_ESTABLISH_INTRO:
      // figure out what kind of establish intro we're dealing with
      if ( ( (RelayPayloadEstablishIntro*)payload )->type == ESTABLISH_INTRO_LEGACY ) {
        // pack the key_length
        pack_two_bytes(
            packed_cell,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->key_length
          );
        // pack the key to the appropriate length
        pack_buffer(
          packed_cell,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->key,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->key_length
          );
        // pack the handshake_auth
        pack_buffer(
          packed_cell,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->handshake_auth,
          20
          );
        // pack the signature
        pack_buffer(
            packed_cell,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature,
          ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature_length
          );
      } else {
        // pack the auth key type
        **packed_cell = ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->auth_key_type;
        *packed_cell += 1;
        // pack the auth_key_length
        pack_two_bytes(
            packed_cell,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->auth_key_length
          );
        // pack the auth key to the appropriate length
        pack_buffer(
          packed_cell,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->auth_key,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->auth_key_length
          );
        // pack the extension count
        **packed_cell = ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extension_count;
        *packed_cell += 1;

        // pack each extension
        for ( i = 0; i < ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extension_count; i++ ) {
          // pack the extension type
          **packed_cell = ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->type;
          *packed_cell += 1;
          // pack the extension length
          **packed_cell = ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->length;
          *packed_cell += 1;

          switch ( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->type ) {
            case Ed25519:
              // pack the nonce to length 16
              pack_buffer(
                packed_cell,
                ( (IntroExtensionFieldEd25519*)( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->intro_extension_field )->nonce,
                16
                );
              // pack the pubkey to length 32
              pack_buffer(
                packed_cell,
                ( (IntroExtensionFieldEd25519*)( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->intro_extension_field )->pubkey,
                32
                );
              // pack the signature to length 64
              pack_buffer(
                packed_cell,
                ( (IntroExtensionFieldEd25519*)( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->intro_extension_field )->signature,
                64
                );

              break;
          }
        }

        // pack the handshake auth into the cell
        pack_buffer(
          packed_cell,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->handshake_auth,
          MAC_LEN
          );
        // pack the signature length
        pack_two_bytes( packed_cell, ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature_length );
        // pack the signature
        pack_buffer(
          packed_cell,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature,
          ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature_length
          );
      }

      break;
    // TODO we shouldn't need to pack an establish rendezvous since we're not running a client
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      break;
    // TODO we shouldn't need to pack an introduce 1 since we're not running a client
    case RELAY_COMMAND_INTRODUCE1:
      break;
    // TODO we shouldn't need to pack an introduce 2 since we're not running a relay
    case RELAY_COMMAND_INTRODUCE2:
      break;
    case RELAY_COMMAND_RENDEZVOUS1:
      // pack the rend cookie to length 20
      pack_buffer(
        packed_cell,
        ( (RelayPayloadCommandRendezvous1*)payload )->rendezvous_cookie,
        20
        );
      // pack the handshake info
      pack_buffer(
        packed_cell,
        ( (RelayPayloadCommandRendezvous1*)payload )->handshake_info->public_key,
        PK_PUBKEY_LEN
        );
      // pack the auth
      pack_buffer(
        packed_cell,
        ( (RelayPayloadCommandRendezvous1*)payload )->handshake_info->auth,
        MAC_LEN
        );

      break;
    // TODO we shouldn't need to pack a rendezvous 2 since we're not running a relay
    case RELAY_COMMAND_RENDEZVOUS2:
      break;
    // TODO we shouldn't need to pack an intro established since we're not running a relay
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      break;
    // TODO we shouldn't need to pack a rendezvous established since we're not running a relay
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      break;
    // TODO we shouldn't need to pack a rendezvous established since we're not running a relay
    case RELAY_COMMAND_INTRODUCE_ACK:
      break;
  }
}

// TODO verify this works on the risc-v chip
// put each char of the integer into the buffer
void pack_four_bytes( unsigned char** packed_cell, unsigned int value ) {
  **packed_cell = (unsigned char)( value >> 24 );
  *packed_cell += 1;
  **packed_cell = (unsigned char)( value >> 16 );
  *packed_cell += 1;
  **packed_cell = (unsigned char)( value >> 8 );
  *packed_cell += 1;
  **packed_cell = (unsigned char)value;
  *packed_cell += 1;
}

// put each char of the short into the buffer
void pack_two_bytes( unsigned char** packed_cell, unsigned short value ) {
  **packed_cell = (unsigned char)( value >> 8 );
  *packed_cell += 1;
  **packed_cell = (unsigned char)value;
  *packed_cell += 1;
}

// put chars from the buffer into the packed cell
void pack_buffer( unsigned char** packed_cell, unsigned char* buffer, int length ) {
  int i;

  for ( i = 0; i < length; i++ ) {
    **packed_cell = buffer[i];
    *packed_cell += 1;
  }
}

// put shorts from the buffer into the packed cell
// the length is the length in chars, not the length in shorts
void pack_buffer_short( unsigned char** packed_cell, unsigned short* buffer, int length ) {
  int i;

  for ( i = 0; i < length / 2; i++ ) {
    pack_two_bytes( packed_cell, buffer[i] );
  }
}

//
// UNPACK CELL
//
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
  if ( unpacked_cell->command == 7 || unpacked_cell->command >= 128 ) {
    unpacked_cell->length = unpack_two_bytes( &packed_cell );
  } else {
    unpacked_cell->length = 0;
  }

  // assign the payload based on what the command was
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
    // TODO we shouldn't need to unpack create fast since we're not running a relay
    case CREATE_FAST:
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
        // set the address type
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
        // set the address type
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
    // TODO figure out the correct thing to do with the encrypted buffer
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

// TODO verify this works on the risc-v chip
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

//
// FREE CELL
//

void free_cell( Cell* unpacked_cell ) {
  int i;

  switch( unpacked_cell->command ) {
    // nothing to do, no malloc pointers
    case PADDING:
      break;
    case CREATE:
      // free the handshake data buffer
      free( ( (PayloadCreate*)unpacked_cell->payload )->handshake_data );

      break;
    case CREATED:
      // free the handshake data buffer
      free( ( (PayloadCreated*)unpacked_cell->payload )->handshake_data );

      break;
    case RELAY:
      // free the relay payload
      free_relay_payload( ( (PayloadRelay*)unpacked_cell->payload )->relay_payload, ( (PayloadRelay*)unpacked_cell->payload )->command );

      break;
    // nothing to do, no malloc pointers
    case DESTROY:
      break;
    // nothing to do, no malloc pointers
    case CREATE_FAST:
      break;
    // nothing to do, no malloc pointers
    case CREATED_FAST:
      break;
    case VERSIONS:
      // free the versions buffer
      free( ( (PayloadVersions*)unpacked_cell->payload )->versions );

      break;
    case NETINFO:
      // free the other addresses' buffer
      free( ( (PayloadNetInfo*)unpacked_cell->payload )->other_address->address );
      // free the other address struct
      free( ( (PayloadNetInfo*)unpacked_cell->payload )->other_address );

      // go through all of my addresses
      for ( i = 0; i < ( (PayloadNetInfo*)unpacked_cell->payload )->address_count; i++ ) {
        // free the address buffer
        free( ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[0]->address );
        // free the address struct
        free( ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses[0] );
      }

      // free the array of structs
      free( ( (PayloadNetInfo*)unpacked_cell->payload )->my_addresses );

      break;
    // nothing to do, no malloc pointers
    case RELAY_EARLY:
      break;
    case CREATE2:
      // free the handshake data
      free ( ( (PayloadCreate2*)unpacked_cell->payload )->handshake_data );

      break;
    case CREATED2:
      // free the handshake data
      free ( ( (PayloadCreated2*)unpacked_cell->payload )->handshake_data );

      break;
    // nothing to do, no malloc pointers
    case PADDING_NEGOTIATE:
      break;
    // nothing to do, no malloc pointers
    case VPADDING:
      break;
    case CERTS:
      // go through each cert
      for ( i = 0; i < ( (PayloadCerts*)unpacked_cell->payload )->cert_count; i++ ) {
        // free the cert buffer
        free( ( (PayloadCerts*)unpacked_cell->payload )->certs[i]->cert );
        // free the Cert struct
        free( ( (PayloadCerts*)unpacked_cell->payload )->certs[i] );
      }

      // free the array of structs
      free( ( (PayloadCerts*)unpacked_cell->payload )->certs );

      break;
    case AUTH_CHALLENGE:
      // free the methods buffer
      free( ( (PayloadAuthChallenge*)unpacked_cell->payload )->methods );

      break;
    case AUTHENTICATE:
      // free the authentication buffer
      free( ( (PayloadAuthenticate*)unpacked_cell->payload )->authentication );

      break;
    // TODO reserved for future use
    case AUTHORIZE:
      break;
  }

  // free the payload buffer
  free( unpacked_cell->payload );
  // free the cell, may not need to do this if we don't create malloc cells
  // free( unpacked_cell );
}

void free_relay_payload( void * payload, unsigned char command ) {
  int i;

  switch ( command ) {
    case RELAY_BEGIN:
      // free the address and port string
      free( ( (RelayPayloadBegin*)payload )->address_and_port );

      break;
    case RELAY_DATA:
      // free the data payload
      free( ( (RelayPayloadData*)payload )->payload );

      break;
    // nothing to do, no malloc pointers
    case RELAY_END:
      break;
    case RELAY_CONNECTED:
      // free the address
      free( ( (RelayPayloadConnected*)payload )->address );

      break;
    case RELAY_SENDME:
      // free the sendme data
      free( ( (RelayPayloadSendMe*)payload )->data );

      break;
    // nothing to do, no malloc pointers
    case RELAY_EXTEND:
      break;
    case RELAY_EXTENDED:
      // free the handshake data
      free( ( (PayloadCreated*)payload )->handshake_data );

      break;
    // nothing to do, no malloc pointers
    case RELAY_TRUNCATE:
      break;
    // nothing to do, no malloc pointers
    case RELAY_TRUNCATED:
      break;
    // nothing to do, no malloc pointers
    case RELAY_DROP:
      break;
    case RELAY_RESOLVE:
      // free the hostname
      free( ( (RelayPayloadResolve*)payload )->hostname );

      break;
    case RELAY_RESOLVED:
      // free the address
      free( ( (RelayPayloadResolved*)payload )->value );

      break;
    // nothing to do, no malloc pointers
    case RELAY_BEGIN_DIR:
      break;
    case RELAY_EXTEND2:
      // go through and free each link specifier
      for ( i = 0; i < ( (RelayPayloadExtend2*)payload )->specifier_count; i++ ) {
        // free the specifier buffer
        free( ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->specifier );
        // free the specifier struct
        free( ( (RelayPayloadExtend2*)payload )->link_specifiers[i]->specifier );
      }

      // free the array of structs
      free( ( (RelayPayloadExtend2*)payload )->link_specifiers );
      // free the handshake data
      free( ( (RelayPayloadExtend2*)payload )->handshake_data );

      break;
    case RELAY_EXTENDED2:
      // free the handshake data
      free( ( (PayloadCreated2*)payload )->handshake_data );

      break;
    case RELAY_COMMAND_ESTABLISH_INTRO:
      if ( ( (RelayPayloadEstablishIntro*)payload )->type == ESTABLISH_INTRO_LEGACY ) {
        // free the key of the legacy establish intro
        free( ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->key );
        // free the signature of the legacy establish intro
        free( ( (EstablishIntroLegacy*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature );
      } else {
        // free the auth key of the current establish intro
        free( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->auth_key );

        // free each extension
        for ( i = 0; i < ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extension_count; i++ ) {
          // TODO for now no intro extension has malloc pointers but they could in the fugure
          // free the intro extensions field
          free( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i]->intro_extension_field );
          // free the extension struct
          free( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions[i] );
        }

        // free the array of structs
        free( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->extensions );
        // free the signature of the current establish intro
        free( ( (EstablishIntroCurrent*)( (RelayPayloadEstablishIntro*)payload )->establish_intro )->signature );
      }

      // free the intro struct
      free( ( (RelayPayloadEstablishIntro*)payload )->establish_intro );

      break;
    // nothing to do, no malloc pointers
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
      break;
    // cells are identical
    case RELAY_COMMAND_INTRODUCE1:
    case RELAY_COMMAND_INTRODUCE2:
      // free the auth key
      free( ( (RelayPayloadIntroduce1*)payload )->auth_key );

      for ( i = 0; i < ( (RelayPayloadIntroduce1*)payload )->extension_count; i++ ) {
          // TODO for now no intro extension has malloc pointers but they could in the fugure
          // free the intro extensions field
        free( ( (RelayPayloadIntroduce1*)payload )->extensions[i]->intro_extension_field );
        // free the extension struct
        free( ( (RelayPayloadIntroduce1*)payload )->extensions[i] );
      }

      // free the array of structs
      free( ( (RelayPayloadIntroduce1*)payload )->extensions );
      // TODO figure out how to properly handle the encrypted data
      // free the encrypted data
      free( ( (RelayPayloadIntroduce1*)payload )->encrypted );

      break;
    // cells are identical
    case RELAY_COMMAND_RENDEZVOUS1:
    case RELAY_COMMAND_RENDEZVOUS2:
      free( ( (RelayPayloadCommandRendezvous1*)payload )->handshake_info );

      break;
    case RELAY_COMMAND_INTRO_ESTABLISHED:
      for ( i = 0; i < ( (RelayPayloadIntroEstablished*)payload )->extension_count; i++ ) {
          // TODO for now no intro extension has malloc pointers but they could in the fugure
          // free the intro extensions field
        free( ( (RelayPayloadIntroEstablished*)payload )->extensions[i]->intro_extension_field );
        // free the extension struct
        free( ( (RelayPayloadIntroEstablished*)payload )->extensions[i] );
      }

      // free the array of structs
      free( ( (RelayPayloadIntroEstablished*)payload )->extensions );

      break;
    // TODO we shouldn't need to free this since we're not running a client
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      break;
    // TODO we shouldn't need to free this since we're not running a client
    case RELAY_COMMAND_INTRODUCE_ACK:
      break;
  }

  free( payload );
}
