/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef MINITOR_STRUCTURES_CELL_H
#define MINITOR_STRUCTURES_CELL_H

#define CELL_LEN 514
#define CIRCID_LEN 4
#define LEGACY_CIRCID_LEN 2
#define KEY_LEN 16
#define DH_LEN 128
#define DH_SEC_LEN 40
#define PK_ENC_LEN 128
#define PK_PAD_LEN 42
#define HASH_LEN 20
#define PAYLOAD_LEN CELL_LEN - 5
#define RELAY_PAYLOAD_LEN PAYLOAD_LEN - 11
#define MAC_LEN 32
#define PK_PUBKEY_LEN 32
#define TAP_C_HANDSHAKE_LEN DH_LEN+KEY_LEN+PK_PAD_LEN
#define TAP_S_HANDSHAKE_LEN DH_LEN+HASH_LEN
#define LEGACY_RENDEZVOUS_PAYLOAD_LEN 168
#define FIXED_CELL_OFFSET 2
#define MINITOR_CELL_LEN CELL_LEN + FIXED_CELL_OFFSET
#define FIXED_CELL_HEADER_SIZE 5
#define VARIABLE_CELL_HEADER_SIZE 7
#define RELAY_CELL_HEADER_SIZE 11

#define NTOR_HANDSHAKE_TAG "ntorNTORntorNTOR\0"

#define AUTH_ONE_TYPE_STRING "AUTH0001"
#define AUTH_THREE_TYPE_STRING "AUTH0003"

typedef enum Command{
  PADDING = 0,
  CREATE = 1,
  CREATED = 2,
  RELAY = 3,
  DESTROY = 4,
  CREATE_FAST = 5,
  CREATED_FAST = 6,
  VERSIONS = 7,
  NETINFO = 8,
  RELAY_EARLY = 9,
  CREATE2 = 10,
  CREATED2 = 11,
  PADDING_NEGOTIATE = 12,

  VPADDING = 128,
  CERTS = 129,
  AUTH_CHALLENGE = 130,
  AUTHENTICATE = 131,
  AUTHORIZE = 132,
} Command;

typedef enum RelayCommand {
  RELAY_BEGIN = 1,
  RELAY_DATA = 2,
  RELAY_END = 3,
  RELAY_CONNECTED = 4,
  RELAY_SENDME = 5,
  RELAY_EXTEND = 6,
  RELAY_EXTENDED = 7,
  RELAY_TRUNCATE = 8,
  RELAY_TRUNCATED = 9,
  RELAY_DROP = 10,
  RELAY_RESOLVE = 11,
  RELAY_RESOLVED = 12,
  RELAY_BEGIN_DIR = 13,
  RELAY_EXTEND2 = 14,
  RELAY_EXTENDED2 = 15,
  RELAY_COMMAND_ESTABLISH_INTRO = 32,
  RELAY_COMMAND_ESTABLISH_RENDEZVOUS = 33,
  RELAY_COMMAND_INTRODUCE1 = 34,
  RELAY_COMMAND_INTRODUCE2 = 35,
  RELAY_COMMAND_RENDEZVOUS1 = 36,
  RELAY_COMMAND_RENDEZVOUS2 = 37,
  RELAY_COMMAND_INTRO_ESTABLISHED = 38,
  RELAY_COMMAND_RENDEZVOUS_ESTABLISHED = 39,
  RELAY_COMMAND_INTRODUCE_ACK = 40,
} RelayCommand;

typedef enum PaddingCommand {
  STOP_PADDING = 1,
  START_PADDING = 2,
} PaddingCommand;

typedef enum DestroyCode {
  NO_DESTROY_CODE = 0,
  PROTOCOL = 1,
  INTERNAL = 2,
  REQUESTED = 3,
  HIBERNATING = 4,
  RESOURCELIMIT = 5,
  CONNECTFAILED = 6,
  OR_IDENTITY = 7,
  OR_CONN_CLOSED = 8,
  FINISHED = 9,
  TIMEOUT = 10,
  DESTROYED = 11,
  NOSUCHSERVICE = 12,
} DestroyCode;

typedef enum RelayEndCode {
  REASON_MISC = 1,
  REASON_RESOLVEFAILED = 2,
  REASON_CONNECTREFUSED = 3,
  REASON_EXITPOLICY = 4,
  REASON_DESTROY = 5,
  REASON_DONE = 6,
  REASON_TIMEOUT = 7,
  REASON_NOROUTE = 8,
  REASON_HIBERNATING = 9,
  REASON_INTERNAL = 10,
  REASON_RESOURCELIMIT = 11,
  REASON_CONNRESET = 12,
  REASON_TORPROTOCOL = 13,
  REASON_NOTDIRECTORY = 14,
} RelayEndCode;

typedef enum AddressType {
  IPv4 = 4,
  IPv6 = 6,
} AddressType;

typedef enum AddressLength {
  IPv4Length = 4,
  IPv6Length = 16,
} AddressLength;

typedef enum HandshakeType {
  TAP = 0x0000,
  NTOR = 0x0002,
} HandshakeType;

typedef enum OnionKeyType
{
  ONION_NTOR = 1,
} OnionKeyType;

typedef enum MinitorCertType {
  LINK_KEY = 1,
  IDENTITY_CERT = 2,
  RSA_AUTH_CERT = 3,
  SIGNING_KEY = 4,
  TLS_LINK_CERT = 5,
  ED_AUTH_KEY = 6,
  ED_IDENTITY = 7,
} MinitorCertType;

typedef enum AuthType {
  AUTH_ONE = 0x0001,
  AUTH_THREE = 0x0003,
} AuthType;

typedef enum SendMeVersion {
  SENDME_IGNORE = 0x00,
  SENDME_AUTH = 0x01,
} SendMeVersion;

typedef enum LinkSpecifierType {
  IPv4Link = 0x00,
  IPv6Link = 0x01,
  LEGACYLink = 0x02,
  EDLink = 0x03,
} LinkSpecifierType;

typedef enum RelayResolvedType {
  Hostname = 0x00,
  IPv4RelayResolved = 0x04,
  IPv6RelayResolved = 0x06,
  TrainsientError = 0xF0,
  NonTrainsientError = 0xF1,
} RelayResolvedType;

typedef enum AuthKeyType {
  EDSHA3 = 0x02,
} AuthKeyType;

typedef enum IntroExtensionType {
  EXTENSION_ED25519 = 0x02,
} IntroExtensionType;

typedef enum EstablishIntroType {
  ESTABLISH_INTRO_LEGACY = 0,
  ESTABLISH_INTRO_CURRENT = 1,
} EstablishIntroType;

typedef enum IntroduceAckStatus {
  Success = 0x0000,
  Failure = 0x0001,
  BadFormat = 0x0002,
  CantRelay = 0x0003,
} IntroduceAckStatus;

typedef enum IntroduceOnionKeyType {
    Ntor = 1,
} IntroduceOnionKeyType;

typedef struct __attribute__((__packed__)) TorCert
{
  uint8_t cert_type;
  uint16_t cert_length;
  uint8_t cert[];
} TorCert;

// Authentication
typedef struct __attribute__((__packed__)) AuthenticationOne
{
  // [0x41, 0x55, 0x54, 0x48, 0x30, 0x30, 0x30, 0x31],
  unsigned char type[8];
  unsigned char client_id[32];
  unsigned char server_id[32];
  unsigned char server_log[32];
  unsigned char client_log[32];
  unsigned char server_cert[32];
  unsigned char tls_secrets[32];
  unsigned char rand[24];
  unsigned char signature[128];
} AuthenticationOne;

typedef struct __attribute__((__packed__)) AuthenticationThree
{
  // [0x41, 0x55, 0x54, 0x48, 0x30, 0x30, 0x30, 0x33],
  unsigned char type[8];
  unsigned char client_id[32];
  unsigned char server_id[32];
  unsigned char client_id_ed[32];
  unsigned char server_id_ed[32];
  unsigned char server_log[32];
  unsigned char client_log[32];
  unsigned char server_cert[32];
  unsigned char tls_secrets[32];
  unsigned char rand[24];
  unsigned char signature[128];
} AuthenticationThree;

typedef struct __attribute__((__packed__)) MyAddr
{
  uint8_t type;
  uint8_t length;
  uint8_t address[];
} MyAddr;

typedef struct __attribute__((__packed__)) LinkSpecifier
{
  uint8_t type;
  uint8_t length;
  uint8_t specifier[];
} LinkSpecifier;

typedef struct __attribute__((__packed__)) Create2
{
  uint16_t handshake_type;
  uint16_t handshake_length;
  uint8_t handshake_data[];
} Create2;

typedef struct __attribute__((__packed__)) Created2
{
  uint16_t handshake_length;
  uint8_t handshake_data[];
} Created2;

typedef struct __attribute__((__packed__)) IntroExtension
{
  uint8_t intro_type;
  uint8_t intro_length;
  uint8_t extension_field[];
} IntroExtension;

typedef struct __attribute__((__packed__)) IntroOnionKey
{
  uint8_t onion_key_type;
  uint16_t onion_key_length;
  uint8_t onion_key[];
} IntroOnionKey;

typedef struct __attribute__((__packed__)) DecryptedIntroduce2
{
  uint8_t rendezvous_cookie[20];
  uint8_t num_extensions;
  uint8_t extensions[];
} DecryptedIntroduce2;

typedef struct __attribute__((__packed__)) TorCrosscert
{
  uint8_t version;
  uint8_t cert_type;
  uint32_t epoch_hours;
  uint8_t cert_key_type;
  uint8_t certified_key[32];
  uint8_t num_extensions;
  uint8_t extensions[];
} TorCrosscert;

typedef struct __attribute__((__packed__)) TorCrosscertExtension
{
  uint16_t ext_length;
  uint8_t ext_type;
  uint8_t ext_flags;
  uint8_t ext_data[];
} TorCrosscertExtension;

typedef union __attribute__((__packed__)) CellPayload
{
  struct __attribute__((__packed__))
  {
    uint8_t num_certs;
    uint8_t certs[];
  } certs;

  struct __attribute__((__packed__))
  {
    uint8_t challenge[32];
    uint16_t num_methods;
    uint16_t methods[];
  } auth_challenge;

  struct __attribute__((__packed__))
  {
    uint16_t auth_type;
    uint16_t auth_length;

    union
    {
      AuthenticationOne auth_1;
      AuthenticationThree auth_3;
    };
  } authenticate;

  struct __attribute__((__packed__))
  {
    uint32_t time;

    union
    {
      struct __attribute__((__packed__))
      {
        struct __attribute__((__packed__))
        {
          uint8_t type;
          uint8_t length;
          uint8_t address[4];
        } otheraddr;

        struct __attribute__((__packed__))
        {
          uint8_t num_myaddr;
          uint8_t addresses[];
        } myaddr;
      } addresses_4;

      struct __attribute__((__packed__))
      {
        struct __attribute__((__packed__))
        {
          uint8_t type;
          uint8_t length;
          uint8_t address[16];
        } otheraddr;

        struct __attribute__((__packed__))
        {
          uint8_t num_myaddr;
          uint8_t addresses[];
        } myaddr;
      } addresses_6;
    };
  } netinfo;

  Create2 create2;

  Created2 created2;

  struct __attribute__((__packed__))
  {
    uint8_t relay_command;
    uint16_t recognized;
    uint16_t stream_id;
    uint32_t digest;
    uint16_t length;

    union
    {
      struct __attribute__((__packed__))
      {
        uint32_t address_4;

        union
        {
          uint32_t ttl_4;

          struct __attribute__((__packed__))
          {
            uint8_t address_type;
            uint8_t address_6[16];
            uint32_t ttl_6;
          };
        };
      } connected;

      struct __attribute__((__packed__))
      {
        uint8_t num_specifiers;
        uint8_t link_specifiers[];
      } extend2;

      Created2 extended2;

      struct __attribute__((__packed__))
      {
        uint8_t auth_key_type;
        uint16_t auth_key_length;
        uint8_t auth_key[];
      } establish_intro;

      struct __attribute__((__packed__))
      {
        uint8_t legacy_key_id[20];
        uint8_t auth_key_type;
        uint16_t auth_key_length;
        uint8_t auth_key[];
      } introduce2;

      struct __attribute__((__packed__))
      {
        uint8_t rendezvous_cookie[20];
        uint8_t public_key[PK_PUBKEY_LEN];
        uint8_t auth[MAC_LEN];
      } rend1;

      struct __attribute__((__packed__))
      {
        uint8_t public_key[PK_PUBKEY_LEN];
        uint8_t auth[MAC_LEN];
      } rend2;

      struct __attribute__((__packed__))
      {
        uint16_t status;
        uint8_t num_extensions;
        uint8_t extensions[];
      } intro_ack;

      uint8_t destroy_code;

      uint8_t data[RELAY_PAYLOAD_LEN];
    };
  } relay;

  uint8_t destroy_code;

  uint16_t versions[PAYLOAD_LEN];

  uint8_t data[PAYLOAD_LEN];
} CellPayload;

typedef struct __attribute__((__packed__)) CellShortVariable
{
  uint16_t circ_id;
  uint8_t command;
  uint16_t length;

  CellPayload payload;
} CellShortVariable;

typedef struct __attribute__((__packed__)) CellVariable
{
  uint32_t circ_id;
  uint8_t command;
  uint16_t length;

  CellPayload payload;
} CellVariable;

typedef struct __attribute__((__packed__)) Cell
{
  // length is above because it is not a part of the cell, it is for our tracking
  // need to add 2 bytes when sending
  uint16_t length;
  uint32_t circ_id;
  uint8_t command;

  CellPayload payload;
} Cell;

/*
typedef struct Cell {
  unsigned int circ_id;
  Command command;
  unsigned short length;
  void* payload;
  int recv_index;
} Cell;
*/

/*
typedef struct Address {
  AddressType address_type;
  AddressLength length;
  unsigned char* address;
} Address;

typedef struct MinitorCert {
  MinitorCertType cert_type;
  unsigned short cert_length;
  unsigned char* cert;
} MinitorCert;
*/

/*
// Payload
typedef struct PayloadPadding {
} PayloadPadding;

typedef struct PayloadRelay {
  RelayCommand command;
  unsigned short recognized;
  unsigned short stream_id;
  unsigned int digest;
  unsigned short length;
  // RelayPayload
  void* relay_payload;
} PayloadRelay;

typedef struct PayloadDestroy {
  DestroyCode destroy_code;
} PayloadDestroy;

typedef struct PayloadCreateFast {
  unsigned char key_material[HASH_LEN];
} PayloadCreateFast;

typedef struct PayloadCreatedFast {
  unsigned char key_material[HASH_LEN];
  unsigned char derivative_key_data[HASH_LEN];
} PayloadCreatedFast;

typedef struct PayloadVersions {
  unsigned short* versions;
} PayloadVersions;

typedef struct PayloadNetInfo {
  unsigned int time;
  Address* other_address;
  unsigned char address_count;
  Address** my_addresses;
} PayloadNetInfo;

struct PayloadRelayEarly {
};

typedef struct PayloadCreate2 {
  HandshakeType handshake_type;
  unsigned short handshake_length;
  unsigned char* handshake_data;
} PayloadCreate2;

typedef struct PayloadCreated2 {
  unsigned short handshake_length;
  unsigned char* handshake_data;
} PayloadCreated2;

typedef struct PayloadCreate {
  char handshake_tag[16];
  unsigned char* handshake_data;
} PayloadCreate;

typedef struct PayloadCreated {
  unsigned char handshake_data[TAP_S_HANDSHAKE_LEN];
} PayloadCreated;

typedef struct PayloadPaddingNegotiate {
  unsigned char version;
  PaddingCommand command;
  unsigned short timeout_low_ms;
  unsigned short timeout_high_ms;
} PayloadPaddingNegotiate;

typedef struct PayloadVpadding {
} PayloadVpadding;

typedef struct PayloadCerts {
  unsigned char cert_count;
  MinitorCert** certs;
} PayloadCerts;

typedef struct PayloadAuthChallenge {
  unsigned char challenge[32];
  unsigned short n_methods;
  unsigned short* methods;
} PayloadAuthChallenge;

typedef struct PayloadAuthenticate {
  AuthType auth_type;
  unsigned short auth_length;
  void* authentication;
} PayloadAuthenticate;

typedef struct IntroExtensionFieldEd25519 {
  unsigned char nonce[16];
  unsigned char pubkey[32];
  unsigned char signature[64];
} IntroExtensionFieldEd25519;

typedef struct IntroExtension {
  IntroExtensionType type;
  unsigned char length;
  void* intro_extension_field;
} IntroExtension;

typedef struct EstablishIntroLegacy {
  unsigned short key_length;
  unsigned char* key;
  unsigned char handshake_auth[20];
  // not actually part of a cell, for packing sanity
  int signature_length;
  unsigned char* signature;
} EstablishIntroLegacy;

typedef struct EstablishIntroCurrent {
  AuthKeyType auth_key_type;
  unsigned short auth_key_length;
  unsigned char* auth_key;
  unsigned char extension_count;
  IntroExtension** extensions;
  unsigned char handshake_auth[MAC_LEN];
  unsigned short signature_length;
  unsigned char* signature;
} EstablishIntroCurrent;

typedef struct RendezvousHandshakeInfo {
  unsigned char public_key[PK_PUBKEY_LEN];
  unsigned char auth[MAC_LEN];
} RendezvousHandshakeInfo;

// RelayPayload
typedef struct RelayPayloadExtend2 {
  unsigned char specifier_count;
  LinkSpecifier** link_specifiers;
  HandshakeType handshake_type;
  unsigned short handshake_length;
  unsigned char* handshake_data;
} RelayPayloadExtend2;

typedef struct RelayPayloadExtend {
  unsigned int address;
  unsigned short port;
  unsigned char onion_skin[TAP_C_HANDSHAKE_LEN];
  unsigned char identity_fingerprint[HASH_LEN];
} RelayPayloadExtend;

typedef struct RelayPayloadBegin {
  char* address;
  unsigned short port;
  unsigned int flags;
} RelayPayloadBegin;

struct RelayPayloadBeginDir {
};

typedef struct RelayPayloadConnected {
  unsigned char* address;
  unsigned int time_to_live;
  AddressType address_type;
} RelayPayloadConnected;

typedef struct RelayPayloadData {
  unsigned char* payload;
} RelayPayloadData;

typedef struct RelayPayloadEnd {
  RelayEndCode reason;
} RelayPayloadEnd;

typedef struct RelayPayloadResolve {
  char* hostname;
} RelayPayloadResolve;

typedef struct RelayPayloadResolved {
  RelayResolvedType type;
  unsigned char length;
  unsigned char* value;
  unsigned int time_to_live;
} RelayPayloadResolved;

typedef struct RelayPayloadSendMe {
  SendMeVersion version;
  unsigned short data_length;
  unsigned char* data;
} RelayPayloadSendMe;

typedef struct RelayPayloadEstablishIntro {
  void* establish_intro;
  // not actually part of the cell, just here for packing sanity
  EstablishIntroType type;
} RelayPayloadEstablishIntro;

typedef struct RelayPayloadIntroEstablished {
  unsigned char extension_count;
  IntroExtension** extensions;
} RelayPayloadIntroEstablished;

typedef struct DecryptedIntroduce2 {
  unsigned char rendezvous_cookie[20];
  unsigned char extension_count;
  IntroExtension** extensions;
  IntroduceOnionKeyType onion_key_type;
  unsigned short onion_key_length;
  unsigned char* onion_key;
  unsigned char specifier_count;
  LinkSpecifier** link_specifiers;
} DecryptedIntroduce2;

typedef struct RelayPayloadIntroduce1 {
  unsigned char legacy_key_id[20];
  AuthKeyType auth_key_type;
  unsigned short auth_key_length;
  unsigned char* auth_key;
  unsigned char extension_count;
  IntroExtension** extensions;
  unsigned char client_pk[PK_PUBKEY_LEN];
  unsigned char* encrypted_data;
  unsigned short encrypted_length;
  unsigned char mac[MAC_LEN];
} RelayPayloadIntroduce1;

struct RelayPayloadIntroduceAck {
  IntroduceAckStatus status;
  unsigned char extension_count;
  IntroExtension** extensions;
};

struct RelayPayloadCommandEstablishRendezvous {
  unsigned char rendezvous_cookie[20];
};

typedef struct RelayPayloadCommandRendezvous1 {
  unsigned char rendezvous_cookie[20];
  RendezvousHandshakeInfo handshake_info;
} RelayPayloadCommandRendezvous1;

unsigned char* pack_and_free( Cell* unpacked_cell );

void pack_relay_payload( unsigned char** packed_cell, void* payload, unsigned char command, unsigned short payload_length );

void unpack_and_free( Cell* unpacked_cell, unsigned char* packed_cell, int circ_id_length );

void* unpack_relay_payload( unsigned char* packed_cell, unsigned char command, unsigned short payload_length );

int d_unpack_introduce_2_data( unsigned char* packed_data, DecryptedIntroduce2* unpacked_data );

void free_cell( Cell* unpacked_cell );

void free_relay_payload( void * payload, unsigned char command );

unsigned int unpack_four_bytes( unsigned char** packed_cell );

unsigned short unpack_two_bytes( unsigned char** packed_cell );

void unpack_buffer( unsigned char* buffer, int length, unsigned char** packed_cell );

void unpack_buffer_short( unsigned short* buffer, int length, unsigned char** packed_cell );

void pack_four_bytes( unsigned char** packed_cell, unsigned int value );

void pack_two_bytes( unsigned char** packed_cell, unsigned short value );

void pack_buffer( unsigned char** packed_cell, unsigned char* buffer, int length );

void pack_buffer_short( unsigned char** packed_cell, unsigned short* buffer, int length );

void v_free_introduce_2_data( DecryptedIntroduce2* unpacked_data );
*/

#endif
