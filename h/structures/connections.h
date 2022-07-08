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

#ifndef MINITOR_STRUCTURES_CONNECTIONS_H
#define MINITOR_STRUCTURES_CONNECTIONS_H

#include "user_settings.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/rsa.h"

typedef enum ConnectionStatus
{
  CONNECTION_WANT_VERSIONS,
  CONNECTION_WANT_CERTS,
  CONNECTION_WANT_CHALLENGE,
  CONNECTION_WANT_NETINFO,
  CONNECTION_LIVE,
} ConnectionStatus;

typedef struct DlConnection
{
  uint32_t conn_id;
  struct DlConnection* next;
  struct DlConnection* previous;
  ConnectionStatus status;
  uint32_t address;
  uint16_t port;
  WOLFSSL* ssl;
  int sock_fd;
  int poll_index;
  int mutex_index;
  uint32_t circ_id;
  uint16_t stream_id;
  time_t last_action;
  uint8_t is_or;
  uint8_t* responder_rsa_identity_key_der;
  int responder_rsa_identity_key_der_size;
  uint8_t* initiator_rsa_identity_key_der;
  int initiator_rsa_identity_key_der_size;
  Sha256 initiator_sha;
  Sha256 responder_sha;
  RsaKey initiator_rsa_auth_key;
  bool has_versions;
  uint32_t cell_ring_start;
  uint32_t cell_ring_end;
  uint8_t* cell_ring_buf[20];
} DlConnection;

void v_add_connection_to_list( DlConnection* connection, DlConnection** list );
void v_remove_connection_from_list( DlConnection* connection, DlConnection** list );

#endif
