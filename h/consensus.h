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

#ifndef MINITOR_CONSENSUS_H
#define MINITOR_CONSENSUS_H

#include "./structures/consensus.h"
#include "./structures/circuit.h"

extern bool have_network_consensus;
extern bool have_relay_descriptors;
extern bool external_want_consensus;
extern MinitorMutex waiting_relays_lock;
extern MinitorQueue external_consensus_queue;
extern MinitorQueue insert_relays_queue;
extern MinitorQueue fetch_relays_queue;

void v_handle_crypto_and_insert( void* pv_parameters );
int d_consensus_request( OnionCircuit* circuit, DlConnection* or_connection );
int d_parse_consensus( OnionCircuit* circuit, DlConnection* or_connection, Cell* data_cell );
int d_descriptors_request( OnionCircuit* circuit, DlConnection* or_connection, OnionRelay** list, int list_length );
int d_parse_descriptors( OnionCircuit* circuit, DlConnection* or_connection, Cell* data_cell );
bool b_consensus_outdated();
int d_reset_relay_files();
int d_get_hs_time_period( time_t fresh_until, time_t valid_after, int hsdir_interval );
int d_fetch_consensus();

#endif
