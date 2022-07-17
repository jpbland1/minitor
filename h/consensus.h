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

extern MinitorMutex fastest_cache_mutex;

void v_handle_relay_fetch( void* pv_parameters );
void v_handle_crypto_and_insert( void* pv_parameters );
int d_get_hs_time_period( time_t fresh_until, time_t valid_after, int hsdir_interval );
int d_set_next_consenus();
int d_fetch_consensus_info();

#endif
