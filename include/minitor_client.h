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

#ifndef MINITOR_CLIENT_H
#define MINITOR_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define MINITOR_ERROR -1
#define MINITOR_CLIENT_ERROR -2
#define MINITOR_STREAM_ERROR -3

void* px_create_onion_client( const char* onion_address );
int d_connect_onion_client( void* client_p, uint16_t port );
int d_write_onion_client( void* client_p, int stream_id, uint8_t* write_buf, uint32_t length );
int d_read_onion_client( void* client_p, int stream_id, uint8_t* read_buf, uint32_t length );
int d_close_onion_client_stream( void* client_p, int stream_id );
void v_close_onion_client( void* client_p );

#ifdef __cplusplus
}
#endif

#endif
