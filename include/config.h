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

#ifndef MINITOR_CONFIG_H
#define MINITOR_CONFIG_H

#define DEBUG_MINITOR
#define MINITOR_RELAY_MAX 60
#define MINITOR_DIR_ADDR 0x76a40dcc
#define MINITOR_DIR_ADDR_STR "204.13.164.118"
#define MINITOR_DIR_PORT 80
//#define MINITOR_CHUTNEY
#define MINITOR_CHUTNEY_ADDRESS 0x7602a8c0
#define MINITOR_CHUTNEY_ADDRESS_STR "192.168.2.118"
#define MINITOR_CHUTNEY_DIR_PORT 7000
#define FILESYSTEM_PREFIX "./local_data/"

extern const char* tor_authorities[];
extern int tor_authorities_count;

#endif
