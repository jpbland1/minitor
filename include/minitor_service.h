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

#ifndef MINITOR_SERVICE_H
#define MINITOR_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

int d_setup_onion_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory );

#ifdef __cplusplus
}
#endif

#endif
