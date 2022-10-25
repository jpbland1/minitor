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

#include "../include/config.h"

#ifdef MINITOR_CHUTNEY
  int tor_authorities_count = 3;
#else
  int tor_authorities_count = 5;
#endif

const char* tor_authorities[] =
{
#ifdef MINITOR_CHUTNEY
MINITOR_CHUTNEY_ADDRESS_STR ":5000:YJbd7vMeA/DLEUXopHBzw115YCI:Y5OWNpeIv5d014YYkaBPczVRcIfRGcanpOA6lJqFEWA",
MINITOR_CHUTNEY_ADDRESS_STR ":5001:z1H2hwe2jM/uskRfkCCS8f+/DdY:0p2wew+3AlgPvAGfNWVUcN5G2UeMGsyOUCKE87BTdhw",
MINITOR_CHUTNEY_ADDRESS_STR ":5002:Kqkl4/6wNUSZYoIMMAguCnUxuCk:NZrQ/8xmQChJf7oevvf49OYV51UJ+qXNZX1gnhQT7wk"
#else
/* type=fallback */
/* version=4.0.0 */
/* timestamp=20210412000000 */
/* source=offer-list */
//
// Generated on: Fri, 04 Feb 2022 15:49:02 +0000

"104.53.221.159:9001",
"162.247.74.201:443",
"195.15.242.99:9001",
"35.220.235.11:443",
"104.244.79.75:443",
#endif
};
