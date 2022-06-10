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
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7000",
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7001",
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7002"
#else
/* type=fallback */
/* version=4.0.0 */
/* timestamp=20210412000000 */
/* source=offer-list */
//
// Generated on: Fri, 04 Feb 2022 15:49:02 +0000

"88.196.80.132 dirport=80",
"81.169.180.28 dirport=9030",
"54.36.112.244 dirport=9030",
"89.58.34.53 dirport=9030",
"185.184.192.252 dirport=9030",
#endif
};
