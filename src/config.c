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
// address:port:identity:ntor-onion-key
// the identity can be found at /tor/status-vote/current/consensus
// the ntor-onion-key can be found at /tor/server/all
#ifdef MINITOR_CHUTNEY
// ip:port:identity:nto_onion_key
MINITOR_CHUTNEY_ADDRESS_STR ":5000:JM022IGoVYCo1n4HRKNmEyRJflI:jq+kM4ZFUbZqYWym4+sCmr9zOUn8DDlPSP0JP1crbBg",
MINITOR_CHUTNEY_ADDRESS_STR ":5001:Ewduz4NDJe1DNGMPLcMZVB/U7oc:z5Yd0lVNE8VLmNjG0Wp3ui9Czbc6E60wKGDb5hQy6B0",
MINITOR_CHUTNEY_ADDRESS_STR ":5002:biV7oePe1m9MXWyQteX44pcEnPI:HMHNA06WJOv/ywNk+6Hw/SUvOse4e12L7Z0/evLS1RI"
#else
/* type=fallback */
/* version=4.0.0 */
/* timestamp=20210412000000 */
/* source=offer-list */
//
// Generated on: Fri, 04 Feb 2022 15:49:02 +0000

"104.53.221.159:9001:AAoQ1DAR6kkoo19hBAX5K0QztNw:S/gTNxofPc0UmPq+D+p1C3BsJPu/UFL8bLVmO9jaylM",
"5.196.8.113:9001:AAw1H4YDNlSoLZ/WrDsXj0TiNr4:s4lfSSbb9iZ1rpmS2w/7HvTuAh08bcfAqc7FSjIjLn0",
"178.218.144.18:443:ABElTMhEQ2myDvERVriZBDgiGlQ:kJv2kjhM/CcyZ4DjSC3Dsjz5YiUDEyy/trR0dielvHQ",
"198.98.61.11:9001:ABH342c01mHoOs0tdlOjeWqRPXc:gcYX7LMXcnJLtWR+IdhlE95nZxLNp1d73gXsqXiTNU8",
"95.111.230.178:443:ACQOyytTWqTB4YdNdE36avLl6UE:B89cfN9nBH9btPE8q1xTvkIJpVyYf9zDsMSnltCepRc",
#endif
};
