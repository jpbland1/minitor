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
