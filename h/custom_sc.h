#ifndef MINITOR_CUSTOM_SC
#define MINITOR_CUSTOM_SC

#include "./port.h"

#define crypto_int64 int64_t
#define crypto_uint64 uint64_t
#define crypto_uint32 uint32_t

/*
 Stop signed left shifts overflowing
 by using unsigned types for bitwise operations
 */

#ifndef OVERFLOW_SAFE_SIGNED_LSHIFT
#define OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, utype, stype) \
  ((stype)((utype)(s) << (utype)(lshift)))
#endif

#define SHL64(s, lshift) \
  OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, crypto_uint64, crypto_int64)

void minitor_sc_muladd(unsigned char *s,const unsigned char *a,const unsigned char *b,const unsigned char *c);

#endif
