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

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"

static const char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* base32_table = "abcdefghijklmnopqrstuvwxyz234567";

// decode a base64 string and put it into the destination byte buffer
// NOTE it is up to the coller to make sure the destination can fit the
// bytes being put into it
int d_base_64_decode( uint8_t* destination, char* source, int source_length )
{
  // index variables
  int i;
  int j;
  // byte to store the value between characters
  uint8_t tmp_byte = 0;
  // how many bits of the tmp_byte are full
  int tmp_byte_length = 0;
  // the src byte which always has the last 6 bits filled
  uint8_t src_byte = 0;
  uint8_t* destination_start = destination;

  // for each character in the base64 string
  for ( i = 0; i < source_length; i++ )
  {
    // find the value of the base64 character by matching it to the table, the index
    // of the table is the value of that character
    for ( j = 0; j < 64; j++ )
    {
      if ( base64_table[j] == source[i] )
      {
        src_byte = (uint8_t)j;
        break;
      }
    }

    if ( j == 64 )
    {
      continue;
    }

    // if we have a fresh byte, just move the src byte over 2, store it set the length
    // to 6
    if ( tmp_byte_length == 0 )
    {
      tmp_byte = src_byte << 2;
      tmp_byte_length = 6;
    // if our length is 6
    }
    else if ( tmp_byte_length == 6 )
    {
      // we only want the first two bits of the src byte, shift the last 4 off and
      // add the first two to the temp_byte
      tmp_byte |= src_byte >> 4;
      // the tmp byte is full, add it to the destination buffer
      *destination = tmp_byte;
      destination++;
      // store the last 4 bits of the src_byte into the tmp byte and set the length
      // to 4
      tmp_byte = src_byte << 4;
      tmp_byte_length = 4;
    // if our length is 4
    }
    else if ( tmp_byte_length == 4 )
    {
      // we only want the first four bits of the src byte, shift the last 2 off and
      // add the first 4 to the tmp_byte
      tmp_byte |= src_byte >> 2;
      // the tmp byte is full, add it to the destination buffer
      *destination = tmp_byte;
      destination++;
      // store the last 2 bits of the src_byte into the tmp byte and set the length
      // to 2
      tmp_byte = src_byte << 6;
      tmp_byte_length = 2;
    // if our length is 2
    }
    else if ( tmp_byte_length == 2 )
    {
      // we can just add 6 bits of our src byte to the tmp byte and add that to the
      // destination buffer, we now have a fresh temp byte so set length to 0
      tmp_byte |= src_byte;
      *destination = tmp_byte;
      destination++;
      tmp_byte_length = 0;
    }
  }

  return destination - destination_start;
}

void v_base_64_encode( char* destination, unsigned char* source, int source_length ) {
  int i;
  unsigned char tmp_byte = 0;
  int tmp_byte_length = 0;

  for ( i = 0; i < source_length; i++ ) {
    if ( tmp_byte_length == 0 ) {
      *destination = base64_table[(int)( source[i] >> 2 )];
      destination++;
      tmp_byte = ( source[i] & 0x03 ) << 4;
      tmp_byte_length = 2;
    } else if ( tmp_byte_length == 2 ) {
      tmp_byte |= source[i] >> 4;
      *destination = base64_table[(int)tmp_byte];
      destination++;
      tmp_byte = ( source[i] & 0x0f ) << 2;
      tmp_byte_length = 4;
    } else if ( tmp_byte_length == 4 ) {
      tmp_byte |= source[i] >> 6;
      *destination = base64_table[(int)tmp_byte];
      destination++;
      *destination = base64_table[(int)( source[i] & ( 0x3f ) )];
      destination++;
      tmp_byte_length = 0;
    }
  }

  if ( tmp_byte_length != 0 ) {
    *destination = base64_table[(int)tmp_byte];
  }
}

void v_base_32_decode( uint8_t* destination, char* source, int source_length )
{
  // index variables
  int i;
  int j;
  // byte to store the value between characters
  uint8_t tmp_byte = 0;
  // how many bits of the tmp_byte are full
  int tmp_byte_length = 0;
  // the src byte which always has the last 6 bits filled
  uint8_t src_byte = 0;

  // for each character in the base64 string
  for ( i = 0; i < source_length; i++ )
  {
    if ( source[i] == '=' )
    {
      if ( tmp_byte_length > 0 )
      {
        *destination = tmp_byte;
      }

      break;
    }

    // find the value of the base64 character by matching it to the table, the index
    // of the table is the value of that character
    for ( j = 0; j < 32; j++ )
    {
      if ( base32_table[j] == source[i] )
      {
        src_byte = j;
        break;
      }
    }

    if ( j == 32 )
    {
      continue;
    }

    switch ( tmp_byte_length )
    {
      case 0:
        tmp_byte = src_byte << 3;
        tmp_byte_length = 5;

        break;
      case 5:
        tmp_byte |= src_byte >> 2;
        *destination = tmp_byte;
        destination++;

        tmp_byte = src_byte << 6;
        tmp_byte_length = 2;

        break;
      case 2:
        tmp_byte |= src_byte << 1;
        tmp_byte_length = 7;

        break;

      case 7:
        tmp_byte |= src_byte >> 4;
        *destination = tmp_byte;
        destination++;

        tmp_byte = src_byte << 4;
        tmp_byte_length = 4;

        break;
      case 4:
        tmp_byte |= src_byte >> 1;
        *destination = tmp_byte;
        destination++;

        tmp_byte = src_byte << 7;
        tmp_byte_length = 1;

        break;
      case 1:
        tmp_byte |= src_byte << 2;
        tmp_byte_length = 6;

        break;
      case 6:
        tmp_byte |= src_byte >> 3;
        *destination = tmp_byte;
        destination++;

        tmp_byte = src_byte << 5;
        tmp_byte_length = 3;

        break;
      case 3:
        tmp_byte |= src_byte;
        *destination = tmp_byte;
        destination++;

        tmp_byte_length = 0;

        break;
      default:
        printf( "BAD DEFAULT\n" );

        break;
    }
  }
}

void v_base_32_encode( char* destination, unsigned char* source, int source_length ) {
  int i;
  unsigned char tmp_byte = 0;
  int tmp_byte_length = 0;

  for ( i = 0; i < source_length; i++ ) {
    if ( tmp_byte_length == 0 ) {
      *destination = base32_table[(int)( source[i] >> 3 )];
      destination++;
      tmp_byte = ( source[i] & 0x07 ) << 2;
      tmp_byte_length = 3;
    } else if ( tmp_byte_length == 3 ) {
      tmp_byte |= source[i] >> 6;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( ( source[i] & 0x3f ) >> 1 )];
      destination++;
      tmp_byte = ( source[i] & 0x01 ) << 4;
      tmp_byte_length = 1;
    } else if ( tmp_byte_length == 1 ) {
      tmp_byte |= source[i] >> 4;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      tmp_byte = ( source[i] & 0x0f ) << 1;
      tmp_byte_length = 4;
    } else if ( tmp_byte_length == 4 ) {
      tmp_byte |= source[i] >> 7;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( ( source[i] & 0x7f ) >> 2 )];
      destination++;
      tmp_byte = ( source[i] & 0x03 ) << 3;
      tmp_byte_length = 2;
    } else if ( tmp_byte_length == 2 ) {
      tmp_byte |= source[i] >> 5;
      *destination = base32_table[(int)tmp_byte];
      destination++;
      *destination = base32_table[(int)( source[i] & 0x1f )];
      destination++;
      tmp_byte_length = 0;
    }
  }

  if ( tmp_byte_length != 0 ) {
    *destination = base32_table[(int)tmp_byte];
  }
}

char* pc_ipv4_to_string( unsigned int address )
{
  int i;
  int length = 0;
  char* result = malloc( sizeof( char ) * 16 );
  int tmp_length = 0;
  unsigned char tmp_byte;

  for ( i = 0; i < 4; i++ )
  {
    tmp_byte = ( address >> ( 8 * i ) ) & 0xff;

    if ( tmp_byte < 10 )
    {
      tmp_length = 1;
    }
    else if ( tmp_byte < 100 )
    {
      tmp_length = 2;
    }
    else
    {
      tmp_length = 3;
    }

    sprintf( result + length, "%d", tmp_byte );
    length += tmp_length;

    if ( i != 3 )
    {
      result[length] = '.';
      length++;
    }
  }

  result[length] = 0;

  return result;
}
