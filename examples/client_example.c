#include "stdio.h"
#include <string.h>
#include <minitor.h>
#include <minitor_client.h>

void main()
{
  const char* REQUEST =
  "GET / HTTP/1.0\r\n"
  "Host: 127.0.0.1\r\n"
  "User-Agent: esp-idf/1.0 esp3266\r\n"
  "Content-Type: text/plain\r\n"
  "\r\n\r\n";

  int i;
  void* client;
  int stream;
  int ret;
  char read_buf[512];

  if ( d_minitor_INIT() < 0 )
  {
    printf( "Failed to init" );

    while ( 1 )
    {
    }
  }

  client = px_create_onion_client( "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion" );

  if ( client == NULL )
  {
    while ( 1 )
    {
      printf( "Failed to create client\n" );
      sleep( 1 );
    }
  }

  // create a stream on the circuit
  stream = d_connect_onion_client( client, 80 );

  if ( stream < 0 )
  {
    while ( 1 )
    {
      printf( "Failed to connect client\n" );
      sleep( 1 );
    }
  }

  // write to the http request to the stream
  if ( d_write_onion_client( client, stream, REQUEST, strlen( REQUEST ) ) != strlen( REQUEST ) )
  {
    while ( 1 )
    {
      printf( "Failed to write client\n" );
      sleep( 1 );
    }
  }

  do
  {
    ret = d_read_onion_client( client, stream, read_buf, sizeof( read_buf ) );

    if ( ret < 0 )
    {
      printf( "Failed to read on stream\n" );
      break;
    }

    printf( "ret %d\n", ret );

    for ( i = 0; i < ret; i++ )
    {
      printf( "read_buf[%d] %c\n", i, read_buf[i] );
    }
  } while ( ret == sizeof( read_buf ) );
}
