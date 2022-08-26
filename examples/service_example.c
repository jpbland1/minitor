#include "stdio.h"
#include <minitor.h>
#include <minitor_client.h>

void main()
{
  if ( d_minitor_INIT() < 0 )
  {
    printf( "Failed to init" );

    while ( 1 )
    {
    }
  }

  printf( "Starting service" );

  if ( d_setup_onion_service( 8080, 80, "./local_data/test_service" ) < 0 )
  {
    printf( "Failed to setup hidden service" );
  }

  while ( 1 )
  {
    sleep( 1000 );
  }
}
