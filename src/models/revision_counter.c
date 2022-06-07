#include <fcntl.h>
#include <fcntl.h>
#include <unistd.h>

#include "../../include/config.h"

int d_roll_revision_counter()
{
  int fd;
  int count = 0;
  struct stat st;

  if ( stat( FILESYSTEM_PREFIX "rev_counter", &st ) != 0 )
  {
    fd = open( FILESYSTEM_PREFIX "rev_counter", O_CREAT | O_TRUNC | O_WRONLY );
    count = -1;
  }
  else
  {
    fd = open( FILESYSTEM_PREFIX "rev_counter", O_RDWR );
  }

  if ( fd < 0 )
  {
#ifdef MINITOR_CHUTNEY
    ESP_LOGE( MINITOR_TAG, "Failed to open " FILESYSTEM_PREFIX "rev_counter" );
#endif
    
    return -1;
  }

  if ( count != -1 )
  {
    if ( read( fd, &count, sizeof( int ) ) != sizeof( int ) )
    {
#ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "Failed to read " FILESYSTEM_PREFIX "rev_counter" );
#endif

      count = -1;
      goto finish;
    }
  }

  count++;

  if ( count == INT_MAX )
  {
    count = 0;
  }

  if ( write( fd, &count, sizeof( int ) ) != sizeof( int ) )
  {
#ifdef MINITOR_CHUTNEY
    ESP_LOGE( MINITOR_TAG, "Failed to write " FILESYSTEM_PREFIX "rev_counter" );
#endif

    count = -1;
    goto finish;
  }

finish:
  close( fd );

  return count;
}
