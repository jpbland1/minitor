#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "esp_log.h"

#include "../../include/config.h"
#include "../../h/constants.h"

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

    if ( lseek( fd, 0, SEEK_SET ) != 0 )
    {
  #ifdef MINITOR_CHUTNEY
      ESP_LOGE( MINITOR_TAG, "Failed to seek " FILESYSTEM_PREFIX "rev_counter" );
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
