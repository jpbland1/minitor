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
