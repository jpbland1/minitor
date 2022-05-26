#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/apps/sntp.h"

#include "wifi_connect.h"
#include "minitor.h"

#include "test/circuit.h"
#include "test/issi.h"
#include "test/fd_tree.h"

#include <esp_event.h>
#include "esp_netif.h"
#include <esp_http_server.h>

static const char* TAG = "MAIN";

#define SPI_DMA_CHAN 1
#define PIN_NUM_CS   4
#define PIN_NUM_CLK  18
#define PIN_NUM_MOSI 23
#define PIN_NUM_MISO 19

// TODO change this if this turns into more than an example
#define FILE_PATH_MAX 50

#define SCRATCH_BUFSIZE  8192
char scratch[SCRATCH_BUFSIZE];

typedef enum LinkType
{
  SIMPLE_PIN,
  SCHEDULED_PIN,
  INTERRUPT_PIN,
} LinkType;

typedef struct SimplePin
{
  uint8_t num;
  bool state;
} SimplePin;

typedef struct ScheduledPin
{
  uint8_t num;
  bool state;
  int duration;
  bool one_shot;
  time_t one_shot_time;
  uint8_t days[7];
  int minute_of_day;
} ScheduledPin;

typedef struct InterruptPin
{
  uint8_t num;
  bool high;
  //bool pos_edge;
  int ms_delay;
  LinkType response_type;
  void* response_body;
} InterruptPin;

typedef struct Link
{
  char name[25];
  int index;
  LinkType type;
  void* body;
} Link;

int link_length = 0;
Link links[20];

static QueueHandle_t link_event_queue = NULL;

static void IRAM_ATTR link_int_handler(void* arg)
{
  uint32_t link_index = (uint32_t) arg;
  xQueueSendFromISR( link_event_queue, &link_index, NULL );
}

static void link_event_task( void* args )
{
  int level;
  int use_index;

  while ( xQueueReceive( link_event_queue, &use_index, portMAX_DELAY ) )
  {
    ESP_LOGE( TAG, "got int" );

    level = gpio_get_level( ((InterruptPin*)(links[use_index].body))->num );

    if (
      (
        ((InterruptPin*)(links[use_index].body))->high == true &&
        level == 1
      ) ||
      (
        ((InterruptPin*)(links[use_index].body))->high == false &&
        level == 0
      )
    )
    {
      ESP_LOGE( TAG, "no state change" );
      continue;
    }
    else
    {
      if ( level == 1 )
      {
        ((InterruptPin*)(links[use_index].body))->high = true;
      }
      else
      {
        ((InterruptPin*)(links[use_index].body))->high = false;
      }
    }

    if ( ((InterruptPin*)(links[use_index].body))->ms_delay < 0 )
    {
      vTaskDelay( ((InterruptPin*)(links[use_index].body))->ms_delay / portTICK_PERIOD_MS );
    }

    switch ( ((InterruptPin*)(links[use_index].body))->response_type )
    {
      case SIMPLE_PIN:
        ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state = !((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state;

        if ( ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state == true )
        {
          gpio_set_level( ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->num, 1 );
        }
        else
        {
          gpio_set_level( ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->num, 0 );
        }

        break;
      case SCHEDULED_PIN:
        break;
      case INTERRUPT_PIN:
        break;
    }
  }
}

// post request to make a new link
static esp_err_t links_post_handler(httpd_req_t *req)
{
  gpio_config_t io_conf;
  char* result_array;
  int current_length = 0;
  int recvd = 0;
  cJSON* json_link;
  cJSON* link_body;
  cJSON* response_body;
  int use_index;

  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

  if ( req->content_len >= sizeof( scratch ) )
  {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
    return ESP_FAIL;
  }

  while ( current_length < req->content_len )
  {
    recvd = httpd_req_recv( req, scratch + current_length, req->content_len - current_length );

    if ( recvd <= 0 )
    {
      httpd_resp_send_err( req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value" );
      return ESP_FAIL;
    }

    current_length += recvd;
  }

  scratch[current_length] = 0;

  ESP_LOGE( TAG, "%s", scratch );

  json_link = cJSON_Parse( scratch );

  use_index = cJSON_GetObjectItem( json_link, "index" )->valueint;

  strcpy( links[use_index].name, cJSON_GetObjectItem( json_link, "name" )->valuestring );
  links[use_index].index = use_index;
  links[use_index].type = cJSON_GetObjectItem( json_link, "type" )->valueint;

  if ( use_index < link_length )
  {
    free( links[use_index].body );
  }

  switch ( links[use_index].type )
  {
    case SIMPLE_PIN:
      links[use_index].body = malloc( sizeof( SimplePin ) );

      link_body = cJSON_GetObjectItemCaseSensitive( json_link, "pin" );

      ((SimplePin*)(links[use_index].body))->num = cJSON_GetObjectItem( link_body, "num" )->valueint;

      if ( cJSON_GetObjectItem( link_body, "state" )->type == cJSON_True )
      {
        ((SimplePin*)(links[use_index].body))->state = true;
      }
      else
      {
        ((SimplePin*)(links[use_index].body))->state = false;
      }

      //disable interrupt
      io_conf.intr_type = GPIO_INTR_DISABLE;
      //set as output mode
      io_conf.mode = GPIO_MODE_OUTPUT;
      //bit mask of the pins that you want to set
      io_conf.pin_bit_mask = ( 1 << ((SimplePin*)(links[use_index].body))->num );
      //disable pull-down mode
      io_conf.pull_down_en = 0;
      //disable pull-up mode
      io_conf.pull_up_en = 0;
      //configure GPIO with the given settings
      gpio_config(&io_conf);

      if ( ((SimplePin*)(links[use_index].body))->state == true )
      {
        gpio_set_level( ((SimplePin*)(links[use_index].body))->num, 1 );
      }
      else
      {
        gpio_set_level( ((SimplePin*)(links[use_index].body))->num, 0 );
      }

      //cJSON_Delete( link_body );

      break;
    case SCHEDULED_PIN:
      break;
    case INTERRUPT_PIN:
      links[use_index].body = malloc( sizeof( InterruptPin ) );

      link_body = cJSON_GetObjectItemCaseSensitive( json_link, "interruptPin" );

      ((InterruptPin*)(links[use_index].body))->num = cJSON_GetObjectItem( link_body, "num" )->valueint;
      ((InterruptPin*)(links[use_index].body))->ms_delay = cJSON_GetObjectItem( link_body, "msDelay" )->valueint;
      ((InterruptPin*)(links[use_index].body))->response_type = cJSON_GetObjectItem( link_body, "responseType" )->valueint;

      /*
      if ( cJSON_GetObjectItem( link_body, "posEdge" )->type == cJSON_True )
      {
        ((InterruptPin*)(links[use_index].body))->pos_edge = true;
      }
      else
      {
        ((InterruptPin*)(links[use_index].body))->pos_edge = false;
      }
      */

      switch ( ((InterruptPin*)(links[use_index].body))->response_type )
      {
        case SIMPLE_PIN:
          ((InterruptPin*)(links[use_index].body))->response_body = malloc( sizeof( SimplePin ) );

          response_body = cJSON_GetObjectItemCaseSensitive( link_body, "pin" );

          ESP_LOGE( TAG, "res body %p", response_body );

          ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->num = cJSON_GetObjectItem( response_body, "num" )->valueint;

          if ( cJSON_GetObjectItem( response_body, "state" )->type == cJSON_True )
          {
            ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state = true;
          }
          else
          {
            ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state = false;
          }

          //disable interrupt
          io_conf.intr_type = GPIO_INTR_DISABLE;
          //set as output mode
          io_conf.mode = GPIO_MODE_OUTPUT;
          //bit mask of the pins that you want to set
          io_conf.pin_bit_mask = ( 1 << ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->num );
          //disable pull-down mode
          io_conf.pull_down_en = 0;
          //disable pull-up mode
          io_conf.pull_up_en = 0;
          //configure GPIO with the given settings
          gpio_config(&io_conf);

          if ( ((SimplePin*)((InterruptPin*)(links[use_index].body))->response_body)->state == true )
          {
            gpio_set_level( ((SimplePin*)(links[use_index].body))->num, 1 );
          }
          else
          {
            gpio_set_level( ((SimplePin*)(links[use_index].body))->num, 0 );
          }

          //cJSON_Delete( response_body );

          break;
        case SCHEDULED_PIN:
          break;
        case INTERRUPT_PIN:
          break;
      }

      //if ( ((InterruptPin*)(links[use_index].body))->pos_edge == true )
      //{
      io_conf.intr_type = GPIO_INTR_ANYEDGE;
      //}
      //else
      //{
        //io_conf.intr_type = GPIO_INTR_NEGEDGE;
      //}

      io_conf.mode = GPIO_MODE_INPUT;
      //bit mask of the pins that you want to set
      io_conf.pin_bit_mask = ( 1 << ((InterruptPin*)(links[use_index].body))->num );
      //disable pull-down mode
      io_conf.pull_down_en = 1;
      //disable pull-up mode
      io_conf.pull_up_en = 0;
      //configure GPIO with the given settings
      gpio_config(&io_conf);

      gpio_isr_handler_add( ((InterruptPin*)(links[use_index].body))->num, link_int_handler, use_index );

      if ( gpio_get_level( ((InterruptPin*)(links[use_index].body))->num ) == 1 )
      {
        ((InterruptPin*)(links[use_index].body))->high = true;
      }
      else
      {
        ((InterruptPin*)(links[use_index].body))->high = false;
      }

      //cJSON_Delete( link_body );

      break;
  }


  if ( use_index >= link_length )
  {
    link_length++;
  }

  cJSON_Delete( json_link );

  httpd_resp_sendstr( req, "Link created successfully" );

  return ESP_OK;
}

static const httpd_uri_t post_links =
{
  .uri       = "/links",
  .method    = HTTP_POST,
  .handler   = links_post_handler,
  /* Let's pass response string in user
   * context to demonstrate it's usage */
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1><div><video controls><source src=\"/media/big_buck_bunny.mp4\" type=\"video/mp4\"></video></div></body></html>"
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1></body></html>"
};

// post request to make a new link
static esp_err_t links_option_handler(httpd_req_t *req)
{
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "OPTIONS, GET, HEAD, POST");
  httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "*");

  httpd_resp_sendstr( req, "Fine option" );

  return ESP_OK;
}

static const httpd_uri_t option_links =
{
  .uri       = "/links",
  .method    = HTTP_OPTIONS,
  .handler   = links_option_handler,
  /* Let's pass response string in user
   * context to demonstrate it's usage */
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1><div><video controls><source src=\"/media/big_buck_bunny.mp4\" type=\"video/mp4\"></video></div></body></html>"
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1></body></html>"
};

/* An HTTP GET handler */
static esp_err_t links_get_handler(httpd_req_t *req)
{
  int i;
  char* result_array;
  cJSON* root = cJSON_CreateArray();
  cJSON* json_link;
  cJSON* link_body;
  cJSON* response_body;

  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

  for ( i = 0; i < link_length; i++ )
  {
    json_link = cJSON_CreateObject();
    cJSON_AddStringToObject( json_link, "name", links[i].name );
    cJSON_AddNumberToObject( json_link, "index", links[i].index );
    cJSON_AddNumberToObject( json_link, "type", links[i].type );

    link_body = cJSON_CreateObject();

    switch ( links[i].type )
    {
      case SIMPLE_PIN:
        cJSON_AddNumberToObject( link_body, "num", ((SimplePin*)(links[i].body))->num );
        cJSON_AddNumberToObject( link_body, "state", ((SimplePin*)(links[i].body))->state );

        cJSON_AddItemToObject( json_link, "pin", link_body );

        break;
      case SCHEDULED_PIN:
        break;
      case INTERRUPT_PIN:
        cJSON_AddNumberToObject( link_body, "num", ((InterruptPin*)(links[i].body))->num );
        cJSON_AddNumberToObject( link_body, "msDelay", ((InterruptPin*)(links[i].body))->ms_delay );
        cJSON_AddNumberToObject( link_body, "responseType", ((InterruptPin*)(links[i].body))->response_type );

        switch ( ((InterruptPin*)(links[i].body))->response_type )
        {
          case SIMPLE_PIN:
            response_body = cJSON_CreateObject();

            cJSON_AddNumberToObject( response_body, "num", ((SimplePin*)((InterruptPin*)(links[i].body))->response_body)->num );
            cJSON_AddNumberToObject( response_body, "state", ((SimplePin*)((InterruptPin*)(links[i].body))->response_body)->state );

            cJSON_AddItemToObject( link_body, "pin", response_body );

            break;
          case SCHEDULED_PIN:
            break;
          case INTERRUPT_PIN:
            break;
        }

        break;
    }

    cJSON_AddItemToArray( root, json_link );
  }

  result_array = cJSON_Print( root );
  cJSON_Delete( root );

  httpd_resp_send( req, result_array, strlen( result_array ) );

  return ESP_OK;
}

static const httpd_uri_t get_links =
{
  .uri       = "/links",
  .method    = HTTP_GET,
  .handler   = links_get_handler,
  /* Let's pass response string in user
   * context to demonstrate it's usage */
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1><div><video controls><source src=\"/media/big_buck_bunny.mp4\" type=\"video/mp4\"></video></div></body></html>"
  //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1></body></html>"
};

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, strlen(resp_str));

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGE(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1><div><video controls><source src=\"/media/big_buck_bunny.mp4\" type=\"video/mp4\"></video></div></body></html>"
    //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1></body></html>"
};

#define IS_FILE_EXT(filename, ext) \
    (strcasecmp(&filename[strlen(filename) - sizeof(ext) + 1], ext) == 0)

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filename)
{
    if (IS_FILE_EXT(filename, ".pdf"))
    {
      return httpd_resp_set_type(req, "application/pdf");
    }
    else if (IS_FILE_EXT(filename, ".html"))
    {
      return httpd_resp_set_type(req, "text/html");
    }
    else if (IS_FILE_EXT(filename, ".mp4"))
    {
      return httpd_resp_set_type(req, "video/mp4");
    }
    else if (IS_FILE_EXT(filename, ".jpeg"))
    {
      return httpd_resp_set_type(req, "image/jpeg");
    }
    else if (IS_FILE_EXT(filename, ".ico"))
    {
      return httpd_resp_set_type(req, "image/x-icon");
    }
    else if (IS_FILE_EXT(filename, ".css"))
    {
      return httpd_resp_set_type(req, "text/css");
    }
    else if (IS_FILE_EXT(filename, ".js"))
    {
      return httpd_resp_set_type(req, "text/javascript");
    }
    /* This is a limited set only */
    /* For any other type always set as plain text */
    return httpd_resp_set_type(req, "text/plain");
}

/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
static const char* get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{
    const size_t base_pathlen = strlen(base_path);
    size_t pathlen = strlen(uri);

    const char *quest = strchr(uri, '?');
    if (quest) {
        pathlen = MIN(pathlen, quest - uri);
    }
    const char *hash = strchr(uri, '#');
    if (hash) {
        pathlen = MIN(pathlen, hash - uri);
    }

    if (base_pathlen + pathlen + 1 > destsize) {
        /* Full path string won't fit into destination buffer */
        return NULL;
    }

    /* Construct full path (base + path) */
    strcpy(dest, base_path);
    strlcpy(dest + base_pathlen, uri, pathlen + 1);

    /* Return pointer to path, skipping the base */
    return dest + base_pathlen;
}

static esp_err_t asset_get_handler( httpd_req_t *req )
{
    char filepath[FILE_PATH_MAX];
    FILE *fd = NULL;
    struct stat file_stat;

    const char *filename = get_path_from_uri(filepath, "/sdcard/local_link",
                                             req->uri, sizeof(filepath));
    ESP_LOGE( TAG, "%s", filename );

    if (!filename) {
        ESP_LOGE(TAG, "Filename is too long");
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* If name has trailing '/', respond with directory contents */
    //if (filename[strlen(filename) - 1] == '/') {
        //return http_resp_dir_html(req, filepath);
    //}

    if (stat(filepath, &file_stat) == -1) {
        /* If file not present on SPIFFS check if URI
         * corresponds to one of the hardcoded paths */
        //if (strcmp(filename, "/index.html") == 0) {
            //return index_html_get_handler(req);
        //} else if (strcmp(filename, "/favicon.ico") == 0) {
            //return favicon_get_handler(req);
        //}
        ESP_LOGE(TAG, "Failed to stat file : %s", filepath);
        /* Respond with 404 Not Found */
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File does not exist");
        return ESP_FAIL;
    }

    fd = fopen(filepath, "r");
    if (!fd) {
        ESP_LOGE(TAG, "Failed to read existing file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
        return ESP_FAIL;
    }

    ESP_LOGE(TAG, "Sending file : %s (%ld bytes)...", filename, file_stat.st_size);
    set_content_type_from_file(req, filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *chunk = scratch;
    size_t chunksize;
    do {
        /* Read file in chunks into the scratch buffer */
        chunksize = fread(chunk, 1, SCRATCH_BUFSIZE, fd);

        if (chunksize > 0) {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
                fclose(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
               return ESP_FAIL;
           }
        }

        /* Keep looping till the whole file is sent */
    } while (chunksize != 0);

    /* Close file after sending complete */
    fclose(fd);
    ESP_LOGE(TAG, "File sending complete");

    /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t get_assets = {
  .uri = "/assets/*",
  .method = HTTP_GET,
  .handler = asset_get_handler,
  //.user_ctx  = "Hello World!"
};

// index
static esp_err_t index_get_handler(httpd_req_t *req)
{
  FILE *fd = NULL;
  const char* index_name = "/sdcard/local_link/index.html";

  fd = fopen( index_name, "r" );

  if (!fd) {
      ESP_LOGE(TAG, "Failed to read existing file : %s", index_name);
      /* Respond with 500 Internal Server Error */
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
      return ESP_FAIL;
  }

  //ESP_LOGE(TAG, "Sending file : %s (%ld bytes)...", index_name, file_stat.st_size);
  set_content_type_from_file(req, index_name);

  /* Retrieve the pointer to scratch buffer for temporary storage */
  char *chunk = scratch;
  size_t chunksize;
  do {
      /* Read file in chunks into the scratch buffer */
      chunksize = fread(chunk, 1, SCRATCH_BUFSIZE, fd);

      if (chunksize > 0) {
          /* Send the buffer contents as HTTP response chunk */
          if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
              fclose(fd);
              ESP_LOGE(TAG, "File sending failed!");
              /* Abort sending file */
              httpd_resp_sendstr_chunk(req, NULL);
              /* Respond with 500 Internal Server Error */
              httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
             return ESP_FAIL;
         }
      }

      /* Keep looping till the whole file is sent */
  } while (chunksize != 0);

  /* Close file after sending complete */
  fclose(fd);
  ESP_LOGE(TAG, "File sending complete");

  /* Respond with an empty chunk to signal HTTP response completion */
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

static const httpd_uri_t get_index = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1><div><video controls><source src=\"/media/big_buck_bunny.mp4\" type=\"video/mp4\"></video></div></body></html>"
    //.user_ctx  = "<!DOCTYPE html><body><h1>Hello World!</h1></body></html>"
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    config.server_port = 8080;
    config.uri_match_fn = httpd_uri_match_wildcard;

    // Start the httpd server
    ESP_LOGE(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGE(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &get_assets);
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &get_links);
        httpd_register_uri_handler(server, &post_links);
        httpd_register_uri_handler(server, &option_links);
        httpd_register_uri_handler(server, &get_index);
        return server;
    }

    ESP_LOGE(TAG, "Error starting server!");
    return NULL;
}

static void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base, 
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGE(TAG, "Stopping webserver");
        stop_webserver(*server);
        *server = NULL;
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base, 
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGE(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

void app_main()
{
  time_t now = 0;
  struct tm time_info = { 0 };
  esp_err_t ret;

  esp_vfs_fat_sdmmc_mount_config_t mount_config = {
    .format_if_mount_failed = true,
    .max_files = 20,
    .allocation_unit_size = 16 * 1024
  };

  // SPI
  sdmmc_host_t host = SDSPI_HOST_DEFAULT();

  spi_bus_config_t bus_cfg = {
    .mosi_io_num = PIN_NUM_MOSI,
    .miso_io_num = PIN_NUM_MISO,
    .sclk_io_num = PIN_NUM_CLK,
    .quadwp_io_num = -1,
    .quadhd_io_num = -1,
    .max_transfer_sz = 4092,
  };

  ret = spi_bus_initialize( host.slot, &bus_cfg, SPI_DMA_CHAN );

  if ( ret != ESP_OK ) {
    ESP_LOGE( TAG, "Failed to initialize bus." );
    return;
  }

  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = host.slot;

  ret = esp_vfs_fat_sdspi_mount( "/sdcard", &host, &slot_config, &mount_config, NULL );

  if (ret != ESP_OK) {
    if (ret == ESP_FAIL) {
      ESP_LOGE(TAG, "Failed to mount filesystem. "
        "If you want the card to be formatted, set format_if_mount_failed = true.");
    } else {
      ESP_LOGE(TAG, "Failed to initialize the card (%s). "
        "Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
    }

    return;
  }

  if ( d_issi_INIT() < 0 )
  {
    ESP_LOGE( TAG, "Failed to init issi ram" );

    return;
  }

  gpio_install_isr_service( 0 );

  static httpd_handle_t server = NULL;
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
  server = start_webserver();

  wifi_init_sta();

  sntp_setoperatingmode( SNTP_OPMODE_POLL );
  sntp_setservername( 0, "pool.ntp.org" );
  sntp_init();

  do {
    vTaskDelay( pdMS_TO_TICKS( 1000 ) );
    time( &now );
    localtime_r( &now, &time_info );
  } while ( time_info.tm_year < (2016 - 1900) );

  //create a queue to handle gpio event from isr
  link_event_queue = xQueueCreate(10, sizeof(uint32_t));
  //start gpio task
  xTaskCreate( link_event_task, "link_event_task", 2048, NULL, 10, NULL );

  ESP_LOGE( TAG, "Starting init" );
  if ( d_minitor_INIT() < 0 )
  {
    ESP_LOGE( TAG, "Failed to init" );

    while ( 1 )
    {
    }
  }

  ESP_LOGE( TAG, "Starting service" );
  if ( d_setup_onion_service( 8080, 80, "/sdcard/test_service" ) < 0 )
  {
    ESP_LOGE( TAG, "Failed to setup hidden service" );
  }

/*
  v_test_setup_issi();
  v_test_d_traverse_hsdir_relays_in_order();

  v_test_setup_fd_tree();
  v_test_d_traverse_hsdir_relays_from_fd_in_order();
*/
}
