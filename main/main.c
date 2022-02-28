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

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/apps/sntp.h"

#include "wifi_connect.h"
#include "minitor.h"

#include "test/circuit.h"

#include <esp_event.h>
#include "esp_netif.h"
/* #include "protocol_examples_common.h" */
#include <esp_http_server.h>

static const char* TAG = "MAIN";

/*
#define SPI_DMA_CHAN 1
#define PIN_NUM_MISO 4
#define PIN_NUM_MOSI 15
#define PIN_NUM_CLK  14
#define PIN_NUM_CS   13
*/

#define SPI_DMA_CHAN 1
#define PIN_NUM_MISO 19
#define PIN_NUM_MOSI 23
#define PIN_NUM_CLK  18
#define PIN_NUM_CS   4

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
    .user_ctx  = "Hello World!"
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

    // Start the httpd server
    ESP_LOGE(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGE(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &hello);
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

  /* sdmmc_card_t* card; */

  // SPI
  sdmmc_host_t host = SDSPI_HOST_DEFAULT();

  spi_bus_config_t bus_cfg = {
    .mosi_io_num = PIN_NUM_MOSI,
    .miso_io_num = PIN_NUM_MISO,
    .sclk_io_num = PIN_NUM_CLK,
    .quadwp_io_num = -1,
    .quadhd_io_num = -1,
    .max_transfer_sz = 4000,
  };

  ret = spi_bus_initialize( host.slot, &bus_cfg, SPI_DMA_CHAN );

  if ( ret != ESP_OK ) {
    ESP_LOGE( TAG, "Failed to initialize bus." );
    return;
  }

  sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
  slot_config.gpio_cs = PIN_NUM_CS;
  slot_config.host_id = host.slot;

  /* ret = esp_vfs_fat_sdspi_mount( "/sdcard", &host, &slot_config, &mount_config, &card ); */
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

  /* sdmmc_card_print_info( stdout, card ); */

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

  /* int err; */
  /* int sock_fd; */
  /* struct sockaddr_in dest_addr; */

  /* dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" ); */
  /* dest_addr.sin_family = AF_INET; */
  /* dest_addr.sin_port = htons( 8080 ); */

  /* sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP ); */

  /* if ( sock_fd < 0 ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( TAG, "couldn't create a socket to the local port" ); */
/* #endif */

    /* return -1; */
  /* } */

  /* err = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) ); */

  /* if ( err != 0 ) { */
/* #ifdef DEBUG_MINITOR */
    /* ESP_LOGE( TAG, "couldn't connect to the local port" ); */
/* #endif */

    /* return -1; */
  /* } */

  v_minitor_INIT();

  OnionService* test_service = px_setup_hidden_service( 8080, 80, "/sdcard/test_service" );

  /* int free_before; */
  /* int free_after; */

  /* free_before = heap_caps_get_free_size( MALLOC_CAP_8BIT ); */

  /* d_test_circuit_memory_leak( 30 ); */

  /* free_after = heap_caps_get_free_size( MALLOC_CAP_8BIT ); */

  /* ESP_LOGE( TAG, "start mem: %d", free_before ); */
  /* ESP_LOGE( TAG, "end mem: %d", free_after ); */
  /* ESP_LOGE( TAG, "total diff mem: %d", free_before - free_after ); */

  /* free_before = heap_caps_get_free_size( MALLOC_CAP_8BIT ); */

  /* d_test_circuit_memory_leak_truncate( 30 ); */

  /* free_after = heap_caps_get_free_size( MALLOC_CAP_8BIT ); */

  /* ESP_LOGE( TAG, "start mem: %d", free_before ); */
  /* ESP_LOGE( TAG, "end mem: %d", free_after ); */
  /* ESP_LOGE( TAG, "total diff mem: %d", free_before - free_after ); */
}
