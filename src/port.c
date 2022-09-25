#include "../h/port.h"

#include "../h/core.h"
#include "../h/connections.h"
#include "../h/consensus.h"

bool b_create_core_task( MinitorTask* handle )
{
  return xTaskCreatePinnedToCore(
    v_minitor_daemon,
    "MINITOR_DAEMON",
    7168,
    NULL,
    7,
    handle,
    tskNO_AFFINITY
  );
}

bool b_create_connections_task( MinitorTask* handle )
{
  return xTaskCreatePinnedToCore(
    v_connections_daemon,
    "CONNECTIONS_DAEMON",
    3072,
    NULL,
    6,
    handle,
    tskNO_AFFINITY
  );
}

bool b_create_poll_task( MinitorTask* handle )
{
  return xTaskCreatePinnedToCore(
    v_poll_daemon,
    "POLL_DAEMON",
    2048,
    NULL,
    8,
    handle,
    tskNO_AFFINITY
  );
}

bool b_create_local_connection_handler( MinitorTask* handle, void* local_connection )
{
  return xTaskCreatePinnedToCore(
    v_handle_local_connection,
    "LOCAL_HANDLER",
    2048,
    NULL,
    8,
    handle,
    tskNO_AFFINITY
  );
}

bool b_create_fetch_task( MinitorTask* handle, void* consensus )
{
  return xTaskCreatePinnedToCore(
    v_handle_relay_fetch,
    "H_RELAY_FETCH",
    3072,
    consensus,
    7,
    handle,
    tskNO_AFFINITY
  );
}

bool b_create_insert_task( MinitorTask* handle, void* consensus )
{
  return xTaskCreatePinnedToCore(
    v_handle_crypto_and_insert,
    "H_CRYPTO_INSERT",
    3072,
    consensus,
    8,
    handle,
    tskNO_AFFINITY
  );
}
