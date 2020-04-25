#ifndef MINITOR_MINITOR_H
#define MINITOR_MINITOR_H

#include "../h/structures/onion_service.h"
#include "../h/structures/circuit.h"

int v_minitor_INIT();
OnionService* px_setup_hidden_service( unsigned short local_port, unsigned short exit_port, const char* onion_service_directory );

#endif
