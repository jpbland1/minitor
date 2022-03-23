#ifndef ISSI_MODEL_H
#define ISSI_MODEL_H

#include "driver/spi_master.h"

#define ISSI_DMA 2
#define ISSI_CS 22
#define ISSI_CLK 16
#define ISSI_MOSI 21
#define ISSI_MISO 17

#define ISSI_READ 0x03
#define ISSI_WRITE 0x02
#define ISSI_ESDI 0x3b
#define ISSI_ESQI 0x38
#define ISSI_RSTDQI 0xff
#define ISSI_RDMR 0x05
#define ISSI_WRMR 0x01

extern spi_device_handle_t issi_spi;

int d_issi_INIT();

#endif
