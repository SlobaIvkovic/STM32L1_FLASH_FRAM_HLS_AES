#ifndef FRAM_MEMORY_H
#define FRAM_MEMORY_H

#include "stm32l1xx_hal.h"
#include "mc_types.h"

/* Function prototypes: */
void ReadFramMemory(uint16_t address, uint8_t* buffer, uint16_t len);
void WriteFramMemory(uint16_t address, uint8_t* buffer, uint16_t len);
Bbool InitFramMemory(void);

#endif /* FRAM_MEMORY_H */
