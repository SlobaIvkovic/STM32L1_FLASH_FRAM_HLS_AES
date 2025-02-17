#ifndef FLASH_MEMORY_H
#define FLASH_MEMORY_H

#include "stm32l1xx_hal.h"
#include "mc_types.h"



/* Function prototypes: */
McStatus_TypeDef ReadFlashMemory(uint32_t address, uint8_t* buffer, uint16_t len);
McStatus_TypeDef WriteFlashMemory(uint32_t address, uint8_t* buffer, uint16_t len);
McStatus_TypeDef ReadFlashDeviceId(uint8_t* deviceId);
McStatus_TypeDef ReadFlashManufacturerId(uint8_t* manufacturerId);
McStatus_TypeDef ReadFlashSize(uint32_t* flashSize);
McProcessState_TypeDef EraseFlashSector4KB(uint32_t address, uint32_t timeout);
McProcessState_TypeDef EraseFlashBlock64KB(uint32_t address, uint32_t timeout);
McProcessState_TypeDef FlashChipErase(uint32_t timeout);
void InitFlashMemory(void);


#endif /* FLASH_MEMORY_H */
