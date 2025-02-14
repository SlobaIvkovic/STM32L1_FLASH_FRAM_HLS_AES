#include "fram_memory.h"

/*
Opis:
Potrebno je napisati drajver za FRAM memoriju.
U brojilu se nalazi eksterna FRAM memorija MB85RS256A. Na mikrokontroler je povezana preko SPI magistrale.
Iskoristen je SPI1 mikrokontrolera na pinovima:
PA_5 - SCLK
PA_6 - MISO
PA_7 - MOSI
PA_11 - SS
Potrebno je obezbediti funkcije za rad sa FRAM memorijom.

Funkcije potrebne za rad sa SPI periferijom mikrokontrolera potraziti u fajlu stm32l1xx_hal_spi.c i odgovarajucem .h fajlu.

Ispod se nalaze zaglavlja funkcija koje je potrebno implementirati. Prototipi ovih funkcija nalaze se u fajlu profile_generic.h.
Sve ostale funkcije koje su pomocne i koriste se samo unutar ovog fajla treba deklarisati kao static a njihova zaglavlja napisati
na vrhu ovog c fajla.
*/

#define SELECT_FRAM_MEMORY			HAL_GPIO_WritePin(GPIOA, GPIO_PIN_11, GPIO_PIN_RESET)
#define DESELECT_FRAM_MEMORY		HAL_GPIO_WritePin(GPIOA, GPIO_PIN_11, GPIO_PIN_SET)

#define SPI_TIMEOUT 10U

#define WREN  0x06
#define WRDI  0x04
#define RDSR  0x05
#define WRSR  0x01
#define READ  0x03
#define WRITE 0x02

static SPI_HandleTypeDef hspi;


static Bbool InitSPImodule(SPI_HandleTypeDef* hspi);
static void HAL_SPI_MspInit(SPI_HandleTypeDef *hspi);
static Bbool WriteEnable(void);

/*******************************************************************************
* Function Name  	: InitSPImodule
* Description    	: Funkcija inicijalizuje SPI modul neophodan za komunikaciju sa FRAM memorijom
* Arguments				: hspi - handle SPI periferije
* Return Value    : TRUE  - ako je SPI periferija uspesno inicijalizovana
                    False - ako periferija nije uspesno inicijalizovana
										
*******************************************************************************/
static Bbool InitSPImodule(SPI_HandleTypeDef* hspi)
{
	hspi->Instance         = SPI1;
	hspi->Init.Mode        = SPI_MODE_MASTER; // SPI_MODE_MASTER (0x00000004 | 0x00000100) MSTR | SSI
	                                          // Slave select internal, ovaj bit ima efekta samo ako je SSM bit postavljen
	
  hspi->Init.Direction   = SPI_DIRECTION_2LINES; // 0x00000000
	hspi->Init.DataSize    = SPI_DATASIZE_8BIT;    // 0x00000000
	hspi->Init.CLKPolarity = SPI_POLARITY_LOW;     // 0x00000000 CLK 0 idle, FLASH radi u oba SPI moda
	                                               // idle clk moze biti i 0 i 1, EN25QH16 strana 8
	
	hspi->Init.CLKPhase    = SPI_PHASE_1EDGE;      // Flash uzorkuje podatke na rastucoj ivici, a slanje pocinje na padajucoj
	                                               // SPI_PHASE_1EDGE(0x00000000) SPI_POLARITY_LOW(0x00000000)
	                                               // master pocinje slanje na padajucoj slejv uzorkuje na rastucoj (str 753 i 8)
	                                          
	hspi->Init.NSS         = SPI_NSS_SOFT;         // 0x00000200, NSS pin je slobodan za druge namene

	hspi->Init.FirstBit = SPI_FIRSTBIT_MSB;
	hspi->Init.TIMode   = SPI_TIMODE_DISABLED;
	hspi->Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;
	
	if(HAL_SPI_Init(hspi) != HAL_OK)
	{
		return FALSE;
	}
	return TRUE;
}

/*******************************************************************************
* Function Name  	: HAL_SPI_MspInit
* Description    	: Inicijalizuje nize resurse potrebne za rad SPI periferije
* Arguments				: hspi - handle SPI periferije
* Return Value    : \
										
*******************************************************************************/
static void HAL_SPI_MspInit(SPI_HandleTypeDef *hspi)
{
	__SPI1_CLK_ENABLE();
	__GPIOA_CLK_ENABLE();
	
	GPIO_InitTypeDef gpioInitStruct; 
	gpioInitStruct.Pin  = GPIO_PIN_5 | GPIO_PIN_6 | GPIO_PIN_7;
	gpioInitStruct.Mode = GPIO_MODE_AF_PP;
	gpioInitStruct.Pull = GPIO_PULLUP;
	gpioInitStruct.Alternate = GPIO_AF5_SPI1;
	HAL_GPIO_Init(GPIOA, &gpioInitStruct);
	
	gpioInitStruct.Pin = GPIO_PIN_11;
	gpioInitStruct.Mode = GPIO_MODE_OUTPUT_PP;
	HAL_GPIO_Init(GPIOA, &gpioInitStruct);
	
}


/*******************************************************************************
* Function Name  	: WriteEnable
* Description    	: Funkcija omogucava upisu FRAM, pre svakog upisa ova funkcija mora biti pozvana
* Arguments				: \
* Return Value    : TRUE  - upis je omogucen
                    FALSE - upis nije omogucen, dogodila se greska
										
*******************************************************************************/
static Bbool WriteEnable()
{
	uint8_t command = WREN;
  SELECT_FRAM_MEMORY;
	HAL_SPI_Transmit(&hspi, &command, 1, SPI_TIMEOUT);
	DESELECT_FRAM_MEMORY;
	return TRUE;
	
// Odkomentarisati za debugging potrebe, 	
/*	command = RDSR;
	SELECT_FRAM_MEMORY;
	HAL_SPI_Transmit(&hspi, &command, 1, SPI_TIMEOUT);
	HAL_SPI_Receive(&hspi, &command, 1, SPI_TIMEOUT);
	DESELECT_FRAM_MEMORY;
	if(command & 0x02)
	{
		return TRUE;
	}
	return FALSE;
*/	
}


/*******************************************************************************
* Function Name  	: ReadFramMemory
* Description    	: Funkcija cita trazeni broj bajtova iz eksterne FRAM memorije. 
* Arguments				: address - Adresa u FRAM memoriji od koje pocinje citanje
										buffer - pokazivac na niz bajtova gde procitani sadrzaj treba da se upise
										len - broj bajtova koje treba procitati iz FRAM memorije
* Return Value    : /
*******************************************************************************/
void ReadFramMemory(uint16_t address, uint8_t* buffer, uint16_t len)
{
	uint8_t commandSequence[3];
	commandSequence[0] = READ;
	commandSequence[1] = address >> 8;
	commandSequence[2] = address;
	
	SELECT_FRAM_MEMORY;
	HAL_SPI_Transmit(&hspi, commandSequence, sizeof(commandSequence), SPI_TIMEOUT);
	HAL_SPI_Receive(&hspi, buffer, len, SPI_TIMEOUT);
	DESELECT_FRAM_MEMORY;
}

/*******************************************************************************
* Function Name  	: WriteFramMemory
* Description    	: Funkcija upisuje niz bajtova iz u eksternu FRAM memoriju od zeljene adrese. 
* Arguments				: address - Adresa u FRAM memoriji od koje pocinje upis
										buffer - pokazivac na niz bajtova gde je pripremljen niz koji se upisuje u FRAM.
										len - broj bajtova koje treba upisati u FRAM
* Return Value    : /
*******************************************************************************/
void WriteFramMemory(uint16_t address, uint8_t* buffer, uint16_t len)
{
	WriteEnable();
	
	uint8_t commandSequence[3]; 
	commandSequence[0] = WRITE;
	commandSequence[1] = address >> 8;
	commandSequence[2] = address;
	
	SELECT_FRAM_MEMORY;
	HAL_SPI_Transmit(&hspi, commandSequence, sizeof(commandSequence), SPI_TIMEOUT);
	HAL_SPI_Transmit(&hspi, buffer, len, SPI_TIMEOUT);
	DESELECT_FRAM_MEMORY;
}

/*******************************************************************************
* Function Name  	: InitFramMemory
* Description    	: Funkcija inicijalizuje FRAM memoriju. Predvidjena je da se pozove jednom po ukljucenju
										brojila.
* Arguments				: /
* Return Value    : TRUE - ako je FRAM memorija uspesno inicijalizovana
										FALSE - ako FRAM memorija nije uspesno inicijalizovana
*******************************************************************************/
Bbool InitFramMemory(void)
{
	DESELECT_FRAM_MEMORY;             // Osigurati da FRAM na pocetku bude deselektovan
	if(InitSPImodule(&hspi) == TRUE)
	{
		return TRUE;
	}
	return FALSE;
}


