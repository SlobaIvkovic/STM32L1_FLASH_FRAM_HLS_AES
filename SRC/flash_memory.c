#include "flash_memory.h"

/*
Opis:
Potrebno je implementirati drajver FLES memoriju.
U brojilu se nalazi eksterna FLES memorija EN25QH16B. Na mikrokontroler je povezana preko SPI magistrale.
Iskoristen je SPI1 mikrokontrolera na pinovima:
PA_5 - SCLK
PA_6 - MISO
PA_7 - MOSI
PC_4 - SS
Potrebno je obezbediti funkcije za rad sa fles memorijom.

Potrebno je voditi racuna o tome da brisanje sektora, bloka ili celog cipa traje previse dugo da bi program stajao 
u mestu dok se to ne zavrsi. Zbog toga funkcije koje brisu sektor, blok ili citavu memoriju moraju da budu realizovane
u vidu masine stanja. Ove funkcije ce se iz ostatka firmvera pozivati uzastopno tako da se izvrsavanje procesa koji ju
je pozvao nastavlja tek kad ona zavrsi posao, ali za to vreme daje se mogucnost preostalim procesima da se izvrsavaju.
S obzirom na cinjenicu da se ostali procesi izvrsavaju dok proces koji je zatrazio brisanje ceka, moze se desiti da neki 
drugi proces koji se izvrsava isto pozove neku od funkcija koje rade sa fles memorijom. Zbog toga sve funkcije ovog
drajvera imaju povratnu vrednost MC_FLASH_TEMPORARY_BUSY koju vracaju u slucaju da je FLES memorija trenutno zauzeta i treba
sacekati.

Funkcije potrebne za rad sa SPI periferijom mikrokontrolera potraziti u fajlu stm32l1xx_hal_spi.c i odgovarajucem .h fajlu.

Ispod se nalaze zaglavlja funkcija koje je potrebno implementirati. Prototipi ovih funkcija nalaze se u fajlu profile_generic.h.
Sve ostale funkcije koje su pomocne i koriste se samo unutar ovog fajla treba deklarisati kao static a njihova zaglavlja napisati
na vrhu ovog c fajla.
*/

#define SELECT_FLASH_MEMORY			HAL_GPIO_WritePin(GPIOC, GPIO_PIN_4, GPIO_PIN_RESET)
#define DESELECT_FLASH_MEMORY		HAL_GPIO_WritePin(GPIOC, GPIO_PIN_4, GPIO_PIN_SET)

#define SPI_TIMEOUT 10U

// Komande
#define RSTEN (uint8_t)0x66  // Reset enable
#define RST   (uint8_t)0x99  // Reset 
#define PP    (uint8_t)0x02  // Page program
#define WE    (uint8_t)0x06  // Write enable
#define RS    (uint8_t)0x05  // Read status register
#define SE    (uint8_t)0x20  // Sector erase
#define BE    (uint8_t)0xD8  // Block erase
#define CE    (uint8_t)0xC7  // Chip erase
#define MD    (uint8_t)0x90  // Read manufacturer/device Id 
#define SFDP  (uint8_t)0x5A  //
#define RD    (uint8_t)0x03  // Read data

#define TRUE  1
#define FALSE 0

#define STATE_0 0
#define STATE_1 1

#define STATE_1_OK        (uint8_t)0
#define STATE_1_ERROR     (uint8_t)1

#define FINAL_STATE_CHECK_OK    (uint8_t)0
#define FINAL_STATE_CHECK_ERROR (uint8_t)1

#define checkBusy() if(flash.mcStatus == MC_FLASH_TEMPORARY_BUSY)\
											return MC_FLASH_TEMPORARY_BUSY;               // Sve funkcije proveravaju da li je memorija zauzeta
                                                                    // checkBusy() makro samo skracuje pisanje

#define shortenTimeout() if(timeout < (HAL_GetTick() - tickstart))\
	                          timeout = 0;\
                          else timeout -= HAL_GetTick() - tickstart;

typedef struct
{
	McStatus_TypeDef       mcStatus;
	McProcessState_TypeDef mcProcessState;
	
}McFlash_TypeDef;


// Globalne promenljive
static McFlash_TypeDef flash;
static SPI_HandleTypeDef hspi;


// SPI funkcije
static void HAL_SPI_MspInit(SPI_HandleTypeDef *hspi);
static void InitSPImodule(SPI_HandleTypeDef *hspi);


// Pomocne funkcije
// Funkcije stanja procesa brisanja
static McProcessState_TypeDef SwitchEraseStates(uint8_t* state, uint32_t address, uint32_t timeout, uint8_t command);
static uint8_t FlashEraseTransitionToState1(uint32_t address, uint32_t timeout, uint8_t command);
static uint8_t FlashEraseTransitionToFinalState(uint32_t timeout, uint8_t* status);

// Ostale pomocne funkcije
static McStatus_TypeDef SendWriteCommand(uint8_t* commandSequence, uint16_t commandSize, uint8_t* buff, uint16_t buffSize, uint32_t timeout);
static McStatus_TypeDef FlashWriteEnable(uint8_t timeout);
static McStatus_TypeDef ReadFlash(uint8_t* commandSequence, uint16_t sequenceSize, uint32_t timeout, uint8_t* read, uint16_t readSize);
static McStatus_TypeDef ReadManufacturerDeviceId(uint8_t ManuDev, uint8_t* Id);



// Definicije funkcija

/*******************************************************************************
* Function Name  	: FlashWriteEnable
* Description    	: Pre svakog upisa u flash ili brisanja bloka, sektora ili celog cipa
                    potrebno je omoguciti upis u flash, funkcija salje WE komandu i cita
										status registar kako bi utvrdila da li je upis omogucen.
* Arguments				: timeout - timeout funkcije brisanja koja poziva ovu funkciju.
* Return Value    : MC_STATUS_OK ako je upis omogucen
                    MC_STATUS_ERROR ako WE komanda nije poslata uspesno ili je stanje stanje
										status registra i dalje takvo da upis nije omogucen (WEL = 0).
										
*******************************************************************************/
static McStatus_TypeDef FlashWriteEnable(uint8_t timeout)
{
	uint8_t sequence = WE;
	uint8_t status;
	
	// send WE instruction
	if(SendWriteCommand(&sequence, 1, NULL, 0, SPI_TIMEOUT) == MC_STATUS_OK)
	{
		// read status register
		SELECT_FLASH_MEMORY;
		sequence = RS;
		if(HAL_SPI_Transmit(&hspi, &sequence, sizeof(sequence), SPI_TIMEOUT) == HAL_OK)
		{
			if(HAL_SPI_Receive(&hspi, &status, sizeof(status), SPI_TIMEOUT) == HAL_OK)
			{
				DESELECT_FLASH_MEMORY;
				if(status & 0x02)
				{
					return MC_STATUS_OK;
				}
				return MC_STATUS_ERROR;
			}
			DESELECT_FLASH_MEMORY;
			return MC_STATUS_ERROR;
		}
		DESELECT_FLASH_MEMORY;
		return MC_STATUS_ERROR;
	}
	return MC_STATUS_ERROR;
}

/*******************************************************************************
* Function Name  	: SendWriteCommand 
* Description    	: Funkcija salje komndu upisa u FLASH, u zavisnotsi od potrebe komanda moze biti
                    bilo koja od komandi PP, CE, SE, BE, ova funkcija ne cita podatke iz FLASH memorije
                    i osigurava da je FLASH deselktovan nakon upisa
* Arguments				: commandSequence - moze biti samo komanda ili komnda na koju je dodata adresa
                    commandSize     - velicina komande koja se salje putem SPI periferije
                    buff            - ako se upisuju podaci u FLASH ovo je pokazivac na niz koji se upisuje
                    buffsize        - velicina podataka koji se upisuju
                    timeout         - timeout funkcije koja poziva ovu funkciju
* Return Value    : MC_STATUS_OK    - komanda i podaci su uspesno poslati
                    MC_STATUS_ERROR - doslo je do greske prilikom transfera komande i podataka
										
*******************************************************************************/
static McStatus_TypeDef SendWriteCommand(uint8_t* commandSequence, uint16_t commandSize, uint8_t* buff, uint16_t buffSize, uint32_t timeout)
{
	SELECT_FLASH_MEMORY;
	if(HAL_SPI_Transmit(&hspi, commandSequence, commandSize, SPI_TIMEOUT) == HAL_OK)
	{
		if(buff != NULL)
		{
			if(HAL_SPI_Transmit(&hspi, buff, buffSize, SPI_TIMEOUT) == HAL_OK)
			{
				DESELECT_FLASH_MEMORY;
				return MC_STATUS_OK;
			}
			DESELECT_FLASH_MEMORY;
			return MC_STATUS_ERROR;
		}
		DESELECT_FLASH_MEMORY;
		return MC_STATUS_OK;
	}
	DESELECT_FLASH_MEMORY;
	return MC_STATUS_ERROR;
}

static McStatus_TypeDef ReadFlash(uint8_t* commandSequence, uint16_t sequenceSize, uint32_t timeout, uint8_t* read, uint16_t readSize)
{
	SELECT_FLASH_MEMORY;
	if(HAL_SPI_Transmit(&hspi, commandSequence, sequenceSize, SPI_TIMEOUT) == HAL_OK)
	{
		if(HAL_SPI_Receive(&hspi, read, readSize, SPI_TIMEOUT) == HAL_OK)
		{
			DESELECT_FLASH_MEMORY;
			return MC_STATUS_OK;
		}
		DESELECT_FLASH_MEMORY;
		return MC_STATUS_ERROR;
	}
	DESELECT_FLASH_MEMORY;
	return MC_STATUS_ERROR;
}

/*******************************************************************************
* Function Name  	: ReadManufacturerDeviceId
* Description    	: U zavisnosti od parametra ManuDev, funkcija vraca identifikaciju proizvodjaca ili uredjaja
* Arguments				: ManuDev - moze biti 0 ili 1, ako je 0 vraca identifikaciju proizvodjaca, ako je 1 vraca identifikaciju uredjaja
* Return Value    : MC_STATUS_OK    - komanda i prijem su uspesno izvrseni
                    MC_STATUS_ERROR - doslo je do greske
										
*******************************************************************************/
static McStatus_TypeDef ReadManufacturerDeviceId(uint8_t ManuDev, uint8_t* id)
{
	uint8_t commandSequence [4];
	commandSequence[0] = MD;
	commandSequence[1] = 0xAA,   // dummy byte
	commandSequence[2] = 0xAA;   // dummy byte
	commandSequence[3] = ManuDev;
	uint8_t rData[2];
	
	SELECT_FLASH_MEMORY;
	if(HAL_SPI_Transmit(&hspi, commandSequence, sizeof(commandSequence), SPI_TIMEOUT) == HAL_OK)
	{
		if(HAL_SPI_Receive(&hspi, rData, sizeof(rData), SPI_TIMEOUT) == HAL_OK)
		{
			DESELECT_FLASH_MEMORY;
			(*id) = rData[0];
			return MC_STATUS_OK;
		}
		else
		{
			DESELECT_FLASH_MEMORY;
			return MC_STATUS_ERROR;
		}
	}
	
	DESELECT_FLASH_MEMORY;
  return MC_STATUS_ERROR;
}


// Sve funkcije brisanja mogu biti u stanju 0 ili stanju 1. Iz tog razloga sve funkcije brisanja pozivaju ovu funkciju
// koja proverava u kom je stanju proces brisanja. U stanju 0 ukoliko flash memorija nije zauzeta funkcija salje 
// flash memoriji jednu od komandi CE, BE ili SE i u slucaju uspesnog slanja komande funkcija zakljucava flash memoriju
// tako sto funkciji koja ju je pozvala (npr EraseFlashSector4KB) dodeljuje stanje 1(samim tim i kontrolu nad memorijom) 
// i pamti adresu koja se brise, funkcija koja ima kontrolu nad memorijom za vreme trajanja procesa brisanja adrese
// moze biti ponovno pozivana samo sa adresom koja se trenutno brise, u suprotnom funkcija ce vratiti MC_PROCESS_IN_PROGRESS.
static McProcessState_TypeDef SwitchEraseStates(uint8_t* state, uint32_t address, uint32_t timeout, uint8_t command)
{
	int i;
	uint8_t status;
	static uint32_t tickstart;
	static uint32_t lockAddress;    // Adresa pri kojoj funkcija moze biti pozvana u stanju 1 ako je addressLocked == 1
	static uint8_t addressLocked;   // Oznacava da je odredjena adresa zakljucana i da funkcija u stanju 1 moze biti pozvana samo za tu adresu

	/*****************************************************************************************************
	                                     FUNKCIJA BRISANJA JE U STANJU 0
	******************************************************************************************************/
	
	if((*state) == STATE_0)
	{
		 // proveriti zauzetost                // Ako je funkcija u stanju STATE_0, proveriti da li je memorija slobodna
		if(flash.mcStatus == MC_FLASH_TEMPORARY_BUSY)
		{
			return MC_PROCESS_TEMPORARY_BUSY;
		}
		else
		{
			tickstart = HAL_GetTick();
			// poslati komande SE, BE ili CE komandu
			if(FlashEraseTransitionToState1(address, timeout, command) == STATE_1_OK)  // Funkcija prelaza iz stanja 0 u stanje 1
			{
				if((timeout == 0) || (HAL_GetTick() - tickstart) > timeout)
				{
					// proveriti Tajmaut na prelasku iz stanja 0 u stanje 1,
					return MC_PROCESS_TIMEOUT_EXPIRED;
				}
				// u slucaju uspeha zauzeti memoriju, promeniti stanje, vratiti MC_PROCESS_IN_PROGRESS, 
				// funkcija brisanja je nadalje u stanju 1
				flash.mcStatus = MC_FLASH_TEMPORARY_BUSY;
				flash.mcProcessState = MC_PROCESS_IN_PROGRESS;
				*state = STATE_1;
				lockAddress = address;             // Zakljucati adresu, funkcija u stanju 1 moze biti pozvana samo sa ovom adresom
				addressLocked = TRUE;
				shortenTimeout();
				//return MC_PROCESS_IN_PROGRESS;
				
			}
			else // dogodila se SPI greska
			{
				tickstart = 0;
				return MC_PROCESS_ERROR;
			}
			
		}
	}

	/*****************************************************************************************************
	                                     FUNKCIJA BRISANJA JE U STANJU 1
	******************************************************************************************************/
	if(*state == STATE_1)
	{
		// Proveriti da li je funkcija pozvana sa istom adresom, sa adresom cije je brisanje u toku
		if(lockAddress != address && addressLocked == TRUE)
		{
			return MC_PROCESS_TEMPORARY_BUSY;
		}
		if(FlashEraseTransitionToFinalState(timeout, &status) == FINAL_STATE_CHECK_OK)
		{
			if((timeout == 0) || (HAL_GetTick() - tickstart) > timeout)
		  {
				// proveriti Tajmaut na prelasku iz stanja 1
				tickstart = 0;
				*state = 0;
				addressLocked = FALSE;
				flash.mcProcessState = MC_PROCESS_TIMEOUT_EXPIRED;
				flash.mcStatus = MC_STATUS_OK;
				return MC_PROCESS_TIMEOUT_EXPIRED;
			}
			// Argument status primice vrednost status registra flash memorije
			else if(status & 0x01)
			{	                                  // ako je WIP bit postavljen, proces brisanja je u toku
				return MC_PROCESS_IN_PROGRESS;
			}
			else                                      // Proces brisanja nije u toku,
			{                                         // brisanje je zavrseno, funkcija je postigla finalno stanje      
				addressLocked = FALSE;                  // osloboditi adresu
				flash.mcProcessState = MC_PROCESS_DONE; // dozvoliti drugim funkcijama pristup flash memoriji
				flash.mcStatus = MC_STATUS_OK;
				*state = STATE_0;                         // resetovati stanje 
				tickstart = 0;
				return MC_PROCESS_DONE;
			}
			
		}
		else
		{
			tickstart = 0;
			*state = 0;
			addressLocked = FALSE;
			flash.mcProcessState = MC_PROCESS_ERROR;
			flash.mcStatus = MC_STATUS_ERROR;
			return MC_PROCESS_ERROR;
		}
	}	
	return MC_PROCESS_DONE;
}

/*******************************************************************************
* Function Name  	:  FlashEraseTransitionToState1
* Description    	:  Funkcija prevodi proces brisanja iz stanja 0 u stanje 1

* Arguments				:  address - adresa u flash memoriji koja se brise
                     timeout - tajmaut funkcije brisanja koja poziva prelaznu funkciju
                     command - Zavisno od toga koja funkcija brisanja poziva prelaznu
                               funkciju ovaj argument moze biti CE, SE ili BE

* Return Value    : STATE_1_ERROR - dogodila se greska prilikom slanja komandi za brisanje
                    STATE_1_ok    - steceni su uslovi da funkcija brisanja predje na stanje 1
										
*******************************************************************************/
static uint8_t FlashEraseTransitionToState1(uint32_t address, uint32_t timeout, uint8_t command)
{
	if(FlashWriteEnable(timeout) != MC_STATUS_OK)
	{
		return STATE_1_ERROR;
	}

	uint8_t tData[4];                          // drzi komandu i adresu koje se salju preko SPI periferija
	tData[0] = command;
	
	if(command != CE)                         // CE komanda ne zahteva adresu, za SE i BE komande mora se poslati i adresa
	{	
		// little endian format, najmanje znacajan bajt je na najnizoj adresi
		tData[1] = address >> 16;                  // prvo poslati najznacajniji bajt
		tData[2] = (address >> 8) & 0x000000FF;
		tData[3] = address & 0x000000FF;
	}
	
	SELECT_FLASH_MEMORY;
	// Ako je komanda CE 3. parametar HAL_SPI_Transmit(duzina) je 1 jer se salje samo CE komanda
	// U suprotnom 3. parametar je 4 jer se salje komanda i 3 bajta adrese
	if(command != CE)
	{
		if(HAL_SPI_Transmit(&hspi, tData, 4, SPI_TIMEOUT) != HAL_OK)
		{
			DESELECT_FLASH_MEMORY;
			return STATE_1_ERROR;
		}
		DESELECT_FLASH_MEMORY;
		return STATE_1_OK;             // Zadovoljeni su uslovi da funkcija brisanja predje na stanje 1
		
	}
  else if(HAL_SPI_Transmit(&hspi, tData, 1, SPI_TIMEOUT) != HAL_OK)
	{
		DESELECT_FLASH_MEMORY;
		return STATE_1_ERROR;
	}
	  DESELECT_FLASH_MEMORY;
		return STATE_1_OK;             // Zadovoljeni su uslovi da funkcija brisanja predje na stanje 1
}

/*******************************************************************************
* Function Name  	: FlashEraseTransitionToFinalState
* Description    	: Funkcija cita sadrzaj status registra FLASH memorije 
* Arguments				: timeout - timeout procesa brisanja
                    status  - uzima sadrzaj status registra FLASH memorije
* Return Value    : FINAL_STATE_CHECK_OK    - ako su steceni uslovi za proveru zavrsetka procesa brisanja
                    FINAL_STATE_CHECK_ERROR - ukoliko je doslo do greske
										
*******************************************************************************/
static uint8_t FlashEraseTransitionToFinalState(uint32_t timeout, uint8_t* status)
{
	uint8_t command = RS;
	
	SELECT_FLASH_MEMORY;	
	if(HAL_SPI_Transmit(&hspi, &command, 1, SPI_TIMEOUT) != HAL_OK)
	{
		DESELECT_FLASH_MEMORY;
		return FINAL_STATE_CHECK_ERROR;
	}
	if(HAL_SPI_Receive(&hspi, status, 1, SPI_TIMEOUT) != HAL_OK)
	{
		DESELECT_FLASH_MEMORY;
		return FINAL_STATE_CHECK_ERROR;
	}
	DESELECT_FLASH_MEMORY;
	return FINAL_STATE_CHECK_OK;                // steceni su uslovi za proveru finalnog stanja funkcije brisanja
}


/*******************************************************************************
* Function Name  	: HAL_SPI_MspInit
* Description    	: Funkcija inicijalizuje nize resurse neophodne za rad SPI1 periferije. 
* Arguments				: *hspi - handle SPI periferije
* Return Value    : /
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
	
	gpioInitStruct.Pin = GPIO_PIN_4;
	gpioInitStruct.Mode = GPIO_MODE_OUTPUT_PP;
	HAL_GPIO_Init(GPIOA, &gpioInitStruct);	
}


static void InitSPImodule(SPI_HandleTypeDef *hspi)
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
	hspi->Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_256;
	hspi->Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;
	
	HAL_SPI_Init(hspi);
}


/*******************************************************************************
* Function Name  	: ReadFlashMemory
* Description    	: Funkcija cita trazeni broj bajtova iz eksterne FLES memorije. 
* Arguments				: address - Adresa u FLES memoriji od koje pocinje citanje
										buffer - pokazivac na niz bajtova gde procitani sadrzaj treba da se upise
										len - broj bajtova koje treba procitati iz fles memorije
* Return Value    : MC_STATUS_OK - funkcija je izvrsena
										MC_FLASH_TEMPORARY_BUSY - FLES memorija je trenutno zauzeta, treba pokusati kasnije
*******************************************************************************/
McStatus_TypeDef ReadFlashMemory(uint32_t address, uint8_t* buffer, uint16_t len)
{
	checkBusy();
	
	
	uint8_t sequence[4] = {RD, address >> 16, address >> 8, address};
	
	if(ReadFlash(sequence, sizeof(sequence), SPI_TIMEOUT, buffer, len) == MC_STATUS_OK);
	{
		return MC_STATUS_OK;
	}
	
}

/*******************************************************************************
* Function Name  	: WriteFlashMemory
* Description    	: Funkcija upisuje niz bajtova u FLES memoriju od zeljene adrese. 
* Arguments				: address - Adresa u FLES memoriji od koje pocinje upis
										buffer - pokazivac na niz bajtova gde se nalazi sadrzaj koji treba upisati
										len - broj bajtova koje treba upisati
* Return Value    : MC_STATUS_OK - ako je upis prosao uspesno
										MC_STATUS_ERROR - ako je upis bio neuspesan
										MC_FLASH_TEMPORARY_BUSY - FLES memorija je trenutno zauzeta, treba pokusati kasnije
*******************************************************************************/
McStatus_TypeDef WriteFlashMemory(uint32_t address, uint8_t* buff, uint16_t len)
{
	checkBusy();
	uint8_t status;
	uint8_t command = RS;
	
	uint16_t pageRest = 0;
	uint8_t firstIndex = 0;
	uint32_t writtenBytes = 0;
	uint16_t bytesToWrite;
	uint16_t lenRest = len;
	
	if(FlashWriteEnable(SPI_TIMEOUT) != MC_STATUS_OK)
	{
		return MC_STATUS_ERROR;
	}
	
	while(writtenBytes != len)
	{
		if(FlashWriteEnable(SPI_TIMEOUT) != MC_STATUS_OK)
	{
		return MC_STATUS_ERROR;
	}
		
		uint8_t sequence[4] = {PP, address >> 16, address >> 8, address};
		if(address != 0)
		{	
			pageRest = (address/256+1)*256 - address;
		}
		else
		{
			pageRest = 256;
		}
		if(lenRest > pageRest)
		{
			bytesToWrite = pageRest;
		}
    else
		{
			bytesToWrite = lenRest;
		}			
		if(SendWriteCommand(sequence, sizeof(sequence), &buff[firstIndex], bytesToWrite, SPI_TIMEOUT) == MC_STATUS_OK)
		{
			do
			{
				ReadFlash(&command, 1, SPI_TIMEOUT, &status, 1);
			}while(status & 0x01);
		}
		else
		{
			return MC_STATUS_ERROR;
		}
		
		lenRest -= bytesToWrite;
		address += bytesToWrite;
		writtenBytes += bytesToWrite;
		firstIndex += bytesToWrite;
	}
	
	return MC_STATUS_OK;
	
}

/*******************************************************************************
* Function Name  	: ReadFlashDeviceId
* Description    	: Funkcija cita jedan bajt koji predstavlja Device Id eksterne FLES memorije.
* Arguments				: deviceId - pokazivac na bajt gde ce biti upisan Device Id FLES memorije
* Return Value    : MC_STATUS_OK - funkcija je izvrsena
										MC_FLASH_TEMPORARY_BUSY - FLES memorija je trenutno zauzeta, treba pokusati kasnije
*******************************************************************************/
McStatus_TypeDef ReadFlashDeviceId(uint8_t* deviceId)
{
	if(flash.mcStatus == MC_FLASH_TEMPORARY_BUSY)
	{
		return MC_FLASH_TEMPORARY_BUSY;
	}
	
	return ReadManufacturerDeviceId(1, deviceId);
	
}

/*******************************************************************************
* Function Name  	: ReadFlashManufacturerId
* Description    	: Funkcija cita jedan bajt koji predstavlja Manufacturer Id eksterne FLES memorije.
* Arguments				: manufacturerId - pokazivac na bajt gde ce biti upisan Manufacturer Id FLES memorije
* Return Value    : MC_STATUS_OK - funkcija je izvrsena
										MC_FLASH_TEMPORARY_BUSY - FLES memorija je trenutno zauzeta, treba pokusati kasnije
*******************************************************************************/
McStatus_TypeDef ReadFlashManufacturerId(uint8_t* manufacturerId)
{
	if(flash.mcStatus == MC_FLASH_TEMPORARY_BUSY)
	{
		return MC_FLASH_TEMPORARY_BUSY;
	}
	
	return ReadManufacturerDeviceId(0, manufacturerId);
}

/*******************************************************************************
* Function Name  	: ReadFlashSize
* Description    	: Funkcija cita kapacitet FLES memorije.
* Arguments				: flashSize - pokazivac na 4-bajtnu lokaciju gde ce biti upisana velicina fles memorije 
																procitana iz cipa. TODO: definisati u cemu je izrazena velicina.
* Return Value    : MC_STATUS_OK - funkcija je izvrsena
										MC_FLASH_TEMPORARY_BUSY - FLES memorija je trenutno zauzeta, treba pokusati kasnije										
*******************************************************************************/
McStatus_TypeDef ReadFlashSize(uint32_t* flashSize)
{
	// Informacija o velicini memorije izrazenoj u bitovima nalazi se na adresi 24 i prostire se do adrese 27
	// na adresi 27 je najznacajniji bajt (str 45.)
	// Nakon slanja sadrzaja sa adrese 24 flash memorija salje sadrzaj sledecih adresa sve dok je CS = 0 (str 43.)
	if(flash.mcStatus == MC_FLASH_TEMPORARY_BUSY)
	{
		return MC_FLASH_TEMPORARY_BUSY;
	}
	
  uint8_t read[4];
	uint8_t sequence[5] = {SFDP, 0x24 >> 16, 0x24 >> 8, 0x24, 0xAA};    // Komanda + 3 bajta adresa + 1 dummy bajt
	if(ReadFlash(sequence, sizeof(sequence), SPI_TIMEOUT, read, sizeof(read)) == MC_STATUS_OK)
	{
		*flashSize = (uint32_t)read[0] | (uint32_t)read[1] << 8 | (uint32_t)read[2] << 16;
		return MC_STATUS_OK;		
	}
	return MC_STATUS_ERROR;
}

/*******************************************************************************
* Function Name  	: EraseFlashSector4KB
* Description    	: Funkcija brise sektor od 4KB kome pripada dostavljena adresa.
										S obzirom da brisanje traje neko vreme za koje ostali procesi u brojilu ne smeju da cekaju
										ova funkcija mora biti realizovana kao masina stanja. Ona ce biti pozivana vise puta i
										sve dok je brisanje u toku ona treba da vraca MC_PROCESS_IN_PROGRESS. Kada se brisanje 
										uspesno zavrsi funkcija vraca MC_PROCESS_DONE. Ako istekne vreme definisano argumentom 
										timeout funkcija treba da vrati vrednost MC_PROCESS_TIMEOUT_EXPIRED. Ako dodje do neke
										greske funkcija vraca MC_PROCESS_ERROR.
										Potrebno je obezbediti da dok je memorija zauzeta, jer je u toku brisanje, preostale 
										funkcije ukoliko budu pozvane vracaju vrednost MC_FLASH_TEMPORARY_BUSY.
* Arguments				: address - adresa unutar sektora koji se brise
										timeout - timeout u ms
* Return Value    : MC_PROCESS_IN_PROGRESS - ako izvrsavanje jos traje
										MC_PROCESS_DONE - ako je M-Bus uredjaj uspesno instaliran
										MC_PROCESS_ERROR - ako M-Bus uredjaj nije uspesno instaliran
										MC_PROCESS_TIMEOUT_EXPIRED - ako postupak nije zavrsen a istekao je zadati timeout									
*******************************************************************************/
McProcessState_TypeDef EraseFlashSector4KB(uint32_t address, uint32_t timeout)
{
	static uint8_t state;                    // Trenutno stanje Procesa brisanja sektora	
	
	return SwitchEraseStates(&state, address, timeout, SE);		
}

/*******************************************************************************
* Function Name  	: EraseFlashBlock64KB
* Description    	: Funkcija brise blok od 64KB kome pripada dostavljena adresa.
										S obzirom da brisanje traje neko vreme za koje ostali procesi u brojilu ne smeju da cekaju
										ova funkcija mora biti realizovana kao masina stanja. Ona ce biti pozivana vise puta i
										sve dok je brisanje u toku ona treba da vraca MC_PROCESS_IN_PROGRESS. Kada se brisanje 
										uspesno zavrsi funkcija vraca MC_PROCESS_DONE. Ako istekne vreme definisano argumentom 
										timeout funkcija treba da vrati vrednost MC_PROCESS_TIMEOUT_EXPIRED. Ako dodje do neke
										greske funkcija vraca MC_PROCESS_ERROR.
										Potrebno je obezbediti da dok je memorija zauzeta, jer je u toku brisanje, preostale 
										funkcije ukoliko budu pozvane vracaju vrednost MC_FLASH_TEMPORARY_BUSY.
* Arguments				: address - adresa unutar sektora koji se brise
										timeout - timeout u ms
* Return Value    : MC_PROCESS_IN_PROGRESS - ako izvrsavanje jos traje
										MC_PROCESS_DONE - ako je M-Bus uredjaj uspesno instaliran
										MC_PROCESS_ERROR - ako M-Bus uredjaj nije uspesno instaliran
										MC_PROCESS_TIMEOUT_EXPIRED - ako postupak nije zavrsen a istekao je zadati timeout									
*******************************************************************************/
McProcessState_TypeDef EraseFlashBlock64KB(uint32_t address, uint32_t timeout)
{
	static uint8_t state;                    // Trenutno stanje Procesa brisanja sektora
                  
	return SwitchEraseStates(&state, address, timeout, BE); // funkcija menja stanje ako dodje do promene
}                                                         // funkcija vraca McProcessState_TypeDef

/*******************************************************************************
* Function Name  	: FlashChipErase
* Description    	: Funkcija brise ceo sadrzaj FLES memorije.
										S obzirom da brisanje traje neko vreme za koje ostali procesi u brojilu ne smeju da cekaju
										ova funkcija mora biti realizovana kao masina stanja. Ona ce biti pozivana vise puta i
										sve dok je brisanje u toku ona treba da vraca MC_PROCESS_IN_PROGRESS. Kada se brisanje 
										uspesno zavrsi funkcija vraca MC_PROCESS_DONE. Ako istekne vreme definisano argumentom 
										timeout funkcija treba da vrati vrednost MC_PROCESS_TIMEOUT_EXPIRED. Ako dodje do neke
										greske funkcija vraca MC_PROCESS_ERROR.
										Potrebno je obezbediti da dok je memorija zauzeta, jer je u toku brisanje, preostale 
										funkcije ukoliko budu pozvane vracaju vrednost MC_FLASH_TEMPORARY_BUSY.
* Arguments				: timeout - timeout u ms
* Return Value    : MC_PROCESS_IN_PROGRESS - ako izvrsavanje jos traje
										MC_PROCESS_DONE - ako je M-Bus uredjaj uspesno instaliran
										MC_PROCESS_ERROR - ako M-Bus uredjaj nije uspesno instaliran
										MC_PROCESS_TIMEOUT_EXPIRED - ako postupak nije zavrsen a istekao je zadati timeout									
*******************************************************************************/
McProcessState_TypeDef FlashChipErase(uint32_t timeout)
{
	static uint8_t state;                    // Trenutno stanje Procesa brisanja sektora
	
	return SwitchEraseStates(&state, 0, timeout, CE);
}

/*******************************************************************************
* Function Name  	: InitFlashMemory
* Description    	: Funkcija vrsi inicijalizaciju fles memorije jednom po ukljucenju brojila ukoliko
										je to potrebno.
* Arguments				: /
* Return Value    : /									
*******************************************************************************/
void InitFlashMemory(void)
{
	InitSPImodule(&hspi);
	
	uint8_t tData = RSTEN;
	SELECT_FLASH_MEMORY;
	if(HAL_SPI_Transmit(&hspi, (uint8_t*)&tData, 1, SPI_TIMEOUT) != HAL_OK)  // Reset enable
	{
		DESELECT_FLASH_MEMORY;
		// Upravljanje greskom
	}
	DESELECT_FLASH_MEMORY;
	
	tData = RST;
	SELECT_FLASH_MEMORY;
	if(HAL_SPI_Transmit(&hspi, (uint8_t*)&tData, 1, SPI_TIMEOUT) != HAL_OK)  // Reset flash memory
	{
		DESELECT_FLASH_MEMORY;
		// Upravljanje greskom
	}
	DESELECT_FLASH_MEMORY;
}

/*******************************************************************************
* Function Name  	: 
* Description    	:  
* Arguments				: 
* Return Value    : 
										
*******************************************************************************/
