#include "hls_aes128.h"


#define CALCULATION_OK    0
#define CALCULATION_ERROR 1

#define CRYPT_OK          0
#define CRYPT_ERROR       1

#define AUTH_ONLY           0x10
#define AUTH_AND_ENCRYPTION 0x30
#define AUTH_KEY_SIZE       16
#define SC_AK               17

#define BLOCK_SIZE 16

#define STR_N_COPY(b, str1, str2, len)    do{\
	                                            for(b = 0; b < len; b++)\
	                                            {\
																								str1[b] = str2[b];\
																							}\
                                            }while(0)

/****************************************************************************
* Function name: CreateIVarray
* Description  : Funkcija sluzi za inicijalizaciju polja Init.pInit strukture CRYP_HandleTypeDef.
                 Koristeci niz od 128 elemenata na sukcesivnim adresama bice upisani bajtovi koji
								 cine invocation counter registar (cine ga 4 registra IV0-IV3 sirkoki po 32 bita)
								 invocation counter registar cine nonce(registri IV3-IV1) i brojac (registar IV0)
								 nonce cini system title (registri IV3-IV2) i invocation counter (registar IV1),
								 sve ovo postize se tako sto se polju Init.pInit dodeli adresa niza koji sadrzi
								 potrebne elemente invocation counter registra rasporedjene na sledeci nacin:
								 prvih 4 bajta niza sistemTitle idu u elemente niza iv[0] - iv[3], a drugih u
								 iv[4]-iv[7], u elemente iv[8][11] pakuje se invocation counter tako da najmanje 
								 znacajan bajt invocationCounter ide na najvisu adresu iv[11] , i na kraju u polja
								 iv[12]-iv[15] pakuje se brojac.
* Arguments    : systemTitle       - 64 najznacajnija bita invocation counter registra
                 invocationCounter - sledecih 32 bita invocation counter registra
                 
***************************************************************************************************/
static void CreateIVarray(uint8_t iv[], uint8_t* systemTitle, uint32_t* invocationCounter, uint32_t counter)
{
	uint8_t i;
	for(i = 0; i < 8; i++)
	{
		iv[i] = *systemTitle;
		systemTitle++;
	}
	
	uint8_t* invocationCounterP = (uint8_t*)invocationCounter;
	for(i = 11; i >= 8; i--)
	{
		iv[i] = *invocationCounterP;
		invocationCounterP++;
	}
	iv[15] = (uint8_t)counter;
	iv[14] = (uint8_t)(counter >> 8);
	iv[13] = (uint8_t)(counter >> 16);
	iv[12] = (uint8_t)(counter >> 24);
}

/*
static void inc32(uint8_t iv[])
{
	uint32_t* p = (uint32_t*)&iv[12];
	(*p)++;
	uint8_t* p1 = (uint8_t*)p;

	iv[12] = *p1;
	p1++;
	iv[13] = *p1;
	p1++;
	iv[14] = *p1;
	p1++;
	iv[15] = *p1;
	
}
*/

/****************************************************************************
* Function name: SwapBytes
* Description  : Neophodna funkcija za pravilno prosledjivanje niza bilo kojoj od HAL funkcija
                 za enkripciju ili dekripciju. Funkcija u serijama od po 4 bajta menja mesta 
								 elementima niza, prvom i cetvrtom i drugom i trecem
* Arguments    : array     - niz kome se zamenjuju bajtovi
                 arraySize - duzina niza
                 
*****************************************************************************/
static void SwapBytes(uint8_t* array, uint16_t arraySize)
{
	uint8_t pom;
	uint8_t i;
	for(i = 0; i < arraySize; i += 4)
	{
		pom = array[i];
		array[i] = array[i+3];
		array[i+3] = pom;
		pom = array[i + 1];
		array[i + 1] = array[i + 2];
		array[i + 2] = pom;
	}
}

/****************************************************************************
* Function name: XorBlocks
* Description  : Vrsi XOR operaciju nad dva bloka duzine 128 bita
* Arguments    : result - pokazivac na niz u koji se smesta rezultat XOR operacije
                 block1 - prvi operand XOR operacije
                 block2 - drigo operand XOR operacije
                 
*****************************************************************************/
static void XorBlocks(uint8_t* result, uint8_t* block1, uint8_t* block2)
{
	uint8_t i;
	for(i = 0; i < 16; i++)
	{
		result[i] = block1[i] ^ block2[i];
	}
}

/****************************************************************************
* Function name: ShiftBits 
* Description  : Jedan korak HASH funkcije, odnosno funkcije mnozenja blokova
                 zahteva da se bitovi jednog bloka pomere za 1 mesto u desno.
* Arguments    : block - niz koji drzi blok kome se pomeraju bitovi
                 
*****************************************************************************/
static void ShiftBits(uint8_t block[])
{
	uint8_t i;
	for(i = 15; i > 0; i--)
	{
		block[i] = (block[i] >> 1) | ((block[i - 1] & 0x01) << 7);
	}
	block[0] = block[0] >> 1;
}

/****************************************************************************
* Function name: BlocksMultiplication
* Description  : Vrsi mnozenje dva bloka od 128 bita koje se odvija u okviru HASH funkcije
* Arguments    : x - pokazivac na niz prvog bloka, u ovaj niz se smesta i rezultat mnozenja
                 y - pokazivac na niz drugog bloka
                 
*****************************************************************************/
static void BlocksMultiplication(uint8_t* x, uint8_t* y)
{
	uint8_t i, j;
	uint8_t z[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; // Z = 0^128
	uint8_t v[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	ShiftBits(z);                           
	XorBlocks(z, z, v);
	for(i = 0; i < 16; i++)                            // V = Y
	{
		v[i] = y[i];
	}
	uint8_t r[16] = {0xE1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	for(i = 0; i < 16; i++)
	{
		for(j = 0; j < 8; j++)
		{
			if(x[i] & (0x80 >> j))
			{
				// xor z with v, XorBlocks();
				XorBlocks(z, z, v);
			}
			// shift v bits to the right, ShiftBits();
						
			if(v[15] & 0x01) // 
			{
				ShiftBits(v);
				// xor v and r
				XorBlocks(v, v, r);
			}
			else
			{
				ShiftBits(v);
			}
		}		
	}
	for(i = 0; i < 16; i++)
	{
		x[i] = z[i];
	}
}

/****************************************************************************
* Function name: Len
* Description  : Formira niz od 16 bajtova koga cine duzina AAD podataka izrazena u bitovima i
                 duzina enkriptovanog teksta takodje izrazena u bitovima
* Arguments    : len[]  - pokazivac na niz koji sadrzi len(AAD) || len(C)
                 lenAAD - duzina AAD podataka
                 lenC   - duzina enkriptovanog teksta
                 
*****************************************************************************/
static void Len(uint8_t len[], uint32_t lenAAD, uint32_t lenC)
{
	uint8_t i;
	uint8_t k = 24;           
	lenAAD = lenAAD * 8;          // izraziti duzinu AAD u bitovima
	lenC = lenC * 8;              // izraziti duzinu enkriptovanog teksta u bitovima
	for(i = 0; i < 4; i++)
	{
		len[i] = 0;
	}
	for(i = 4; i < 8; i++)
	{
		len[i] = lenAAD >> k;
		k -= 8;
	}
	for(i = 8; i < 12; i++)
	{
		len[i] = 0;
	}
	k = 24;
	for(i = 12; i < 16; i++)
	{
		len[i] = lenC >> k;
		k -= 8;
	}
}

/****************************************************************************
* Function name: PopulateAAD
* Description  : Formira niz AAD podataka koji cine securityControlByte i authenticationKey u slucaju
                 autentikacije i enkripcije, ili securityControlByte, authenticationKey i plainText u slucaju
                 kada se vrsi samo autentikacija.
* Arguments    : aad               - niz koji drzi AAD podatke za koje se proracunava tag
                 controlByte       - zauzima prvo mesto u nizu aad
                 authenticationKey - sledecih 16 bajtova zauzima authenticationKey
                 plaintext         - U slucaju autentikacije bez enkripcije ovaj niz zauzima pozicije u nastavku
                                     U slucaju enkripcije i autentikacije ova funkcija se poziva sa parametrom 
                                     plaintext = NULL
                 plaintextLen      - duzina neenkriptovanog teksta, u slucaju autentikacije i enkripcije ova funkcija
                                     se poziva sa parametrom plaintextLen = 0
                 
*****************************************************************************/
static void PopulateAAD(uint8_t* aad, uint8_t controlByte, uint8_t* authenticationKey, uint8_t* plaintext, uint32_t plaintextLen)
{
	uint8_t i;
	aad[0] = controlByte;
	for(i = 1; i < SC_AK; i++)
	{
		aad[i] = authenticationKey[i - 1];
	}
	// ako je funkcija pozvana sa parametrom plaintextLen = 0 ovaj deo se ne izvrsava
	for(i = SC_AK; i < SC_AK + plaintextLen; i++)
	{
		aad[i] = plaintext[i - SC_AK]; 
	}
}

/****************************************************************************
* Function name: HashParts
* Description  : funkcija izvrsava delove HASH funkcije:
                 deo:
                 Xi = (Xi-1 ^ Ai) * H, i = 1,2,...,m-1
                 Xi = (Xi-1 ^ (Ai||0^(128-v))) * H, i = m
                 ili deo:
                 Xi = (Xi-1 ^ Ci) * H, i = m+1,...,n-1
                 Xi = (Xi-1 ^ (Cn||0^(128-u))) * H, i = m + n

         
                 gde je m ukupan broj blokova A(dodatnih podataka), n ukupan broj blokova C(sifrovanog teksta),
                 duzina poslednjeg Ai bloka (Am) iznosi v, duzina poslednjeg C bloka iznosi u. Funkcija ne izvrsava
                 zavrsni korak HASH funkcije. Prvi korak HASH funkcije (x0 = 0^128) vrsi se neposredno pre poziva ove funkcije.
* Arguments    : x          - odgovara Xi parametru HASH funkcije, 
                 xorOperand - odgovara Ai i Ci parametrima HASH funkcije zavisno od toga koji se deo HASH funkcije izvrsava,
                 h          - hash subkey, odgovara H parametru. 
                 dataLen    - odgovara parametrima u i v, zavisno od toga koji se deo HASH funkcije vrsi.
                 numberOfCompleteBlocks - ukupan broj celih blokova A ili C niza
                 
*****************************************************************************/
static void HashParts(uint8_t x[], uint8_t xorOperand[], uint8_t h[], uint32_t dataLen, uint32_t numberOfCompleteBlocks)
{
	uint8_t k, j = 0, i;
	for(i = 0; i < numberOfCompleteBlocks; i++)
	{
		for(k = 0; k < 16; k++)
		{		
			x[k] = x[k] ^ xorOperand[j + k]; // x je duzine 16 bajta (128 bita) u svakom koraku x se XORuje sa sledecim blokom aad
	
		}
		BlocksMultiplication(x, h);
		j += 16;
	}
	if(dataLen % 16 != 0)
	{
		// incomplete block size
		uint8_t incBs = dataLen % BLOCK_SIZE;
		//	uint8_t incBs = (17 + dataLen) % 16;
		// incomplete block begin
		uint8_t incBb = BLOCK_SIZE * numberOfCompleteBlocks;
		uint8_t rest[BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		for(i = 0; i < incBs; i++)
		{
			rest[i] = xorOperand[incBb + i];
		}
		for(i = 0; i < BLOCK_SIZE; i++)
		{
			x[i] = x[i] ^ rest[i];
		}
		BlocksMultiplication(x, h);
	}

}

/****************************************************************************
* Function name: CalculateTag 
* Description  : Funkcija u zavisnosti od vrednosti argumenta securityControlByte proracunava authenticationTag.
                 Funkcija provacunava tag i za slucaj enkripcije i autentikacija i za slucaj autentikacije bez
                 enkripcije.
* Arguments    : data              - moze biti pokazivac na niz ciphertext ili na niz plaintext, zavisno od toga da li se 
                                     vrsi samo autentikacija ili i enkripcija i autentikacija
                 dataLen           - duzina palintext ili ciphertext
                 authenticationKey - pokazivac na niz od 16 bajtova koji zajedno sa securityControlByte(koji dolazi na prvo mesto)
                                     cine prvih 17 bajtova aad niza dodatnih podataka za autentikaciju.
                 encryptionKey     - pokazivac na niz od 16 bajtova gde se nalazi encryptionKey
                 systemTitle       - systemTitle, zauzece prvih 8 bajtova iv niza (invocation vector)
                 invocationCounter - vrednost argumenta zauzece sledeca 4 bajta iv niza
                 authenticationTag - pokazivac na niz od 12 bajtova u koji se smesta proracunati tag
                 securityControlByte - dolazi na prvo mesto aad niza
                 
*****************************************************************************/
static uint8_t CalculateTag(uint8_t* data,
												    uint32_t dataLen,
												    uint8_t* authenticationKey,
  											    uint8_t* encryptionKey,
  										    	uint8_t* systemTitle,
												    uint32_t* invocationCounter,
												    uint8_t* authenticationTag,
												    uint8_t securityControlByte)
{
	uint8_t i;

	uint8_t x[BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; // za funkciju mnozenja polja
	                                                           // prvi korak HASH funkcije X0 = 0^128
	
	uint8_t h[BLOCK_SIZE];                                     // hash subkey
	uint8_t kY0[BLOCK_SIZE];                                   // drzace rezultat operacie E(K, Y0)
	
	uint32_t numberOfCompleteBlocksAAD;
	uint32_t numberOfCompleteBlocksC = dataLen / 16;
	
	uint32_t aadLen;
//	uint8_t securityControl = AUTH_ONLY;           // samo za testiranje
	uint8_t aad[SC_AK + dataLen];             //[dataLen + 17], u najgorem slucaju treba odvojiti 17 + broj bajtova
	                                          // plaintexta za ovaj niz
	
	if(securityControlByte == AUTH_ONLY)
	{	
		// Slucaj kada se vrsi autentikacija bez enkripcije
		// ulazni niz podataka AAD = SC || AK || plaintext
		numberOfCompleteBlocksAAD = (SC_AK + dataLen)/16;     // broj celih blokova(od 128 bita) AAD podataka
                                                                 		
		aadLen = SC_AK + dataLen;  // aadLen = BLOCK_SIZE + 1 + dataLen kontrol bajt odlucuje
	// AAD podatke za koje se proracunava tag, cini jedan kontrolni bajt,
	// 16 bajtova kljuca za autentikaciju (authentication key) i ostatak plaintext, ukupno 17 + plaintextLen
		
		PopulateAAD(aad, securityControlByte, authenticationKey, data, dataLen );
	}
	else if(securityControlByte == AUTH_AND_ENCRYPTION)
	{
		// U slucaju autentikacije i enkripcije niz plainText ne ulazi u sastav AAD,
		// tako da se se funkcija PopulateAAD poziva sa parametrima plaintext = NULL i plaintextLen = 0
		numberOfCompleteBlocksAAD = 1;
		aadLen = SC_AK;                            // aadLen = 17  kontrol bajt odlucuje

		PopulateAAD(aad, securityControlByte, authenticationKey, NULL, 0);
	}
	else
	{
		return CALCULATION_ERROR;
	}
	
	// Inicijalizacija AES periferije
	CRYP_HandleTypeDef hcryp;
	hcryp.Instance = AES;
	uint8_t iv[16];                                             //

	CreateIVarray(iv, systemTitle, invocationCounter, 1);       // Dobija se Y0
//	inc32(iv);
	HAL_CRYP_DeInit(&hcryp);
	hcryp.Init.pInitVect = iv;
	hcryp.Init.DataType = CRYP_DATATYPE_32B;
	hcryp.Init.pKey = encryptionKey;
	HAL_CRYP_Init(&hcryp);
	
	// Generate hash subkey, E(K,0^128), ukupna duzina x je 128 bita (jedan blok) inicijalna vrednost bitova je 0
	if(HAL_CRYP_AESECB_Encrypt(&hcryp, x, 16, h, 10) != HAL_OK)
	{
		return CALCULATION_ERROR;
	}
	SwapBytes(iv, sizeof(kY0));
	if(HAL_CRYP_AESECB_Encrypt(&hcryp, iv, 16, kY0, 10) != HAL_OK) // Neophodno da bi se proracunao tag
	{                                                              // Neophodno za korak, T = MSBt(GHASH(H, A, C) ^ E(K, Y0))
		return CALCULATION_ERROR;
	}
	SwapBytes(kY0, sizeof(kY0));
	SwapBytes(h, sizeof(h));

	// Deo HASH funkcije koji radi sa dodatnim podacima A(aad)
	// (Xi ^ Ai)*H
	HashParts(x, aad, h, aadLen, numberOfCompleteBlocksAAD);
	// Deo HASH funkcije koji radi sa sifrovanim tekstom C(data)
	// (Xi ^ Ci)*H
	if(securityControlByte  != AUTH_ONLY)
	{
		HashParts(x, data, h, dataLen, numberOfCompleteBlocksC);
	}
	else
	{
		dataLen = 0;
	}
	
	uint8_t len[BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	Len(len, aadLen, dataLen); 
  // Zavrsni korak HASH funkcije Xi = (Xm+n ^ (len(A)||len(C))) * H, i = m + n + 1
	XorBlocks(x, x, len);
	BlocksMultiplication(x, h);
	// Kraj zavrsnog koraka HASH funkcije
	
	//T = MSBt(GHASH(H, A, C) ^ E(K, Y0))
	XorBlocks(x, x, kY0);	
	for(i = 0; i < 12; i++)
	{
		authenticationTag[i] = x[i];
	}
	return CALCULATION_OK;
}

/****************************************************************************
* Function name: Encrypt
* Description  : Ovu funkciju pozivaju funkcije Aes128EncryptPlaintext i Aes128EncryptAndAuthenticatePlaintext
                 funkcija vrsi enkripciju argumenta plaintext i rezultat enkripcije smesta u niz ciphertext.
                 Funkcija ima iste argumente kao i Aes128EncryptPlaintext, jedina razlika je u tome sto ova 
                 funkcija ne vrsi promenu vrednosti invocationCountera.
* Arguments    : plaintext - pokazivac na niz gde se nalazi ulazni podatak koji treba enkriptovati
								 ciphertext - pokazivac na niz gde se nalazi enkriptovani niz koji ce funkcija kreirati
								 plaintextLen - duzina niza na koji pokazuje argument plaintext. Ista duzina ce biti i niza ciphertext.
								 encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
								 systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
								 invocationCounter - pokazivac na 32-bitni broj u kome se nalazi Invocation Counter
* Return value : CRYPT_OK    - ako je enkripcija uspesno izvrsena
                 CRYPT_ERROR - ako enkripcija nije uspesno izvrsena
                 
*****************************************************************************/
static uint8_t Encrypt(uint8_t* plaintext, uint8_t* ciphertext, uint32_t plaintextLen,
                       uint8_t* encryptionKey, uint8_t* systemTitle, uint32_t* invocationCounter)
{	
	CRYP_HandleTypeDef hcryp;
	hcryp.Instance = AES;
	uint8_t iv[16];
	uint8_t rest[16];
	uint8_t plainCopy[plaintextLen + plaintextLen%4];
	uint8_t cipherCopy[plaintextLen + plaintextLen%4];
	uint8_t i;

	CreateIVarray(iv, systemTitle, invocationCounter, 2);
//	inc32(iv);
	HAL_CRYP_DeInit(&hcryp);
	hcryp.Init.pInitVect = iv;
	hcryp.Init.DataType = CRYP_DATATYPE_32B;
	hcryp.Init.pKey = encryptionKey;
	HAL_CRYP_Init(&hcryp);
	
	STR_N_COPY(i, plainCopy, plaintext, plaintextLen);
	SwapBytes(plainCopy, plaintextLen);
	if(plaintextLen % 16 == 0)
	{	
		if(HAL_CRYP_AESCTR_Encrypt(&hcryp, plainCopy, (uint16_t)plaintextLen, cipherCopy, 10) == HAL_OK)
		{
			SwapBytes(cipherCopy, plaintextLen);
			STR_N_COPY(i, ciphertext, cipherCopy, plaintextLen);
			return CRYPT_OK;
		}
		return CRYPT_ERROR;
	}
	if(HAL_CRYP_AESCTR_Encrypt(&hcryp, plainCopy, plaintextLen - (plaintextLen % BLOCK_SIZE), cipherCopy, 10) == HAL_OK)
	{
		SwapBytes(plainCopy, plaintextLen);
		SwapBytes(cipherCopy, plaintextLen);
		
		// formirati Yn
		CreateIVarray(iv, systemTitle, invocationCounter, 2 + plaintextLen / 16);

		HAL_CRYP_DeInit(&hcryp);
		HAL_CRYP_Init(&hcryp);
		SwapBytes(iv, sizeof(iv));
		if(HAL_CRYP_AESECB_Encrypt(&hcryp, iv, 16, rest, 10) == HAL_OK)
		{
			SwapBytes(rest, 16);
			for(i = 0; i < plaintextLen%16; i++)
			{
				cipherCopy[plaintextLen -1 - i] = plainCopy[plaintextLen - 1 - i] ^  rest[(plaintextLen % 16) -1 - i];
			}
			STR_N_COPY(i, ciphertext, cipherCopy, plaintextLen);
			return CRYPT_OK;
		}
		return CRYPT_ERROR;
	}	
	return CRYPT_ERROR;
}

/****************************************************************************
* Function name: Decrypt
* Description  : Ovu funkciju pozivaju funkcije Aes128DecryptCiphertext i Aes128DecryptAndCheckAuthenticationTag,
                 funkcija vrsi dekripciju argumenta ciphertext i rezultat enkripcije smesta u niz plaintext.
                 Funkcija ima iste argumente kao i Aes128DecryptPlaintext izuzev argumenta lowestAcceptableInvocationCounter
                 jer ova funkcija ne vrsi promenu najnize prihvatljive vrednosti invocation countera, promenu vrednosti 
                 vrse gore navedene funkcije.

* Arguments    : ciphertext - pokazivac na niz gde se nalazi ulazni podatak koji treba dekriptovati
								 plaintext - pokazivac na niz gde ce funkcija upisati dekriptovani sadrzaj, duzina mu je jednaka kao i za ciphertext 
								 ciphertextLen - duzina niza na koji pokazuje argument ciphertext. Ista duzina ce biti i niza plaintext.
								 encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
								 systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
								 invocationCounter - 32-bitni broj u kome se nalazi Invocation Counter koji je izvucen iz ulazne poruke
								
* Return value : CRYPT_OK    - ako je dekripcija uspesno izvrsena
                 CRYPT_ERROR - ako dekripcija nije uspesno izvrsena
                 
*****************************************************************************/
static uint8_t Decrypt(uint8_t* ciphertext, uint8_t* plaintext, uint32_t ciphertextLen,
                       uint8_t* encryptionKey, uint8_t* systemTitle, uint32_t invocationCounter)
{
	CRYP_HandleTypeDef hcryp;
	hcryp.Instance = AES;
	uint8_t iv[16];
	uint8_t rest[16];
	
	// cipherCopy i plainCopy sluze za promenu mesta bajtovima nizova ciphertext i plaintext
  // ciphertext i plaintext mogu biti duzine koja nije deljiva sa 4 (swapBytes mora uzeti niz duzine deljive sa 4)
  // iz tog razloga	se nizovi plainCopy i cipherCopy deklarisu tako da budu produzene vrednosti nizova ciphertext i plaintext
	uint8_t cipherCopy[ciphertextLen + ciphertextLen%4]; // Da bi se swap bytes izvrsio
	uint8_t plainCopy[ciphertextLen + ciphertextLen%4];
	
	uint8_t i;
	CreateIVarray(iv, systemTitle, &invocationCounter, 2);
	hcryp.Init.DataType = CRYP_DATATYPE_32B;
	hcryp.Init.pKey = encryptionKey;
	hcryp.Init.pInitVect = iv; 
	
	HAL_CRYP_DeInit(&hcryp);
	HAL_CRYP_Init(&hcryp);
	STR_N_COPY(i, cipherCopy, ciphertext, ciphertextLen);

	// Izmenjati bajtove da bi se sifrovali svi celi blokovi
	SwapBytes(cipherCopy, ciphertextLen);
	if(ciphertextLen % BLOCK_SIZE == 0)
	{
			
		if(HAL_CRYP_AESCTR_Decrypt(&hcryp, cipherCopy, (uint16_t)ciphertextLen, plainCopy, 10) == HAL_OK)
		{
			SwapBytes(plainCopy, ciphertextLen);
			STR_N_COPY(i, plaintext, plainCopy, ciphertextLen);
			return CRYPT_OK;
		}
		return CRYPT_ERROR;
	}
	if(HAL_CRYP_AESCTR_Decrypt(&hcryp, cipherCopy, ciphertextLen - (ciphertextLen % 16), plainCopy, 10) == HAL_OK)
	{
		// Celi blokovi su sifrovani, vratiti cipherCopy i plainCopy u prvobitno stanje da bi se 
		// izvrsilo sifrovanje nekompletnog bloka
		SwapBytes(plainCopy, ciphertextLen);
		SwapBytes(cipherCopy, ciphertextLen);
		
		// formirati Yn
		CreateIVarray(iv, systemTitle, &invocationCounter, 2 + ciphertextLen / 16);
		HAL_CRYP_DeInit(&hcryp);
		HAL_CRYP_Init(&hcryp);
		
		SwapBytes(iv, sizeof(iv));
		if(HAL_CRYP_AESECB_Encrypt(&hcryp, iv, 16, rest, 10) == HAL_OK)
		{
			SwapBytes(rest, 16);
			for(i = 0; i < ciphertextLen%16; i++)
			{
				plainCopy[ciphertextLen - 1 - i] = cipherCopy[ciphertextLen - 1 - i] ^  rest[(ciphertextLen % 16) -1 - i];
				// prva ispravka fajla, problem:
				// nepotrebni bajtovi 15 i 16 bivaju dekriptovani jer se posle swap funkcije nalaze na pozicijama 13 i 14
				// bitni bajtovi 13 i 14 bivaju preskoceni jer se upis vrsi od pozicije 14 u nazad (14 znaci [13])
				//
			}
//			SwapBytes(plainCopy, ciphertextLen);
//			(*lowestAcceptableInvocationCounter) = invocationCounter++;
			STR_N_COPY(i, plaintext, plainCopy, ciphertextLen);
			return CRYPT_OK;
		}	
		return CRYPT_ERROR;
	
	}
	return CRYPT_ERROR;
}	

//
static uint8_t UnwrapParts(uint8_t j, uint8_t* t, uint8_t* a, uint8_t* r, uint8_t* kek)
{
	uint8_t k;
	uint8_t w[16];
	uint8_t b[16];
	
	CRYP_HandleTypeDef hcryp;
	hcryp.Instance = AES;
	hcryp.Init.DataType = CRYP_DATATYPE_32B;
	hcryp.Init.pKey = kek;
	if(HAL_CRYP_DeInit(&hcryp) != HAL_OK)
	{
		return CRYPT_ERROR;
	}
	if(HAL_CRYP_Init(&hcryp) != HAL_OK)
	{
		return CRYPT_ERROR;
	}
	
		// b =  xor A i t, nastaviti R na to, pa desifrovati
	for(k = 0; k < 8; k++)
	{
		a[k] = a[k] ^ t[k];
	}
	for(k = 0; k < 8; k++)
	{
		w[k] = a[k];
		w[k + 8] = r[k];
	}
	SwapBytes(w, sizeof(w));
	if(HAL_CRYP_AESECB_Decrypt(&hcryp, w, sizeof(w), b, 10) != CRYPT_OK)
	{
		return CRYPT_ERROR;
	}
	SwapBytes(b, sizeof(b));
	// a = 64 najznacajnija bita b
	// r2 = 64 najmanje znacajna bita b
	for(k = 0; k < 8; k++)
	{
		a[k] = b[k];
		r[k] = b[k + 8];
	}
	return CRYPT_OK;
}

/*******************************************************************************
* Function Name  	: Aes128CalculateAuthenticationTag
* Description    	: Ova funkcija se koristi za generisanje Authentication Tag-a. Authentication Tag je duzine 12 bajtova
										i bice upisan u niz na koji pokazuje argument authenticationTag. Prilikom racunanja Authentication tag-a
										koristi se GMAC algoritam koji je mod rada algoritma AES 128. U ovom slucaju ne vrsi se enkripcija
										plaintext-a vec se samo izracunava Authentication tag. Za detalje pogledati Green book.
										Svaki put kada se ova funkcija izracuna tag inkrementira se brojac na koji pokazuje argumet invocationCounter.
										Kada brojac dostigne maksimalnu vrednost, pri narednim pozivima funkcije, on se vise ne inkrementira a 
										funkcija vraca MC_STATUS_FC_ERROR. 
* Arguments				: plaintext - pokazivac na niz gde se nalazi ulazni podatak za koji treba izracunati Authentication Tag.
										plaintextLen - duzina niza na koji pokazuje argument plaintext
										authenticationKey - pokazivac na niz od 16 bajtova u kome se nalazi Authentication Key
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - pokazivac na 32-bitni broj u kome se nalazi Invocation Counter
                    authenticationTag - pokazivac na niz od 12 bajtova u koji ce funkcija upisati izracunati Authentication Tag
										securityControlByte - Security Control Byte koji je neophodan kao ulazni parametar (pogledati Green Book)
* Return Value    : MC_STATUS_OK - Ako je Authentication tag uspesno izracunat
										MC_STATUS_ERROR - Ako je Authentication tag nije uspesno izracunat
										MC_STATUS_FC_ERROR - Ako invocationCounter ima maksimalnu vrednost
*******************************************************************************/
McStatus_TypeDef Aes128CalculateAuthenticationTag(uint8_t* plaintext,
																									uint32_t plaintextLen,
																									uint8_t* authenticationKey,
																									uint8_t* encryptionKey,
																									uint8_t* systemTitle,
																									uint32_t* invocationCounter,
																									uint8_t* authenticationTag,
																									uint8_t securityControlByte)		
{
	if(*invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(CalculateTag(plaintext, plaintextLen, authenticationKey, encryptionKey, systemTitle,
	    invocationCounter, authenticationTag, securityControlByte) != CALCULATION_OK)
	{
		return MC_STATUS_ERROR;
	}
	(*invocationCounter)++;
	return MC_STATUS_OK;
}
/*******************************************************************************
* Function Name  	: CheckAuthenticationTag
* Description    	: Ova funkcija se koristi za proveru Authentication Tag-a po GMAC algoritmu. Ulazna vrednost Authentication Tag-a
										je dostavljena preko argumenta authenticationTag koji pokazuje na niz od 12 bajtova gde se nalazi tag koji treba
										proveriti. Argument lowestAcceptableInvocationCounter pokazuje na 32-bitni broj u kome se nalazi najniza prihvatljiva 
										vrednost Invocation Counter-a. Argument invocationCounter je 32-bitna vrednost invocation counter-a koja je 
										pristigla u dolaznoj poruci. Ako je pristigla vrednost invocation counter-a manja od minimalne prihvatljive vrednosti 
										invocation counter-a funkcija ne proverava Authentication Tag i vraca MC_STATUS_FC_ERROR. Ako je dolazna vrednost invocation 
										counter-a prihvatljiva, funkcija vrsi proveru Authentication Tag-a. Ako poruka ima ispravan Authentication Tag funkcija 
										postavlja vrednost na koju pokazuje argument lowestAcceptableInvocationCounter na vrednost invocation counter-a pristiglog 
										u poruci (invocationCounter) uvecanog za 1. Ako je vrednost parametra invocationCounter jednaka maksimalnoj vrednosti 
										(0xFFFFFFFF) funkcija treba da vrati MC_STATUS_FC_ERROR i ne vrsi proveru Authentication Tag-a.
										Ulazni niz bajtova za koji treba proveriti dostavljeni Authentication Tag je dostavljen preko argumenta ciphertext koji
										pokazuje na taj niz. Duzina ulaznog niza data je argumentom ciphertextLen. 
										Ostali parametri potrebni za ovaj proces su dati preko preostalih argumenata. 
										Za detalje pogledati Green Book.
* Arguments				: ciphertext - pokazivac na niz gde se nalazi ulazni podatak za koji treba proveriti Authentication Tag
										ciphertextLen - duzina niza na koji pokazuje argument ciphertext
										authenticationTag - pokazivac na niz od 12 bajtova u kome ce biti dostavljen Authentication Tag koji treba da se proveri
										authenticationKey - pokazivac na niz od 16 bajtova u kome se nalazi Authentication Key
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - 32-bitni broj u kome se nalazi Invocation Counter koji je izvucen iz ulazne poruke
										lowestAcceptableInvocationCounter - pokazivac na 32-bitni broj u kome se nalazi najniza prihvatljiva vrednost
																												invocation counter-a pristiglog u dolaznoj poruci.
										securityControlByte - Security Control Byte koji je neophodan kao ulazni parametar (pogledati Green Book)
* Return Value    : MC_STATUS_OK - Ako primljeni Authentication Tag odgovara poruci na koju pokazuje ciphertext 
										MC_STATUS_ERROR - Ako tag nije ispravan
										MC_STATUS_FC_ERROR - Ako vrednost pristiglog invocation counter-a nije odgovarajuca
*******************************************************************************/
McStatus_TypeDef CheckAuthenticationTag(uint8_t* ciphertext,
																				uint32_t ciphertextLen,
																				uint8_t* authenticationTag,
																				uint8_t* authenticationKey,
																				uint8_t* encryptionKey,
																				uint8_t* systemTitle,
																				uint32_t invocationCounter,
																				uint32_t* lowestAcceptableInvocationCounter,
																				uint8_t securityControlByte)
{
	if((*lowestAcceptableInvocationCounter) > invocationCounter)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	uint8_t calculatedTag[12];
	if(CalculateTag(ciphertext, ciphertextLen, authenticationKey, encryptionKey, systemTitle,
	    &invocationCounter, calculatedTag, securityControlByte) != CALCULATION_OK)
	{
		return MC_STATUS_ERROR;
	}
	uint8_t i;
	for(i = 0; i < 12; i++)
	{
		if(calculatedTag[i] != authenticationTag[i])
		{
			return MC_STATUS_ERROR;
		}
	}
	(*lowestAcceptableInvocationCounter) = (++invocationCounter);
	return MC_STATUS_OK;

}

/*******************************************************************************
* Function Name  	: Aes128EncryptPlaintext
* Description    	: Ova funkcija se koristi za enkripciju ulaznog podatka dostavljenog preko argumenta plaintext. Za enkripciju
										se koristi GCM algoritam u cijoj osnovi je AES 128. Proizvod enkripcije je izlazni niz na koji pokazuje 
										argument ciphertext. On je iste duzine kao i ulazni niz plaintext. Preostali podaci neophodni za ovu enkripciju 
										dostavljeni su kroz argumente. Svaki put kada funkcija uspesno izvrsi enkripciju inkrementira se invocationCounter
										a funkcija vraca MC_STATUS_OK. Kada invocationCounter dostigne maksimalnu vrednost, pri svakom narednom 
										pozivu, funkcija vise ne enkriptuje dostavljeni niz a kao povratnu vrednost vraca MC_STATUS_FC_ERROR.
										Detalji se nalaze u Green Book-u.
* Arguments				: plaintext - pokazivac na niz gde se nalazi ulazni podatak koji treba enkriptovati
										ciphertext - pokazivac na niz gde se nalazi enkriptovani niz koji ce funkcija kreirati
										plaintextLen - duzina niza na koji pokazuje argument plaintext. Ista duzina ce biti i niza ciphertext.
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - pokazivac na 32-bitni broj u kome se nalazi Invocation Counter
* Return Value    : MC_STATUS_OK - Ako je enkripcija uspesno izvrsena
										MC_STATUS_ERROR - Ako enkripcija nije izvrsena uspesno
										MC_STATUS_FC_ERROR - Ako invocationCounter ima maksimalnu vrednost
*******************************************************************************/
McStatus_TypeDef Aes128EncryptPlaintext(uint8_t* plaintext,
																				uint8_t* ciphertext,
																				uint32_t plaintextLen,
																				uint8_t* encryptionKey,
																				uint8_t* systemTitle,
																				uint32_t* invocationCounter)
{
	if(*invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(Encrypt(plaintext, ciphertext, plaintextLen, encryptionKey, systemTitle, invocationCounter) != CRYPT_OK)
	{
		return MC_STATUS_ERROR;
	}
	(*invocationCounter)++;
	return MC_STATUS_OK;

}

/*******************************************************************************
* Function Name  	: Aes128DecryptCiphertext
* Description    	: Ova funkcija se koristi za dekripciju ulaznog enkriptovanog niza koji u sebi ne sadrzi Authentication Tag.
										Koristi se GCM algoritam. Za detalje pogledati Green Book.
										Izlaz funkcije je niz koji ce funkcija upisati od adrese na koju pokazuje argument plaintext a duzine je jednake 
										duzini ulaznog enkriptovanog sadrzaja dostavljenog preko niza ciphertext. Ta duzina je data argumentom ciphertextLen.
										Argument lowestAcceptableInvocationCounter pokazuje na 32-bitni broj u kome se nalazi najniza prihvatljiva vrednost 
										Invocation Counter-a. Argument invocationCounter je 32-bitna vrednost invocation counter-a koja je pristigla 
										u dolaznoj poruci koja se dekriptuje. Ako je pristigla vrednost invocation counter-a manja od minimalne prihvatljive 
										vrednosti invocation counter-a funkcija ne vrsi dekripciju i vraca MC_STATUS_FC_ERROR. Ako je dolazna vrednost invocation 
										counter-a prihvatljiva, funkcija vrsi dekripciju. Ako je poruka uspesno dekriptovana funkcija postavlja vrednost na koju 
										pokazuje argument lowestAcceptableInvocationCounter na vrednost invocation counter-a pristiglog u poruci (invocationCounter) 
										uvecanog za 1.Ako je vrednost argumenta invocationCounter jednaka maksimalnoj vrednosti (0xFFFFFFFF) funkcija treba 
										da vrati MC_STATUS_FC_ERROR i ne vrsi dekripciju.
										Ostali parametri potrebni za ovaj proces su dati preko preostalih argumenata. 										
* Arguments				: ciphertext - pokazivac na niz gde se nalazi ulazni podatak koji treba dekriptovati
										plaintext - pokazivac na niz gde ce funkcija upisati dekriptovani sadrzaj, duzina mu je jednaka kao i za ciphertext 
										ciphertextLen - duzina niza na koji pokazuje argument ciphertext. Ista duzina ce biti i niza plaintext.
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - 32-bitni broj u kome se nalazi Invocation Counter koji je izvucen iz ulazne poruke
										lowestAcceptableInvocationCounter - pokazivac na 32-bitni broj u kome se nalazi najniza prihvatljiva vrednost
																												invocation counter-a pristiglog u dolaznoj poruci.
* Return Value    : MC_STATUS_OK - Ako je dekripcija prosla uspesno
										MC_STATUS_ERROR - Ako nije prosla uspesno
										MC_STATUS_FC_ERROR - Ako vrednost pristiglog invocation counter-a nije odgovarajuca
*******************************************************************************/
McStatus_TypeDef Aes128DecryptCiphertext(uint8_t* ciphertext,
																				 uint8_t* plaintext,
																				 uint32_t ciphertextLen,
																				 uint8_t* encryptionKey,
																				 uint8_t* systemTitle,
																				 uint32_t invocationCounter,
																				 uint32_t* lowestAcceptableInvocationCounter)
{
	if(invocationCounter < (*lowestAcceptableInvocationCounter))
	{
		return MC_STATUS_FC_ERROR;
	}

	if(invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(Decrypt(ciphertext, plaintext, ciphertextLen, encryptionKey, systemTitle, invocationCounter) != CRYPT_OK)
	{
		return MC_STATUS_ERROR;
	}
	*lowestAcceptableInvocationCounter = ++invocationCounter;
	return MC_STATUS_OK;
	

}

/*******************************************************************************
* Function Name  	: Aes128EncryptAndAuthenticatePlaintext
* Description    	: Ova funkcija se koristi za enkripciju i autentifikaciju ulaznog niza bajtova dostavljenog preko argumenta
										plaintext. Rezultat funkcije je kreiranje niza ciphertext u kome ce se nalaziti enkriptovan plaintext kao
										i izracunavanje Authentication tag-a duzine 12 bajtova. Enkriptovani niz (ciphertext) je iste duzine kao i
										ulazni niz plaintext. Algoritam je GCM.
										Svaki put kada funkcija uspesno izvrsi enkripciju i generisanje Authentication tag-a inkrementira se invocationCounter
										a funkcija vraca MC_STATUS_OK. Kada invocationCounter dostigne maksimalnu vrednost funkcija vise ne enkriptuje 
										dostavljeni niz niti kreira Authentication tag a kao povratnu vrednost vraca MC_STATUS_FC_ERROR.
										Detalji se nalaze u Green Book-u.
* Arguments				: plaintext - pokazivac na niz gde se nalazi ulazni podatak koji treba enkriptovati
										ciphertext - pokazivac na niz gde se nalazi enkriptovani niz koji ce funkcija kreirati
										plaintextLen - duzina niza na koji pokazuje argument plaintext. Ista duzina ce biti i niza ciphertext.
										authenticationKey - pokazivac na niz od 16 bajtova u kome se nalazi Authentication Key
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - pokazivac na 32-bitni broj u kome se nalazi Invocation Counter
										authenticationTag - pokazivac na niz od 12 bajtova u koji ce funkcija upisati izracunati Authentication Tag
										securityControlByte - Security Control Byte koji je neophodan kao ulazni parametar (pogledati Green Book)
* Return Value    : MC_STATUS_OK - Ako je enkripcija uspesno izvrsena
										MC_STATUS_ERROR - Ako enkripcija nije izvrsena uspesno
										MC_STATUS_FC_ERROR - Ako invocationCounter ima maksimalnu vrednost
*******************************************************************************/
McStatus_TypeDef Aes128EncryptAndAuthenticatePlaintext(uint8_t* plaintext,
																											 uint8_t* ciphertext,
																											 uint32_t plaintextLen,
																											 uint8_t* authenticationKey,
																											 uint8_t* encryptionKey,
																											 uint8_t* systemTitle,
																											 uint32_t* invocationCounter,
																											 uint8_t* authenticationTag,
																											 uint8_t securityControlByte)
{
	if(*invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(Encrypt(plaintext, ciphertext, plaintextLen,
	        encryptionKey,  systemTitle, invocationCounter) != CRYPT_OK)
	{
		return MC_STATUS_ERROR;
	}

	if(CalculateTag(ciphertext, plaintextLen, authenticationKey, encryptionKey, systemTitle,
              invocationCounter, authenticationTag, securityControlByte) != CRYPT_OK)
	{
		return MC_STATUS_ERROR;
	}
	(*invocationCounter)++;
	return MC_STATUS_OK;
}


/*******************************************************************************
* Function Name  	: Aes128DecryptAndCheckAuthenticationTag
* Description    	: Ova funkcija se koristi za dekripciju i proveru Authentication Tag-a po GCM algoritmu. Izlaz funkcije je
										niz koji ce funkcija upisati od adrese na koju pokazuje argument plaintext a duzine je jednake duzini
										ulaznog enkriptovanog sadrzaja dostavljenog preko niza ciphertext. Ta duzina je data argumentom ciphertextLen.
										Pored dekripcije ciphertext-a funkcija vrsi proveru i Authentication Tag-a duzine 12 bajtova koji se dostavlja
										preko argumenta authenticationTag. Argument lowestAcceptableInvocationCounter pokazuje na 32-bitni broj u 
										kome se nalazi najniza prihvatljiva vrednost Invocation Counter-a. Argument invocationCounter je
										32-bitna vrednost invocation counter-a koja je pristigla u dolaznoj poruci koja se dekriptuje. Ako je pristigla
										vrednost invocation counter-a manja od minimalne prihvatljive vrednosti invocation counter-a funkcija ne vrsi
										dekripciju i proveru Authentication Tag-a a vraca MC_STATUS_FC_ERROR. Ako je dolazna vrednost invocation counter-a
										prihvatljiva, funkcija vrsi dekripciju i proveru Authentication Tag-a. Ako je poruka uspesno dekriptovana i ima
										ispravan Authentication Tag funkcija postavlja vrednost na koju pokazuje argument lowestAcceptableInvocationCounter
										na vrednost invocation counter-a pristiglog u poruci (invocationCounter) uvecanog za 1. Ako je vrednost argumenta 
										invocationCounter jednaka maksimalnoj vrednosti (0xFFFFFFFF) funkcija treba da vrati MC_STATUS_FC_ERROR i ne 
										vrsi dekripciju niti proveru Authentication Tag-a.
										Ostali parametri potrebni za ovaj proces su dati preko preostalih argumenata. 
										Za detalje pogledati Green Book.
* Arguments				: ciphertext - pokazivac na niz gde se nalazi ulazni podatak koji treba dekriptovati
										plaintext - pokazivac na niz gde ce funkcija upisati dekriptovani sadrzaj, duzina mu je jednaka kao i za ciphertext 
										ciphertextLen - duzina niza na koji pokazuje argument ciphertext. Ista duzina ce biti i niza plaintext.
										authenticationTag - pokazivac na niz od 12 bajtova u kome ce biti dostavljen Authentication Tag koji treba da se proveri
										authenticationKey - pokazivac na niz od 16 bajtova u kome se nalazi Authentication Key
										encryptionKey - pokazivac na niz od 16 bajtova u kome se nalazi Encryption Key
										systemTitle - pokazivac na niz od 8 bajtova u kome se nalazi System Title
										invocationCounter - 32-bitni broj u kome se nalazi Invocation Counter koji je izvucen iz ulazne poruke
										lowestAcceptableInvocationCounter - pokazivac na 32-bitni broj u kome se nalazi najniza prihvatljiva vrednost
																												invocation counter-a pristiglog u dolaznoj poruci.
										securityControlByte - Security Control Byte koji je neophodan kao ulazni parametar (pogledati Green Book)
* Return Value    : MC_STATUS_OK - Ako je dekripcija i provera Authentication Tag-a prosla uspesno
										MC_STATUS_ERROR - Ako nije proslo uspesno
										MC_STATUS_FC_ERROR - Ako vrednost pristiglog invocation counter-a nije odgovarajuca
*******************************************************************************/
McStatus_TypeDef Aes128DecryptAndCheckAuthenticationTag(uint8_t* ciphertext,
																												uint8_t* plaintext,
																												uint32_t ciphertextLen,
																												uint8_t* authenticationTag,
																												uint8_t* authenticationKey,
																												uint8_t* encryptionKey,
																												uint8_t* systemTitle,
																												uint32_t invocationCounter,
																												uint32_t* lowestAcceptableInvocationCounter,
																												uint8_t securityControlByte)
{
	if(invocationCounter < (*lowestAcceptableInvocationCounter))
	{
		return MC_STATUS_FC_ERROR;
	}

	if(invocationCounter == 0xFFFFFFFF)
	{
		return MC_STATUS_FC_ERROR;
	}
	if(Decrypt(ciphertext, plaintext, ciphertextLen, encryptionKey, systemTitle, invocationCounter) != CRYPT_OK)
	{
		return MC_STATUS_ERROR;
	}
	uint8_t calculatedTag[12];
	calculatedTag[0] = authenticationTag[0];
	if(CalculateTag(ciphertext, ciphertextLen, authenticationKey, encryptionKey, systemTitle,
		 &invocationCounter, calculatedTag, securityControlByte) != CALCULATION_OK)
	{
		return MC_STATUS_ERROR;
	}
	uint8_t i;
	for(i = 0; i < 12; i++)
	{
		if(calculatedTag[i] != authenticationTag[i])
		{
			return MC_STATUS_ERROR;
		}
	}
	(*lowestAcceptableInvocationCounter) = (++invocationCounter);
	return MC_STATUS_OK;
}


/*******************************************************************************
* Function Name  	: Aes128UnwrapKey
* Description    	: Ova funkcija vrsi dekripciju novog primljenog kljuca koji se do brojila preneo tako sto je bio enkriptovan 
										kljucem za enkripciju kljuceva (KEK). Postupak je opisan u Green Book-u u poglavlju "AES key wrap".
* Arguments				: kek - pokazivac na kljuc duzine 16 bajtova koji se koristi za enkripciju/dekripciju kljuceva
										ciphertext - pokazivac na enkriptovani sadrzaj kljuca koji treba dekriptovati pomocu kljuca na koji pokazuje kek. 
										plaintext - pokazivac na niz gde ce funkcija upisati dekriptovanu vrednost kljuca.
* Return Value    : MC_STATUS_OK - Ako je dekripcija prosla uspesno
										MC_STATUS_ERROR - Ako nije proslo uspesno
*******************************************************************************/
McStatus_TypeDef Aes128UnwrapKey(uint8_t* kek, uint8_t* ciphertext, uint8_t* plaintext)
{
	// n = 2, broj 64 - bitnih blokova
	// s = 6n, broj koraka za enkripciju i dekripciju
	
	uint8_t k;
	uint8_t a[8];
	uint8_t r1[8];
	uint8_t r2[8];
	uint8_t t[8] = {0,0,0,0,0,0,0,0};

  short int	j;
	
	
	STR_N_COPY(k, a, ciphertext, 8);
	// r1 jednako prvi blok sifre
	for(k = 0; k < 8; k++)
	{
		r1[k] = ciphertext[k + 8];
	}
	// r2 jednako drugi blok sifre
	for(k = 0; k < 8; k++)
	{
		r2[k] = ciphertext[k + 16];
	}
	
	for(j = 5; j >= 0; j--)
	{
		t[7] = j*2 + 2;
		if(UnwrapParts(j, t, a, r2, kek) != CRYPT_OK)
		{
			return MC_STATUS_ERROR;
		}
		
		 t[7] = j*2 + 1;
		if(UnwrapParts(j, t, a, r1, kek) != CRYPT_OK)
		{
			return MC_STATUS_ERROR;
		}

	}
	for(k = 0; k < 8; k++)
	{
		plaintext[k] = r1[k];
		plaintext[k + 8] = r2[k];
	}
	return MC_STATUS_OK;
}

/****************************************************************************
* Function name: 
* Description  : 
* Arguments    : 
                 
*****************************************************************************/



