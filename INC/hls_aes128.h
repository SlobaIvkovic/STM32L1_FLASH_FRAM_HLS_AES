#ifndef HLS_AES128_H
#define HLS_AES128_H

#include "stm32l1xx_hal.h"
#include "mc_types.h"

/* Function prototypes: */
McStatus_TypeDef Aes128CalculateAuthenticationTag(
																										uint8_t* plaintext, 
																										uint32_t plaintextLen, 
																										uint8_t* authenticationKey, 
																										uint8_t* encryptionKey,
																										uint8_t* systemTitle, 
																										uint32_t* invocationCounter, 
																										uint8_t* authenticationTag, 
																										uint8_t securityControlByte
																									);
McStatus_TypeDef CheckAuthenticationTag(
																					uint8_t* ciphertext, 
																					uint32_t ciphertextLen, 
																					uint8_t* authenticationTag, 
																					uint8_t* authenticationKey,
																					uint8_t* encryptionKey, 
																					uint8_t* systemTitle, 
																					uint32_t invocationCounter, 
																					uint32_t* lowestAcceptableInvocationCounter, 
																					uint8_t securityControlByte
																			 );
McStatus_TypeDef Aes128EncryptPlaintext(
																					uint8_t* plaintext, 
																					uint8_t* ciphertext, 
																					uint32_t plaintextLen, 
																					uint8_t* encryptionKey, 
																					uint8_t* systemTitle,
																					uint32_t* invocationCounter
																				);
McStatus_TypeDef Aes128DecryptCiphertext(
																					uint8_t* ciphertext, 
																					uint8_t* plaintext, 
																					uint32_t ciphertextLen, 
																					uint8_t* encryptionKey, 
																					uint8_t* systemTitle,
																					uint32_t invocationCounter, 
																					uint32_t* lowestAcceptableInvocationCounter
																				);
McStatus_TypeDef Aes128EncryptAndAuthenticatePlaintext(
																												uint8_t* plaintext, 
																												uint8_t* ciphertext, 
																												uint32_t plaintextLen, 
																												uint8_t* authenticationKey,
																												uint8_t* encryptionKey, 
																												uint8_t* systemTitle, 
																												uint32_t* invocationCounter, 
																												uint8_t* authenticationTag, 
																												uint8_t securityControlByte
																											);
McStatus_TypeDef Aes128DecryptAndCheckAuthenticationTag(
																													uint8_t* ciphertext, 
																													uint8_t* plaintext, 
																													uint32_t ciphertextLen,
																													uint8_t* authenticationTag,
																													uint8_t* authenticationKey,
																													uint8_t* encryptionKey,
																													uint8_t* systemTitle,
																													uint32_t invocationCounter,
																													uint32_t* lowestAcceptableInvocationCounter,
																													uint8_t securityControlByte
																												);
McStatus_TypeDef Aes128UnwrapKey(uint8_t* kek, uint8_t* ciphertext, uint8_t* plaintext);

#endif /* HLS_AES128_H */
