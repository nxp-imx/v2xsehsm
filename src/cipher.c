
/*
 * Copyright 2020 NXP
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *
 * @file cipher.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer CIPHER API
 *
 */

#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Perform CIPHER encryption using hsm
 *
 * This function performs CIPHER encryption using the hsm.  It takes parameters
 * in v2xSe format, converts them to hsm_api format and launches the
 * encryption.
 *
 * @param keyHandle handle of key to use for encryption
 * @param keyType type of key for hsm to create
 * @param pCipherData pointer to encryption parameters in v2xSe format
 * @param pVctLen length of encrypted data on output
 * @param pVctData pointer to location to write the encrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static hsm_err_t doHsmEncryption(uint32_t keyHandle, hsm_key_type_t keyType,
			TypeEncryptCipher_t *pCipherData,
			TypeLen_t *pVctLen, TypeVCTData_t *pVctData)
{
	op_cipher_one_go_args_t args;
	hsm_err_t retVal;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.iv = pCipherData->iv;
	args.iv_size = pCipherData->ivLen;
	args.cipher_algo = convertAlgoId(pCipherData->algoId);
	args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	args.input = pCipherData->pMsgData->data;
	args.output = pVctData->data;
	args.input_size = pCipherData->msgLen;
	args.output_size = *pVctLen;
	TRACE_HSM_CALL(PROFILE_ID_HSM_HASH_ONE_GO);
	retVal = hsm_cipher_one_go(hsmCipherHandle, &args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_HASH_ONE_GO);
	if (!retVal)
		*pVctLen = args.output_size;
	return retVal;
}

/**
 *
 * @brief Perform CIPHER decryption using hsm
 *
 * This function performs CIPHER decryption using the hsm.  It takes parameters
 * in v2xSe format, converts them to hsm_api format and launches the
 * decrpytion.
 *
 * @param keyHandle handle of key to use for decryption
 * @param keyType type of key for hsm to create
 * @param pCipherData pointer to decrpytion parameters in v2xSe format
 * @param pMsgLen msg size on output
 * @param pMsgData location to write decrpyted message
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static hsm_err_t doHsmDecryption(uint32_t keyHandle, hsm_key_type_t keyType,
			TypeDecryptCipher_t *pCipherData,
			TypeLen_t *pMsgLen, TypePlainText_t *pMsgData)
{
	op_cipher_one_go_args_t args;
	hsm_err_t retVal;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.iv = pCipherData->iv;
	args.iv_size = pCipherData->ivLen;
	args.cipher_algo = convertAlgoId(pCipherData->algoId);
	args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	args.input = pCipherData->pVctData->data;
	args.output = pMsgData->data;
	args.input_size = pCipherData->vctLen;
	args.output_size = *pMsgLen;
	TRACE_HSM_CALL(PROFILE_ID_HSM_HASH_ONE_GO);
	retVal = hsm_cipher_one_go(hsmCipherHandle, &args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_HASH_ONE_GO);
	if (!retVal)
		*pMsgLen = args.output_size;
	return retVal;
}

/**
 *
 * @brief Encrypt data using CIPHER and runtime key
 * @ingroup cipher
 *
 * This function encrypts data using CIPHER and the specified runtime key.
 * The data to encrypt and all other parameters needed to perform the
 * encryption are provided by the caller.
 *
 * @param rtKeyId key slot of runtime key to use
 * @param pCipherData pointer to structure with data and encryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pVctLen msg buffer size on input, length of encrypted data on output
 * @param pVctData pointer to location to write the encrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_encryptUsingRtCipher (TypeRtKeyId_t rtKeyId,
				    TypeEncryptCipher_t  *pCipherData,
				    TypeSW_t *pHsmStatusCode,
				    TypeLen_t *pVctLen,
				    TypeVCTData_t *pVctData)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ENCRYPTUSINGRTCIPHER);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pCipherData != NULL) &&
			(pVctLen != NULL) &&
			(pVctData != NULL)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmEncryption(keyHandle, convertCurveId(curveId),
					pCipherData, pVctLen, pVctData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_ENCRYPTUSINGRTCIPHER);
	return retval;
}

/**
 *
 * @brief Decrypt data using CIPHER and runtime key
 * @ingroup cipher
 *
 * This function decrypts data using CIPHER and the specified runtime key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param rtKeyId key slot of runtime key to use
 * @param pCipherData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingRtCipher (TypeRtKeyId_t rtKeyId,
				    TypeDecryptCipher_t  *pCipherData,
				    TypeSW_t *pHsmStatusCode,
				    TypeLen_t *pMsgLen,
				    TypePlainText_t *pMsgData)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPYUSINGRTCIPHER);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pCipherData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmDecryption(keyHandle, convertCurveId(curveId),
					pCipherData, pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPYUSINGRTCIPHER);
	return retval;
}
