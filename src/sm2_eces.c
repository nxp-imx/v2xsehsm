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
 * @file sm2_eces.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer SM2 ECES API
 *
 */

#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Perform SM2 ECES decryption using hsm
 *
 * This function performs SM2 ECES decryption using the hsm.
 *
 * @param keyHandle handle of the key to use for decryption
 * @param keyType type of key for hsm to create
 * @param pSm2EcesData pointer to decryption parameters
 * @param pMsgLen msg size on output
 * @param pMsgData location to write decrypted message
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 */
static hsm_err_t doHsmSm2EcesDecryption(uint32_t keyHandle,
		hsm_key_type_t keyType, TypeDecryptSm2Eces_t *pSm2EcesData,
		TypeLen_t *pMsgLen, TypePlainText_t *pMsgData)
{

	op_sm2_eces_dec_args_t args;
	hsm_err_t hsmret;

	memset(&args, 0, sizeof(args));
	args.input = pSm2EcesData->encryptedData;
	args.output = pMsgData->data;
	args.key_identifier = keyHandle;
	args.input_size = pSm2EcesData->encryptedDataSize;
	args.output_size = args.input_size - SM2_PKE_OVERHEAD;
	args.key_type = keyType;
	args.flags = 0;

	TRACE_HSM_CALL(PROFILE_ID_HSM_SM2_ECES_DECRYPTION);
	hsmret = hsm_sm2_eces_decryption(hsmSm2EcesHandle, &args);
	TRACE_HSM_CALL(PROFILE_ID_HSM_SM2_ECES_DECRYPTION);

	if (!hsmret)
		*pMsgLen = args.output_size;

	return hsmret;
}


/**
 *
 * @brief Encrypt data using SM2 ECES
 * @ingroup sm2_eces
 *
 * This function encrypts data using the SM2 ECES encryption scheme. The data to
 * encrypt, and all parameters needed to perform the encryption are provided
 * by the caller.
 *
 * @param pSm2EcesData pointer to structure with data and encryption parameters
 * @param pHsmStatusCode poiinter to location to write extended result code
 * @param pEncryptedDataSize length of encrypted data on output
 * @param pEncryptedData pointer to location to write the encrypted data
 *
 * @return V2XSE_SUCCESS is no error, non-zero on error
 *
 */
int32_t v2xSe_encryptUsingSm2Eces(TypeEncryptSm2Eces_t *pSm2EcesData,
		TypeSW_t *pHsmStatusCode,
		TypeLen_t *pEncryptedDataSize, uint8_t *pEncryptedData)
{
	op_sm2_eces_enc_args_t args;
	hsm_key_type_t keyType;
	uint8_t hsm_key[V2XSE_384_EC_PUB_KEY];
	int32_t retval = V2XSE_FAILURE;
	hsm_err_t hsmret;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ENCRYPTUSINGSM2ECES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
		!enforceActivatedState(pHsmStatusCode, &retval) &&
		(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
		(pSm2EcesData != NULL) &&
		(pEncryptedDataSize != NULL) &&
		(pEncryptedData != NULL)) {

		keyType = convertCurveId(pSm2EcesData->curveId);
		convertPublicKeyToHsmApi(keyType, pSm2EcesData->pEccPublicKey,
				hsm_key);

		memset(&args, 0, sizeof(args));
		args.input = pSm2EcesData->pMsgData->data;
		args.output = pEncryptedData;
		args.pub_key = hsm_key;
		args.input_size = pSm2EcesData->msgLen;
		/* output_size: align to 32 bits to respect V2X accelerator
		 * hardware constraints */
		args.output_size =
			((pSm2EcesData->msgLen + SM2_PKE_OVERHEAD + 3) / 4) * 4;
		args.pub_key_size = keyLenFromCurveID(pSm2EcesData->curveId);
		args.key_type = keyType;
		args.flags = 0;

		TRACE_HSM_CALL(PROFILE_ID_HSM_SM2_ECES_ENCRYPTION);
		hsmret = hsm_sm2_eces_encryption(hsmSessionHandle, &args);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_SM2_ECES_ENCRYPTION);
		if (hsmret) {
			*pEncryptedDataSize = 0;
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pEncryptedDataSize = pSm2EcesData->msgLen + SM2_PKE_OVERHEAD;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_ENCRYPTUSINGSM2ECES);

	return retval;
}


/**
 *
 * @brief Decrypt data using SM2 ECES and runtime key
 * @ingroup sm2_eces
 *
 * This function decrypts data using SM2 ECES and the specified runtime key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param rtKeyId key slot of runtime key to use
 * @param pSm2EcesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingRtSm2Eces(TypeRtKeyId_t rtKeyId,
		TypeDecryptSm2Eces_t *pSm2EcesData,
		TypeSW_t *pHsmStatusCode,
		TypeLen_t *pMsgLen,
		TypePlainText_t *pMsgData)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPTUSINGRTSM2ECES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pSm2EcesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
					&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmSm2EcesDecryption(keyHandle,
				convertCurveId(curveId), pSm2EcesData,
				pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPTUSINGRTSM2ECES);

	return retval;
}


/**
 *
 * @brief Decrypt data using SM2 ECES and module authentication key
 * @ingroup sm2_eces
 *
 * This function decrypts data using SM2 ECES and the module authentication
 * key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param pSm2EcesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingMaSm2Eces(TypeDecryptSm2Eces_t *pSm2EcesData,
		TypeSW_t *pHsmStatusCode,
		TypeLen_t *pMsgLen,
		TypePlainText_t *pMsgData)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPTUSINGMASM2ECES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pSm2EcesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmSm2EcesDecryption(keyHandle,
				convertCurveId(curveId), pSm2EcesData,
				pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPTUSINGMASM2ECES);

	return retval;
}


/**
 *
 * @brief Decrypt data using SM2 ECES and base key
 * @ingroup sm2_eces
 *
 * This function decrypts data using SM2 ECES and the specified base key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param baseKeyId key slot of base key to use
 * @param pSm2EcesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingBaSm2Eces(TypeBaseKeyId_t baseKeyId,
		TypeDecryptSm2Eces_t *pSm2EcesData,
		TypeSW_t *pHsmStatusCode,
		TypeLen_t *pMsgLen,
		TypePlainText_t *pMsgData)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPTUSINGBASM2ECES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pSm2EcesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
					&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmSm2EcesDecryption(keyHandle,
				convertCurveId(curveId), pSm2EcesData,
				pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPTUSINGBASM2ECES);

	return retval;
}
