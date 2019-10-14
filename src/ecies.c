
/*
 * Copyright 2019-2020 NXP
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
 * @file ecies.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer ECIES API
 *
 */

#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Convert public key from v2xse to hsm API format
 *
 * This function converts a public key from v2xse to hsm API format.
 * The hsm API format is as follows:
 *  - for 256 bit curve: x in bits 0 - 31, y in bits 32 - 63
 *  - for 384 bit curve: x in bits 0 - 47, y in bits 48 - 95
 * The v2xse API format is as follows for all curve sizes:
 *  - x in bits 0 - 47, y in bits 48 - 95
 *  - in case of 256 bit curves, bits 32 - 47 of x and y unused
 * The v2xSe format key comes directly from the API caller, the
 * new key is placed in a separate buffer.  It is possible to modify
 * the original buffer to the new format, but this creates a side effect
 * that the key passed by the caller is modified - which can cause hard
 * to debug issues if the caller expects to store a copy of the key and
 * use it multiple times.
 * Conversion is only required for 256 bit keys.  Unused bits are not
 * cleared in case output buffer is allocated for size of hsm key (i.e.
 * no unused bits).
 *
 * @param keyType The ECC curve used to generate the public key
 * @param pPublicKeyPlain location of the public key in v2xSe API format
 * @param hsm_key location of buffer to place public key in hsm API format
 *
 */
static void convertPublicKeyToHsmApi(hsm_key_type_t keyType,
			TypePublicKey_t *pPublicKeyPlain, uint8_t *hsm_key)
{
	if (is256bitCurve(keyType)) {
		hsmPubKey256_t *hsmApiPtr = (hsmPubKey256_t *)hsm_key;

		memcpy(hsmApiPtr->x, pPublicKeyPlain->x,
				sizeof(hsmApiPtr->y));
		memcpy(hsmApiPtr->y, pPublicKeyPlain->y,
				sizeof(hsmApiPtr->y));
	} else {
		hsmPubKey384_t *hsmApiPtr = (hsmPubKey384_t *)hsm_key;

		memcpy(hsmApiPtr->x, pPublicKeyPlain->x,
				sizeof(hsmApiPtr->y));
		memcpy(hsmApiPtr->y, pPublicKeyPlain->y,
				sizeof(hsmApiPtr->y));
	}
}

/**
 *
 * @brief Perform ECIES decryption using hsm
 *
 * This function performs ECIES decryption using the hsm.  It takes parameters
 * in v2xSe format, converts them to hsm_api format and launches the
 * decrpytion.
 *
 * @param keyHandle handle of key to use for decryption
 * @param keyType type of key for hsm to create
 * @param pEciesData pointer to decrpytion parameters in v2xSe format
 * @param pMsgLen msg size on output
 * @param pMsgData location to write decrpyted message
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static hsm_err_t doHsmDecryption(uint32_t keyHandle, hsm_key_type_t keyType,
			TypeDecryptEcies_t *pEciesData,
			TypeLen_t *pMsgLen, TypePlainText_t *pMsgData)
{
	hsm_op_ecies_dec_args_t args;
	hsm_err_t retVal;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	if (pEciesData->kdfParamP1Len) {
		args.p1 = pEciesData->kdfParamP1;
		args.p1_size = pEciesData->kdfParamP1Len;
	}
	if (pEciesData->macParamP2Len) {
		args.p2 = pEciesData->macParamP2;
		args.p2_size = pEciesData->macParamP2Len;
	}
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	args.output_size = HSM_ECIES_MESSAGE_SIZE;
	args.mac_size = pEciesData->macLen;
	args.key_type = keyType;
	TRACE_HSM_CALL(PROFILE_ID_HSM_ECIES_DECRYPTION);
	retVal = hsm_ecies_decryption(hsmCipherHandle, &args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_ECIES_DECRYPTION);
	if (!retVal)
		*pMsgLen = args.output_size;
	return retVal;
}

/**
 *
 * @brief Encrypt data using ECIES
 * @ingroup ecies
 *
 * This function encrypts data using the ECIES encryption scheme.  The data to
 * encrypt, public key, and all other parameters needed to perform the
 * encryption are provided by the caller.
 *
 * @param pEciesData pointer to structure with data and encryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pVctLen length of encrypted data on output
 * @param pVctData pointer to location to write the encrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_encryptUsingEcies (TypeEncryptEcies_t *pEciesData,
					TypeSW_t *pHsmStatusCode,
					TypeLen_t *pVctLen,
					TypeVCTData_t *pVctData )
{
	hsm_op_ecies_enc_args_t args;
	hsm_key_type_t keyType;
	uint8_t hsm_key[V2XSE_384_EC_PUB_KEY];
	int32_t retval = V2XSE_FAILURE;
	hsm_err_t hsmret;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ENCRYPTUSINGECIES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pEciesData != NULL) &&
			(pVctLen != NULL) &&
			(pVctData != NULL)) {

		keyType = convertCurveId(pEciesData->curveId);
		convertPublicKeyToHsmApi(keyType, pEciesData->pEccPublicKey,
								hsm_key);

		memset(&args, 0, sizeof(args));
		args.input = pEciesData->pMsgData->data;
		args.pub_key = hsm_key;
		if (pEciesData->kdfParamP1Len) {
			args.p1 = pEciesData->kdfParamP1;
			args.p1_size = pEciesData->kdfParamP1Len;
		}
		if (pEciesData->macParamP2Len) {
			args.p2 = pEciesData->macParamP2;
			args.p2_size = pEciesData->macParamP2Len;
		}
		args.output = pVctData->data;
		args.input_size = pEciesData->msgLen;
		args.pub_key_size = keyLenFromCurveID(pEciesData->curveId);
		args.mac_size = pEciesData->macLen;
		args.out_size = HSM_ECIES_VECTOR_SIZE;
		args.key_type = keyType;
		TRACE_HSM_CALL(PROFILE_ID_HSM_ECIES_ENCRYPTION);
		hsmret = hsm_ecies_encryption(hsmSessionHandle, &args);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_ECIES_ENCRYPTION);
		if (hsmret) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pVctLen = args.out_size;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_ENCRYPTUSINGECIES);
	return retval;
}

/**
 *
 * @brief Decrypt data using ECIES and runtime key
 * @ingroup ecies
 *
 * This function decrypts data using ECIES and the specified runtime key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param rtKeyId key slot of runtime key to use
 * @param pEciesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingRtEcies (TypeRtKeyId_t rtKeyId,
					TypeDecryptEcies_t *pEciesData,
					TypeSW_t *pHsmStatusCode,
					TypeLen_t *pMsgLen,
					TypePlainText_t *pMsgData )
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPYUSINGRTECIES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pEciesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmDecryption(keyHandle, convertCurveId(curveId),
					pEciesData, pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPYUSINGRTECIES);
	return retval;
}

/**
 *
 * @brief Decrypt data using ECIES and module authentication key
 * @ingroup ecies
 *
 * This function decrypts data using ECIES and the module authentication key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param pEciesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingMaEcies
(
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPTUSINGMAECIES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pEciesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmDecryption(keyHandle, convertCurveId(curveId),
					pEciesData, pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPTUSINGMAECIES);
	return retval;
}

/**
 *
 * @brief Decrypt data using ECIES and base key
 * @ingroup ecies
 *
 * This function decrypts data using ECIES and the specified base key.
 * The data to decrypt and all other parameters needed to perform the
 * decryption are provided by the caller.
 *
 * @param baseKeyId key slot of base key to use
 * @param pEciesData pointer to structure with data and decryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pMsgLen msg buffer size on input, length of decrypted data on output
 * @param pMsgData pointer to location to write the decrypted data
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_decryptUsingBaEcies
(
    TypeBaseKeyId_t baseKeyId,
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DECRYPTUSINGBAECIES);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pEciesData != NULL) &&
			(pMsgLen != NULL) &&
			(pMsgData != NULL)) {

		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (doHsmDecryption(keyHandle, convertCurveId(curveId),
					pEciesData, pMsgLen, pMsgData)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DECRYPTUSINGBAECIES);
	return retval;
}
