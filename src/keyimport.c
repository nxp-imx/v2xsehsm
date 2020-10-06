// SPDX-License-Identifier: BSD-3-Clause
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
 * @file keyimport.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer key injection API
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"
#include <string.h>

/**
 *
 * @brief Import hsm ECC private key
 *
 * This function imports an ECC private key to the hsm key store.
 *
 * @param pKeyHandle pointer to key handle location
 * @param keyType type of key for hsm to create
 * @param action indicates whether to create or update key
 * @param usage indicates required key usage (rt, ba or ma)
 * @param group key group used by HSM for secure storage
 * @param pKeyData data field containing encrypted key to import
 * @param keyDataSize size of key data
 * @param kekId slot corresponding to the KEK identifier
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static int32_t importHsmKey(uint32_t *pKeyHandle, hsm_key_type_t keyType,
		genKeyAction_t action, keyUsage_t usage, hsm_key_group_t group,
		uint8_t *pKeyData, uint16_t keyDataSize, uint32_t kekHandle)
{
	op_manage_key_args_t import_args;
	hsm_err_t hsmret;

	memset(&import_args, 0, sizeof(import_args));
	import_args.key_identifier = pKeyHandle;
	import_args.kek_identifier = kekHandle;
	import_args.input_size = keyDataSize;
	if (action == UPDATE_KEY)
		import_args.flags = HSM_OP_MANAGE_KEY_FLAGS_IMPORT_UPDATE;
	else /* CREATE_KEY */
		import_args.flags = HSM_OP_MANAGE_KEY_FLAGS_IMPORT_CREATE;
	/* Always use strict update - need to modify for closed part */
	import_args.flags |= HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION;
	import_args.key_type = keyType;
	import_args.key_group = group;
	/* All keys persistent */
	import_args.key_info = HSM_KEY_INFO_PERSISTENT;
	switch (usage) {
	case RT_KEY:
		/* RT key does not need any extra flags set */
		break;
	case BA_KEY:
		/* BA keys can be used for butterfly */
		import_args.key_info |= HSM_KEY_INFO_MASTER;
		break;
	case MA_KEY:
		/* MA key cannot be modified */
		import_args.key_info |= HSM_KEY_INFO_PERMANENT;
		break;
	}
	import_args.input_data = pKeyData;

	TRACE_HSM_CALL(PROFILE_ID_HSM_MANAGE_KEY);
	hsmret = hsm_manage_key(hsmKeyMgmtHandle, &import_args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_MANAGE_KEY);
	return hsmret;
}

/**
 *
 * @brief Get key encryption key
 * @ingroup keyimport
 *
 * This function retrieves the key encryption key.  This key is
 * used to encrypt private keys used for key injection.
 *
 * Note: this API is about to be deprecated and is currently only supported on
 * earlier versions of HSM (i.e.: SECO HSM on i.MX8 QXP C0).
 * It will be replaced by v2xSe_createKek() API for newer versions of HSM,
 * including i.MX8 DXL.
 *
 * @param kekType indicates type of KEK to retrieve, 0=unique, 1=common
 * @param pSignedMessage pointer to location of authorizing signed message
 * @param signedMessageLength length of signed message
 * @param pKek pointer to location to write KEK
 * @param pKekLength pointer to length of KEK buffer
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getKek(
	uint16_t kekType,
	uint8_t *pSignedMessage,
	uint16_t signedMessageLength,
	uint8_t *pKek,
	uint16_t *pKekLength,
	TypeSW_t *pHsmStatusCode)
{
	op_export_root_kek_args_t args;
	int32_t retval = V2XSE_FAILURE;
	int32_t hsmret;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETKEKPUBLICKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(kekType <= KEK_TYPE_COMMON) &&
			(pSignedMessage != NULL) &&
			(pKek != NULL) &&
			(pKekLength != NULL)) {

		memset(&args, 0, sizeof(args));
		args.signed_message = pSignedMessage;
		args.out_root_kek = pKek;
		args.signed_msg_size = signedMessageLength;
		args.root_kek_size = *pKekLength;
		if (kekType == KEK_TYPE_UNIQUE)
			args.flags |= HSM_OP_EXPORT_ROOT_KEK_FLAGS_UNIQUE_KEK;
		else if (kekType == KEK_TYPE_COMMON)
			args.flags |= HSM_OP_EXPORT_ROOT_KEK_FLAGS_COMMON_KEK;
		TRACE_HSM_CALL(PROFILE_ID_HSM_EXPORT_ROOT_KEY_ENCRYPTION_KEY);
		hsmret = hsm_export_root_key_encryption_key(hsmSessionHandle,
									&args);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_EXPORT_ROOT_KEY_ENCRYPTION_KEY);
		if (!hsmret) {
			retval = V2XSE_SUCCESS;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			*pKekLength = args.root_kek_size;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETKEKPUBLICKEY);
	return retval;
}

/**
 *
 * @brief Create a Runtime key encryption key (KEK) based on key exchange
 * @ingroup keyimport
 *
 * This function creates a Runtime symmetric key encryption key, derived from the
 * initiator's public key and the responder's key, based on the SHA KDF algorithm.
 * The user of this API is considered as the initiator while the HSM end is seen
 * as the responder.
 * This shared key is used to encrypt private/secret keys used for key injection.
 * If a runtime key exists in the specified slot, it will be overwritten.
 * The symmetric KEK is stored by the HSM in the key store for the current applet.
 *
 * @param[in]  pSignedMessage pointer to location of authorizing signed message
 * @param[in]  signedMessageLength length of signed message
 * @param[in]  pInitiatorPublicKey initiator's public key used to create the KEK
 * @param[out] pResponderPublicKey pointer to location to write the responder's
 *             public key. It shall be used by the initiator to compute the KEK
 * @param[in]  rtKeyId slot number for the created runtime KEK
 * @param[out] pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_createKek(
	uint8_t *pSignedMessage,
	uint16_t signedMessageLength,
	TypePublicKey_t *pInitiatorPublicKey,
	TypePublicKey_t *pResponderPublicKey,
	TypeRtKeyId_t rtKeyId,
	TypeSW_t *pHsmStatusCode)
{
	TypeCurveId_t exchCurveId = V2XSE_CURVE_NISTP256;
	hsm_key_type_t exchKeyType;
	TypeSymmetricKeyId_t sharedSymmetricKeyId = V2XSE_SYMMK_AES_256;
	TypeSymmetricKeyId_t storedSymmetricKeyId;
	hsm_key_type_t sharedKeyType;
	op_key_exchange_args_t args = {0};
	hsm_err_t hsmret;
	uint8_t hsm_initPubKey[V2XSE_384_EC_PUB_KEY];
	uint32_t keyHandle;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;
	int32_t retval = V2XSE_FAILURE;

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode, &retval)) {
			break;
		}

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		exchKeyType = convertCurveId(exchCurveId);
		sharedKeyType = convertSymmetricKeyId(sharedSymmetricKeyId);
		if (!sharedKeyType) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		if (!nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
						&storedSymmetricKeyId)) {
			keyModified = 1;
			/* Check if can overwrite */
			if (sharedSymmetricKeyId != storedSymmetricKeyId) {
				/* Different type, must delete */
				if (deleteRtKey(rtKeyId))
					break;
			}
		}
		convertPublicKeyToHsmApi(exchKeyType, pInitiatorPublicKey,
				hsm_initPubKey);

		memset(&args, 0, sizeof(args));
		/* An ephemeral key will be generated by HSM */
		args.key_identifier = 0;
		args.shared_key_identifier_array = (uint8_t *)&keyHandle;
		args.ke_input = hsm_initPubKey;
		args.ke_output = (uint8_t *)pResponderPublicKey;
		args.kdf_input = NULL;
		args.kdf_output = NULL;
		args.shared_key_group = getKeyGroup(RT_KEY, rtKeyId);
		args.shared_key_info = HSM_KEY_INFO_KEK;
		args.shared_key_type = sharedKeyType;
		args.initiator_public_data_type = convertCurveId(exchCurveId);
		args.key_exchange_scheme = HSM_KE_SCHEME_ECDH_NIST_P256;
		args.kdf_algorithm = HSM_KDF_ONE_STEP_SHA_256;
		args.ke_input_size = keyLenFromCurveID(exchCurveId);
		args.ke_output_size = keyLenFromCurveID(exchCurveId);
		args.shared_key_identifier_array_size = sizeof(keyHandle);
		args.kdf_input_size = 0;
		args.kdf_output_size = 0;
		args.flags = (!rtKeyHandle[rtKeyId] ?
					HSM_OP_KEY_EXCHANGE_FLAGS_CREATE :
					HSM_OP_KEY_GENERATION_FLAGS_UPDATE) |
					HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL;
		/* Always use strict update - need to modify for closed part */
		args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;

		args.signed_message = pSignedMessage;
		args.signed_msg_size = signedMessageLength;
		hsmret = hsm_key_exchange(hsmKeyMgmtHandle, &args);
		if (hsmret) {
			break;
		}
		keyCreated = 1;
		if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId,
				(uint8_t *)&sharedSymmetricKeyId,
				sizeof(sharedSymmetricKeyId))) {
			break;
		}
		if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
				(uint8_t *)&keyHandle,
				sizeof(keyHandle))) {
			break;
		}
		convertPublicKeyToV2xseApi(sharedKeyType, pResponderPublicKey);
		rtKeyHandle[rtKeyId] = keyHandle;
		rtCurveId[rtKeyId] = sharedSymmetricKeyId;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	} while (0);

	if (retval != V2XSE_SUCCESS) {
		if (keyModified || keyCreated) {
			deleteRtKey(rtKeyId);
			/* Flag no change only if previous key not modified */
			if (!keyModified)
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		}
	}

	return retval;
}

/**
 *
 * @brief Inject MA private key
 * @ingroup keyimport
 *
 * This function injects the MA private key into the device.
 *
 * @param curveId The ECC curve to be used with the injected key
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write derived public key
 * @param pKeyData data containing encrypted private key
 * @param keyDataSize size of data containing encrypted private key
 * @param kekId slot corresponding to the KEK identifier
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_injectMaEccPrivateKey(
	TypeCurveId_t curveId,
	TypeSW_t *pHsmStatusCode,
	TypePublicKey_t *pPublicKeyPlain,
	uint8_t *pKeyData,
	uint16_t keyDataSize,
	TypeRtKeyId_t kekId)
{
	int32_t retval = V2XSE_FAILURE;
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	uint32_t kekHandle;
	TypeCurveId_t storedCurveId;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_INJECTMAECCPRIVATEKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pPublicKeyPlain != NULL) &&
			(pKeyData != NULL)) {

		do {
			if (kekId >= NUM_STORAGE_SLOTS) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
				break;
			}
			if (!nvm_retrieve_rt_key_handle(kekId, &kekHandle,
							&storedCurveId)) {
				/* KEK must be an AES 256 symmetric key */
				if (storedCurveId != V2XSE_SYMMK_AES_256)
					break;
			} else {
				/* can't inject a new key without KEK */
				break;
			}
			keyType = convertCurveId(curveId);
			if (!keyType) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
				break;
			}
			if (!nvm_retrieve_ma_key_handle(&keyHandle,
							&storedCurveId)) {
				/* MA is already assigned */
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			if (importHsmKey(&keyHandle, keyType, CREATE_KEY,
					MA_KEY, MA_KEY_GROUP, pKeyData,
						keyDataSize, kekHandle)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			keyCreated = 1;
			if (nvm_update_var(MA_CURVEID_NAME,
						(uint8_t *)&curveId,
							sizeof(curveId))) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			if (nvm_update_var(MA_KEYHANDLE_NAME,
						(uint8_t *)&keyHandle,
							sizeof(keyHandle))) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			if (getHsmPubKey(keyHandle, keyType,
					keyLenFromCurveID(curveId),
						(uint8_t *)pPublicKeyPlain)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
			maCurveId = curveId;
			maKeyHandle = keyHandle;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		} while (0);
		/* Clear key handle in case of error when creating*/
		if ((retval != V2XSE_SUCCESS) && (keyCreated)) {
			(void)deleteHsmKey(keyHandle, keyType, MA_KEY_GROUP);
			maKeyHandle = 0;
			(void)nvm_delete_var(MA_CURVEID_NAME);
			(void)nvm_delete_var(MA_KEYHANDLE_NAME);
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_INJECTMAECCPRIVATEKEY);
	return retval;
}

/**
 *
 * @brief Inject RT private key
 * @ingroup keyimport
 *
 * This function injects an RT private key into the device.
 *
 * @param rtKeyId slot to store injected private key
 * @param curveId The ECC curve to be used with the injected key
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write derived public key
 * @param pKeyData data containing encrypted private key
 * @param keyDataSize size of data containing encrypted private key
 * @param kekId slot corresponding to the KEK identifier
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_injectRtEccPrivateKey(
	TypeRtKeyId_t rtKeyId,
	TypeCurveId_t curveId,
	TypeSW_t *pHsmStatusCode,
	TypePublicKey_t *pPublicKeyPlain,
	uint8_t *pKeyData,
	uint16_t keyDataSize,
	TypeRtKeyId_t kekId)
{
	int32_t retval = V2XSE_FAILURE;
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	uint32_t kekHandle;
	TypeCurveId_t storedCurveId;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_INJECTRTECCPRIVATEKEY);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode,
								&retval) ||
				(pPublicKeyPlain == NULL) ||
				(pKeyData == NULL)) {
			break;
		}
		if (kekId >= NUM_STORAGE_SLOTS || rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		if (!nvm_retrieve_rt_key_handle(kekId, &kekHandle,
						&storedCurveId)) {
			/* KEK must be an AES 256 symmetric key */
			if (storedCurveId != V2XSE_SYMMK_AES_256)
				break;
		} else {
			/* can't inject a new key without KEK */
			break;
		}
		keyType = convertCurveId(curveId);
		if (!keyType) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		if (!nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
						&storedCurveId)) {
			keyModified = 1;
			/* Check if can overwrite */
			if (curveId != storedCurveId) {
				/* Different type, must delete */
				if (deleteRtKey(rtKeyId))
					break;
			}
		}
		if (importHsmKey(&keyHandle,
					keyType,
					rtKeyHandle[rtKeyId] ? UPDATE_KEY :
							CREATE_KEY,
					RT_KEY,
					getKeyGroup(RT_KEY, rtKeyId),
					pKeyData,
					keyDataSize,
					kekHandle)) {
			break;
		}
		keyCreated = 1;
		if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId,
				(uint8_t *)&curveId, sizeof(curveId))) {
			break;
		}
		if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
					(uint8_t *)&keyHandle,
						sizeof(keyHandle))) {
			break;
		}
		if (getHsmPubKey(keyHandle, keyType,
				keyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain)) {
			break;
		}
		convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
		rtKeyHandle[rtKeyId] = keyHandle;
		rtCurveId[rtKeyId] = curveId;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	} while (0);
	if (retval != V2XSE_SUCCESS) {
		if (keyModified || keyCreated) {
			(void)deleteRtKey(rtKeyId);
			/* Flag no change only if previous key not modified */
			if (!keyModified)
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_INJECTRTECCPRIVATEKEY);
	return retval;
}

/**
 *
 * @brief Inject BA private key
 * @ingroup keyimport
 *
 * This function injects an BA private key into the device.
 *
 * @param baseKeyId slot to store injected private key
 * @param curveId The ECC curve to be used with the injected key
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write derived public key
 * @param pKeyData data containing encrypted private key
 * @param keyDataSize size of data containing encrypted private key
 * @param kekId slot corresponding to the KEK identifier
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_injectBaEccPrivateKey(
	TypeBaseKeyId_t baseKeyId,
	TypeCurveId_t curveId,
	TypeSW_t *pHsmStatusCode,
	TypePublicKey_t *pPublicKeyPlain,
	uint8_t *pKeyData,
	uint16_t keyDataSize,
	TypeRtKeyId_t kekId)
{
	int32_t retval = V2XSE_FAILURE;
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	uint32_t kekHandle;
	TypeCurveId_t storedCurveId;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_INJECTBAECCPRIVATEKEY);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode,
								&retval) ||
				(pPublicKeyPlain == NULL) ||
				(pKeyData == NULL)) {
			break;
		}
		if (kekId >= NUM_STORAGE_SLOTS || baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		if (!nvm_retrieve_rt_key_handle(kekId, &kekHandle,
						&storedCurveId)) {
			/* KEK must be an AES 256 symmetric key */
			if (storedCurveId != V2XSE_SYMMK_AES_256)
				break;
		} else {
			/* can't inject a new key without KEK */
			break;
		}
		keyType = convertCurveId(curveId);
		if (!keyType) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		if (!nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
						&storedCurveId)) {
			keyModified = 1;
			/* Check if can overwrite */
			if (curveId != storedCurveId) {
				/* Different type, must delete */
				if (deleteBaKey(baseKeyId))
					break;
			}
		}
		if (importHsmKey(&keyHandle,
					keyType,
					baKeyHandle[baseKeyId] ? UPDATE_KEY :
							CREATE_KEY,
					BA_KEY,
					getKeyGroup(BA_KEY, baseKeyId),
					pKeyData,
					keyDataSize,
					kekHandle)) {
			break;
		}
		keyCreated = 1;
		if (nvm_update_array_data(BA_CURVEID_NAME, baseKeyId,
				(uint8_t *)&curveId, sizeof(curveId))) {
			break;
		}
		if (nvm_update_array_data(BA_KEYHANDLE_NAME, baseKeyId,
					(uint8_t *)&keyHandle,
						sizeof(keyHandle))) {
			break;
		}
		if (getHsmPubKey(keyHandle, keyType,
				keyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain)) {
			break;
		}
		convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
		baKeyHandle[baseKeyId] = keyHandle;
		baCurveId[baseKeyId] = curveId;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	} while (0);
	if (retval != V2XSE_SUCCESS) {
		if (keyModified || keyCreated) {
			(void)deleteBaKey(baseKeyId);
			/* Flag no change only if previous key not modified */
			if (!keyModified)
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		}
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_INJECTBAECCPRIVATEKEY);
	return retval;
}
