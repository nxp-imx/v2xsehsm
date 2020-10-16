
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
 * @file keymanagement.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer key management API
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"
#include <string.h>

/**
 *
 * @brief Convert public key from hsm to v2xse API format
 *
 * This function converts a public key from hsm_api to v2xse API format.
 * The hsm API format is as follows:
 *  - for 256 bit curve: x in bits 0 - 31, y in bits 32 - 63
 *  - for 384 bit curve: x in bits 0 - 47, y in bits 48 - 95
 * The v2xse API format is as follows for all curve sizes:
 *  - x in bits 0 - 47, y in bits 48 - 95
 *  - in case of 256 bit curves, upper bits of x and y unused
 * Conversion is only required for 256 bit keys, which involves moving the
 * contents of the y coordinate up 128 bits in memory.
  *
 * @param keyType The ECC curve used to generate the public key
 * @param pPublicKeyPlain location of the generated public key
 *
 */
void convertPublicKeyToV2xseApi(hsm_key_type_t keyType,
					TypePublicKey_t *pPublicKeyPlain)
{
	hsmPubKey256_t *hsmApiPtr = (hsmPubKey256_t*)pPublicKeyPlain;

	if (is256bitCurve(keyType)) {
		memmove(pPublicKeyPlain->y, hsmApiPtr->y,
				sizeof(hsmApiPtr->y));
		memset(&(pPublicKeyPlain->x[V2XSE_256_EC_PUB_KEY_XY_SIZE]), 0,
			V2XSE_384_EC_PUB_KEY_XY_SIZE -
						V2XSE_256_EC_PUB_KEY_XY_SIZE);
		memset(&(pPublicKeyPlain->y[V2XSE_256_EC_PUB_KEY_XY_SIZE]), 0,
			V2XSE_384_EC_PUB_KEY_XY_SIZE -
						V2XSE_256_EC_PUB_KEY_XY_SIZE);
	}
}

/**
 *
 * @brief Calculate HSM secure storage group to use for given key
 *
 * The HSM stores keys in groups of 100 keys, with 1024 groups being
 * available.  This adaptation layer selects the group to use based on
 * the key ID from the API and the key usage, using the following mapping:
 * 0: EU, US & CN MA keys
 * 1 to 128: EU RT keys
 * 129 to 256: EU BA keys
 * 257 to 384: US RT keys
 * 385 to 512: US BA keys
 * 513 to 640: CN RT keys
 * 641 to 768: CN BA keys
 * 769 to 1023: Generic data (not yet implemented in keystore)
 *
 * @param keyUsage type of key, used to calculate the offset
 * @param keyId key Id, used to select which group of 100 keys
 *
 * @return key group to use
 *
 */
hsm_key_group_t getKeyGroup(keyUsage_t keyUsage, TypeRtKeyId_t keyId)
{
	hsm_key_group_t keyGroup;

	/* Starting group based on applet, US, EU or CN */
	if ((v2xseAppletId == e_US) || (v2xseAppletId == e_US_AND_GS))
		keyGroup = US_KEYGROUP_START;
	else if ((v2xseAppletId == e_EU) || (v2xseAppletId == e_EU_AND_GS))
		keyGroup = EU_KEYGROUP_START;
	else
		keyGroup = CN_KEYGROUP_START;

	/* Add BA key offset if base key */
	if (keyUsage == BA_KEY)
		keyGroup += BA_KEYGROUP_OFFSET;

	/* Add further offset based on keyId, 100 keys per group */
	keyGroup += (keyId / KEYS_PER_GROUP);

	return keyGroup;
}

/**
 *
 * @brief Generate hsm ECC key pair
 *
 * This function generates an ECC key pair in the hsm key store.  It may
 * either create a new key, or update an existing key, depending on the
 * flags parameter.  The key may be permanent or not depending on key_info.
 *
 * @param pKeyHandle pointer to key handle location
 * @param keyType type of key for hsm to create
 * @param pubKeySize size of public key to generate
 * @param pPubKey location to write public key
 * @param action indicates whether to create or update key
 * @param usage indicates required key usage (rt, ba or ma)
 * @param group key group used by HSM for secure storage
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static int32_t genHsmKey(uint32_t *pKeyHandle, hsm_key_type_t keyType,
		uint16_t pubKeySize, uint8_t *pPubKey, genKeyAction_t action,
		keyUsage_t usage, hsm_key_group_t group)
{
	op_generate_key_args_t args;
	hsm_err_t hsmret;

	memset(&args, 0, sizeof(args));
	args.key_identifier = pKeyHandle;
	args.out_size = pubKeySize;
	if (action == UPDATE_KEY)
		args.flags = HSM_OP_KEY_GENERATION_FLAGS_UPDATE;
	else /* CREATE_KEY */
		args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	/* Always use strict update - need to modify for closed part */
	args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	args.key_group = group;
	/* All keys persistent */
	args.key_info = HSM_KEY_INFO_PERSISTENT;
	switch (usage) {
	case RT_KEY:
		/* RT key does not need any extra flags set */
		break;
	case BA_KEY:
		/* BA keys can be used for butterfly */
		args.key_info |= HSM_KEY_INFO_MASTER;
		break;
	case MA_KEY:
		/* MA key cannot be modified */
		args.key_info |= HSM_KEY_INFO_PERMANENT;
		break;
	}
	args.key_type = keyType;
	args.out_key = pPubKey;
	TRACE_HSM_CALL(PROFILE_ID_HSM_GENERATE_KEY);
	hsmret = hsm_generate_key(hsmKeyMgmtHandle, &args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_GENERATE_KEY);
	return hsmret;
}

/**
 *
 * @brief Calculate ECC public key in hsm
 *
 * This function requests the hsm to generate the ECC public key corresponding
 * to the referenced private key.
 *
 * @param keyHandle handle of key to generate pub key for
 * @param keyType type of key for hsm to create
 * @param pubKeySize size of public key to generate
 * @param pPubKey location to write public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t getHsmPubKey(uint32_t keyHandle, hsm_key_type_t keyType,
		uint16_t pubKeySize, uint8_t *pPubKey)
{
	op_pub_key_recovery_args_t args;
	hsm_err_t hsmret;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.out_key = pPubKey;
	args.out_key_size = pubKeySize;
	args.key_type = keyType;
	TRACE_HSM_CALL(PROFILE_ID_HSM_PUB_KEY_RECOVERY);
	hsmret = hsm_pub_key_recovery(hsmKeyStoreHandle, &args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_PUB_KEY_RECOVERY);
	return hsmret;
}

/**
 *
 * @brief Delete hsm ECC private key
 *
 * This function deletes a ECC private key from the hsm key store.
 *
 * @param keyHandle hsm handle for private key to delete
 * @param keyType type of key to delete
 * @param group key group used by HSM for secure storage
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t deleteHsmKey(uint32_t keyHandle, hsm_key_type_t keyType,
							hsm_key_group_t group)
{
	op_manage_key_args_t del_args;
	hsm_err_t hsmret;

	memset(&del_args, 0, sizeof(del_args));
	del_args.key_identifier = &keyHandle;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	/* Always use strict update - need to modify for closed part */
	del_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	del_args.key_type = keyType;
	del_args.key_group = group;
	TRACE_HSM_CALL(PROFILE_ID_HSM_MANAGE_KEY);
	hsmret = hsm_manage_key(hsmKeyMgmtHandle, &del_args);
	TRACE_HSM_RETURN(PROFILE_ID_HSM_MANAGE_KEY);
	return hsmret;
}

/**
 *
 * @brief Delete runtime ECC key pair
 *
 * This function deletes the runtime ECC key pair from the specified slot.
 * The corresponding private key is deleted from the HSM key store, the
 * key handle is removed from memory and nvm, and the curveId is removed
 * from nvm.
 *
 * @param rtKeyId slot number of the runtime key pair to delete
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t deleteRtKey(TypeRtKeyId_t rtKeyId)
{
	int32_t retval = V2XSE_SUCCESS;
	uint32_t keyHandle = rtKeyHandle[rtKeyId];

	rtKeyHandle[rtKeyId] = 0;

	if (deleteHsmKey(keyHandle, convertCurveId(rtCurveId[rtKeyId]),
						getKeyGroup(RT_KEY, rtKeyId)))
		retval = V2XSE_FAILURE;
	if (nvm_delete_array_data(RT_CURVEID_NAME, rtKeyId))
		retval = V2XSE_FAILURE;
	if (nvm_delete_array_data(RT_KEYHANDLE_NAME, rtKeyId))
		retval = V2XSE_FAILURE;

	return retval;
}

/**
 *
 * @brief Delete base ECC key pair
 *
 * This function deletes the base ECC key pair from the specified slot.
 * The corresponding private key is deleted from the HSM key store, the
 * key handle is removed from memory and nvm, and the curveId is removed
 * from nvm.
 *
 * @param baKeyId slot number of the base key pair to delete
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */

int32_t deleteBaKey(TypeBaseKeyId_t baKeyId)
{
	int32_t retval = V2XSE_SUCCESS;
	uint32_t keyHandle = baKeyHandle[baKeyId];

	baKeyHandle[baKeyId] = 0;

	if (deleteHsmKey(keyHandle, convertCurveId(baCurveId[baKeyId]),
						getKeyGroup(BA_KEY, baKeyId)))
		retval = V2XSE_FAILURE;
	if (nvm_delete_array_data(BA_CURVEID_NAME, baKeyId))
		retval = V2XSE_FAILURE;
	if (nvm_delete_array_data(BA_KEYHANDLE_NAME, baKeyId))
		retval = V2XSE_FAILURE;

	return retval;
}

/**
 *
 * @brief Generate Module Authentication ECC key pair
 * @ingroup keymanagement
 *
 * This function instructs the system to randomly generate the Module
 * Authentication ECC key pair for the current applet.  This will fail
 * if the current applet already has an MA key pair.  The HSM is used to
 * generate a new key pair, and the handle and curveId of the new key is
 * stored in NVM.  The private key is stored by the HSM in the key store
 * for the current applet.
 *
 * @param curveId The ECC curve to be used to generate the key pair
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_generateMaEccKeyPair
(
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
)
{
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t savedCurveId;
	int32_t retval = V2XSE_FAILURE;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GENERATEMAECCKEYPAIR);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE) &&
			(pPublicKeyPlain != NULL)) {

		do {
			keyType = convertCurveId(curveId);
			if (!keyType) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
				break;
			}
			if (!nvm_retrieve_ma_key_handle(&keyHandle,
							&savedCurveId)) {
				/* MA is already assigned */
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				break;
			}
			if (genHsmKey(&keyHandle, keyType,
					keyLenFromCurveID(curveId),
					(uint8_t *)pPublicKeyPlain, CREATE_KEY,
						MA_KEY, MA_KEY_GROUP)) {
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
			convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
			maCurveId = curveId;
			maKeyHandle = keyHandle;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		} while (0);
		/* Clear key handle in case of error when creating */
		if ((retval != V2XSE_SUCCESS) && (keyCreated)) {
			deleteHsmKey(keyHandle, keyType, MA_KEY_GROUP);
			maKeyHandle = 0;
			nvm_delete_var(MA_CURVEID_NAME);
			nvm_delete_var(MA_KEYHANDLE_NAME);
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GENERATEMAECCKEYPAIR);
	return retval;
}

/**
 *
 * @brief Creates a Module Authentication secret shared key from the
 * specified initiator's (user) and responder's (HSM) runtime keys
 * @ingroup keymanagement
 *
 * This function derives a Module Authentication key from the specified keys
 * using the kdf algorithm specified in input.
 * During the key exchange, there is an initiator and a responder. The former is
 * considered as the user of the HSM and the latter the HSM itself.
 * The result of this operation is the creation of a secret shared key.
 *
 * NOTE: This operation is only permitted for the CN applet.
 *
 * @param initiatorCurveId curve ID associated with the initiator's key pair,
 *        this value also defines the key exchange scheme ;
 *        valid value is V2XSE_CURVE_SM2_256
 * @param pInitiatorPublicKey initiator's public key
 * @param pResponderPublicKey pointer to location to write the responder's
 *        public key
 * @param pkeyExchangeData pointer to specific data depending on scheme and
 *        algorithm used
 * @param sharedKeyTypeId ECC curve or Symmetric key type associated with
 *        the shared key ;
 *        supported range is {V2XSE_CURVE_SM2_256, V2XSE_SYMMK_SM4_128}
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 */
int32_t v2xSe_exchangeMaPrivateKey
(
    TypeCurveId_t initiatorCurveId,
    TypePublicKey_t *pInitiatorPublicKey,
    TypePublicKey_t *pResponderPublicKey,
    TypeKeyExchange_t *pkeyExchangeData,
    TypeKeyTypeId_t sharedKeyTypeId,
    TypeSW_t *pHsmStatusCode
)
{
	return V2XSE_FUNC_NOT_SUPPORTED;
}

/**
 *
 * @brief Get Module Authenitication public key
 * @ingroup keymanagement
 *
 * This function retrieves the public key and curveId for the Module
 * Authentication ECC key pair.  The handle of the MA key is retrieved
 * from nvm then the HSM is requested to calculate the public key that
 * corresponds to the private key stored in the key store.  The curveId
 * is directly retrieved from nvm.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pCurveId pointer to location to write retrieved curveId
 * @param pPublicKeyPlain pointer to location to write calculated public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getMaEccPublicKey
(
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_key_type_t keyType;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETMAECCPUBLICKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pCurveId != NULL) &&
			(pPublicKeyPlain != NULL)) {

		if (nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
			*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		} else {
			keyType = convertCurveId(curveId);
			if (!keyType) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
			} else if (getHsmPubKey(keyHandle, keyType,
					keyLenFromCurveID(curveId),
					(uint8_t *)pPublicKeyPlain)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
			} else {
				convertPublicKeyToV2xseApi(keyType,
							pPublicKeyPlain);
				*pCurveId = curveId;
				*pHsmStatusCode = V2XSE_NO_ERROR;
				retval = V2XSE_SUCCESS;
			}
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETMAECCPUBLICKEY);
	return retval;
}

/**
 *
 * @brief Generate Runtime ECC key pair
 * @ingroup keymanagement
 *
 * This function instructs the system to randomly generate a Runtime ECC
 * key pair in the specified slot for the current applet.  If a runtime
 * key exists in the specified slot, it will be overwritten.  The HSM is
 * used to generate a new key pair, and the handle and curveId of the
 * new key is stored in NVM.  The slot number is used as the index into
 * a table storing runtime key handles.  The private key is stored by the
 * HSM in the key store for the current applet.
 *
 * @param rtKeyId slot number for the generated runtime key pair
 * @param curveId The ECC curve to be used to generate the key pair
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_generateRtEccKeyPair
(
    TypeRtKeyId_t rtKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
)
{
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;
	int32_t retval = V2XSE_FAILURE;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GENERATERTECCKEYPAIR);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode,
								&retval) ||
				(v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) ||
				(pPublicKeyPlain == NULL)) {
			break;
		}

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		keyType = convertCurveId(curveId);
		if (!is256bitCurve(keyType)) {
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
		if (genHsmKey(&keyHandle, keyType,
				keyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain,
				rtKeyHandle[rtKeyId] ? UPDATE_KEY :
						CREATE_KEY,
				RT_KEY,
				getKeyGroup(RT_KEY, rtKeyId))) {
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
		convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
		rtKeyHandle[rtKeyId] = keyHandle;
		rtCurveId[rtKeyId] = curveId;
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
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GENERATERTECCKEYPAIR);
	return retval;
}

/**
 *
 * @brief Creates a runtime secret shared key from the specified initiator's (user)
 * and responder's (HSM) runtime keys
 * @ingroup keymanagement
 *
 * This function derives a runtime key from the specified keys using the kdf
 * algorithm specified in input.
 * During the key exchange, there is an initiator and a responder. The former is
 * considered as the user of the HSM and the latter the HSM itself.
 * The result of this operation is the creation of a secret shared key.
 *
 * NOTE: This operation is only permitted for the CN applet.
 *
 * @param initiatorCurveId curve ID associated with the initiator's key pair,
 *        this value also defines the key exchange scheme ;
 *        valid value is V2XSE_CURVE_SM2_256
 * @param pInitiatorPublicKey initiator's public key
 * @param pResponderPublicKey pointer to location to write the responder's
 *        public key
 * @param pkeyExchangeData pointer to specific data depending on scheme and
 *        algorithm used
 * @param sharedKeyTypeId ECC curve or Symmetric key type associated with
 *        the shared key ;
 *        supported range is {V2XSE_CURVE_SM2_256, V2XSE_SYMMK_SM4_128}
 * @param sharedKeyId slot to store the secret shared key identifier
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 */
int32_t v2xSe_exchangeRtEccPrivateKey
(
    TypeCurveId_t initiatorCurveId,
    TypePublicKey_t *pInitiatorPublicKey,
    TypePublicKey_t *pResponderPublicKey,
    TypeKeyExchange_t *pkeyExchangeData,
    TypeKeyTypeId_t sharedKeyTypeId,
    TypeRtKeyId_t sharedKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	return V2XSE_FUNC_NOT_SUPPORTED;
}

/**
 *
 * @brief Delete runtime ECC key pair
 * @ingroup keymanagement
 *
 * This function deletes the runtime ECC key pair from the specified slot.
 * The corresponding private key is deleted from the HSM key store, the
 * key handle is removed from memory and nvm, and the curveId is removed
 * from nvm.
 *
 * @param rtKeyId slot number of the runtime key pair to delete
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deleteRtEccPrivateKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DELETERTECCPRIVATEKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
							&storedCurveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (deleteRtKey(rtKeyId)) {
			*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DELETERTECCPRIVATEKEY);
	return retval;
}

/**
 *
 * @brief Get Runtime public key
 * @ingroup keymanagement
 *
 * This function retrieves the public key and curveId for the runtime key
 * in the specified slot.  The handle of the runtime key is retrieved
 * from nvm then the HSM is requested to calculate the public key that
 * corresponds to the private key stored in the key store.  The curveId
 * is directly retrieved from nvm.
 *
 * @param rtKeyId slot number of the runtime key
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pCurveId pointer to location to write retrieved curveId
 * @param pPublicKeyPlain pointer to location to write calculated public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getRtEccPublicKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_key_type_t keyType;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETRTECCPUBLICKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pCurveId != NULL) &&
			(pPublicKeyPlain != NULL)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			keyType = convertCurveId(curveId);
			if (!is256bitCurve(keyType)) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
			} else if (getHsmPubKey(keyHandle, keyType,
					keyLenFromCurveID(curveId),
					(uint8_t *)pPublicKeyPlain)) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
			} else {
				convertPublicKeyToV2xseApi(keyType,
							pPublicKeyPlain);
				*pCurveId = curveId;
				*pHsmStatusCode = V2XSE_NO_ERROR;
				retval = V2XSE_SUCCESS;
			}
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETRTECCPUBLICKEY);
	return retval;
}

/**
 *
 * @brief Generate Base ECC key pair
 * @ingroup keymanagement
 *
 * This function instructs the system to randomly generate a Base ECC
 * key pair in the specified slot for the current applet.  If a Base
 * key exists in the specified slot, it will be overwritten.  The HSM is
 * used to generate a new key pair, and the handle and curveId of the
 * new key is stored in NVM.  The slot number is used as the index into
 * a table storing base key handles.  The private key is stored by the
 * HSM in the key store for the current applet.
 *
 * @param baseKeyId slot number for the generated base key pair
 * @param curveId The ECC curve to be used to generate the key pair
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPublicKeyPlain pointer to location to write public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_generateBaEccKeyPair
(
    TypeBaseKeyId_t baseKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
)
{
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;
	int32_t retval = V2XSE_FAILURE;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GENERATEBAECCKEYPAIR);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode,
								&retval) ||
				(v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) ||
				(pPublicKeyPlain == NULL)) {
			break;
		}

		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
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
		if (genHsmKey(&keyHandle, keyType,
				keyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain,
				baKeyHandle[baseKeyId] ?
					UPDATE_KEY : CREATE_KEY,
				BA_KEY,
				getKeyGroup(BA_KEY, baseKeyId))) {
			break;
		}
		keyCreated = 1;
		if (nvm_update_array_data(BA_CURVEID_NAME, baseKeyId,
						(uint8_t *)&curveId,
						sizeof(curveId))) {
			break;
		}
		if (nvm_update_array_data(BA_KEYHANDLE_NAME, baseKeyId,
						(uint8_t *)&keyHandle,
						sizeof(keyHandle))) {
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
			deleteBaKey(baseKeyId);
			/* Flag no change only if previous key not modified */
			if (!keyModified)
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GENERATEBAECCKEYPAIR);
	return retval;
}

/**
 *
 * @brief Creates a base secret shared key from the specified initiator's (user)
 * and responder's (HSM) runtime keys
 * @ingroup keymanagement
 *
 * This function derives a base key from the specified keys using the kdf
 * algorithm specified in input.
 * During the key exchange, there is an initiator and a responder. The former is
 * considered as the user of the HSM and the latter the HSM itself.
 * The result of this operation is the creation of a secret shared key.
 *
 * NOTE: This operation is only permitted for the CN applet.
 *
 * @param initiatorCurveId curve ID associated with the initiator's key pair,
 *        this value also defines the key exchange scheme ;
 *        valid value is V2XSE_CURVE_SM2_256
 * @param pInitiatorPublicKey initiator's public key
 * @param pResponderPublicKey pointer to location to write the responder's
 *        public key
 * @param pkeyExchangeData pointer to specific data depending on scheme and
 *        algorithm used
 * @param sharedKeyTypeId ECC curve or Symmetric key type associated with
 *        the shared key ;
 *        supported range is {V2XSE_CURVE_SM2_256, V2XSE_SYMMK_SM4_128}
 * @param sharedKeyId slot to store the secret shared key identifier
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 */
int32_t v2xSe_exchangeBaPrivateKey
(
    TypeCurveId_t initiatorCurveId,
    TypePublicKey_t *pInitiatorPublicKey,
    TypePublicKey_t *pResponderPublicKey,
    TypeKeyExchange_t *pkeyExchangeData,
    TypeKeyTypeId_t sharedKeyTypeId,
    TypeBaseKeyId_t sharedKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	return V2XSE_FUNC_NOT_SUPPORTED;
}

/**
 *
 * @brief Delete base ECC key pair
 * @ingroup keymanagement
 *
 * This function deletes the base ECC key pair from the specified slot.
 * The corresponding private key is deleted from the HSM key store, the
 * key handle is removed from memory and nvm, and the curveId is removed
 * from nvm.
 *
 * @param baseKeyId slot number of the base key pair to delete
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deleteBaEccPrivateKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DELETEBAECCPRIVATEKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {

		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
							&storedCurveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (deleteBaKey(baseKeyId)) {
			*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DELETEBAECCPRIVATEKEY);
	return retval;
}

/**
 *
 * @brief Get Base public key
 * @ingroup keymanagement
 *
 * This function retrieves the public key and curveId for the base key
 * in the specified slot.  The handle of the base key is retrieved
 * from nvm then the HSM is requested to calculate the public key that
 * corresponds to the private key stored in the key store.  The curveId
 * is directly retrieved from nvm.
 *
 * @param baseKeyId slot number of the base key
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pCurveId pointer to location to write retrieved curveId
 * @param pPublicKeyPlain pointer to location to write calculated public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getBaEccPublicKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_key_type_t keyType;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETBAECCPUBLICKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pCurveId != NULL) &&
			(pPublicKeyPlain != NULL)) {

		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
								&curveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			keyType = convertCurveId(curveId);
			if (!keyType) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
			} else if (getHsmPubKey(keyHandle, keyType,
					keyLenFromCurveID(curveId),
					(uint8_t *)pPublicKeyPlain)) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
			} else {
				convertPublicKeyToV2xseApi(keyType,
							pPublicKeyPlain);
				*pCurveId = curveId;
				*pHsmStatusCode = V2XSE_NO_ERROR;
				retval = V2XSE_SUCCESS;
			}
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETBAECCPUBLICKEY);
	return retval;
}

/**
 *
 * @brief Dervice a runtime key from the specified base key
 * @ingroup keymanagement
 *
 * This function derives a runtime key from the specified base key using
 * the butterfly algorithm.
 * NOTE: This operation is only permitted for the US applet.
 *
 * @param baseKeyId slot of base key to use
 * @param pFvSign pointer to expansion value used in key derivation
 * @param pRvij pointer to private reconstruction value used in key derivation
 * @param pHvij pointer to hash value used in key derivation
 * @param rtKeyId slot to store the generated runtime key
 * @param returnPubKey flag indicating whether public key should be returned
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pCurveID pointer to location to write curveId of derived key
 * @param pPublicKeyPlain pointer to location to write derived public key
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deriveRtEccKeyPair
(
    TypeBaseKeyId_t baseKeyId,
    TypeInt256_t *pFvSign,
    TypeInt256_t *pRvij,
    TypeInt256_t *pHvij,
    TypeRtKeyId_t rtKeyId,
    TypePubKeyOut_t returnPubKey,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveID,
    TypePublicKey_t *pPublicKeyPlain
)
{
	uint32_t inputBaKeyHandle;
	TypeCurveId_t inputBaCurveId;
	uint32_t outputRtKeyHandle;
	TypeCurveId_t storedRtCurveId;
	hsm_key_type_t keyType;
	op_butt_key_exp_args_t args;
	int32_t retval = V2XSE_FAILURE;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;
	hsm_err_t hsmret;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DERIVERTECCKEYPAIR);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode,
								&retval) ||
				(v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) ||
				(pFvSign == NULL) ||
				(pRvij == NULL) ||
				(pHvij == NULL)) {
			break;
		}

		if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
			if ((pPublicKeyPlain == NULL) || (pCurveID == NULL))
				break;
		}

		if ((v2xseAppletId != e_US_AND_GS) &&
					(v2xseAppletId != e_US)) {
			*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
			break;
		}
		if (baseKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		if (nvm_retrieve_ba_key_handle(baseKeyId,
				&inputBaKeyHandle, &inputBaCurveId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		keyType = convertCurveId(inputBaCurveId);
		if (!is256bitCurve(keyType)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		/* Delete exiting rt key if different type */
		if (!nvm_retrieve_rt_key_handle(rtKeyId,
				&outputRtKeyHandle, &storedRtCurveId)) {
			keyModified = 1;
			/*
			 * HSM PRC2 has a bug where the update
			 * overwrites the base key instead of the rt
			 * key.  For the moment delete key even if
			 * same type, to avoid this bug.
			 */
			/* if (storedRtCurveId != inputBaCurveId) { */
			if (1) {
				if (deleteRtKey(rtKeyId))
					break;
			}
		}

		memset(&args, 0, sizeof(args));
		args.key_identifier = inputBaKeyHandle;
		args.expansion_function_value = pFvSign->data;
		args.hash_value = pHvij->data;
		args.pr_reconstruction_value = pRvij->data;
		args.expansion_function_value_size = V2XSE_INT256_SIZE;
		args.hash_value_size = V2XSE_INT256_SIZE;
		args.pr_reconstruction_value_size = V2XSE_INT256_SIZE;
		if (rtKeyHandle[rtKeyId])
			args.flags = HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE;
		else
			args.flags = HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE;
		/* Always use strict update - WA for current code */
		args.flags |=
			HSM_OP_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION;
		args.key_group = getKeyGroup(RT_KEY, rtKeyId);
		/* Params correspond to implicit certificate */
		args.flags |=
			HSM_OP_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF;
		args.dest_key_identifier = &outputRtKeyHandle;
		if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
			args.output = (uint8_t *)pPublicKeyPlain;
			args.output_size = V2XSE_256_EC_PUB_KEY;
		}
		args.key_type = keyType;
		TRACE_HSM_CALL(PROFILE_ID_HSM_BUTTERFLY_KEY_EXPANSION);
		hsmret = hsm_butterfly_key_expansion(hsmKeyMgmtHandle, &args);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_BUTTERFLY_KEY_EXPANSION);
		if (hsmret)
			break;
		keyCreated = 1;
		if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId,
				(uint8_t *)&inputBaCurveId,
					sizeof(inputBaCurveId))) {
			break;
		}
		if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
			(uint8_t *)&outputRtKeyHandle,
					sizeof(outputRtKeyHandle))) {
			break;
		}
		convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
		rtKeyHandle[rtKeyId] = outputRtKeyHandle;
		rtCurveId[rtKeyId] = inputBaCurveId;
		if (returnPubKey == V2XSE_RSP_WITH_PUBKEY)
			*pCurveID = inputBaCurveId;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	} while (0);
	/* Clear key handle in case of error */
	if (retval != V2XSE_SUCCESS) {
		if (keyModified || keyCreated) {
			deleteRtKey(rtKeyId);
			/* Flag no change only if previous key not modified */
			if (!keyModified)
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DERIVERTECCKEYPAIR);
	return retval;
}

/**
 *
 * @brief Generate Runtime symmetric key
 * @ingroup keymanagement
 *
 * This function instructs the system to randomly generate a Runtime symmetric
 * key in the specified slot for the current applet.  If a runtime
 * key exists in the specified slot, it will be overwritten.  The HSM is
 * used to generate a new symmetric key, and the handle and symmetricKeyId of the
 * new key is stored in NVM.  The slot number is used as the index into
 * a table storing runtime key handles.  The symmetric key is stored by the
 * HSM in the key store for the current applet.
 *
 * @param rtKeyId slot number for the generated runtime symmetric key
 * @param symmetricKeyId The key type to be used to generate the symmetric key
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_generateRtSymmetricKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSymmetricKeyId_t symmetricKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	hsm_key_type_t keyType;
	uint32_t keyHandle;
	TypeSymmetricKeyId_t storedSymmetricKeyId;
	int32_t retval = V2XSE_FAILURE;
	int32_t keyModified = 0;
	int32_t keyCreated = 0;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GENERATERTECCKEYPAIR);

	do {
		if (setupDefaultStatusCode(pHsmStatusCode) ||
				enforceActivatedState(pHsmStatusCode, &retval) ||
				(v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE)) {
			break;
		}

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}

		keyType = convertSymmetricKeyId(symmetricKeyId);
		if (!keyType) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
			break;
		}
		if (!nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
						&storedSymmetricKeyId)) {
			keyModified = 1;
			/* Check if can overwrite */
			if (symmetricKeyId != storedSymmetricKeyId) {
				/* Different type, must delete */
				if (deleteRtKey(rtKeyId))
					break;
			}
		}
		if (genHsmKey(&keyHandle, keyType,
				0, NULL,
				rtKeyHandle[rtKeyId] ? UPDATE_KEY :
						CREATE_KEY,
				RT_KEY,
				getKeyGroup(RT_KEY, rtKeyId))) {
			break;
		}
		keyCreated = 1;
		if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId,
				(uint8_t *)&symmetricKeyId,
				sizeof(symmetricKeyId))) {
			break;
		}
		if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
					(uint8_t *)&keyHandle,
						sizeof(keyHandle))) {
			break;
		}
		rtKeyHandle[rtKeyId] = keyHandle;
		rtCurveId[rtKeyId] = symmetricKeyId;
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
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GENERATERTSYMMETRICKEY);
	return retval;
}

/**
 *
 * @brief Delete runtime symmetric key
 * @ingroup keymanagement
 *
 * This function deletes the symmetric key from the specified slot.
 * The corresponding key is deleted from the HSM key store, the
 * key handle is removed from memory and nvm, and the symmetricKeyId is removed
 * from nvm.
 *
 * @param rtKeyId slot number of the runtime key to delete
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deleteRtSymmetricKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	uint32_t keyHandle;
	TypeSymmetricKeyId_t storedSymmetricKeyId;
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DELETERTSYMMETRICKEY);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {

		if (rtKeyId >= NUM_STORAGE_SLOTS) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle,
							&storedSymmetricKeyId)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (deleteRtKey(rtKeyId)) {
			*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DELETERTSYMMETRICKEY);
	return retval;
}
