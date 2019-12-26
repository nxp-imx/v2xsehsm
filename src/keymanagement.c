
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
static void convertPublicKeyToV2xseApi(hsm_key_type_t keyType,
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
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static int32_t genHsmKey(uint32_t *pKeyHandle, hsm_key_type_t keyType,
		uint16_t pubKeySize, uint8_t *pPubKey, genKeyAction_t action,
		keyUsage_t usage)
{
	op_generate_key_args_t args;

	memset(&args, 0, sizeof(args));
	args.key_identifier = pKeyHandle;
	args.out_size = pubKeySize;
	if (action == UPDATE_KEY)
		args.flags = HSM_OP_KEY_GENERATION_FLAGS_UPDATE;
	else /* CREATE_KEY */
		args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	/* Always use strict update - need to modify for closed part */
	args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	/* For now map each key usage to a different group */
	args.key_group = usage;
	switch (usage) {
	case RT_KEY:
		/* RT key does not need any flags set */
		break;
	case BA_KEY:
		/* BA keys can be used for butterfly */
		args.key_info = HSM_KEY_INFO_MASTER;
		break;
	case MA_KEY:
		/* MA key cannot be modified */
		args.key_info = HSM_KEY_INFO_PERMANENT;
		break;
	}
	args.key_type = keyType;
	args.out_key = pPubKey;
	return hsm_generate_key(hsmKeyMgmtHandle, &args);
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
static int32_t getHsmPubKey(uint32_t keyHandle, hsm_key_type_t keyType,
		uint16_t pubKeySize, uint8_t *pPubKey)
{
	hsm_op_pub_key_recovery_args_t args;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.out_key = pPubKey;
	args.out_key_size = pubKeySize;
	args.key_type = keyType;
	return hsm_pub_key_recovery(hsmKeyStoreHandle, &args);
}

/**
 *
 * @brief Delete hsm ECC private key
 *
 * This function deletes a ECC private key from the hsm key store.
 *
 * @param keyHandle hsm handle for private key to delete
 * @param keyType type of key to delete
 * @param usage key usage of key to delete (rt or ba)
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static int32_t deleteHsmKey(uint32_t keyHandle, hsm_key_type_t keyType,
							keyUsage_t usage)
{
	op_manage_key_args_t del_args;

	memset(&del_args, 0, sizeof(del_args));
	del_args.key_identifier = &keyHandle;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	/* Always use strict update - need to modify for closed part */
	del_args.flags |= HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	del_args.key_type = keyType;
	del_args.key_group = usage;
	return hsm_manage_key(hsmKeyMgmtHandle, &del_args);
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
static int32_t deleteRtKey(TypeRtKeyId_t rtKeyId)
{
	uint32_t keyHandle = rtKeyHandle[rtKeyId];

	rtKeyHandle[rtKeyId] = 0;
	if (deleteHsmKey(keyHandle, convertCurveId(rtCurveId[rtKeyId]), RT_KEY))
		return V2XSE_FAILURE;
	if (nvm_delete_array_data(RT_CURVEID_NAME, rtKeyId))
		return V2XSE_FAILURE;
	if (nvm_delete_array_data(RT_KEYHANDLE_NAME, rtKeyId))
		return V2XSE_FAILURE;
	return V2XSE_SUCCESS;
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

static int32_t deleteBaKey(TypeBaseKeyId_t baKeyId)
{
	uint32_t keyHandle = baKeyHandle[baKeyId];

	baKeyHandle[baKeyId] = 0;
	if (deleteHsmKey(keyHandle, convertCurveId(baCurveId[baKeyId]), BA_KEY))
		return V2XSE_FAILURE;
	if (nvm_delete_array_data(BA_CURVEID_NAME, baKeyId))
		return V2XSE_FAILURE;
	if (nvm_delete_array_data(BA_KEYHANDLE_NAME, baKeyId))
		return V2XSE_FAILURE;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate Module Authentication ECC key pair
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	keyType = convertCurveId(curveId);
	if (!keyType) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	/* Check if MA is already assigned */
	if(!nvm_retrieve_ma_key_handle(&keyHandle, &savedCurveId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (genHsmKey(&keyHandle, keyType, v2xSe_getKeyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain, CREATE_KEY,
								MA_KEY)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (nvm_update_var(MA_CURVEID_NAME, (uint8_t *)&curveId,
							sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_var(MA_KEYHANDLE_NAME, (uint8_t *)&keyHandle,
							sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	maCurveId = curveId;
	maKeyHandle = keyHandle;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Get Module Authenitication public key
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pCurveId);
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	if(nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!keyType) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (getHsmPubKey(keyHandle, keyType,
			v2xSe_getKeyLenFromCurveID(curveId),
			(uint8_t *)pPublicKeyPlain)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	*pCurveId = curveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate Runtime ECC key pair
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!is256bitCurve(keyType)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (!nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &storedCurveId)) {
		if (curveId != storedCurveId) {
			if (deleteRtKey(rtKeyId)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
		}
	}

	if (genHsmKey(&keyHandle, keyType, v2xSe_getKeyLenFromCurveID(curveId),
				(uint8_t *)pPublicKeyPlain,
				rtKeyHandle[rtKeyId] ? UPDATE_KEY : CREATE_KEY,
								RT_KEY)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId, (uint8_t *)&curveId,
							sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
				(uint8_t *)&keyHandle, sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	rtKeyHandle[rtKeyId] = keyHandle;
	rtCurveId[rtKeyId] = curveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &storedCurveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (deleteRtKey(rtKeyId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Get Runtime public key
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pCurveId);
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!is256bitCurve(keyType)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (getHsmPubKey(keyHandle, keyType,
			v2xSe_getKeyLenFromCurveID(curveId),
			(uint8_t *)pPublicKeyPlain)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	*pCurveId = curveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate Base ECC key pair
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!keyType) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (!nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle,
							&storedCurveId)) {
		if (curveId != storedCurveId) {
			if (deleteBaKey(baseKeyId)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
		}
	}

	if (genHsmKey(&keyHandle, keyType, v2xSe_getKeyLenFromCurveID(curveId),
			(uint8_t *)pPublicKeyPlain,
			baKeyHandle[baseKeyId] ? UPDATE_KEY : CREATE_KEY,
								BA_KEY)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (nvm_update_array_data(BA_CURVEID_NAME, baseKeyId,
					(uint8_t *)&curveId,
					sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data(BA_KEYHANDLE_NAME, baseKeyId,
					(uint8_t *)&keyHandle,
					sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	baKeyHandle[baseKeyId] = keyHandle;
	baCurveId[baseKeyId] = curveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &storedCurveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (deleteBaKey(baseKeyId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Get Base public key
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pCurveId);
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!keyType) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (getHsmPubKey(keyHandle, keyType,
			v2xSe_getKeyLenFromCurveID(curveId),
			(uint8_t *)pPublicKeyPlain)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	*pCurveId = curveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Dervice a runtime key from the specified base key
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pFvSign);
	ENFORCE_POINTER_NOT_NULL(pRvij);
	ENFORCE_POINTER_NOT_NULL(pHvij);
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
		ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain);
		ENFORCE_POINTER_NOT_NULL(pCurveID);
	}

	if ((v2xseAppletId != e_US_AND_GS) && (v2xseAppletId != e_US)){
		*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
		return V2XSE_FAILURE;
	}
	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_ba_key_handle(baseKeyId, &inputBaKeyHandle,
							&inputBaCurveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	keyType = convertCurveId(inputBaCurveId);
	if (!is256bitCurve(keyType)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	/* Delete rt key if it already exists and is of different type */
	if (!nvm_retrieve_rt_key_handle(rtKeyId, &outputRtKeyHandle,
							&storedRtCurveId)) {
		if (storedRtCurveId != inputBaCurveId) {
			if (deleteRtKey(rtKeyId)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
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
	/* Always use strict update - need to modify for closed part */
	args.flags |= HSM_OP_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION;
	/* For now map each key usage to a different group */
	args.key_group = RT_KEY;
	/* Params provided to this API correspond to implicit certificate */
	args.flags |= HSM_OP_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF;
	args.dest_key_identifier = &outputRtKeyHandle;
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
		args.output = (uint8_t *)pPublicKeyPlain;
		args.output_size = V2XSE_256_EC_PUB_KEY;
	}
	args.key_type = keyType;
	if (hsm_butterfly_key_expansion(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data(RT_CURVEID_NAME, rtKeyId,
			(uint8_t *)&inputBaCurveId, sizeof(inputBaCurveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data(RT_KEYHANDLE_NAME, rtKeyId,
		(uint8_t *)&outputRtKeyHandle, sizeof(outputRtKeyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	convertPublicKeyToV2xseApi(keyType, pPublicKeyPlain);
	rtKeyHandle[rtKeyId] = outputRtKeyHandle;
	rtCurveId[rtKeyId] = inputBaCurveId;
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY)
		*pCurveID = inputBaCurveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
