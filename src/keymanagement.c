
/*
 * Copyright 2019 NXP
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
	op_generate_key_args_t args;
	uint16_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t savedCurveId;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

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

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE_PERSISTENT;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.key_info = HSM_KEY_INFO_PERMANENT;
	args.out_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_generate_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (nvm_update_var("maCurveId", (uint8_t*)&curveId,
							sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_var("maKeyHandle", (uint8_t*)&keyHandle,
							sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

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
	uint16_t keyType;
	op_calc_pubkey_args_t args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pCurveId)
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

	if(nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	keyType = convertCurveId(curveId);
	if (!keyType) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = 0;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.output_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_calculate_public_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

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
	op_generate_key_args_t args;
	uint16_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

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
			op_manage_key_args_t del_args;

			del_args.key_identifier = &keyHandle;
			del_args.input_size = 0;
			del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
			del_args.key_type = convertCurveId(storedCurveId);
			del_args.key_type_ext = 0;
			del_args.key_info = 0;
			del_args.input_key = NULL;
			if (hsm_manage_key(hsmKeyMgmtHandle, &del_args)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("rtCurveId", rtKeyId)) {
				rtKeyHandle[rtKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("rtKeyHandle", rtKeyId)) {
				rtKeyHandle[rtKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			rtKeyHandle[rtKeyId] = 0;
		}
	}

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE_PERSISTENT;
	if (rtKeyHandle[rtKeyId])
		args.flags |= HSM_OP_KEY_GENERATION_FLAGS_UPDATE;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.key_info = 0;
	args.out_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_generate_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("rtCurveId", rtKeyId,	(uint8_t*)&curveId,
							sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("rtKeyHandle", rtKeyId, (uint8_t*)&keyHandle,
							sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
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
 * @param pPublicKeyPlain pointer to location to write public key
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
	op_manage_key_args_t del_args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &storedCurveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	del_args.key_identifier = &keyHandle;
	del_args.input_size = 0;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	del_args.key_type = convertCurveId(storedCurveId);
	del_args.key_type_ext = 0;
	del_args.key_info = 0;
	del_args.input_key = NULL;
	if (hsm_manage_key(hsmKeyMgmtHandle, &del_args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_delete_array_data("rtCurveId", rtKeyId)) {
		rtKeyHandle[rtKeyId] = 0;
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_delete_array_data("rtKeyHandle", rtKeyId)) {
		rtKeyHandle[rtKeyId] = 0;
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	rtKeyHandle[rtKeyId] = 0;
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
	uint16_t keyType;
	op_calc_pubkey_args_t args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pCurveId)
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

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

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = 0;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.output_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_calculate_public_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

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
	op_generate_key_args_t args;
	uint16_t keyType;
	uint32_t keyHandle;
	TypeCurveId_t storedCurveId;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

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
			op_manage_key_args_t del_args;

			del_args.key_identifier = &keyHandle;
			del_args.input_size = 0;
			del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
			del_args.key_type = convertCurveId(storedCurveId);
			del_args.key_type_ext = 0;
			del_args.key_info = 0;
			del_args.input_key = NULL;
			if (hsm_manage_key(hsmKeyMgmtHandle, &del_args)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("baCurveId", baseKeyId)) {
				baKeyHandle[baseKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("baKeyHandle", baseKeyId)) {
				baKeyHandle[baseKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			baKeyHandle[baseKeyId] = 0;
		}
	}

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE_PERSISTENT;
	if (baKeyHandle[baseKeyId])
		args.flags |= HSM_OP_KEY_GENERATION_FLAGS_UPDATE;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.key_info = 0;
	args.out_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_generate_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("baCurveId", baseKeyId,
					(uint8_t*)&curveId,
					sizeof(curveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("baKeyHandle", baseKeyId,
					(uint8_t*)&keyHandle,
					sizeof(keyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

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
	op_manage_key_args_t del_args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &storedCurveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	del_args.key_identifier = &keyHandle;
	del_args.input_size = 0;
	del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
	del_args.key_type = convertCurveId(storedCurveId);
	del_args.key_type_ext = 0;
	del_args.key_info = 0;
	del_args.input_key = NULL;
	if (hsm_manage_key(hsmKeyMgmtHandle, &del_args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_delete_array_data("baCurveId", baseKeyId)) {
		baKeyHandle[baseKeyId] = 0;
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_delete_array_data("baKeyHandle", baseKeyId)) {
		baKeyHandle[baseKeyId] = 0;
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	baKeyHandle[baseKeyId] = 0;
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
	uint16_t keyType;
	op_calc_pubkey_args_t args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pCurveId)
	ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)

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

	args.key_identifier = &keyHandle;
	args.out_size = v2xSe_getKeyLenFromCurveID(curveId);
	args.flags = 0;
	args.key_type = keyType;
	args.key_type_ext = 0;
	args.output_key = (uint8_t*)pPublicKeyPlain;
	if (hsm_calculate_public_key(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

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
 * @param pCurveId pointer to location to write curveId of derived key
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
	uint16_t keyType;
	op_butt_key_exp_args_t args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pFvSign)
	ENFORCE_POINTER_NOT_NULL(pRvij)
	ENFORCE_POINTER_NOT_NULL(pHvij)
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
		ENFORCE_POINTER_NOT_NULL(pPublicKeyPlain)
		ENFORCE_POINTER_NOT_NULL(pCurveID)
	}

	if ((v2xseAppletId != e_US_AND_GS) && (v2xseAppletId != e_US)){
		*pHsmStatusCode = V2XSE_INS_NOT_SUPPORTED;
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
			op_manage_key_args_t del_args;

			del_args.key_identifier = &outputRtKeyHandle;
			del_args.input_size = 0;
			del_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
			del_args.key_type = convertCurveId(storedRtCurveId);
			del_args.key_type_ext = 0;
			del_args.key_info = 0;
			del_args.input_key = NULL;
			if (hsm_manage_key(hsmKeyMgmtHandle, &del_args)) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("rtCurveId", rtKeyId)) {
				rtKeyHandle[rtKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			if (nvm_delete_array_data("rtKeyHandle", rtKeyId)) {
				rtKeyHandle[rtKeyId] = 0;
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
				return V2XSE_FAILURE;
			}
			rtKeyHandle[rtKeyId] = 0;
		}
	}

	args.key_identifier = inputBaKeyHandle;
	args.data1 = pFvSign->data;
	args.data2 = pHvij->data;
	args.data3 = pRvij->data;
	args.data1_size = V2XSE_INT256_SIZE;
	args.data2_size = V2XSE_INT256_SIZE;
	args.data3_size = V2XSE_INT256_SIZE;
	args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE_PERSISTENT;
	if (rtKeyHandle[rtKeyId])
		args.flags |= HSM_OP_KEY_GENERATION_FLAGS_UPDATE;
	args.dest_key_identifier = outputRtKeyHandle;
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY) {
		args.output = (uint8_t*)pPublicKeyPlain;
		args.output_size = V2XSE_256_EC_PUB_KEY;
	} else {
		args.output_size = 0;
	}
	args.key_type = keyType;

	if (hsm_butterfly_key_expansion(hsmKeyMgmtHandle, &args)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("rtCurveId", rtKeyId,
			(uint8_t*)&inputBaCurveId, sizeof(inputBaCurveId))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (nvm_update_array_data("rtKeyHandle", rtKeyId,
		(uint8_t*)&outputRtKeyHandle, sizeof(outputRtKeyHandle))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	rtKeyHandle[rtKeyId] = outputRtKeyHandle;
	rtCurveId[rtKeyId] = inputBaCurveId;
	if (returnPubKey == V2XSE_RSP_WITH_PUBKEY)
		*pCurveID = inputBaCurveId;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
