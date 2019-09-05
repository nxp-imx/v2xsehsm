
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file ecies.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer ECIES API
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Encrypt data using ECIES
 *
 * This function encrypts data using the ECIES encryption scheme.  The data to
 * encrypt, public key, and all other parameters needed to perform the
 * encryption are provided by the caller.
 *
 * @param pEciesData pointer to structure with data and encryption parameters
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pVctLen data buffer size on input, length of encrypted data on output
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

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pEciesData);
	ENFORCE_POINTER_NOT_NULL(pVctLen);
	ENFORCE_POINTER_NOT_NULL(pVctData);

	memset(&args, 0, sizeof(args));
	args.input = pEciesData->pMsgData->data;
	args.pub_key = (uint8_t*)(pEciesData->pEccPublicKey);
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
	args.pub_key_size = v2xSe_getKeyLenFromCurveID(pEciesData->curveId);
	args.mac_size = pEciesData->macLen;
	args.out_size = *pVctLen;
	args.key_type = convertCurveId(pEciesData->curveId);
	if (hsm_ecies_encryption(hsmSessionHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	*pVctLen = args.out_size;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Decrypt data using ECIES and runtime key
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
	hsm_op_ecies_dec_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pEciesData);
	ENFORCE_POINTER_NOT_NULL(pMsgLen);
	ENFORCE_POINTER_NOT_NULL(pMsgData);

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if(nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	if (pEciesData->kdfParamP1Len) {
		args.p1 = pEciesData->kdfParamP1;
		args.p1_size = pEciesData->kdfParamP1Len;
	}
	if (pEciesData->macParamP2) {
		args.p2 = pEciesData->macParamP2;
		args.p2_size = pEciesData->macParamP2Len;
	}
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	args.output_size = *pMsgLen;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	if (hsm_ecies_decryption(hsmCipherHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	*pMsgLen = args.output_size;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Decrypt data using ECIES and module authentication key
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
	hsm_op_ecies_dec_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pEciesData);
	ENFORCE_POINTER_NOT_NULL(pMsgLen);
	ENFORCE_POINTER_NOT_NULL(pMsgData);

	if(nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	if (pEciesData->kdfParamP1Len) {
		args.p1 = pEciesData->kdfParamP1;
		args.p1_size = pEciesData->kdfParamP1Len;
	}
	if (pEciesData->macParamP2) {
		args.p2 = pEciesData->macParamP2;
		args.p2_size = pEciesData->macParamP2Len;
	}
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	args.output_size = *pMsgLen;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	if (hsm_ecies_decryption(hsmCipherHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	*pMsgLen = args.output_size;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Decrypt data using ECIES and base key
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
	hsm_op_ecies_dec_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pEciesData);
	ENFORCE_POINTER_NOT_NULL(pMsgLen);
	ENFORCE_POINTER_NOT_NULL(pMsgData);

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if(nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	if (pEciesData->kdfParamP1Len) {
		args.p1 = pEciesData->kdfParamP1;
		args.p1_size = pEciesData->kdfParamP1Len;
	}
	if (pEciesData->macParamP2) {
		args.p2 = pEciesData->macParamP2;
		args.p2_size = pEciesData->macParamP2Len;
	}
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	args.output_size = *pMsgLen;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	if (hsm_ecies_decryption(hsmCipherHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	*pMsgLen = args.output_size;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
