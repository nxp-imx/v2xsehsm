
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file signature.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer signature API
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Generate signature using MA private key
 *
 * This function calculates the signature of the given hash using the MA
 * private key.
 *
 * @param hashLength length of the hash to sign
 * @param pHashValue pointer to the hash data to sign
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pSignature pointer to location to write the generated signature
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_createMaSign
(
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_signature_scheme_id_t sig_scheme;
	TypeHashLength_t expectedHashLength;
	op_generate_sign_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pHashValue);
	ENFORCE_POINTER_NOT_NULL(pSignature);

	if(nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	sig_scheme = convertCurveId(curveId);
	if (!sig_scheme) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (is256bitCurve(sig_scheme))
		expectedHashLength = V2XSE_256_EC_HASH_SIZE;
	else
		expectedHashLength = V2XSE_384_EC_HASH_SIZE;
	if (hashLength != expectedHashLength) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t*)pSignature;
	args.message_size = hashLength;
	args.signature_size = v2xSe_getSigLenFromHashLen(hashLength);
	args.scheme_id = sig_scheme;
	args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	if (hsm_generate_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Activate specified run time key for low latency signing
 *
 * This function prepares for low latency signing by performing
 * the initial signature calculations that do not rely on the data to sign.
 * A later call to v2xSe_createRtSignLowLatency will provide the data to
 * sign and finalize the signature calcualtion.
 *
 * @param rtKeyId runtime key to use for initial calculations
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_activateRtKeyForSigning
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_signature_scheme_id_t sig_scheme;
	op_prepare_sign_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	sig_scheme = convertCurveId(curveId);
	if (!sig_scheme) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	preparedKeyHandle = keyHandle;
	//?? args does not have a field for key handle!?
	args.scheme_id = sig_scheme;
	args.flags = 0;
	if (hsm_prepare_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate low latency signature using runtime private key
 *
 * This function finalizes the signature calculation of the given hash.
 * The key to use must already have been specified using the function
 * v2xSe_activateRtKeyForSigning, which performs the initial signature
 * calculations that do not rely on the data to sign.  A fast indicator
 * is provided to indicate whether the signature was generated via a low
 * latency calculation, this is always true for this implementation unless
 * an error has occurred.
 *
 * @param pHashValue pointer to the hash data to sign
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pSignature pointer to location to write the generated signature
 * @param pFastIndicator pointer to location to write fast indicator status
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_createRtSignLowLatency
(
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature,
    TypeLowlatencyIndicator_t *pFastIndicator
)
{
	op_finalize_sign_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pHashValue);
	ENFORCE_POINTER_NOT_NULL(pSignature);
	ENFORCE_POINTER_NOT_NULL(pFastIndicator);

	if (!preparedKeyHandle) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	args.key_identifier = preparedKeyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t*)pSignature;
	args.message_size = V2XSE_256_EC_HASH_SIZE;
	args.signature_size =
		v2xSe_getSigLenFromHashLen(V2XSE_256_EC_HASH_SIZE);
	args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	if (hsm_finalize_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pFastIndicator = 1;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate signature using runtime private key
 *
 * This function calculates the signature of the given hash using the runtime
 * private key in the specified slot.
 *
 * @param rtKeyId slot of runtime key to use
 * @param pHashValue pointer to the hash data to sign
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pSignature pointer to location to write the generated signature
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_createRtSign
(
    TypeRtKeyId_t rtKeyId,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature

)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_signature_scheme_id_t sig_scheme;
	op_generate_sign_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pHashValue);
	ENFORCE_POINTER_NOT_NULL(pSignature);

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	sig_scheme = convertCurveId(curveId);
	if (!sig_scheme) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if (!is256bitCurve(sig_scheme)){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t*)pSignature;
	args.message_size = V2XSE_256_EC_HASH_SIZE;
	args.signature_size =
		v2xSe_getSigLenFromHashLen(V2XSE_256_EC_HASH_SIZE);
	args.scheme_id = sig_scheme;
	args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	if (hsm_generate_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate signature using base private key
 *
 * This function calculates the signature of the given hash using the base
 * private key in the specified slot.
 *
 * @param baseKeyId slot of base key to use
 * @param hashLength length of the hash data to sign
 * @param pHashValue pointer to the hash data to sign
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pSignature pointer to location to write the generated signature
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_createBaSign
(
    TypeBaseKeyId_t baseKeyId,
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
)
{
	uint32_t keyHandle;
	TypeCurveId_t curveId;
	hsm_signature_scheme_id_t sig_scheme;
	TypeHashLength_t expectedHashLength;
	op_generate_sign_args_t args;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pHashValue);
	ENFORCE_POINTER_NOT_NULL(pSignature);

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if(nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	sig_scheme = convertCurveId(curveId);
	if (!sig_scheme) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	if (is256bitCurve(sig_scheme))
		expectedHashLength = V2XSE_256_EC_HASH_SIZE;
	else
		expectedHashLength = V2XSE_384_EC_HASH_SIZE;
	if (hashLength != expectedHashLength) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t*)pSignature;
	args.message_size = hashLength;
	args.signature_size = v2xSe_getSigLenFromHashLen(hashLength);
	args.scheme_id = sig_scheme;
	args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	if (hsm_generate_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
