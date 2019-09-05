
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

#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Convert signature from hsm to v2xse API format
 *
 * This function converts a signature from hsm_api to v2xse API format.
 * The hsm API format is as follows:
 *  - for 256 bit curve: r in bits 0 - 31, s in bits 32 - 63, Ry in bit 64
 *  - for 384 bit curve: r in bits 0 - 47, s in bits 48 - 95, Ry in bit 96
 * The v2xse API format is as follows for all curve sizes:
 *  - r in bits 0 - 47, Ry in bit 48, s in bits 49 - 96
 *  - in case of 256 bit curves, upper bits of r and s unused
 *
 * @param is256bits true if the ECC curve for the signature is 256 bits
 * @param pSignature location of the generatedsignature
 *
 */
static void convertSignatureToV2xseApi(uint32_t is256bits,
					TypeSignature_t *pSignature)
{
	uint8_t Ry;

	if (is256bits) {
		hsmSignature256_t *hsmApiPtr = (hsmSignature256_t*)pSignature;

		Ry = hsmApiPtr->Ry;
		memmove(pSignature->s, hsmApiPtr->s, sizeof(hsmApiPtr->s));
		memset(&(pSignature->r[V2XSE_256_EC_R_SIGN]), 0,
			V2XSE_384_EC_R_SIGN - V2XSE_256_EC_R_SIGN);
	} else {
		hsmSignature384_t *hsmApiPtr = (hsmSignature384_t*)pSignature;

		Ry = hsmApiPtr->Ry;
		memmove(pSignature->s, hsmApiPtr->s, sizeof(hsmApiPtr->s));
	}
	pSignature->Ry = Ry;
}

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
	uint32_t is256bits;

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
	is256bits = is256bitCurve(sig_scheme);
	if (is256bits)
		expectedHashLength = V2XSE_256_EC_HASH_SIZE;
	else
		expectedHashLength = V2XSE_384_EC_HASH_SIZE;
	if (hashLength != expectedHashLength) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	memset(&args, 0, sizeof(args));
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
	convertSignatureToV2xseApi(is256bits, pSignature);

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
	memset(&args, 0, sizeof(args));
	args.scheme_id = sig_scheme;
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

	memset(&args, 0, sizeof(args));
	args.key_identifier = preparedKeyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t*)pSignature;
	args.message_size = V2XSE_256_EC_HASH_SIZE;
	args.signature_size =
		v2xSe_getSigLenFromHashLen(V2XSE_256_EC_HASH_SIZE);
	args.flags = HSM_OP_FINALIZE_SIGN_INPUT_DIGEST;
	if (hsm_finalize_signature(hsmSigGenHandle, &args)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	convertSignatureToV2xseApi(1, pSignature);

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

	memset(&args, 0, sizeof(args));
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
	convertSignatureToV2xseApi(1, pSignature);

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
	uint32_t is256bits;

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
	is256bits = is256bitCurve(sig_scheme);
	if (is256bits)
		expectedHashLength = V2XSE_256_EC_HASH_SIZE;
	else
		expectedHashLength = V2XSE_384_EC_HASH_SIZE;
	if (hashLength != expectedHashLength) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	memset(&args, 0, sizeof(args));
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
	convertSignatureToV2xseApi(is256bits, pSignature);

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
