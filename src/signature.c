
/*
 * Copyright 2019 NXP
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
 * @brief Generate signature using hsm
 *
 * This function generates a signature using the hsm.  It takes parameters
 * in v2xSe format, converts them to hsm_api format and launches the
 * signature generation.
 *
 * @param keyHandle handle of key to use for signature
 * @param sig_scheme singature scheme to use
 * @param pHashValue pointer to hash value to sign
 * @param hashLength length of hash to sign
 * @param pSignature location to write signature
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
static hsm_err_t genHsmSignature(uint32_t keyHandle,
			hsm_signature_scheme_id_t sig_scheme,
			TypeHash_t *pHashValue,
			TypeHashLength_t hashLength,
			TypeSignature_t *pSignature)
{
	op_generate_sign_args_t args;

	memset(&args, 0, sizeof(args));
	args.key_identifier = keyHandle;
	args.message = pHashValue->data;
	args.signature = (uint8_t *)pSignature;
	args.message_size = hashLength;
	args.signature_size = v2xSe_getSigLenFromHashLen(hashLength);
	args.scheme_id = sig_scheme;
	args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	return hsm_generate_signature(hsmSigGenHandle, &args);
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
	uint32_t is256bits;

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
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
	if (hashLength != expectedHashLength)
		return V2XSE_FAILURE;

	if (genHsmSignature(keyHandle, sig_scheme, pHashValue, hashLength,
							pSignature))
		return V2XSE_FAILURE;
	convertSignatureToV2xseApi(is256bits, pSignature);

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Activate specified run time key for low latency signing
 *
 * This function is meant to prepare for low latency signing by performing
 * the initial signature calculations that do not rely on the data to sign.
 * A later call to v2xSe_createRtSignLowLatency will provide the data to
 * sign and finalize the signature calculation.
 * The v2xSe API states that a single activate call can be made, followed
 * by multiple low latency signatures if they all use the same key.  This
 * is achieved on the SXF1800 by a background processing creating a pool of
 * pre-prepared data sets during idle time, with each low latency signature
 * consuming one entry.
 * The hsm prepare/finalize signature calls need to be paired 1:1.  There
 * is no background process that can know when the CAAM is idle to create
 * a pool of prepared data.  For this reason, we cannot use the hsm prepare/
 * finalize calls, and always perform normal latency signatures (which at
 * ~1ms are fairly low latency anyway).
 * This function stores the handle/sigScheme of the provided key, so that a
 * normal signature call can be made with the activated key when the low
 * latency signature is requested.
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
	hsm_signature_scheme_id_t sigScheme;

	/* Clear previous data */
	activatedKeyHandle = 0;
	activatedSigScheme = 0;

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
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

	sigScheme = convertCurveId(curveId);
	if (!sigScheme) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	activatedKeyHandle = keyHandle;
	activatedSigScheme = sigScheme;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Generate low latency signature using runtime private key
 *
 * This function finalizes the signature calculation of the given hash.
 * The key to use must already have been specified using the function
 * v2xSe_activateRtKeyForSigning.
 * The v2xSe API states that a single activate call can be made, followed
 * by multiple low latency signatures if they all use the same key.  This
 * is achieved on the SXF1800 by a background processing creating a pool of
 * pre-prepared data sets during idle time, with each low latency signature
 * consuming one entry.
 * The hsm prepare/finalize signature calls need to be paired 1:1.  There
 * is no background process that can know when the CAAM is idle to create
 * a pool of prepared data.  For this reason, we cannot use the hsm prepare/
 * finalize calls, and always perform normal latency signatures (which at
 * ~1ms are fairly low latency anyway).
 * This function performs a normal signature, using the key handle and
 * signature scheme stored during the call to v2xSe_activateRtKeyForSigning.
 * A fast indicator is provided to indicate whether the signature was
 * generated via a low latency calculation. This is always false for this
 * implementation.
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
	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();
	ENFORCE_POINTER_NOT_NULL(pHashValue);
	ENFORCE_POINTER_NOT_NULL(pSignature);
	ENFORCE_POINTER_NOT_NULL(pFastIndicator);

	if (!activatedKeyHandle) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}

	if (genHsmSignature(activatedKeyHandle, activatedSigScheme, pHashValue,
					V2XSE_256_EC_HASH_SIZE, pSignature))
		return V2XSE_FAILURE;
	convertSignatureToV2xseApi(1, pSignature);

	*pFastIndicator = 0;
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

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
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

	if (genHsmSignature(keyHandle, sig_scheme, pHashValue,
				V2XSE_256_EC_HASH_SIZE,	pSignature))
		return V2XSE_FAILURE;
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
	uint32_t is256bits;

	VERIFY_STATUS_PTR_AND_SET_DEFAULT();
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
	if (hashLength != expectedHashLength)
		return V2XSE_FAILURE;

	if (genHsmSignature(keyHandle, sig_scheme, pHashValue, hashLength,
							pSignature))
		return V2XSE_FAILURE;
	convertSignatureToV2xseApi(is256bits, pSignature);

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
