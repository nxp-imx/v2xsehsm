
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
 * @file utility.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer data utility API
 *
 */

#include "v2xsehsm.h"
#include <string.h>

/**
 *
 * @brief Convert curveId to keyType
 *
 * This function converts the curveId value from the V2XSE API to the
 * corresponding keyType value for the HSM API.  Returns zero if the
 * curveId is invalid, all valid values are non-zero.
 *
 * @param curveId ECC curve type in V2X SE API format
 *
 * @return keyType in HSM API format, or 0 if ERROR
 *
 */
hsm_key_type_t convertCurveId(TypeCurveId_t curveId)
{
	hsm_key_type_t keyType;

	switch(curveId) {
		case V2XSE_CURVE_NISTP256:
			keyType = HSM_KEY_TYPE_ECDSA_NIST_P256;
			break;
		case V2XSE_CURVE_BP256R1:
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
			break;
		case V2XSE_CURVE_BP256T1:
#ifdef NO_BP_T1
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
#else
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256;
#endif
			break;
		case V2XSE_CURVE_NISTP384:
			keyType = HSM_KEY_TYPE_ECDSA_NIST_P384;
			break;
		case V2XSE_CURVE_BP384R1:
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384;
			break;
		case V2XSE_CURVE_BP384T1:
#ifdef NO_BP_T1
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384;
#else
			keyType = HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384;
#endif
			break;
		default:
			keyType = 0;
	}
	return keyType;
}

/**
 *
 * @brief Check whether keyType is 256 bits
 *
 * This function checks whether the ECC curve corresponding the the keyType
 * passed as parameter is 256 bits or not.  Many V2X SE API functions only
 * allow 256 bit keys.
 *
 * @param keyType keyType in HSM API format
 *
 * @return 1 if ECC curve is 256 bits, 0 if invalid or not 256 bits
 *
 */
int is256bitCurve(hsm_key_type_t keyType)
{
	int retval = 0;

	switch (keyType) {
		case HSM_KEY_TYPE_ECDSA_NIST_P256:
		case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256:
			retval = 1;
	}
	return retval;
}

/**
 *
 * @brief Retrive the version of the V2X or storage applet
 * @ingroup devicemanagement
 *
 * This function retrieves the version of the V2X or storage applet.  As
 * this system does not actually use applets, the version of this adaptation
 * layer is returned
 *
 * @param appletType indicates applet to query: V2X or storage
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pVersion pointer to location to write version info (3 bytes)
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getAppletVersion
(
    appletSelection_t appletType,
    TypeSW_t *pHsmStatusCode,
    TypeVersion_t *pVersion
)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETAPPLETVERSION);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pVersion != NULL)) {

		if ((appletType != e_V2X) && (appletType != e_GS)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if ((appletType == e_GS) &&
				((v2xseAppletId == e_EU) ||
				(v2xseAppletId == e_US))) {
			*pHsmStatusCode = V2XSE_INS_NOT_SUPPORTED;
		} else {
			pVersion->data[0] = VERSION_MAJOR;
			pVersion->data[1] = VERSION_MINOR;
			pVersion->data[2] = VERSION_PATCH;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETAPPLETVERSION);
	return retval;
}

/**
 *
 * @brief Retrive information regarding SE capabilities
 * @ingroup devicemanagement
 *
 * This function fills a structure indicating SE capabilities.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pInfo pointer to location to write SE capability info.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getSeInfo
(
    TypeSW_t *pHsmStatusCode,
    TypeInformation_t *pInfo
)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETSEINFO);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pInfo != NULL)) {

		/* Maximum Runtime keys supported by applet */
		pInfo->maxRtKeysAllowed = NUM_STORAGE_SLOTS;

		/* Maximum Base keys supported by applet */
		pInfo->maxBaKeysAllowed = NUM_STORAGE_SLOTS;

		/* Maximum number of prepared values supported */
		pInfo->numPreparedVal = 0;

		/* FIPS approved mode indicator */
		pInfo->fipsModeIndicator = 0;

		/* Proof of possession support indicator */
		pInfo->proofOfPossession = 0;

		/* Rollback protection status indicator */
		pInfo->rollBackProtection = 1;

		/* Key derivation support indicator */
		if ((v2xseAppletId == e_US_AND_GS) || (v2xseAppletId == e_US))
			pInfo->rtKeyDerivation = 1;
		else
			pInfo->rtKeyDerivation = 0;

		/* ECIES support indicator */
		pInfo->eciesSupport = 1;

		/* Maximum number of data slots supported by GS applet */
		if ((v2xseAppletId == e_EU_AND_GS) ||
						(v2xseAppletId == e_US_AND_GS))
			pInfo->maxDataSlots = NUM_STORAGE_SLOTS;
		else
			pInfo->maxDataSlots = 0;

		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETSEINFO);
	return retval;
}

/**
 *
 * @brief Retrieve version of CryptoLibrary
 * @ingroup devicemanagement
 *
 * This function retrieves the version of the CryptoLibrary, which in this
 * system corresponds to this adaptation layer.

 * @param pVersion pointer to location to write version info (3 bytes)
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getCryptoLibVersion
(
    TypeVersion_t *pVersion
)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETCRYPTOLIBVERSION);

	if (pVersion) {
		pVersion->data[0] = VERSION_MAJOR;
		pVersion->data[1] = VERSION_MINOR;
		pVersion->data[2] = VERSION_PATCH;
		retval = V2XSE_SUCCESS;
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETCRYPTOLIBVERSION);
	return retval;
}

/**
 *
 * @brief Retrieve platform identification info
 * @ingroup devicemanagement
 *
 * This function retrieves a string that provides information about the
 * platform being used to run the SE implementation.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPlatformIdentifier pointer to location to write platform info
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getPlatformInfo(TypeSW_t *pHsmStatusCode,
			TypePlatformIdentity_t *pPlatformIdentifier)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETPLATFORMINFO);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceNotInitState(&retval) &&
				(pPlatformIdentifier != NULL)) {
		/* TODO: Figure out real values */
		memcpy(pPlatformIdentifier->data, PLATFORMINFO_STRING,
						V2XSE_PLATFORM_IDENTITY);
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETPLATFORMINFO);
	return retval;
}

/**
 *
 * @brief Retrieve trust provisioning profile info
 * @ingroup devicemanagement
 *
 * This function retrives a 4 byte indicator that refers to the trust
 * provisioning profile of the SE implementation.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pPlatformConfig pointer to location to write platform config
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,
			TypePlatformConfiguration_t *pPlatformConfig)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETPLATFORMCONFIG);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceNotInitState(&retval) &&
				(pPlatformConfig != NULL)) {
		/* TODO: Figure out real values */
		pPlatformConfig->data[0] = 0;
		pPlatformConfig->data[1] = 'H';
		pPlatformConfig->data[2] = 'S';
		pPlatformConfig->data[3] = 'M';
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETPLATFORMCONFIG);
	return retval;
}

/**
 *
 * @brief Retrieve serial number of SE chip
 * @ingroup devicemanagement
 *
 * This function retrives the serial number of the SE chip.  This is
 * currently simulated by returning a fixed value.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pChipInfo pointer to location to write serial number
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getChipInfo(TypeSW_t *pHsmStatusCode,
					TypeChipInformation_t *pChipInfo)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETCHIPINFO);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceNotInitState(&retval) &&
				(pChipInfo != NULL)) {
		/* TODO: Figure out real values */
		memcpy(pChipInfo->data, serialNumber, V2XSE_SERIAL_NUMBER);
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETCHIPINFO);
	return retval;
}

/**
 *
 * @brief Retrieve SE attack log
 * @ingroup devicemanagement
 *
 * This function retrives the attack log from the SE device.  This system
 * does not support an attack log, so the log will always be empty.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pAttackLog pointer to location to write the attack log
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,
					TypeAttackLog_t *pAttackLog)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETATTACKLOG);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceNotInitState(&retval) &&
				(pAttackLog != NULL)) {
		pAttackLog->currAttackCntrStatus = V2XSE_ATTACK_CNT_ZERO;
		pAttackLog->len = 0;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETATTACKLOG);
	return retval;
}

/**
 *
 * @brief Get key length from curveId
 *
 * This  function returns the key length that corresponds to the specified
 * curveId
 *
 * @param curveID curveId value to query
 *
 * @return key length, or V2XSE_FAILURE in case of error
 *
 */
int32_t keyLenFromCurveID(TypeCurveId_t curveID)
{
	int32_t lengthVal;

	switch(curveID)
	{
		case V2XSE_CURVE_NISTP256:
		case V2XSE_CURVE_BP256R1:
		case V2XSE_CURVE_BP256T1:
			lengthVal = V2XSE_256_EC_PUB_KEY;
			break;

		case V2XSE_CURVE_NISTP384:
		case V2XSE_CURVE_BP384R1:
		case V2XSE_CURVE_BP384T1:
			lengthVal = V2XSE_384_EC_PUB_KEY;
			break;

		default:
			lengthVal = V2XSE_FAILURE;
	}
	return lengthVal;
}

/**
 *
 * @brief External API function to get key length from curveId
 * @ingroup utility
 *
 * This  function returns the key length that corresponds to the specified
 * curveId.  It just calls the helper function, which is a separate function
 * to allow API profiling.
 *
 * @param curveID curveId value to query
 *
 * @return key length, or V2XSE_FAILURE in case of error
 *
 */
int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID)
{
	int32_t lengthVal;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETKEYLENFROMCURVEID);

	lengthVal = keyLenFromCurveID(curveID);

	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETKEYLENFROMCURVEID);
	return lengthVal;
}

/**
 *
 * @brief Get signature length from hash length
 *
 * This function returns the signature length used to sign a hash of the
 * specified length.
 *
 * @param hashLength hash length to sign
 *
 * @return length of signature, or V2XSE_FAILURE on error
 *
 */
int32_t sigLenFromHashLen(TypeHashLength_t hashLength)
{
	int32_t sigLen;

	switch(hashLength)
	{
		case V2XSE_256_EC_HASH_SIZE:
			sigLen = V2XSE_256_EC_COMP_SIGN;
			break;
		case V2XSE_384_EC_HASH_SIZE:
			sigLen = V2XSE_384_EC_COMP_SIGN;
			break;
		default:
			sigLen = V2XSE_FAILURE;
	}
	return sigLen;
}

/**
 *
 * @brief External API function to get signature length from hash length
 * @ingroup utility
 *
 * This function returns the signature length used to sign a hash of the
 * specified length. It just calls the helper function, which is a separate
 * function to allow API profiling.
 *
 * @param hashLength hash length to sign
 *
 * @return length of signature, or V2XSE_FAILURE on error
 *
 */
int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength)
{
	int32_t sigLen;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETSIGLENFROMHASHLEN);

	sigLen = sigLenFromHashLen(hashLength);

	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETSIGLENFROMHASHLEN);
	return sigLen;
}

/**
 *
 * @brief Invoke garbage collector
 * @ingroup devicemanagement
 *
 * This function invokes the JavaCard garbage collector on an SE.  As this
 * system does not use JavaCard, this function does nothing.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_INVOKEGARBAGECOLLECTOR);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {

		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_INVOKEGARBAGECOLLECTOR);
	return retval;
}
