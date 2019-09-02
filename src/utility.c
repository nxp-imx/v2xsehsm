
/*
 * Copyright 2019 NXP
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
uint16_t convertCurveId(TypeCurveId_t curveId)
{
	switch(curveId) {
		case V2XSE_CURVE_NISTP256:
			return HSM_KEY_TYPE_ECDSA_NIST_P256;
		case V2XSE_CURVE_BP256R1:
			return HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256;
		case V2XSE_CURVE_BP256T1:
			return HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256;
		case V2XSE_CURVE_NISTP384:
			return HSM_KEY_TYPE_ECDSA_NIST_P384;
		case V2XSE_CURVE_BP384R1:
			return HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384;
		case V2XSE_CURVE_BP384T1:
			return HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384;
		default:
			return 0;
	}
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
int is256bitCurve(uint32_t keyType)
{
	switch (keyType) {
		case HSM_KEY_TYPE_ECDSA_NIST_P256:
		case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256:
			return 1;
	}
	return 0;
}

/**
 *
 * @brief Retrive the version of the V2X or storage applet
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pVersion);

	if ((appletType != e_V2X) && (appletType != e_GS)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if (appletType == e_GS) {
		if ((v2xseAppletId != e_EU_AND_GS) &&
			(v2xseAppletId != e_US_AND_GS)) {
			*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
			return V2XSE_FAILURE;
		}
	}
	pVersion->data[0] = VERSION_GENERATION;
	pVersion->data[1] = VERSION_MAJOR;
	pVersion->data[2] = VERSION_MINOR;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrive information regarding SE capabilities
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pInfo);

	/* TODO: Figure out real values */

	/*Maximum Runtime keys supported by applet*/
        pInfo->maxRtKeysAllowed = NUM_STORAGE_SLOTS;

        /*Maximum Base keys supported by applet*/
        pInfo->maxBaKeysAllowed = NUM_STORAGE_SLOTS;

        /*Maximum number of prepared values supported */
        pInfo->numPreparedVal = 1;

        /*FIPS approved mode indicator */
        pInfo->fipsModeIndicator = 0;

        /*Proof of possession support indicator */
        pInfo->proofOfPossession = 0;

        /*Rollback protection status indicator */
        pInfo->rollBackProtection = 0;

        /*Key derivation support indicator */
        pInfo->rtKeyDerivation = 1;

        /*Active Applet Instance indicator */
        pInfo->eciesSupport = 1;

        /*Maximum number of data slots supported by Generic storage applet */
        pInfo->maxDataSlots = NUM_STORAGE_SLOTS;

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve version of CryptoLibrary
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
	if (!pVersion)
		return V2XSE_FAILURE;
	pVersion->data[0] = VERSION_GENERATION;
	pVersion->data[1] = VERSION_MAJOR;
	pVersion->data[2] = VERSION_MINOR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve platform identification info
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_NOT_INIT();
	ENFORCE_POINTER_NOT_NULL(pPlatformIdentifier);

	/* TODO: Figure out real values */
	memcpy(pPlatformIdentifier->data, PLATFORMINFO_STRING,
					V2XSE_PLATFORM_IDENTITY);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve trust provisioning profile info
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_NOT_INIT();
	ENFORCE_POINTER_NOT_NULL(pPlatformConfig);

	/* TODO: Figure out real values */
	pPlatformConfig->data[0] = 0;
	pPlatformConfig->data[1] = 'H';
	pPlatformConfig->data[2] = 'S';
	pPlatformConfig->data[3] = 'M';
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve serial number of SE chip
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_NOT_INIT();
	ENFORCE_POINTER_NOT_NULL(pChipInfo);

	/* TODO: Figure out real values */
	memcpy(pChipInfo->data, serialNumber, V2XSE_SERIAL_NUMBER);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve SE attack log
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_NOT_INIT();
	ENFORCE_POINTER_NOT_NULL(pAttackLog);

	pAttackLog->currAttackCntrStatus = V2XSE_ATTACK_CNT_ZERO;
	pAttackLog->len = 0;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
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
int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID)
{
	switch(curveID)
	{
		case V2XSE_CURVE_NISTP256:
		case V2XSE_CURVE_BP256R1:
		case V2XSE_CURVE_BP256T1:
			return V2XSE_256_EC_PUB_KEY;

		case V2XSE_CURVE_NISTP384:
		case V2XSE_CURVE_BP384R1:
		case V2XSE_CURVE_BP384T1:
			return V2XSE_384_EC_PUB_KEY;

		default:
			return V2XSE_FAILURE;
	}
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
int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength)
{
	switch(hashLength)
	{
		case V2XSE_256_EC_HASH_SIZE:
			return V2XSE_256_EC_COMP_SIGN;
		case V2XSE_384_EC_HASH_SIZE:
			return V2XSE_384_EC_COMP_SIGN;
		default:
			return V2XSE_FAILURE;
	}
}

/**
 *
 * @brief Invoke garbage collector
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_NORMAL_OPERATING_PHASE();

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
