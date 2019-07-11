
#include "adaptlib.h"
#include <string.h>

uint8_t	v2xseState = V2XSE_STATE_INIT;
channelSecLevel_t v2xseSecurityLevel;
appletSelection_t v2xseAppletId;
const uint8_t serialNumber[V2XSE_SERIAL_NUMBER] = SERIALNUM_BYTES;

/*TODO: read nvm vars from filesystem */
uint8_t	v2xsePhase = V2XSE_KEY_INJECTION_PHASE;

int32_t v2xSe_connect(void)
{
	if (v2xseState != V2XSE_STATE_INIT) {
		if (v2xseState == V2XSE_STATE_CONNECTED)
			return V2XSE_FAILURE_CONNECTED;
		if (v2xseState == V2XSE_STATE_ACTIVATED)
			return V2XSE_FAILURE_ACTIVATED;
		return V2XSE_FAILURE;
	}
	v2xseState = V2XSE_STATE_CONNECTED;
	return V2XSE_SUCCESS;
}


int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode)
{
	return v2xSe_activateWithSecurityLevel(appletId, e_channelSecLevel_5, pHsmStatusCode);
}

int32_t v2xSe_activateWithSecurityLevel(appletSelection_t appletId, channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (v2xseState != V2XSE_STATE_INIT) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		if (v2xseState == V2XSE_STATE_CONNECTED)
			return V2XSE_FAILURE_CONNECTED;
		if (v2xseState == V2XSE_STATE_ACTIVATED)
			return V2XSE_FAILURE_ACTIVATED;
		return V2XSE_FAILURE;
	}
	/* TODO: open nvm */
	/* TODO: open hsm */
	if ((appletId < e_EU) || (appletId > e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if ((securityLevel < e_channelSecLevel_1)||(securityLevel > e_channelSecLevel_5)){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	v2xseState = V2XSE_STATE_ACTIVATED;
	v2xseAppletId = appletId;
	v2xseSecurityLevel = securityLevel;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_reset(void)
{
	return v2xSe_deactivate();
}

int32_t v2xSe_deactivate(void)
{
	if (v2xseState == V2XSE_STATE_INIT)
		return V2XSE_FAILURE_INIT;
	if (v2xseState == V2XSE_STATE_ACTIVATED) {
		/* TODO: close hsm */
	}
	v2xseState = V2XSE_STATE_INIT;
	return V2XSE_SUCCESS;
}
/*
int32_t v2xSe_generateMaEccKeyPair
(
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
);
int32_t v2xSe_getMaEccPublicKey
(
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);
int32_t v2xSe_createMaSign
(
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
);
int32_t v2xSe_generateRtEccKeyPair
(
    TypeRtKeyId_t rtKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
) ;
int32_t v2xSe_deleteRtEccPrivateKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
);
int32_t v2xSe_getRtEccPublicKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);
int32_t v2xSe_createRtSignLowLatency
(
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature,
    TypeLowlatencyIndicator_t *pFastIndicator
);
int32_t v2xSe_createRtSign
(
    TypeRtKeyId_t rtKeyId,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature

);
int32_t v2xSe_generateBaEccKeyPair
(
    TypeBaseKeyId_t baseKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
);
int32_t v2xSe_deleteBaEccPrivateKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode
);
int32_t v2xSe_getBaEccPublicKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);int32_t v2xSe_createBaSign
(
    TypeBaseKeyId_t baseKeyId,
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
);
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
);
int32_t v2xSe_activateRtKeyForSigning
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
);
*/
int32_t v2xSe_getAppletVersion
(
    appletSelection_t appletType,
    TypeSW_t *pHsmStatusCode,
    TypeVersion_t *pVersion
)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if ((appletType != e_V2X) && (appletType != e_GS)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if (v2xseState != V2XSE_STATE_ACTIVATED) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (appletType == e_GS) {
		if ((v2xseAppletId != e_EU_AND_GS) &&
			(v2xseAppletId != e_US_AND_GS)) {
			*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
			return V2XSE_FAILURE;
		}
	}
	if (!pVersion) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	pVersion->data[0] = VERSION_GENERATION;
	pVersion->data[1] = VERSION_MAJOR;
	pVersion->data[2] = VERSION_MINOR;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/*
int32_t v2xSe_getRandomNumber
(
    TypeLen_t length,
    TypeSW_t *pHsmStatusCode,
    TypeRandomNumber_t *pRandomNumber
);
*/

int32_t v2xSe_getSeInfo
(
    TypeSW_t *pHsmStatusCode,
    TypeInformation_t *pInfo
)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (v2xseState != V2XSE_STATE_ACTIVATED) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (!pInfo) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	/* TODO: Figure out real values */

	/*Maximum Runtime keys supported by applet*/
        pInfo->maxRtKeysAllowed = 10000;

        /*Maximum Base keys supported by applet*/
        pInfo->maxBaKeysAllowed = 10000;

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
        pInfo->maxDataSlots = 10000;

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

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

int32_t v2xSe_getPlatformInfo(TypeSW_t *pHsmStatusCode,
			TypePlatformIdentity_t *pPlatformIdentifier)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (!pPlatformIdentifier) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	if (v2xseState == V2XSE_STATE_INIT) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	/* TODO: Figure out real values */
	memcpy(pPlatformIdentifier->data, PLATFORMINFO_STRING,
					V2XSE_PLATFORM_IDENTITY);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,
			TypePlatformConfiguration_t *pPlatformConfig)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (!pPlatformConfig) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	if (v2xseState == V2XSE_STATE_INIT) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	/* TODO: Figure out real values */
	pPlatformConfig->data[0] = 0;
	pPlatformConfig->data[1] = 'H';
	pPlatformConfig->data[2] = 'S';
	pPlatformConfig->data[3] = 'M';
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getChipInfo(TypeSW_t *pHsmStatusCode,
					TypeChipInformation_t *pChipInfo)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (!pChipInfo) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	if (v2xseState == V2XSE_STATE_INIT) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	/* TODO: Figure out real values */
	memcpy(pChipInfo->data, serialNumber, V2XSE_SERIAL_NUMBER);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,
					TypeAttackLog_t *pAttackLog)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (!pAttackLog) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	if (v2xseState == V2XSE_STATE_INIT) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	pAttackLog->currAttackCntrStatus = V2XSE_ATTACK_CNT_ZERO;
	pAttackLog->len = 0;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/*
int32_t v2xSe_encryptUsingEcies (TypeEncryptEcies_t *pEciesData, TypeSW_t *pHsmStatusCode,
                                 TypeLen_t *pVctLen,TypeVCTData_t *pVctData );
int32_t v2xSe_decryptUsingRtEcies (TypeRtKeyId_t rtKeyId,
                                   TypeDecryptEcies_t *pEciesData,TypeSW_t *pHsmStatusCode, TypeLen_t *pMsgLen,
                                   TypePlainText_t *pMsgData );
int32_t v2xSe_decryptUsingMaEcies
(
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
);
int32_t v2xSe_decryptUsingBaEcies
(
    TypeBaseKeyId_t baseKeyId,
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
);
int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID);
int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength);
*/

int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen,  uint16_t *pRxLen, uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
	return V2XSE_FAILURE;
}

/*
int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length, uint8_t  *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength, uint8_t *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode);
*/

int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (v2xseState != V2XSE_STATE_ACTIVATED) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/*
int32_t v2xSe_getRemainingNvm (uint32_t *pSize, TypeSW_t *pHsmStatusCode);
*/

int32_t v2xSe_endKeyInjection (TypeSW_t *pHsmStatusCode)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (v2xseState != V2XSE_STATE_ACTIVATED) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (v2xsePhase != V2XSE_KEY_INJECTION_PHASE) {
		*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
		return V2XSE_FAILURE;
	}
	if (v2xseSecurityLevel != e_channelSecLevel_5) {
		*pHsmStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
		return V2XSE_FAILURE;
	}
	/*TODO: update nvm */
	v2xsePhase = V2XSE_NORMAL_OPERATING_PHASE;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getSePhase (uint8_t *pPhaseInfo, TypeSW_t *pHsmStatusCode)
{
	if (!pHsmStatusCode)
		return V2XSE_FAILURE;
	if (v2xseState != V2XSE_STATE_ACTIVATED) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (v2xseSecurityLevel != e_channelSecLevel_5) {
		*pHsmStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
		return V2XSE_FAILURE;
	}
	if (!pPhaseInfo) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	*pPhaseInfo = v2xsePhase;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
