
#include "adaptlib.h"

uint8_t	V2xSe_State = V2XSE_STATE_INIT;


int32_t v2xSe_connect(void)
{
	if (V2xSe_State != V2XSE_STATE_INIT) {
		if (V2xSe_State == V2XSE_STATE_CONNECTED)
			return V2XSE_FAILURE_CONNECTED;
		if (V2xSe_State == V2XSE_STATE_ACTIVATED)
			return V2XSE_FAILURE_ACTIVATED;
		return V2XSE_FAILURE;
	}
	V2xSe_State = V2XSE_STATE_CONNECTED;
	return V2XSE_SUCCESS;
}

/*
int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_activateWithSecurityLevel(appletSelection_t appletId, channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_reset(void);
int32_t v2xSe_deactivate(void);
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
int32_t v2xSe_getAppletVersion
(
    appletSelection_t appletType,
    TypeSW_t *pHsmStatusCode,
    TypeVersion_t *pVersion
);
int32_t v2xSe_getRandomNumber
(
    TypeLen_t length,
    TypeSW_t *pHsmStatusCode,
    TypeRandomNumber_t *pRandomNumber
);
int32_t v2xSe_getSeInfo
(
    TypeSW_t *pHsmStatusCode,
    TypeInformation_t *pInfo
);
int32_t v2xSe_getCryptoLibVersion
(
    TypeVersion_t *pVersion
);
int32_t v2xSe_getPlatformInfo(TypeSW_t *pHsmStatusCode,TypePlatformIdentity_t *pPlatformIdentifier);
int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,TypePlatformConfiguration_t *pPlatformConfig);
int32_t v2xSe_getChipInfo(TypeSW_t *pHsmStatusCode,TypeChipInformation_t *pChipInfo);
int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,TypeAttackLog_t *pAttackLog);
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
int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen,  uint16_t *pRxLen, uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length, uint8_t  *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength, uint8_t *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getRemainingNvm (uint32_t *pSize, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_endKeyInjection (TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getSePhase (uint8_t *pPhaseInfo, TypeSW_t *pHsmStatusCode);
*/
