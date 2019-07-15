
#include "adaptlib.h"
#include "nvm.h"
#include <string.h>

uint8_t	v2xseState = V2XSE_STATE_INIT;
channelSecLevel_t v2xseSecurityLevel;
appletSelection_t v2xseAppletId;
const uint8_t serialNumber[V2XSE_SERIAL_NUMBER] = SERIALNUM_BYTES;

/* HSM handles */
hsm_hdl_t hsmSessionHandle;
hsm_hdl_t hsmRngHandle;
hsm_hdl_t hsmKeyStoreHandle;
hsm_hdl_t hsmKeyMgmtHandle;
hsm_hdl_t hsmCipherHandle;
hsm_hdl_t hsmSigGenHandle;

/* NVM vars, initialized from filesystem */
uint8_t	v2xsePhase;
uint32_t key_store_nonce;

int32_t v2xSe_connect(void)
{
	ENFORCE_STATE_INIT();
	v2xseState = V2XSE_STATE_CONNECTED;
	return V2XSE_SUCCESS;
}


int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode)
{
	return v2xSe_activateWithSecurityLevel(appletId, e_channelSecLevel_5,
						pHsmStatusCode);
}

int32_t v2xSe_activateWithSecurityLevel(appletSelection_t appletId,
		channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode)
{
	open_session_args_t session_args;
	open_svc_rng_args_t rng_open_args;
	op_get_random_args_t rng_get_args;
	open_svc_key_store_args_t key_store_args;
	open_svc_key_management_args_t key_mgmt_args;
	open_svc_cipher_args_t cipher_args;
	open_svc_sign_gen_args_t sig_gen_args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_INIT();

	if ((appletId < e_EU) || (appletId > e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_APP_MISSING;
		return V2XSE_FAILURE;
	}
	if ((securityLevel < e_channelSecLevel_1) ||
			(securityLevel > e_channelSecLevel_5)){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_load()) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	session_args.session_priority = EXPECTED_SESSION_PRIORITY;
	session_args.operating_mode = EXPECTED_OPERATING_MODE;
	if (hsm_open_session(&session_args, &hsmSessionHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	rng_open_args.flags = 0;
	if (hsm_open_rng_service(hsmSessionHandle, &rng_open_args,
							&hsmRngHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	if (nvm_load_var("key_store_nonce", (uint8_t*)&key_store_nonce,
			sizeof(key_store_nonce)) != sizeof(key_store_nonce)) {
		/* value doesn't exist, create key store */
		rng_get_args.output = (uint8_t*)&key_store_nonce;
		rng_get_args.random_size = sizeof(key_store_nonce);
		if (hsm_get_random(hsmRngHandle, &rng_get_args)) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
		key_store_args.key_store_identifier =
						EXPECTED_KEYSTORE_IDENTIFIER;
		key_store_args.authentication_nonce = key_store_nonce;
		key_store_args.max_updates_number = EXPECTED_MAX_UPDATES;
		key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE |
						HSM_SVC_KEY_STORE_FLAGS_UPDATE;
		if (hsm_open_key_store_service(hsmSessionHandle,
					&key_store_args, &hsmKeyStoreHandle)) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
		nvm_update_var("key_store_nonce", (uint8_t*)&key_store_nonce,
						sizeof(key_store_nonce));
	} else {
		key_store_args.key_store_identifier =
						EXPECTED_KEYSTORE_IDENTIFIER;
		key_store_args.authentication_nonce = key_store_nonce;
		key_store_args.max_updates_number = EXPECTED_MAX_UPDATES;
		key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_UPDATE;
		if (hsm_open_key_store_service(hsmSessionHandle,
					&key_store_args, &hsmKeyStoreHandle)) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
	}
	key_mgmt_args.flags = 0;
	if (hsm_open_key_management_service(hsmKeyStoreHandle, &key_mgmt_args,
							&hsmKeyMgmtHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	cipher_args.flags = 0;
	if (hsm_open_cipher_service(hsmKeyStoreHandle, &cipher_args,
							&hsmCipherHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	sig_gen_args.flags = 0;
	if (hsm_open_signature_generation_service(hsmKeyStoreHandle,
					&sig_gen_args, &hsmSigGenHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
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
		if (hsm_close_session(hsmSessionHandle))
			return V2XSE_FAILURE;
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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pVersion)
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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pInfo)

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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pPlatformIdentifier)

	/* TODO: Figure out real values */
	memcpy(pPlatformIdentifier->data, PLATFORMINFO_STRING,
					V2XSE_PLATFORM_IDENTITY);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,
			TypePlatformConfiguration_t *pPlatformConfig)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pPlatformConfig)

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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pChipInfo)

	/* TODO: Figure out real values */
	memcpy(pChipInfo->data, serialNumber, V2XSE_SERIAL_NUMBER);
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,
					TypeAttackLog_t *pAttackLog)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pAttackLog)

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

int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength)
{
	switch(hashLength)
	{
		case V2XSE_256_EC_HASH_SIZE:
		case V2XSE_384_EC_HASH_SIZE:
			return hashLength*2;
		default:
			return V2XSE_FAILURE;
	}
}

int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen,  uint16_t *pRxLen,
				uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()

	*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
	return V2XSE_FAILURE;
}


int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length,
				uint8_t  *pData,TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (!pData || (length < V2XSE_MIN_DATA_SIZE_GSA) ||
			(length > V2XSE_MAX_DATA_SIZE_GSA) ||
			(index > (NUM_STORAGE_SLOTS-1))) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (nvm_update_generic_data(index, pData, length) == -1) {
		*pHsmStatusCode = V2XSE_FILE_FULL;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength,
				uint8_t *pData,TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (!pData || (!pLength) || (index > (NUM_STORAGE_SLOTS-1))) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (nvm_retrieve_generic_data(index, pData, pLength) == -1) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (index > (NUM_STORAGE_SLOTS-1)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (nvm_delete_generic_data(index) == -1) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getRemainingNvm (uint32_t *pSize, TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pSize)

	/* For now, return fixed value 2MB */
	*pSize = 2 * 1024 * 1024;

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}


int32_t v2xSe_endKeyInjection (TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()

	if (v2xsePhase != V2XSE_KEY_INJECTION_PHASE) {
		*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
		return V2XSE_FAILURE;
	}
	if (v2xseSecurityLevel != e_channelSecLevel_5) {
		*pHsmStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
		return V2XSE_FAILURE;
	}
	v2xsePhase = V2XSE_NORMAL_OPERATING_PHASE;
	nvm_update_var(STORAGE_PATH"v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase));
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

int32_t v2xSe_getSePhase (uint8_t *pPhaseInfo, TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pPhaseInfo)

	if (v2xseSecurityLevel != e_channelSecLevel_5) {
		*pHsmStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
		return V2XSE_FAILURE;
	}
	*pPhaseInfo = v2xsePhase;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
