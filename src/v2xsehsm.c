
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file v2xsehsm.c
 *
 * @brief Core implementation of V2X SE to HSM adaptation layer
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"
#include <string.h>

/** State of emulated SXF1800, can be INIT, CONNECTED or ACTIVATED */
uint8_t	v2xseState = V2XSE_STATE_INIT;

/** Security level of emulated SXF1800, can be 1 - 5 */
channelSecLevel_t v2xseSecurityLevel;

/** AppletId of emulated SXF1800: e_EU, e_US, e_EU_AND_GS or e_US_AND_GS */
appletSelection_t v2xseAppletId;

/** Path to NVM storage in filesystem for the current applet */
const char* appletVarStoragePath;
/** Fixed path to NVM storage for US applet */
const char usVarStorage[] = US_NVM_VAR_PATH;
/** Fixed path to NVM storage for EU applet */
const char euVarStorage[] = EU_NVM_VAR_PATH;

/** Handle of key pre-loaded for low latency certificate generation */
uint32_t preparedKeyHandle = 0;

/** Emulated serial number for device - currently fixed for all devices */
const uint8_t serialNumber[V2XSE_SERIAL_NUMBER] = SERIALNUM_BYTES;


/* HSM handles */
/** Handle for HSM session */
hsm_hdl_t hsmSessionHandle;
/** Handle for HSM RNG service */
hsm_hdl_t hsmRngHandle;
/** Handle for HSM key store service */
hsm_hdl_t hsmKeyStoreHandle;
/** Handle for HSM key management service */
hsm_hdl_t hsmKeyMgmtHandle;
/** Handle for HSM cipher service */
hsm_hdl_t hsmCipherHandle;
/** Handle for HSM signature generation service */
hsm_hdl_t hsmSigGenHandle;

/* NVM vars, initialized from filesystem on activate */
/** Phase of emulated SXF1800, can be key injection or normal phase */
uint8_t	v2xsePhase;
/** Nonce value needed to access HSM key store */
uint32_t key_store_nonce;

/* NVM Key handles, initialized as zero, read from fs when first used */
/* Module authentication key handle */
uint32_t maKeyHandle;
/* Module authentication key curve id */
TypeCurveId_t maCurveId;
/* Runtime key handle */
uint32_t rtKeyHandle[NUM_STORAGE_SLOTS];
/*Runtime key curve id */
TypeCurveId_t rtCurveId[NUM_STORAGE_SLOTS];
/* Base key handle */
uint32_t baKeyHandle[NUM_STORAGE_SLOTS];
/* Base key curve id */
TypeCurveId_t baCurveId[NUM_STORAGE_SLOTS];

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
 * @brief Move emulated SXF1800 state machine to Connected state
 *
 * Move emulated SXF1800 state machine to Connected state.  This state is
 * only used to allow/disallow specific V2X SE API commands.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_connect(void)
{
	ENFORCE_STATE_INIT()

	v2xseState = V2XSE_STATE_CONNECTED;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Activate V2X opertions using default security level
 *
 * This function activates V2X operations using the default security level.
 * It simply calls v2xSe_activate specifying e_channelSecLevel_5 for security
 * level.

 * @param appletId Applet(s) to activate: US or EU, and optionally GS
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode)
{
	return v2xSe_activateWithSecurityLevel(appletId, e_channelSecLevel_5,
						pHsmStatusCode);
}

/**
 *
 * @brief Activate V2X opertions
 *
 * This function activates V2X operations using the specified security level.
 * The appletId and securtyLevel are stored in global variables for later
 * use.  Non-volatile variables for the chosen applet are initialized from
 * the filesystem.  A session is opened with the HSM, and all services
 * that can be used are also opened.  The v2xseState is set to activated.
 *
 * @param appletId Applet(s) to activate: US or EU, and optionally GS
 * @param: Security level for emulated SXF1800
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
	uint32_t keystore_identifier;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_INIT()

	if ((appletId == e_US_AND_GS) || (appletId == e_US)){
		appletVarStoragePath = usVarStorage;
		keystore_identifier = MAGIC_KEYSTORE_IDENTIFIER_US;
	} else if ((appletId == e_EU_AND_GS) || (appletId == e_EU)){
		appletVarStoragePath = euVarStorage;
		keystore_identifier = MAGIC_KEYSTORE_IDENTIFIER_EU;
	} else {
		*pHsmStatusCode = V2XSE_APP_MISSING;
		return V2XSE_FAILURE;
	}
	if ((securityLevel < e_channelSecLevel_1) ||
			(securityLevel > e_channelSecLevel_5)){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	if (nvm_init()) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	session_args.session_priority = HSM_SESSION_PRIORITY;
	session_args.operating_mode = HSM_OPERATING_MODE;
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
	if (key_store_nonce == 0) {
		/* value doesn't exist, create key store */
		rng_get_args.output = (uint8_t*)&key_store_nonce;
		rng_get_args.random_size = sizeof(key_store_nonce);
		while (key_store_nonce == 0) {
			/* Get non-zero random number (0 = initialized) */
			if (hsm_get_random(hsmRngHandle, &rng_get_args)) {
				*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
				return V2XSE_FAILURE;
			}
		}
		key_store_args.key_store_identifier = keystore_identifier;
		key_store_args.authentication_nonce = key_store_nonce;
		key_store_args.max_updates_number = MAX_KEYSTORE_UPDATES;
		key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
		if (hsm_open_key_store_service(hsmSessionHandle,
					&key_store_args, &hsmKeyStoreHandle)) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
		if (nvm_update_var("key_store_nonce",
						(uint8_t*)&key_store_nonce,
						sizeof(key_store_nonce))) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
	} else {
		key_store_args.key_store_identifier = keystore_identifier;
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
	preparedKeyHandle = 0; /* Keys just opened, so no prepared key yet */

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

/**
 *
 * @brief Resets the connection to the emulated SXF1800
 *
 * This function resets the connection to the emulated SXF1800, which has no
 * functional difference in this system to deactivate, so the v2xSe_deactivate
 * function is directly called so avoid code duplication.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_reset(void)
{
	return v2xSe_deactivate();
}

/**
 *
 * @brief Deactivates the emulated SXF1800
 *
 * This function deactivates the emulated SXF1800.  This is performed by
 * closing the session to the HSM and setting the v2xseState to idle.  By
 * closing the HSM session, all previously opened HSM services are
 * automatically closed.  All variables required for activated state cannot
 * be accessed from init state, and will be initialized when activated state
 * is enabled again.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pHashValue)
	ENFORCE_POINTER_NOT_NULL(pSignature)

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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pHashValue)
	ENFORCE_POINTER_NOT_NULL(pSignature)
	ENFORCE_POINTER_NOT_NULL(pFastIndicator)

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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pHashValue)
	ENFORCE_POINTER_NOT_NULL(pSignature)

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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pHashValue)
	ENFORCE_POINTER_NOT_NULL(pSignature)

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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()

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

/**
 *
 * @brief Generate a random number
 *
 * This function calls the HSM to generate a random number of the requested
 * size.
 *
 * @param length size of random number to generate, in bytes
 * @param pHsmStatusCode pointer to location to write extended result code
 * @param pRandomNumber pointer to location to write random number
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getRandomNumber
(
    TypeLen_t length,
    TypeSW_t *pHsmStatusCode,
    TypeRandomNumber_t *pRandomNumber
)
{
	op_get_random_args_t args;

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_POINTER_NOT_NULL(pRandomNumber)

	args.output = (uint8_t*)pRandomNumber;
	args.random_size = length;
	if (hsm_get_random(hsmRngHandle, &args)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pPlatformIdentifier)

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
 * @param pPlatformIdentifier pointer to location to write platform info
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pChipInfo)

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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_NOT_INIT()
	ENFORCE_POINTER_NOT_NULL(pAttackLog)

	pAttackLog->currAttackCntrStatus = V2XSE_ATTACK_CNT_ZERO;
	pAttackLog->len = 0;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}


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
 * @param pVctLen pointer to location to write the length of encrypted data
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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pEciesData)
	ENFORCE_POINTER_NOT_NULL(pVctLen)
	ENFORCE_POINTER_NOT_NULL(pVctData)

	args.input = pEciesData->pMsgData->data;
	args.pub_key = (uint8_t*)(pEciesData->pEccPublicKey);
	args.p1 = pEciesData->kdfParamP1;
	args.p2 = pEciesData->macParamP2;
	args.output = pVctData->data;
	args.input_size = pEciesData->msgLen;
	args.p1_size = pEciesData->kdfParamP1Len;
	args.p2_size = pEciesData->macParamP2Len;
	args.pub_key_size = v2xSe_getKeyLenFromCurveID(pEciesData->curveId);
	args.mac_size = pEciesData->macLen;
	args.out_size = *pVctLen;
	args.key_type = convertCurveId(pEciesData->curveId);
	args.flags = 0;
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
 * @param pMsgLen pointer to location to write the length of decrypted data
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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pEciesData)
	ENFORCE_POINTER_NOT_NULL(pMsgLen)
	ENFORCE_POINTER_NOT_NULL(pMsgData)

	if (rtKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if(nvm_retrieve_rt_key_handle(rtKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	args.p1 = pEciesData->kdfParamP1;
	args.p2 = pEciesData->macParamP2;
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	args.output_size = *pMsgLen;
	args.p1_size = pEciesData->kdfParamP1Len;
	args.p2_size = pEciesData->macParamP2Len;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	args.flags = 0;

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
 * @param pMsgLen pointer to location to write the length of decrypted data
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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pEciesData)
	ENFORCE_POINTER_NOT_NULL(pMsgLen)
	ENFORCE_POINTER_NOT_NULL(pMsgData)

	if(nvm_retrieve_ma_key_handle(&keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	args.p1 = pEciesData->kdfParamP1;
	args.p2 = pEciesData->macParamP2;
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	/* expect args.output_size to be filled in by HSM */
	args.p1_size = pEciesData->kdfParamP1Len;
	args.p2_size = pEciesData->macParamP2Len;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	args.flags = 0;

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
 * @param pMsgLen pointer to location to write the length of decrypted data
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

	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()
	ENFORCE_POINTER_NOT_NULL(pEciesData)
	ENFORCE_POINTER_NOT_NULL(pMsgLen)
	ENFORCE_POINTER_NOT_NULL(pMsgData)

	if (baseKeyId >= NUM_STORAGE_SLOTS){
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if(nvm_retrieve_ba_key_handle(baseKeyId, &keyHandle, &curveId)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}

	args.key_identifier = keyHandle;
	args.input = pEciesData->pVctData->data;
	args.p1 = pEciesData->kdfParamP1;
	args.p2 = pEciesData->macParamP2;
	args.output = pMsgData->data;
	args.input_size = pEciesData->vctLen;
	/* expect args.output_size to be filled in by HSM */
	args.p1_size = pEciesData->kdfParamP1Len;
	args.p2_size = pEciesData->macParamP2Len;
	args.mac_size = pEciesData->macLen;
	args.key_type = convertCurveId(curveId);
	args.flags = 0;

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
		case V2XSE_384_EC_HASH_SIZE:
			return hashLength*2;
		default:
			return V2XSE_FAILURE;
	}
}

/**
 *
 * @brief Exchange APDU packets with SE
 *
 * This function exchanges APDU packets with the SE.  As this system does
 * not support APDU packets, this function will always return error
 *
 * @param pTxBuf pointer to APDU packets to send
 * @param txLen length of APDU packet to send
 * @param pRxLen pointer to location to write length of received APDU packet
 * @param pRxBuf pointer to location to write received APDU packet
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_FAILURE in all cases
 *
 */
int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen,  uint16_t *pRxLen,
				uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode)
{
	VERIFY_STATUS_CODE_PTR()

	*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
	return V2XSE_FAILURE;
}


/**
 *
 * @brief Store generic data in NVM
 *
 * This function stores generic data in NVM in the specified slot.  For this
 * system, it is stored in plaintext in the filesystem.   The data must be
 * between 1 and 239 bytes long. If data already exists in the specified
 * slot, it is overwritten.
 *
 * @param index slot to use to store generic data
 * @param length length of generic data to store
 * @param pData pointer to generic data to store
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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

/**
 *
 * @brief Retrieve generic data from NVM
 *
 * This function retrieves generic data in NVM from the specified slot.
 *
 * @param index slot to retrieve generic data from
 * @param plength pointer to location to write length of generic data retrieved
 * @param pData pointer to location to write generic data retrieved
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
	if (nvm_load_generic_data(index, pData, pLength) == -1) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Delete generic data from NVM
 *
 * This function deletes generic data in NVM from the specified slot.
 *
 * @param index slot to delete generic data from
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
	VERIFY_STATUS_CODE_PTR()
	ENFORCE_STATE_ACTIVATED()
	ENFORCE_NORMAL_OPERATING_PHASE()

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve amount of available NVM
 *
 * This function returns the amount of available NVM.  As this system only
 * simulates NVM and actually uses the filesystem to store nvm data, for the
 * moment this function simply returns a fixed value.  This may be changed in
 * the future if needed.
 *
 * @param pSize pointer to location to write the amount of available nvm
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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


/**
 *
 * @brief End key injection phase
 *
 * This function ends key injection phase for the selected applet.  For the
 * moment this simply involves updating a variable in NVM.  This function
 * will need to be updated when a more secure method to end key injection
 * phase has been implemented on the HSM.
 *
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
	if (nvm_update_var("v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase))) {
		*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
		return V2XSE_FAILURE;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve the phase of the current applet
 *
 * This function retrieves the phase (key injection or normal operating) for
 * the current applet.  For the moment this simply involves querying a variable
 * in NVM.  This function will need to be updated when a more secure method to
 * handle key injection phase has been implemented on the HSM.
 *
 * @param pPhaseInfo pointer to location to write the current phase
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
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
