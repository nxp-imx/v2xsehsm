
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
 * @file v2xsehsm.c
 *
 * @brief Core implementation of V2X SE to HSM adaptation layer
 *
 */

#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

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

/* NVM Key handles, initialized as zero, read from fs when first used */
/** Module authentication key handle */
uint32_t maKeyHandle;
/** Module authentication key curve id */
TypeCurveId_t maCurveId;
/** Runtime key handle */
uint32_t rtKeyHandle[NUM_STORAGE_SLOTS];
/** Runtime key curve id */
TypeCurveId_t rtCurveId[NUM_STORAGE_SLOTS];
/** Base key handle */
uint32_t baKeyHandle[NUM_STORAGE_SLOTS];
/** Base key curve id */
TypeCurveId_t baCurveId[NUM_STORAGE_SLOTS];

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
	ENFORCE_STATE_INIT();

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
 * @param securityLevel Security level for emulated SXF1800
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
	open_svc_key_store_args_t key_store_args;
	open_svc_key_management_args_t key_mgmt_args;
	open_svc_cipher_args_t cipher_args;
	open_svc_sign_gen_args_t sig_gen_args;
	uint32_t keystore_identifier;
	uint32_t key_store_nonce;

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_INIT();

	if ((appletId == e_US_AND_GS) || (appletId == e_US)){
		appletVarStoragePath = usVarStorage;
#ifdef SINGLE_KEYSTORE
		/* Workaround for single keystore support in current hsm */
		/*  - both apps use EU keystore defines			 */
		keystore_identifier = MAGIC_KEYSTORE_IDENTIFIER_EU;
		key_store_nonce = MAGIC_KEYSTORE_NONCE_EU;
#else
		keystore_identifier = MAGIC_KEYSTORE_IDENTIFIER_US;
		key_store_nonce = MAGIC_KEYSTORE_NONCE_US;
#endif
	} else if ((appletId == e_EU_AND_GS) || (appletId == e_EU)){
		appletVarStoragePath = euVarStorage;
		keystore_identifier = MAGIC_KEYSTORE_IDENTIFIER_EU;
		key_store_nonce = MAGIC_KEYSTORE_NONCE_EU;
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

	memset(&session_args, 0, sizeof(session_args));
	session_args.session_priority = HSM_SESSION_PRIORITY;
	session_args.operating_mode = HSM_OPERATING_MODE;
	if (hsm_open_session(&session_args, &hsmSessionHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	memset(&rng_open_args, 0, sizeof(rng_open_args));
	if (hsm_open_rng_service(hsmSessionHandle, &rng_open_args,
							&hsmRngHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	/* Assume keystore exists, try to open */
	memset(&key_store_args, 0, sizeof(key_store_args));
	key_store_args.key_store_identifier = keystore_identifier;
	key_store_args.authentication_nonce = key_store_nonce;
	key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_UPDATE;
	if (hsm_open_key_store_service(hsmSessionHandle,
				&key_store_args, &hsmKeyStoreHandle)) {
		/*
		 * Failure to open, try to create
		 *  - re-initialize argument structure in case it was
		 *    modified by hsm_open_key_store_service above
		 */
		memset(&key_store_args, 0, sizeof(key_store_args));
		key_store_args.key_store_identifier = keystore_identifier;
		key_store_args.authentication_nonce = key_store_nonce;
		key_store_args.max_updates_number = MAX_KEYSTORE_UPDATES;
		key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
		if (hsm_open_key_store_service(hsmSessionHandle,
					&key_store_args, &hsmKeyStoreHandle)) {
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
			return V2XSE_FAILURE;
		}
	}

	memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));
	if (hsm_open_key_management_service(hsmKeyStoreHandle, &key_mgmt_args,
							&hsmKeyMgmtHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}
	preparedKeyHandle = 0; /* Keys just opened, so no prepared key yet */

	memset(&cipher_args, 0, sizeof(cipher_args));
	if (hsm_open_cipher_service(hsmKeyStoreHandle, &cipher_args,
							&hsmCipherHandle)) {
		*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;
		return V2XSE_FAILURE;
	}

	memset(&sig_gen_args, 0, sizeof(sig_gen_args));
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
 * This function resets the emulated SXF1800.  This is performed by closing
 * closing the session to the HSM if it is active and setting the v2xseState to
 * idle.  By closing the HSM session, all previously opened HSM services are
 * automatically closed.  All variables required for activated state cannot
 * be accessed from init state, and will be initialized when activated state
 * is enabled again.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_reset(void)
{
	hsm_err_t error_seen = 0;
	if (v2xseState == V2XSE_STATE_ACTIVATED) {
		if (hsm_close_signature_generation_service(hsmSigGenHandle))
			error_seen = 1;
		if (hsm_close_cipher_service(hsmCipherHandle))
			error_seen = 1;
		if (hsm_close_key_management_service(hsmKeyMgmtHandle))
			error_seen = 1;
		if (hsm_close_key_store_service(hsmKeyStoreHandle))
			error_seen = 1;
		if (hsm_close_rng_service(hsmRngHandle))
			error_seen = 1;
		if (hsm_close_session(hsmSessionHandle))
			error_seen = 1;
	}
	v2xseState = V2XSE_STATE_INIT;
	if (error_seen)
		return V2XSE_FAILURE;

	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Deactivates the emulated SXF1800
 *
 * This function deactivates the emulated SXF1800.  The only functional
 * difference from v2xSe_reset is that it cannot be called from init state.
 * To avoid code duplication, this function will simply check if the current
 * state is not init, and if so call v2xSe_reset.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deactivate(void)
{
	if (v2xseState == V2XSE_STATE_INIT)
		return V2XSE_FAILURE_INIT;
	return v2xSe_reset();
}

/**
 *
 * @brief Disconnects the emulated SXF1800
 *
 * This function disconnects the emulated SXF1800, which has no
 * functional difference in this system to deactivate, so the v2xSe_deactivate
 * function is directly called to avoid code duplication.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_disconnect(void)
{
	return v2xSe_deactivate();
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

	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pRandomNumber);

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
	VERIFY_STATUS_CODE_PTR();

	*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
	return V2XSE_FAILURE;
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();

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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();
	ENFORCE_POINTER_NOT_NULL(pPhaseInfo);

	if (v2xseSecurityLevel != e_channelSecLevel_5) {
		*pHsmStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
		return V2XSE_FAILURE;
	}
	*pPhaseInfo = v2xsePhase;
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
