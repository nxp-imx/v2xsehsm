
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

/** Handle of key pre-loaded for low latency signature generation */
uint32_t activatedKeyHandle;
/** Signature scheme for key pre-loaded for low latency signing */
hsm_signature_scheme_id_t activatedSigScheme;

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
 * @ingroup devicemanagement
 *
 * Move emulated SXF1800 state machine to Connected state.  This state is
 * only used to allow/disallow specific V2X SE API commands.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_connect(void)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_CONNECT);

	if (!enforceInitState(&retval)) {
		v2xseState = V2XSE_STATE_CONNECTED;
		retval = V2XSE_SUCCESS;
	}

	TRACE_API_EXIT(PROFILE_ID_V2XSE_CONNECT);
	return retval;
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
int32_t activateV2x(appletSelection_t appletId,
		channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode)
{
	open_session_args_t session_args;
	open_svc_rng_args_t rng_open_args;
	open_svc_key_store_args_t key_store_args;
	open_svc_key_management_args_t key_mgmt_args;
	open_svc_cipher_args_t cipher_args;
	open_svc_sign_gen_args_t sig_gen_args;
	int32_t retval = V2XSE_FAILURE;
	uint32_t justCreatedKeystore = 0;
	hsm_err_t hsmret;

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceInitState(&retval)) {

		do {
			if ((appletId == e_US_AND_GS) || (appletId == e_US)) {
				appletVarStoragePath = usVarStorage;
			} else if ((appletId == e_EU_AND_GS) ||
							(appletId == e_EU)) {
				appletVarStoragePath = euVarStorage;
			} else {
				*pHsmStatusCode = V2XSE_APP_MISSING;
				break;
			}

			if ((securityLevel < e_channelSecLevel_1) ||
					(securityLevel > e_channelSecLevel_5)
									) {
				*pHsmStatusCode = V2XSE_WRONG_DATA;
				break;
			}

			if (nvm_init())
				break;

			memset(&session_args, 0, sizeof(session_args));
			session_args.session_priority = HSM_SESSION_PRIORITY;
			session_args.operating_mode = HSM_OPERATING_MODE;
			TRACE_HSM_CALL(PROFILE_ID_HSM_OPEN_SESSION);
			hsmret = hsm_open_session(&session_args,
							&hsmSessionHandle);
			TRACE_HSM_RETURN(PROFILE_ID_HSM_OPEN_SESSION);
			if (hsmret)
				break;

			memset(&rng_open_args, 0, sizeof(rng_open_args));
			TRACE_HSM_CALL(PROFILE_ID_HSM_OPEN_RNG_SERVICE);
			hsmret = hsm_open_rng_service(hsmSessionHandle,
						&rng_open_args, &hsmRngHandle);
			TRACE_HSM_RETURN(PROFILE_ID_HSM_OPEN_RNG_SERVICE);
			if (hsmret)
				break;

			/* Assume keystore exists, try to open */
			memset(&key_store_args, 0, sizeof(key_store_args));
			key_store_args.key_store_identifier =
						MAGIC_KEYSTORE_IDENTIFIER;
			key_store_args.authentication_nonce =
						MAGIC_KEYSTORE_NONCE;
			key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_UPDATE;
			TRACE_HSM_CALL(PROFILE_ID_HSM_OPEN_KEY_STORE_SERVICE);
			hsmret = hsm_open_key_store_service(hsmSessionHandle,
					&key_store_args, &hsmKeyStoreHandle);
			TRACE_HSM_RETURN(PROFILE_ID_HSM_OPEN_KEY_STORE_SERVICE);
			if (hsmret) {
				/*
				 * Failure to open, try to create
				 *  - re-initialize argument structure in case
				 *    it was modified by
				 *    hsm_open_key_store_service above
				 */
				memset(&key_store_args, 0,
						sizeof(key_store_args));
				key_store_args.key_store_identifier =
						MAGIC_KEYSTORE_IDENTIFIER;
				key_store_args.authentication_nonce =
						MAGIC_KEYSTORE_NONCE;
				key_store_args.max_updates_number =
						MAX_KEYSTORE_UPDATES;
				key_store_args.flags =
						HSM_SVC_KEY_STORE_FLAGS_CREATE;
				TRACE_HSM_CALL(
					PROFILE_ID_HSM_OPEN_KEY_STORE_SERVICE);
				hsmret = hsm_open_key_store_service(
					hsmSessionHandle, &key_store_args,
							&hsmKeyStoreHandle);
				TRACE_HSM_RETURN(
					PROFILE_ID_HSM_OPEN_KEY_STORE_SERVICE);
				if (hsmret)
					break;
				justCreatedKeystore = 1;
			}

			memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));
			TRACE_HSM_CALL(
				PROFILE_ID_HSM_OPEN_KEY_MANAGEMENT_SERVICE);
			hsmret = hsm_open_key_management_service(
					hsmKeyStoreHandle, &key_mgmt_args,
							&hsmKeyMgmtHandle);
			TRACE_HSM_RETURN(
				PROFILE_ID_HSM_OPEN_KEY_MANAGEMENT_SERVICE);
			if (hsmret)
				break;

			if (justCreatedKeystore) {
				/*
				 * Workaround: create dummy key to make sure
				 * key store is updated in filesystem, so that
				 * it can be opened in the future
				 */
				op_generate_key_args_t args;
				uint8_t dummyPubKey[V2XSE_256_EC_PUB_KEY];
				uint32_t dummyKeyHandle;

				memset(&args, 0, sizeof(args));
				args.key_identifier = &dummyKeyHandle;
				args.out_size = V2XSE_256_EC_PUB_KEY;
				args.flags =
					HSM_OP_KEY_GENERATION_FLAGS_CREATE |
				HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
				args.key_group = MA_KEY;
				args.key_type = HSM_KEY_TYPE_ECDSA_NIST_P256;
				args.out_key = dummyPubKey;
				TRACE_HSM_CALL(PROFILE_ID_HSM_GENERATE_KEY);
				hsmret = hsm_generate_key(hsmKeyMgmtHandle,
									&args);
				TRACE_HSM_RETURN(PROFILE_ID_HSM_GENERATE_KEY);
				if (hsmret)
					break;
			}

			/* Keys just opened, no activated key/sigScheme yet */
			activatedKeyHandle = 0;
			activatedSigScheme = 0;

			memset(&cipher_args, 0, sizeof(cipher_args));
			TRACE_HSM_CALL(PROFILE_ID_HSM_OPEN_CIPHER_SERVICE);
			hsmret = hsm_open_cipher_service(hsmKeyStoreHandle,
					&cipher_args, &hsmCipherHandle);
			TRACE_HSM_RETURN(PROFILE_ID_HSM_OPEN_CIPHER_SERVICE);
			if (hsmret)
				break;

			memset(&sig_gen_args, 0, sizeof(sig_gen_args));
			TRACE_HSM_CALL(
			    PROFILE_ID_HSM_OPEN_SIGNATURE_GENERATION_SERVICE);
			hsmret = hsm_open_signature_generation_service(
					hsmKeyStoreHandle, &sig_gen_args,
							&hsmSigGenHandle);
			TRACE_HSM_RETURN(
			    PROFILE_ID_HSM_OPEN_SIGNATURE_GENERATION_SERVICE);
			if (hsmret)
				break;

			v2xseState = V2XSE_STATE_ACTIVATED;
			v2xseAppletId = appletId;
			v2xseSecurityLevel = securityLevel;
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		} while (0);
	}
	return retval;
}

/**
 *
 * @brief Activate V2X opertions using specified security level
 * @ingroup devicemanagement
 *
 * This function activates V2X operations using the specified security level.
 * It calls the activateV2x helper function.

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
	int32_t retval;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ACTIVATEWITHSECURITYLEVEL);

	retval = activateV2x(appletId, securityLevel, pHsmStatusCode);

	TRACE_API_EXIT(PROFILE_ID_V2XSE_ACTIVATEWITHSECURITYLEVEL);
	return retval;
}

/**
 *
 * @brief Activate V2X opertions using default security level
 * @ingroup devicemanagement
 *
 * This function activates V2X operations using the default security level.
 * It calls the activateV2x helper function specifying e_channelSecLevel_1
 * for security level.

 * @param appletId Applet(s) to activate: US or EU, and optionally GS
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode)
{
	int32_t retval;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ACTIVATE);

	retval = activateV2x(appletId, e_channelSecLevel_1, pHsmStatusCode);

	TRACE_API_EXIT(PROFILE_ID_V2XSE_ACTIVATE);
	return retval;
}

/**
 *
 * @brief Resets the connection to the emulated SXF1800
 *
 * This function resets the emulated SXF1800.  This is performed by closing
 * closing the session to the HSM if it is active and setting the v2xseState to
 * idle. All variables required for activated state cannot be accessed from
 * init state, and will be initialized when activated state is enabled again.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t resetV2x(void)
{
	int32_t retval = V2XSE_SUCCESS;
	hsm_err_t hsmret;

	if (v2xseState == V2XSE_STATE_ACTIVATED) {
		TRACE_HSM_CALL(
			PROFILE_ID_HSM_CLOSE_SIGNATURE_GENERATION_SERVICE);
		hsmret = hsm_close_signature_generation_service(
							hsmSigGenHandle);
		TRACE_HSM_RETURN(
			PROFILE_ID_HSM_CLOSE_SIGNATURE_GENERATION_SERVICE);
		if (hsmret)
			retval = V2XSE_FAILURE;
		TRACE_HSM_CALL(PROFILE_ID_HSM_CLOSE_CIPHER_SERVICE);
		hsmret = hsm_close_cipher_service(hsmCipherHandle);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_CLOSE_CIPHER_SERVICE);
		if (hsmret)
			retval = V2XSE_FAILURE;
		TRACE_HSM_CALL(PROFILE_ID_HSM_CLOSE_KEY_MANAGEMENT_SERVICE);
		hsmret = hsm_close_key_management_service(hsmKeyMgmtHandle);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_CLOSE_KEY_MANAGEMENT_SERVICE);
		if (hsmret)
			retval = V2XSE_FAILURE;
		TRACE_HSM_CALL(PROFILE_ID_HSM_CLOSE_KEY_STORE_SERVICE);
		hsmret = hsm_close_key_store_service(hsmKeyStoreHandle);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_CLOSE_KEY_STORE_SERVICE);
		if (hsmret)
			retval = V2XSE_FAILURE;
		TRACE_HSM_CALL(PROFILE_ID_HSM_CLOSE_RNG_SERVICE);
		hsmret = hsm_close_rng_service(hsmRngHandle);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_CLOSE_RNG_SERVICE);
		if (hsmret)
			retval = V2XSE_FAILURE;
		TRACE_HSM_CALL(PROFILE_ID_HSM_CLOSE_SESSION);
		hsmret = hsm_close_session(hsmSessionHandle);
		TRACE_HSM_RETURN(PROFILE_ID_HSM_CLOSE_SESSION);
		if (hsmret)
			retval = V2XSE_FAILURE;
	}
	v2xseState = V2XSE_STATE_INIT;

	return retval;
}


/**
 *
 * @brief Resets the connection to the emulated SXF1800
 * @ingroup devicemanagement
 *
 * Calls the helper function resetV2x.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_reset(void)
{
	int32_t retval;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_RESET);

	retval = resetV2x();

	TRACE_API_EXIT(PROFILE_ID_V2XSE_RESET);
	return retval;
}

/**
 *
 * @brief Deactivates the emulated SXF1800
 * @ingroup devicemanagement
 *
 * This function deactivates the emulated SXF1800.  The only functional
 * difference from v2xSe_reset is that it cannot be called from init state.
 * To avoid code duplication, this function will simply check if the current
 * state is not init, and if so call resetV2x.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deactivate(void)
{
	int32_t retval;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DEACTIVATE);

	if (v2xseState == V2XSE_STATE_INIT)
		retval = V2XSE_FAILURE_INIT;
	else
		retval = resetV2x();

	TRACE_API_EXIT(PROFILE_ID_V2XSE_DEACTIVATE);
	return retval;
}

/**
 *
 * @brief Disconnects the emulated SXF1800
 * @ingroup devicemanagement
 *
 * This function disconnects the emulated SXF1800, which has no
 * functional difference in this system to deactivate.
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_disconnect(void)
{
	int32_t retval = V2XSE_SUCCESS;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DISCONNECT);

	if (v2xseState == V2XSE_STATE_INIT)
		retval = V2XSE_FAILURE_INIT;
	else
		retval = resetV2x();

	TRACE_API_EXIT(PROFILE_ID_V2XSE_DISCONNECT);
	return retval;
}

/**
 *
 * @brief Generate a random number
 * @ingroup utility
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
	int32_t retval = V2XSE_FAILURE;
	hsm_err_t hsmret;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETRANDOMNUMBER);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pRandomNumber != NULL)) {

		if (!length || length > V2XSE_MAX_RND_NUM_SIZE) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			args.output = pRandomNumber->data;
			args.random_size = length;
			TRACE_HSM_CALL(PROFILE_ID_HSM_GET_RANDOM);
			hsmret = hsm_get_random(hsmRngHandle, &args);
			TRACE_HSM_RETURN(PROFILE_ID_HSM_GET_RANDOM);
			if (!hsmret) {
				*pHsmStatusCode = V2XSE_NO_ERROR;
				retval = V2XSE_SUCCESS;
			}
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETRANDOMNUMBER);
	return retval;
}

/**
 *
 * @brief Exchange APDU packets with SE
 * @ingroup devicemanagement
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
	TRACE_API_ENTRY(PROFILE_ID_V2XSE_SENDRECEIVE);

	if (pHsmStatusCode)
		*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;

	TRACE_API_EXIT(PROFILE_ID_V2XSE_SENDRECEIVE);
	return V2XSE_FAILURE;
}


/**
 *
 * @brief End key injection phase
 * @ingroup keyinjection
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
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_ENDKEYINJECTION);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceSecurityLevel5(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval)) {

		if (v2xsePhase != V2XSE_KEY_INJECTION_PHASE) {
			*pHsmStatusCode = V2XSE_FUNC_NOT_SUPPORTED;
		} else {
			v2xsePhase = V2XSE_NORMAL_OPERATING_PHASE;
			if (nvm_update_var(V2XSE_PHASE_NAME, &v2xsePhase,
							sizeof(v2xsePhase))) {
				*pHsmStatusCode = V2XSE_NVRAM_UNCHANGED;
			} else {
				*pHsmStatusCode = V2XSE_NO_ERROR;
				retval = V2XSE_SUCCESS;
			}
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_ENDKEYINJECTION);
	return retval;
}

/**
 *
 * @brief Retrieve the phase of the current applet
 * @ingroup devicemanagement
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
	int32_t retval = V2XSE_FAILURE;


	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETSEPHASE);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceSecurityLevel5(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval) &&
			(pPhaseInfo != NULL)) {
		*pPhaseInfo = v2xsePhase;
		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETSEPHASE);
	return retval;
}

/**
 *
 * @brief Utility function to verify status code ptr & set default status
 *
 * This function verifies that the status code pointer provided is not
 * NULL, and if not NULL it initializes the default status code.
 *
 * @param pStatusCode status code pointer to check
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t setupDefaultStatusCode(TypeSW_t *pStatusCode)
{
	int32_t localret = -1;

	if (pStatusCode != NULL) {
		*pStatusCode = V2XSE_UNDEFINED_ERROR;
		localret = 0;
	}
	return localret;
}

/**
 *
 * @brief Utility function to verify system is in init state
 *
 * This function verifies that the system is in init state, and in case
 * of error it sets the API return code appropriately.
 *
 * @param pApiRetVal pointer to value that v2xSe API will return
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t enforceInitState(int32_t *pApiRetVal)
{
	int32_t localret = -1;

	switch (v2xseState) {
	case V2XSE_STATE_INIT:
		localret = 0;
		break;
	case V2XSE_STATE_CONNECTED:
		*pApiRetVal = V2XSE_FAILURE_CONNECTED;
		break;
	case V2XSE_STATE_ACTIVATED:
		*pApiRetVal = V2XSE_FAILURE_ACTIVATED;
		break;
	}

	return localret;
}

/**
 *
 * @brief Utility function to verify system is not in init state
 *
 * This function verifies that the system is not in init state, and in case
 * of error it sets the API return code appropriately.
 *
 * @param pApiRetVal pointer to value that v2xSe API will return
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t enforceNotInitState(int32_t *pApiRetVal)
{
	int32_t localret = -1;

	if (v2xseState != V2XSE_STATE_INIT)
		localret = 0;
	else
		*pApiRetVal = V2XSE_DEVICE_NOT_CONNECTED;

	return localret;
}

/**
 *
 * @brief Utility function to verify system is in activated state
 *
 * This function verifies that the system is in activated state, and in case
 * of error it sets the API return or status code appropriately.
 *
 * @param pStatusCode status code pointer to check
 * @param pApiRetVal pointer to value that v2xSe API will return
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t enforceActivatedState(TypeSW_t *pStatusCode, int32_t *pApiRetVal)
{
	int32_t localret = -1;

	switch (v2xseState) {
	case V2XSE_STATE_ACTIVATED:
		localret = 0;
		break;
	case V2XSE_STATE_CONNECTED:
		*pStatusCode = V2XSE_INACTIVE_CHANNEL;
		break;
	default:
		*pApiRetVal = V2XSE_DEVICE_NOT_CONNECTED;
		break;
	}

	return localret;
}

/**
 *
 * @brief Utility function to verify system is at security level 5
 *
 * This function verifies that the system is at security level 5, and in case
 * of error it sets the status code appropriately.
 *
 * @param pStatusCode status code pointer to check
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t enforceSecurityLevel5(TypeSW_t *pStatusCode)
{
	int32_t localret = -1;

	if (v2xseSecurityLevel != e_channelSecLevel_5)
		*pStatusCode = V2XSE_SECURITY_STATUS_NOT_SATISFIED;
	else
		localret = 0;

	return localret;
}
