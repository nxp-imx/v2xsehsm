
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
 * @file v2xsehsm.h
 *
 * @brief Header file for V2X SE to HSM adaptation layer
 *
 */

#ifndef V2XSEHSM_H
#define V2XSEHSM_H

#include "v2xseapi.h"
#include "hsmstub.h"
#include "version.h"

/** Init state: not connected to SE */
#define V2XSE_STATE_INIT	0
/** Connected state: connected to JavaCard manager (no functionality)*/
#define V2XSE_STATE_CONNECTED	1
/** Activated state: connected to HSM, ready for V2X operations */
#define V2XSE_STATE_ACTIVATED	2

/** US V2X applet selected */
#define V2XSE_APP_US	0
/** EU V2X applet selected */
#define V2XSE_APP_EU	1

/** Filesystem path to store nvm data */
#define COMMON_STORAGE_PATH "/etc/v2x_hsm_adaptation/"
/** Filesystem path to store generic data */
#define GENERIC_STORAGE_PATH COMMON_STORAGE_PATH"/genericStorage/"
/** Filesystem path to store data for US applet */
#define US_NVM_VAR_PATH COMMON_STORAGE_PATH"/US/"
/** Filesystem path to store data for EU applet */
#define EU_NVM_VAR_PATH COMMON_STORAGE_PATH"/EU/"

/** Number of slots for generic data and key storage */
#define NUM_STORAGE_SLOTS	10000

extern uint8_t	v2xseState;
extern appletSelection_t v2xseAppletId;

extern hsm_hdl_t hsmSessionHandle;
extern hsm_hdl_t hsmKeyMgmtHandle;
extern hsm_hdl_t hsmCipherHandle;
extern hsm_hdl_t hsmSigGenHandle;

extern uint8_t	v2xsePhase;
extern const char* appletVarStoragePath;
extern uint32_t maKeyHandle;
extern TypeCurveId_t maCurveId;
extern uint32_t rtKeyHandle[NUM_STORAGE_SLOTS];
extern TypeCurveId_t rtCurveId[NUM_STORAGE_SLOTS];
extern uint32_t baKeyHandle[NUM_STORAGE_SLOTS];
extern TypeCurveId_t baCurveId[NUM_STORAGE_SLOTS];

extern const char usVarStorage[];
extern const char euVarStorage[];

extern uint32_t preparedKeyHandle;

extern const uint8_t serialNumber[V2XSE_SERIAL_NUMBER];

/** Keystore identifier for US applet keystore */
#define MAGIC_KEYSTORE_IDENTIFIER_US	0x13196687
/** Keystore nonce for US applet keystore */
#define MAGIC_KEYSTORE_NONCE_US	0xFA32D21E
/** Keystore identifier for EU applet keystore */
#define MAGIC_KEYSTORE_IDENTIFIER_EU	0x87131966
/** Keystore nonce for EU applet keystore */
#define MAGIC_KEYSTORE_NONCE_EU	0x75A8CC6D
/** Number of expected keystore updates in product lifetime */
#define MAX_KEYSTORE_UPDATES		0xffff

/** Priority of session opened with HSM */
#define HSM_SESSION_PRIORITY	0
/** Operating mode for session opened with HSM */
#define HSM_OPERATING_MODE	0

uint16_t convertCurveId(TypeCurveId_t curveId);
int is256bitCurve(uint32_t keyType);

/** Abort function (return) if pHsmStatusCode is NULL */
#define VERIFY_STATUS_CODE_PTR() do {				\
	if (!pHsmStatusCode)					\
		return V2XSE_FAILURE;				\
} while (0)

/** Abort function (return) if not in init state */
#define ENFORCE_STATE_INIT() do {				\
	if (v2xseState != V2XSE_STATE_INIT) {			\
		if (v2xseState == V2XSE_STATE_CONNECTED)	\
			return V2XSE_FAILURE_CONNECTED;		\
		if (v2xseState == V2XSE_STATE_ACTIVATED)	\
			return V2XSE_FAILURE_ACTIVATED;		\
		return V2XSE_FAILURE;				\
	}							\
} while (0)

/** Abort function (return) if currently in init state */
#define ENFORCE_STATE_NOT_INIT() do {				\
	if (v2xseState == V2XSE_STATE_INIT) {			\
		if (pHsmStatusCode)				\
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;\
		return V2XSE_DEVICE_NOT_CONNECTED;		\
	}							\
} while (0)

/** Abort function (return) if not in activated state */
#define ENFORCE_STATE_ACTIVATED() do {				\
	if (v2xseState != V2XSE_STATE_ACTIVATED) {		\
		if (pHsmStatusCode)				\
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;\
		return V2XSE_DEVICE_NOT_CONNECTED;		\
	}							\
} while (0)

/** Abort function (return) if ptr is NULL */
#define ENFORCE_POINTER_NOT_NULL(ptr) do {			\
	if (!ptr) {						\
		if (pHsmStatusCode)				\
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;\
		return V2XSE_FAILURE;				\
	}							\
} while (0)

/** Abort function (return) if not in normal operating phase */
#define ENFORCE_NORMAL_OPERATING_PHASE() do {			\
	if (v2xsePhase != V2XSE_NORMAL_OPERATING_PHASE) {	\
		if (pHsmStatusCode)				\
			*pHsmStatusCode = V2XSE_UNDEFINED_ERROR;\
		return V2XSE_FAILURE;				\
	}							\
} while (0)

/**
 * This structure describes the format that the hsm uses to encode
 * public keys for 256 bit curves
 */
typedef struct
{
	/** X coordinate of public key */
	uint8_t x[V2XSE_256_EC_PUB_KEY_XY_SIZE];
	/** Y coordinate of public key */
	uint8_t y[V2XSE_256_EC_PUB_KEY_XY_SIZE];
} hsmPubKey256_t;

/**
 * This structure describes the format that the hsm uses to encode
 * public keys for 384 bit curves
 */
typedef struct
{
	/** X coordinate of public key */
	uint8_t x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	/** Y coordinate of public key */
	uint8_t y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
} hsmPubKey384_t;

/**
 * This structure describes the format that the hsm uses to encode
 * signatures for 256 bit curves
 */
typedef struct
{
	/** R component of signature */
	uint8_t r[V2XSE_256_EC_R_SIGN];
	/** S component of signature */
	uint8_t s[V2XSE_256_EC_S_SIGN];
	/** Ry[0] point of signature */
	uint8_t Ry;
} hsmSignature256_t;

/**
 * This structure describes the format that the hsm uses to encode
 * signatures for 384 bit curves
 */
typedef struct
{
	/** R component of signature */
	uint8_t r[V2XSE_384_EC_R_SIGN];
	/** S component of signature */
	uint8_t s[V2XSE_384_EC_S_SIGN];
	/** Ry[0] point of signature */
	uint8_t Ry;
} hsmSignature384_t;

#endif
