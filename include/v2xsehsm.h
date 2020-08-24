
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
 * @file v2xsehsm.h
 *
 * @brief Header file for V2X SE to HSM adaptation layer
 *
 */

#ifndef V2XSEHSM_H
#define V2XSEHSM_H

#include "trace.h"
#include "v2xSe.h"
#include "hsm/hsm_api.h"
#include "hsmMISSING.h"
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
/** CN V2X applet selected */
#define V2XSE_APP_CN	2

/** Filesystem path to store nvm data */
#define COMMON_STORAGE_PATH "/etc/v2x_hsm_adaptation/"
/** Filesystem path to store generic data */
#define GENERIC_STORAGE_PATH COMMON_STORAGE_PATH"/genericStorage/"
/** Filesystem path to store data for US applet */
#define US_NVM_VAR_PATH COMMON_STORAGE_PATH"/US/"
/** Filesystem path to store data for EU applet */
#define EU_NVM_VAR_PATH COMMON_STORAGE_PATH"/EU/"
/** Filesystem path to store data for CN applet */
#define CN_NVM_VAR_PATH COMMON_STORAGE_PATH"/CN/"

/** Number of slots for generic data and key storage */
#define NUM_STORAGE_SLOTS	12800

extern uint8_t	v2xseState;
extern appletSelection_t v2xseAppletId;

extern hsm_hdl_t hsmSessionHandle;
extern hsm_hdl_t hsmKeyStoreHandle;
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

extern uint32_t activatedKeyHandle;
extern hsm_signature_scheme_id_t activatedSigScheme;

extern const uint8_t serialNumber[V2XSE_SERIAL_NUMBER];

/** Keystore identifier */
#define MAGIC_KEYSTORE_IDENTIFIER	0x87131966
/** Keystore nonce */
#define MAGIC_KEYSTORE_NONCE		0x75A8CC6D
/** Number of expected keystore updates in product lifetime - set to max */
#define MAX_KEYSTORE_UPDATES		0
/*
 * Keystore layout (groups):
 * 0: EU, US & CN MA keys
 * 1 to 128: EU RT keys
 * 129 to 256: EU BA keys
 * 257 to 384: US RT keys
 * 385 to 512: US BA keys
 * 513 to 640: CN RT keys
 * 641 to 768: CN BA keys
 * 769 to 1023: Generic data (not yet implemented in keystore)
 */
/** Keystore group used for MA keys */
#define MA_KEY_GROUP		0
/** Keystore group offset for EU RT keys */
#define EU_RT_GROUP_OFFSET	1
/** Keystore group offset for EU BA keys */
#define EU_BA_GROUP_OFFSET	129
/** Keystore group offset for US RT keys */
#define US_RT_GROUP_OFFSET	257
/** Keystore group offset for US BA keys */
#define US_BA_GROUP_OFFSET	385
/** Keystore group offset for CN RT keys */
#define CN_RT_GROUP_OFFSET  513
/** Keystore group offset for CN BA keys */
#define CN_BA_GROUP_OFFSET  641
/** Keystore group offset for generic data storage */
#define DATA_GROUP_OFFSET	769
/** Number of RT/BA key groups */
#define KEYGROUP_SIZE		128
/** First EU key group */
#define EU_KEYGROUP_START	1
/** First US key group */
#define US_KEYGROUP_START	257
/** First CN key group */
#define CN_KEYGROUP_START   513
/** Offset from RT to BA key groups */
#define BA_KEYGROUP_OFFSET	128
/** Number of keys per group */
#define KEYS_PER_GROUP		71

/** Priority of session opened with HSM */
#define HSM_SESSION_PRIORITY	0
/** Operating mode for session opened with HSM */
#define HSM_OPERATING_MODE	0

/** Required size for ECIES message for hsm */
#define HSM_ECIES_MESSAGE_SIZE	16
/** Required size for ECIES vector for hsm */
#define HSM_ECIES_VECTOR_SIZE	96

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

/**
 * This structure described the possible key usages, which determine the
 * flags used to create the key.  It can be:
 *  - RT_KEY - run time key
 *  - BA_KEY - base key
 *  - MA_KEY - module authentication
 */
typedef enum {
	RT_KEY,
	BA_KEY,
	MA_KEY
} keyUsage_t;

/**
 * This structure describes the two options possible when generating a
 * new key:
 *  - CREATE_KEY generates a new key in the key store
 *  - UPDATE_KEY updates an existing key in the key store
 */
typedef enum {
	CREATE_KEY,
	UPDATE_KEY
} genKeyAction_t;

hsm_key_type_t convertCurveId(TypeCurveId_t curveId);
int32_t is256bitCurve(hsm_key_type_t keyType);
int32_t setupDefaultStatusCode(TypeSW_t *pStatusCode);
int32_t enforceInitState(int32_t *pApiRetVal);
int32_t enforceNotInitState(int32_t *pApiRetVal);
int32_t enforceActivatedState(TypeSW_t *pStatusCode, int32_t *pApiRetVal);
int32_t keyLenFromCurveID(TypeCurveId_t curveID);
int32_t sigLenFromHashLen(TypeHashLength_t hashLength);
hsm_key_group_t getKeyGroup(keyUsage_t keyUsage, TypeRtKeyId_t keyId);
int32_t deleteRtKey(TypeRtKeyId_t rtKeyId);
int32_t deleteBaKey(TypeBaseKeyId_t baKeyId);
int32_t deleteHsmKey(uint32_t keyHandle, hsm_key_type_t keyType,
						hsm_key_group_t group);
int32_t getHsmPubKey(uint32_t keyHandle, hsm_key_type_t keyType,
		uint16_t pubKeySize, uint8_t *pPubKey);
void convertPublicKeyToV2xseApi(hsm_key_type_t keyType,
					TypePublicKey_t *pPublicKeyPlain);

#endif
