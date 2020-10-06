
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
 * @file v2xSe.h
 *
 * @brief Header file for V2X SE public API
 *
 */

#ifndef V2XSE_H
#define V2XSE_H

#include <stdint.h>

/* Return codes for V2X SE API calls */
/** Successful execution */
#define V2XSE_SUCCESS			0
/** Generic failure */
#define V2XSE_FAILURE			-1
/** Cannot connect to required service */
#define V2XSE_DEVICE_NOT_CONNECTED	-2
/** Command not supported in connected state */
#define V2XSE_FAILURE_CONNECTED		-3
/** Command not supported in activated state */
#define V2XSE_FAILURE_ACTIVATED		-4
/** Command not supported in init state */
#define V2XSE_FAILURE_INIT		-5
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_FAILURE_RMAC		-6
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_FAILURE_KEY_FILE		-7

/* Extended return codes (passed in pHsmStatusCode) */
/** No specific error information */
#define V2XSE_UNDEFINED_ERROR			0x0000u
/** Command completed successfully */
#define V2XSE_NO_ERROR				0x9000u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_AUTHENTICATION_FAILED		0x6300u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_PROCESS_COMP_WITH_WARNING		0x6310u
/** Internal error, NVM unchanged */
#define V2XSE_NVRAM_UNCHANGED			0x6400u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_MEMORY_FAILURE			0x6581u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_RESTRICTED_MODE			0x66A5u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_WRONG_LENGTH			0x6700u
/** Logical channel to required applet not active */
#define V2XSE_INACTIVE_CHANNEL			0x6881u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SECMSG_NOT_SUPPORTED		0x6882u
/** Security level not sufficient for command */
#define V2XSE_SECURITY_STATUS_NOT_SATISFIED	0x6982u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_CONDITIONS_NOT_SATISFIED		0x6985u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SSD_LOCKED			0x6999u
/** Invalid parameter provided to command */
#define V2XSE_WRONG_DATA			0x6A80u
/** Function not supported in current state */
#define V2XSE_FUNC_NOT_SUPPORTED		0x6A81u
/** Requested applet not found */
#define V2XSE_APP_MISSING			0x6A82u
/** Nvm memory full */
#define V2XSE_FILE_FULL				0x6A84u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_INCORRECT_P1P2			0x6A86u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_REF_DATA_NOT_FOUND		0x6A88u
/** Instruction not supported */
#define V2XSE_INS_NOT_SUPPORTED			0x6D00u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_CLA_NOT_SUPPORTED			0x6E00u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_NO_PRECISE_DIAGNOSIS		0x6F00u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_KEY_AGREEMENT_ERROR		0x6F01u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_TAG_CHECK_ERROR			0x6F02u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SCP03_KEYFILE_ERROR		0x6F03u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SCP03_SESSIONKEY_ERROR		0x6F04u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SCP03_CARDCRYPTO_ERROR		0x6F05u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_SCP03_HOSTCRYPTO_ERROR		0x6F06u
 /** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_AUTH_CTR_ERROR			0x6F07u
/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_MAX_AUTH_COUNTER_VALUE		0x00FFF000

/** NIST P256 ECC */
#define V2XSE_CURVE_NISTP256	0u
/** Brainpool R1 256 ECC */
#define V2XSE_CURVE_BP256R1	1u
/** Brainpool T1 256 ECC */
#define V2XSE_CURVE_BP256T1	2u
/** NIST P384 ECC */
#define V2XSE_CURVE_NISTP384	3u
/** Brainpool R1 384 ECC */
#define V2XSE_CURVE_BP384R1	4u
/** Brainpool T1 384 ECC */
#define V2XSE_CURVE_BP384T1	5u
/** SM2 256 ECC */
#define V2XSE_CURVE_SM2_256	64u

/** AES 128 SYMMETRIC KEY */
#define V2XSE_SYMMK_AES_128	100u
/** AES 192 SYMMETRIC KEY */
#define V2XSE_SYMMK_AES_192	101u
/** AES 256 SYMMETRIC KEY */
#define V2XSE_SYMMK_AES_256	103u
/** SM4 128 SYMMETRIC KEY */
#define V2XSE_SYMMK_SM4_128	104u

/** AES ECB */
#define V2XSE_ALGO_AES_ECB 0u
/** AES CBC */
#define V2XSE_ALGO_AES_CBC 1u
/** AES CCM */
#define V2XSE_ALGO_AES_CCM 2u
/** SM4 ECB */
#define V2XSE_ALGO_SM4_ECB 3u
/** SM4 CBC */
#define V2XSE_ALGO_SM4_CBC 4u

/** Do not copy public key on return */
#define V2XSE_RSP_WITHOUT_PUBKEY	0u
/** Copy public key on return */
#define V2XSE_RSP_WITH_PUBKEY		1u

/** No attacks in attack log */
#define V2XSE_ATTACK_CNT_ZERO		0u
/** One or more attacks in attack log */
#define V2XSE_ATTACK_CNT_NON_ZERO	1u

/** Size in bytes of 256 bits of data */
#define V2XSE_INT256_SIZE		32u

/** Size in bytes of public key for 256 bit curve */
#define V2XSE_256_EC_PUB_KEY		64u
/** Size in bytes of 256 bit curve public key X or Y component */
#define V2XSE_256_EC_PUB_KEY_XY_SIZE	32u
/** Size in bytes of 256 bit curve compressed public key */
#define V2XSE_256_EC_COMP_PUB_KEY	33u
/** Size in bytes of 256 bit curve signature r component */
#define V2XSE_256_EC_R_SIGN		32u
/** Size in bytes of 256 bit curve signature s component */
#define V2XSE_256_EC_S_SIGN		32u
/** Size in bytes of 256 bit curve compressed signature */
#define V2XSE_256_EC_COMP_SIGN		65u
/** Size in bytes of 256 bit HASH */
#define V2XSE_256_EC_HASH_SIZE		32u

/** Maximum private key size in bytes */
#define V2XSE_MAX_PRIVATE_KEY_SIZE	48u

/** Size in bytes of public key for 384 bit curve */
#define V2XSE_384_EC_PUB_KEY		96u
/** Size in bytes of 384 bit curve public key X or Y component */
#define V2XSE_384_EC_PUB_KEY_XY_SIZE	48u
/** Size in bytes of 384 bit curve compressed public key */
#define V2XSE_384_EC_COMP_PUB_KEY	49u
/** Size in bytes of 384 bit curve signature r component */
#define V2XSE_384_EC_R_SIGN		48u
/** Size in bytes of 384 bit curve signature s component */
#define V2XSE_384_EC_S_SIGN		48u
/** Size in bytes of 384 bit curve compressed signature */
#define V2XSE_384_EC_COMP_SIGN		97u
/** Size in bytes of 384 bit HASH */
#define V2XSE_384_EC_HASH_SIZE		48u

/** Size in bytes of version information */
#define V2XSE_VERSION_SIZE		3u
/** Maximum size in bytes of random numbers */
#define V2XSE_MAX_RND_NUM_SIZE		239u
/** Size in bytes of platform identity information */
#define V2XSE_PLATFORM_IDENTITY		16u
/** Size in bytes of platform configuration information */
#define V2XSE_PLATFORM_CONFIGURATION	4u
/** Size in bytes of serial number */
#define V2XSE_SERIAL_NUMBER		24u
/** Size in bytes of attack log */
#define V2XSE_ATTACK_LOG		1419u

/** Maximum encrypted data size in bytes for ECIES and CIPHER */
#define V2XSE_MAX_VCT_DATA_SIZE		169u
/** Maximum plain text data size in bytes for ECIES and CIPHER */
#define V2XSE_MAX_MSG_SIZE		97u
/** Maximum KDF P1 parameter size in bytes for ECIES */
#define V2XSE_MAX_KDF_PARAMP1_SIZE	32u
/** Maximum MAC P2 parameter size in bytes for ECIES */
#define V2XSE_MAX_MAC_PARAMP2_SIZE	32u
/** Maximum MAC size in bytes for ECIES */
#define V2XSE_MAX_MAC_SIZE		32u

/** Maximum size of generic data */
#define V2XSE_MAX_DATA_SIZE_GSA 239u
/** Minimum size of generic data */
#define V2XSE_MIN_DATA_SIZE_GSA 1u

/** Size in bytes of SM2 identifier */
#define V2XSE_SM2_ID_SIZE 16u

/** Size in bytes of SM2 ZA */
#define V2XSE_SM2_ZA_SIZE 32u

/** Key injection phase - unused in adaptation layer */
#define V2XSE_KEY_INJECTION_PHASE	0u
/** Normal operating phase */
#define V2XSE_NORMAL_OPERATING_PHASE	1u

/** Unused in adaptation layer - added for legacy compilation */
#define V2XSE_MAX_TX_RX_SIZE		261

/** Size in bytes of cipher initialization vector */
#define V2XSE_MAX_IV_SIZE 16u


/******************************************************************************
 * TYPE DEFINITIONS
 ******************************************************************************/

/** Nvm slot for runtime key */
typedef uint16_t TypeRtKeyId_t;

/** SW status code */
typedef uint16_t TypeSW_t;

/** Length of hash in bytes */
typedef uint8_t TypeHashLength_t;

/** Flag indicating if signature was calculated using low latency method */
typedef uint8_t TypeLowlatencyIndicator_t;

/** ECC curve identifier */
typedef uint8_t TypeCurveId_t;

/** Symmetric key type identifier */
typedef uint8_t TypeSymmetricKeyId_t;

/** Cipher algo type */
typedef uint8_t TypeAlgoId_t;

/** Nvm slot for base key */
typedef uint16_t TypeBaseKeyId_t;

/** Length in bytes */
typedef uint8_t TypeLen_t;

/** Flag indicating whether public key should be returned */
typedef uint8_t TypePubKeyOut_t;

/** Nvm slot for generic data */
typedef uint16_t TypeGsDataIndex_t;

/**
 * This structure holds the X and Y coordinates of a public key
 * This structure is used for both 256 and 384 bit elliptic curves
 */
typedef struct
{
	/** X coordinate of public key */
	uint8_t x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	/** Y coordinate of public key */
	uint8_t y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
} TypePublicKey_t;

/**
 * This structure holds the r, Ry[0] and s components of a signature
 * This structure is used for both 256 and 384 bit elliptic curves
 */
typedef struct
{
	/** R component of signature */
	uint8_t r[V2XSE_384_EC_R_SIGN];
	/** Ry[0] point of signature */
	uint8_t Ry;
	/** S component of signature */
	uint8_t s[V2XSE_384_EC_S_SIGN];
} TypeSignature_t;

/** This structure holds the hash data used for signature */
typedef struct
{
	/** Hash data for signature */
	uint8_t data[V2XSE_384_EC_HASH_SIZE];
} TypeHash_t;

/** This structure holds the data used for deriving runtime private key */
typedef struct
{
	/** Hash data for key derivation */
	uint8_t data[V2XSE_INT256_SIZE];
} TypeInt256_t;

/** This structure holds software version info */
typedef struct
{
	/** Software version info */
	uint8_t data[V2XSE_VERSION_SIZE];
} TypeVersion_t;

/** This structure holds a random number */
typedef struct
{
	/** Random number data */
	uint8_t data[V2XSE_MAX_RND_NUM_SIZE];
} TypeRandomNumber_t;

/** This structure holds ECIES encrypted data */
typedef struct
{
	/** Encrypted data */
	uint8_t data[V2XSE_MAX_VCT_DATA_SIZE];
} TypeVCTData_t;

/** This structure holds plain text data */
typedef struct
{
	/** Plain text data */
	uint8_t data[V2XSE_MAX_MSG_SIZE];
} TypePlainText_t;

/** This structure holds SM2 identifier */
typedef struct
{
	/** SM2 identifier data */
	uint8_t data[V2XSE_SM2_ID_SIZE];
} TypeSM2Identifier_t;

/** This structure holds SM2 ZA */
typedef struct
{
	/** SM2 ZA data */
	uint8_t data[V2XSE_SM2_ZA_SIZE];
} TypeSM2ZA_t;

/** This structure holds parameters for ECIES-Encrypt functions */
typedef struct
{
	/** Recipient's public key used for encryption */
	TypePublicKey_t *  pEccPublicKey;

	/** Curve ID associated with public key, valid range is 0-2 */
	TypeCurveId_t  curveId;

	/** Length of parameter KDFParamP1, valid range is 0 to 32 bytes */
	uint8_t kdfParamP1Len;  //

	/** Parameter P1 for the key derivation function of ECIES */
	uint8_t kdfParamP1[V2XSE_MAX_KDF_PARAMP1_SIZE];

	/** Length of the MAC, valid range is 8 to 32 bytes */
	uint8_t macLen;

	/** Length of parameter MacParamP2, valid range is 0 to 32 bytes */
	uint8_t macParamP2Len;

	/** Parameter P2 for the MAC function of ECIES */
	uint8_t macParamP2[V2XSE_MAX_MAC_PARAMP2_SIZE];

	/** Length of message to be encrypted */
	TypeLen_t  msgLen;

	/** Message data to encrypt */
	TypePlainText_t *  pMsgData;
} TypeEncryptEcies_t;

/** This structure holds parameters for ECIES-Decrypt functions */
typedef struct
{
	/** Length of parameter KDFParamP1, valid range is 0 to 32 bytes */
	uint8_t kdfParamP1Len;

	/** Parameter P1 for the key derivation function of ECIES */
	uint8_t kdfParamP1[V2XSE_MAX_KDF_PARAMP1_SIZE];

	/** Length of the MAC, valid range is 8 to 32 bytes */
	uint8_t macLen;

	/** Length of parameter MacParamP2, valid range is 0 to 32 bytes */
	uint8_t macParamP2Len;

	/** Parameter P2 for the MAC function of ECIES */
	uint8_t macParamP2[V2XSE_MAX_MAC_PARAMP2_SIZE];

	/** Length of encrypted data, valid range is 73 to 169 bytes */
	TypeLen_t  vctLen;

	/**
	 * Encrypted data, with:
	 * - V-Ephimeral public key
	 * - C-Cipher text
	 * - T-Tag
	 */
	TypeVCTData_t *  pVctData;
} TypeDecryptEcies_t;

/** This structure holds parameters for SM2 ECES-Encrypt functions */
typedef struct
{
	/** Recipient's public key used for encryption */
	TypePublicKey_t *  pEccPublicKey;

	/** Curve ID associated with public key, valid value is 6 */
	TypeCurveId_t  curveId;

	/** Length of message to be encrypted */
	TypeLen_t  msgLen;

	/** Message data to encrypt */
	TypePlainText_t *  pMsgData;
} TypeEncryptSm2Eces_t;

/** This structure holds parameters for SM2 ECES-Decrypt functions */
typedef struct
{
	/** Length of encrypted data*/
	TypeLen_t  encryptedDataSize;

	/** Encrypted data */
	uint8_t *  encryptedData;
} TypeDecryptSm2Eces_t;

/**
 * Overhead size in bytes for SM2 ECES encryption.
 * The encrypted buffer must be the size of the input message + this overhead,
 * rounded up to 32 bits.
 */
#define SM2_PKE_OVERHEAD (97u)

/** This structure holds parameters for CIPHER-Encrypt functions */
typedef struct
{
	/** Cipher initialization vector data */
	uint8_t iv[V2XSE_MAX_IV_SIZE];

	/** Length of initialization vector */
	TypeLen_t  ivLen;

	/** Algo to be used for the cipher operation */
	TypeAlgoId_t  algoId;

	/** Length of message to be encrypted */
	TypeLen_t  msgLen;

	/** Message data to encrypt */
	TypePlainText_t *pMsgData;
} TypeEncryptCipher_t;

/** This structure holds parameters for CIPHER-Decrypt functions */
typedef struct
{
	/** Cipher initialization vector data */
	uint8_t iv[V2XSE_MAX_IV_SIZE];

	/** Length of initialization vector */
	TypeLen_t  ivLen;

	/** Algo to be used for the cipher operation */
	TypeAlgoId_t  algoId;

	/** Length of encrypted data */
	TypeLen_t  vctLen;

	/** Encrypted data */
	TypeVCTData_t *pVctData;
} TypeDecryptCipher_t;

/** This structure holds information of supported features of SE */
typedef struct
{
	/** Maximum Runtime keys supported by applet*/
	uint16_t maxRtKeysAllowed;

	/** Maximum Base keys supported by applet*/
	uint16_t maxBaKeysAllowed;

	/** Maximum number of prepared values supported */
	uint8_t numPreparedVal;

	/** FIPS approved mode indicator */
	uint8_t fipsModeIndicator;

	/** Proof of possession support indicator */
	uint8_t proofOfPossession;

	/** Rollback protection status indicator */
	uint8_t rollBackProtection;

	/** Key derivation support indicator */
	uint8_t rtKeyDerivation;

	/** Active Applet Instance indicator */
	uint8_t eciesSupport;

	/** SM2 ECES support indicator */
	uint8_t sm2EcesSupport;

	/** Maximum number of data slots supported by Generic storage applet */
	uint16_t maxDataSlots;

	/** Cipher support indicator */
	uint8_t cipherSupport;
} TypeInformation_t;

/** This structure holds the Platform identification information */
typedef struct
{
	/** Platform indentification information */
	uint8_t data[V2XSE_PLATFORM_IDENTITY];
} TypePlatformIdentity_t;

/** This structure holds the Platform Configuration information */
typedef struct
{
	/** Platform configuration data */
	uint8_t data[V2XSE_PLATFORM_CONFIGURATION];
} TypePlatformConfiguration_t;

/** This structure holds the Serial number of the SE chip */
typedef struct
{
	/** SE chip serial number */
	uint8_t data[V2XSE_SERIAL_NUMBER];
} TypeChipInformation_t;

/** This structure holds the Attack log */
typedef struct
{
	/** Flag indicating whether attacks have been logged */
	uint8_t currAttackCntrStatus;
	/** Length of attack log contents */
	uint32_t len;
	/** Attack log data */
	uint8_t data[V2XSE_ATTACK_LOG];
} TypeAttackLog_t;

/**
 * This enum specifies applets that can be selected when activating the SE,
 * and applet classes used when querying version info.
 */
typedef enum
{
	/** Select EU instance of V2X applet during activation */
	e_EU,
	/** Select US instance of V2X applet during activation */
	e_US,
	/** Select EU V2X and data storage applets during activation */
	e_EU_AND_GS,
	/** Select US V2X and data storage applets during activation */
	e_US_AND_GS,
	/** Query V2X applet version */
	e_V2X,
	/** Query generic storage applet version */
	e_GS,
	/** Select CN instance of V2X applet during activation */
	e_CN,
	/** Select CN V2X and data storage applets during activation */
	e_CN_AND_GS
} appletSelection_t;

/**
 *  This enumeration specifies the security level used to communicate with
 * the SE.
 */
typedef enum
{
	/** C-MAC */
	e_channelSecLevel_1 = 1,
	/** C-DECRYPTION and C-MAC */
	e_channelSecLevel_2 = 2,
	/** C-MAC and R-MAC */
	e_channelSecLevel_3 = 3,
	/** C-DECRYPTION, C-MAC and R-MAC */
	e_channelSecLevel_4 = 4,
	/** C-DECRYPTION, R-ENCRYPTION, C-MAC and R-MAC */
	e_channelSecLevel_5 = 5
} channelSecLevel_t;


int32_t v2xSe_connect(void);
int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_activateWithSecurityLevel(appletSelection_t appletId,
        channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_reset(void);
int32_t v2xSe_deactivate(void);
int32_t v2xSe_disconnect(void);
int32_t v2xSe_generateMaEccKeyPair(TypeCurveId_t curveId,
        TypeSW_t *pHsmStatusCode, TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_getMaEccPublicKey(TypeSW_t *pHsmStatusCode,
        TypeCurveId_t *pCurveId,TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_createMaSign(TypeHashLength_t hashLength, TypeHash_t *pHashValue,
        TypeSW_t *pHsmStatusCode, TypeSignature_t *pSignature);
int32_t v2xSe_generateRtEccKeyPair(TypeRtKeyId_t rtKeyId,
        TypeCurveId_t curveId, TypeSW_t *pHsmStatusCode,
        TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_deleteRtEccPrivateKey(TypeRtKeyId_t rtKeyId,
        TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getRtEccPublicKey(TypeRtKeyId_t rtKeyId,
        TypeSW_t *pHsmStatusCode, TypeCurveId_t *pCurveId,
        TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_createRtSignLowLatency(TypeHash_t *pHashValue,
        TypeSW_t *pHsmStatusCode, TypeSignature_t *pSignature,
        TypeLowlatencyIndicator_t *pFastIndicator);
int32_t v2xSe_createRtSign(TypeRtKeyId_t rtKeyId, TypeHash_t *pHashValue,
        TypeSW_t *pHsmStatusCode, TypeSignature_t *pSignature);
int32_t v2xSe_generateBaEccKeyPair(TypeBaseKeyId_t baseKeyId,
        TypeCurveId_t curveId, TypeSW_t *pHsmStatusCode,
        TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_deleteBaEccPrivateKey(TypeBaseKeyId_t baseKeyId,
        TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getBaEccPublicKey(TypeBaseKeyId_t baseKeyId,
        TypeSW_t *pHsmStatusCode, TypeCurveId_t *pCurveId,
        TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_createBaSign(TypeBaseKeyId_t baseKeyId,
        TypeHashLength_t hashLength, TypeHash_t *pHashValue,
        TypeSW_t *pHsmStatusCode, TypeSignature_t *pSignature);
int32_t v2xSe_deriveRtEccKeyPair(TypeBaseKeyId_t baseKeyId,
        TypeInt256_t *pFvSign, TypeInt256_t *pRvij, TypeInt256_t *pHvij,
        TypeRtKeyId_t rtKeyId, TypePubKeyOut_t returnPubKey,
        TypeSW_t *pHsmStatusCode, TypeCurveId_t *pCurveID,
        TypePublicKey_t *pPublicKeyPlain);
int32_t v2xSe_generateRtSymmetricKey(TypeRtKeyId_t rtKeyId,
        TypeSymmetricKeyId_t symmetricKeyId, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_deleteRtSymmetricKey(TypeRtKeyId_t rtKeyId,
        TypeSW_t *pHsmStatusCode);
int32_t v2xSe_activateRtKeyForSigning(TypeRtKeyId_t rtKeyId,
        TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getAppletVersion(appletSelection_t appletType,
        TypeSW_t *pHsmStatusCode, TypeVersion_t *pVersion);
int32_t v2xSe_getRandomNumber(TypeLen_t length, TypeSW_t *pHsmStatusCode,
        TypeRandomNumber_t *pRandomNumber);
int32_t v2xSe_getSeInfo(TypeSW_t *pHsmStatusCode, TypeInformation_t *pInfo);
int32_t v2xSe_getCryptoLibVersion(TypeVersion_t *pVersion);
int32_t v2xSe_getPlatformInfo(TypeSW_t *pHsmStatusCode,
        TypePlatformIdentity_t *pPlatformIdentifier);
int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,
        TypePlatformConfiguration_t *pPlatformConfig);
int32_t v2xSe_getChipInfo(TypeSW_t *pHsmStatusCode,
        TypeChipInformation_t *pChipInfo);
int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,
        TypeAttackLog_t *pAttackLog);
int32_t v2xSe_encryptUsingEcies(TypeEncryptEcies_t *pEciesData,
        TypeSW_t *pHsmStatusCode, TypeLen_t *pVctLen,
        TypeVCTData_t *pVctData);
int32_t v2xSe_decryptUsingRtEcies(TypeRtKeyId_t rtKeyId,
        TypeDecryptEcies_t *pEciesData, TypeSW_t *pHsmStatusCode,
        TypeLen_t *pMsgLen, TypePlainText_t *pMsgData);
int32_t v2xSe_decryptUsingMaEcies(TypeDecryptEcies_t *pEciesData,
        TypeSW_t *pHsmStatusCode, TypeLen_t *pMsgLen,
        TypePlainText_t *pMsgData);
int32_t v2xSe_decryptUsingBaEcies(TypeBaseKeyId_t baseKeyId,
        TypeDecryptEcies_t *pEciesData, TypeSW_t *pHsmStatusCode,
        TypeLen_t *pMsgLen, TypePlainText_t *pMsgData);
int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID);
int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength);
int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen, uint16_t *pRxLen,
        uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length,
        uint8_t *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength,
        uint8_t *pData,TypeSW_t *pHsmStatusCode);
int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getRemainingNvm(uint32_t *pSize, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_endKeyInjection(TypeSW_t *pHsmStatusCode);
int32_t v2xSe_getSePhase(uint8_t *pPhaseInfo, TypeSW_t *pHsmStatusCode);

int32_t v2xSe_getKek(uint16_t keyType, uint8_t *pSignedMessage,
	uint16_t signedMessageLength, uint8_t *pKekPublicKey,
	uint16_t *pKekLength, TypeSW_t *pHsmStatusCode);
	/*
	 * TODO: remove references to KEK_TYPE_xxx flags and getKek() API
	 */
/** Flag to use KEK that is unique per device */
#define KEK_TYPE_UNIQUE	(0u)
/** Flag to use KEK that is common for all devices */
#define KEK_TYPE_COMMON	(1u)
int32_t v2xSe_createKek(uint8_t *pSignedMessage, uint16_t signedMessageLength,
	TypePublicKey_t *pInitiatorPublicKey, TypePublicKey_t *pResponderPublicKey,
	TypeRtKeyId_t kekId, TypeSW_t *pHsmStatusCode);
int32_t v2xSe_injectMaEccPrivateKey(TypeCurveId_t curveId,
	TypeSW_t *pHsmStatusCode, TypePublicKey_t *pPublicKeyPlain,
	uint8_t *pKeyData, uint16_t keyDataSize, TypeRtKeyId_t kekId);
int32_t v2xSe_injectRtEccPrivateKey(TypeRtKeyId_t rtKeyId,
	TypeCurveId_t curveId, TypeSW_t *pHsmStatusCode,
	TypePublicKey_t *pPublicKeyPlain, uint8_t *pKeyData,
	uint16_t keyDataSize, TypeRtKeyId_t kekId);
int32_t v2xSe_injectBaEccPrivateKey(TypeBaseKeyId_t baseKeyId,
	TypeCurveId_t curveId, TypeSW_t *pHsmStatusCode,
	TypePublicKey_t *pPublicKeyPlain, uint8_t *pKeyData,
	uint16_t keyDataSize, TypeRtKeyId_t kekId);

int32_t v2xSe_sm2_get_z(TypePublicKey_t pubKey, TypeSM2Identifier_t sm2_id,
	TypeSM2ZA_t *sm2_za);

int32_t v2xSe_encryptUsingSm2Eces(TypeEncryptSm2Eces_t *pSm2EcesData,
	TypeSW_t *pHsmStatusCode,
	TypeLen_t *pEncryptedDataSize, uint8_t *pEncryptedData);
int32_t v2xSe_decryptUsingRtSm2Eces(TypeRtKeyId_t rtKeyId,
	TypeDecryptSm2Eces_t *pSm2EcesData,
	TypeSW_t *pHsmStatusCode,
	TypeLen_t *pMsgLen, TypePlainText_t *pMsgData);
int32_t v2xSe_decryptUsingMaSm2Eces(TypeDecryptSm2Eces_t *pSm2EcesData,
	TypeSW_t *pHsmStatusCode,
	TypeLen_t *pMsgLen,
	TypePlainText_t *pMsgData);
int32_t v2xSe_decryptUsingBaSm2Eces(TypeBaseKeyId_t baseKeyId,
	TypeDecryptSm2Eces_t *pSm2EcesData,
	TypeSW_t *pHsmStatusCode,
	TypeLen_t *pMsgLen,
	TypePlainText_t *pMsgData);

int32_t v2xSe_encryptUsingRtCipher(TypeRtKeyId_t rtKeyId,
	TypeEncryptCipher_t *pCipherData, TypeSW_t *pHsmStatusCode,
	TypeLen_t *pVctLen, TypeVCTData_t *pVctData);
int32_t v2xSe_decryptUsingRtCipher(TypeRtKeyId_t rtKeyId,
	TypeDecryptCipher_t *pCipherData, TypeSW_t *pHsmStatusCode,
	TypeLen_t *pMsgLen, TypePlainText_t *pMsgData);
#endif
