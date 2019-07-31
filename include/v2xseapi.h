
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file v2xseapi.h
 *
 * @brief Header file for V2X SE public API
 *
 */

#ifndef V2XSEAPI_H
#define V2XSEAPI_H

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
#define V2XSE_FAILURE_INIT  -5


/* Extended return codes (passed in pHsmStatusCode) */
/** Command completed successfully */
#define V2XSE_NO_ERROR				0x9000u
/** Invalid parameter provided to command */
#define V2XSE_WRONG_DATA			0x6A80u
/** Nvm memory full */
#define V2XSE_FILE_FULL				0x6A84u
/** Internal error, NVM unchanged */
#define V2XSE_NVRAM_UNCHANGED			0x6400u
/** Security level not sufficient for command */
#define V2XSE_SECURITY_STATUS_NOT_SATISFIED	0x6982u
/** No specific error information */
#define V2XSE_UNDEFINED_ERROR			0x0000u
/** Function not supported in current state */
#define V2XSE_FUNC_NOT_SUPPORTED		0x6A81u
/** Requested applet not found */
#define V2XSE_APP_MISSING			0x6A82u
/** Logical channel to required applet not active */
#define V2XSE_INACTIVE_CHANNEL			0x6881u

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
//#define V2XSE_384_EC_COMP_SIGN 97u//in bytes

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

/** Maximum encrypted data size in bytes for ECIES */
#define V2XSE_MAX_VCT_DATA_SIZE		169u
/** Maximum plain text data size in bytes for ECIES */
#define V2XSE_MAX_MSG_SIZE		97u
/** Maximum KDF P1 parameter size in bytes for ECIES */
#define V2XSE_MAX_KDF_PARAMP1_SIZE	32u
/** Maximum MAC P2 parameter size in bytes for ECIES */
#define V2XSE_MAX_MAC_PARAMP2_SIZE	32u

/** Maximum size of generic data */
#define V2XSE_MAX_DATA_SIZE_GSA 239u
/** Minimum size of generic data */
#define V2XSE_MIN_DATA_SIZE_GSA 1u

/** Key injection phase */
#define V2XSE_KEY_INJECTION_PHASE	0u
/** Normal operating phase */
#define V2XSE_NORMAL_OPERATING_PHASE	1u

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

	/** Maximum number of data slots supported by Generic storage applet */
	uint16_t maxDataSlots;
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
	e_GS
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
#endif
