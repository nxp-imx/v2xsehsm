/*
   (c) NXP B.V. 2017. All rights reserved.

   Disclaimer
   1. The NXP Software/Source Code is provided to Licensee "AS IS" without any
      warranties of any kind. NXP makes no warranties to Licensee and shall not
      indemnify Licensee or hold it harmless for any reason related to the NXP
      Software/Source Code or otherwise be liable to the NXP customer. The NXP
      customer acknowledges and agrees that the NXP Software/Source Code is
      provided AS-IS and accepts all risks of utilizing the NXP Software under
      the conditions set forth according to this disclaimer.

   2. NXP EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING,
      BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
      FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY
      RIGHTS. NXP SHALL HAVE NO LIABILITY TO THE NXP CUSTOMER, OR ITS
      SUBSIDIARIES, AFFILIATES, OR ANY OTHER THIRD PARTY FOR ANY DAMAGES,
      INCLUDING WITHOUT LIMITATION, DAMAGES RESULTING OR ALLEGDED TO HAVE
      RESULTED FROM ANY DEFECT, ERROR OR OMMISSION IN THE NXP SOFTWARE/SOURCE
      CODE, THIRD PARTY APPLICATION SOFTWARE AND/OR DOCUMENTATION, OR AS A
      RESULT OF ANY INFRINGEMENT OF ANY INTELLECTUAL PROPERTY RIGHT OF ANY
      THIRD PARTY. IN NO EVENT SHALL NXP BE LIABLE FOR ANY INCIDENTAL,
      INDIRECT, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL DAMAGES
      (INCLUDING LOST PROFITS) SUFFERED BY NXP CUSTOMER OR ITS SUBSIDIARIES,
      AFFILIATES, OR ANY OTHER THIRD PARTY ARISING OUT OF OR RELATED TO THE NXP
      SOFTWARE/SOURCE CODE EVEN IF NXP HAS BEEN ADVISED OF THE POSSIBILITY OF
      SUCH DAMAGES.

   3. NXP reserves the right to make changes to the NXP Software/Sourcecode any
      time, also without informing customer.

   4. Licensee agrees to indemnify and hold harmless NXP and its affiliated
      companies from and against any claims, suits, losses, damages,
      liabilities, costs and expenses (including reasonable attorney's fees)
      resulting from Licensee's and/or Licensee customer's/licensee's use of the
      NXP Software/Source Code.

 */

/*******************************************************************************
 *
 * \file v2xSe.h
 *
 * \author SANDEEP BB
 *
 * \version 3.7
 *
 * \brief   This file contains the API definition of the V2X Secure Element access library.
 *          This file must be included when using the library.
 *
 *
 *******************************************************************************/
#ifndef V2XSE_H_
#define V2XSE_H_


/******************************************************************************
 * INCLUDES
 *****************************************************************************/
#include <stdint.h>
#include "v2xSeCommTypes.h"


/******************************************************************************
 * DEFINES
 *****************************************************************************/

#define V2XSE_CURVE_NISTP256  0u
#define V2XSE_CURVE_BP256R1   1u
#define V2XSE_CURVE_BP256T1   2u
#define V2XSE_CURVE_NISTP384  3u
#define V2XSE_CURVE_BP384R1   4u
#define V2XSE_CURVE_BP384T1   5u

#define V2XSE_RSP_WITHOUT_PUBKEY 0u
#define V2XSE_RSP_WITH_PUBKEY 1u

#define V2XSE_ATTACK_CNT_ZERO 0u
#define V2XSE_ATTACK_CNT_NON_ZERO 1u

//Error Codes
#define V2XSE_NO_ERROR (0x9000u)// The function completed successfully.
#define V2XSE_CLA_NOT_SUPPORTED (0x6E00u)//The CLA value is not supported.
#define V2XSE_INS_NOT_SUPPORTED (0x6D00u)//The INS value is not supported.
#define V2XSE_INCORRECT_P1P2 (0x6A86u)//The value of parameter P1 or P2 is invalid.
#define V2XSE_WRONG_LENGTH (0x6700u)//The value of parameter Lc or Le is invalid.
#define V2XSE_WRONG_DATA (0x6A80u)//The data field of the command contains wrong data.
#define V2XSE_FILE_FULL (0x6A84u)//No more memory available.
#define V2XSE_NVRAM_UNCHANGED (0x6400u)//Internal execution error and the result is that the NVRAM is unchanged.
#define V2XSE_NO_PRECISE_DIAGNOSIS (0x6F00u)//Generic error when exception occurred but no precise diagnosis is available or when private key is not valid, for example when injected private key is out of the range
//("1 to n-1" where n is order of the elliptic curve)
//This error code should also be used in case security intrusion is detected.
#define V2XSE_PROCESS_COMP_WITH_WARNING (0x6310u) //Process completed with warning
#define V2XSE_CONDITIONS_NOT_SATISFIED (0x6985u)// Conditions of use not satisfied
#define V2XSE_SECURITY_STATUS_NOT_SATISFIED (0x6982u)// Security conditions not satisfied
#define V2XSE_UNDEFINED_ERROR (0x0000u)// Error code not relevant.
#define V2XSE_MEMORY_FAILURE  (0x6581u)//EEPROM errors, one or more cells defective
#define V2XSE_AUTHENTICATION_FAILED (0x6300u)// Authentication of host cryptogram failed
#define V2XSE_REF_DATA_NOT_FOUND (0x6A88u)//Reference keys to be used for secure messaging not found
#define V2XSE_SECMSG_NOT_SUPPORTED (0x6882u)//Secure messaging not supported
#define V2XSE_FUNC_NOT_SUPPORTED   (0x6A81u)//Function not supported as per Life cycle
#define V2XSE_APP_MISSING (0x6A82u)//Selected Application/file not found
#define V2XSE_RESTRICTED_MODE (0x66A5u) //Card has entered restricted mode
#define V2XSE_SSD_LOCKED (0x6999u)// Security domain locked
#define V2XSE_KEY_AGREEMENT_ERROR (0x6F01u)//Error during key agreement
#define V2XSE_TAG_CHECK_ERROR (0x6F02u)//Error during tag checking or calculation
#define V2XSE_INACTIVE_CHANNEL (0x6881u)//if logical channel not active

//DEFINITIONS FOR SCP03
#define V2XSE_AUTH_CTR_ERROR (0x6F07u) //SCP03 sequence counter has reached maximum

//DEFINITIONS FOR KEY AND SIGNATURE MANAGEMENT
#define V2XSE_INT256_SIZE 32u //in bytes
#define V2XSE_256_EC_PUB_KEY 64u //in bytes
#define V2XSE_256_EC_PUB_KEY_XY_SIZE 32u //in bytes
#define V2XSE_256_EC_HASH_SIZE 32u//in bytes
#define V2XSE_256_EC_R_SIGN 32u // in bytes
#define V2XSE_256_EC_S_SIGN 32u // in bytes
#define V2XSE_256_EC_COMP_SIGN 65u//in bytes
#define V2XSE_MAX_PRIVATE_KEY_SIZE 48u //in bytes



#define V2XSE_384_EC_PUB_KEY 96u //in bytes
#define V2XSE_384_EC_PUB_KEY_XY_SIZE 48u
#define V2XSE_384_EC_R_SIGN 48u//in bytes
#define V2XSE_384_EC_S_SIGN 48u//in bytes
#define V2XSE_384_EC_COMP_PUB_KEY 49u//in bytes
#define V2XSE_384_EC_HASH_SIZE 48u//in bytes
#define V2XSE_384_EC_COMP_SIGN 97u//in bytes

//DEFINITIONS FOR DEVICE MANAGEMENT
#define V2XSE_VERSION_SIZE 3u//in bytes
#define V2XSE_MAX_RND_NUM_SIZE 239u//in bytes
#define V2XSE_PLATFORM_IDENTITY 16u//in bytes
#define V2XSE_PLATFORM_CONFIGURATION 4u//in bytes
#define V2XSE_SERIAL_NUMBER 24u//in bytes
#define V2XSE_ATTACK_LOG  1419u//in bytes



//DEFINITIONS FOR ECIES
#define V2XSE_MAX_VCT_DATA_SIZE 169u //in bytes
#define V2XSE_MAX_MSG_SIZE 97u //in bytes
#define V2XSE_MAX_MAC_SIZE 32u// in bytes
#define V2XSE_MAX_KDF_PARAMP1_SIZE 32u //in bytes
#define V2XSE_MAX_MAC_PARAMP2_SIZE 32u //in bytes

//DEFINITION FOR GSA
#define V2XSE_MAX_DATA_SIZE_GSA 239u
#define V2XSE_MIN_DATA_SIZE_GSA 1u


//DEFINITION FOR SEND RECEIVE FUNCTION
#define V2XSE_MAX_TX_RX_SIZE 261

//DEFINITION FOR AUTHENTICATION COUNTER
#define V2XSE_MAX_AUTH_COUNTER_VALUE    0x00FFF000

//DEFINITIONS FOR SE PHASE
#define V2XSE_KEY_INJECTION_PHASE       0u
#define V2XSE_NORMAL_OPERATING_PHASE    1u

/******************************************************************************
 * TYPE DEFINITIONS
 ******************************************************************************/

typedef uint16_t TypeRtKeyId_t;

typedef uint16_t TypeSW_t;

typedef uint8_t TypeHashLength_t;

typedef uint8_t TypeLowlatencyIndicator_t;

typedef uint8_t TypeCurveId_t;

typedef uint16_t TypeBaseKeyId_t;

typedef uint8_t TypeLen_t;

typedef uint8_t TypePubKeyOut_t;

typedef uint8_t TypeVerificationResult_t;

typedef uint16_t TypeGsDataIndex_t;

/*!
 *  This structure holds the X and Y coordinates of public key having maximum size of 96 bytes.
 *  This structure shall be used for both 256 and 384 bit elliptic curves
 *
 */
typedef struct
{
    uint8_t x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
    uint8_t y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
} TypePublicKey_t;


/*!
 *   This structure holds the r, Ry[0] and s parts of signature for 256 & 384 bit elliptic curves
 */
typedef struct
{
    uint8_t r[V2XSE_384_EC_R_SIGN];
    uint8_t Ry;
    uint8_t s[V2XSE_384_EC_S_SIGN];
} TypeSignature_t;

/*!
 *   This structure holds the hash data used for signature
 *
 */
typedef struct
{
    uint8_t data[V2XSE_384_EC_HASH_SIZE];
} TypeHash_t;

/*!
 *   This structure holds the data used for deriving runtime private key
 *
 */
typedef struct
{
    uint8_t data[V2XSE_INT256_SIZE];
} TypeInt256_t;

/*!
 *   This structure holds the data used for indicating version of software on SE
 *
 */
typedef struct
{
    uint8_t data[V2XSE_VERSION_SIZE];
} TypeVersion_t;


/*!
 *   This structure holds the random number generated using SE
 *
 */
typedef struct
{
    uint8_t data[V2XSE_MAX_RND_NUM_SIZE];
} TypeRandomNumber_t;


/*!
 *   This structure holds the ECIES encrypted data
 *
 */
typedef struct
{
    uint8_t data[V2XSE_MAX_VCT_DATA_SIZE];
} TypeVCTData_t;

/*!
 *   This structure holds the plain data
 *
 */
typedef struct
{
    uint8_t data[V2XSE_MAX_MSG_SIZE];
} TypePlainText_t;



/*!
 *   This structure holds parameters for ECIES-Encrypt functions
 *
 */
typedef struct
{

    /*!Recipient's public key used for encryption */
    TypePublicKey_t *  pEccPublicKey;

    /*! Curve ID associated with public key, valid range is 0-2 */
    TypeCurveId_t  curveId;

    /*! Length of parameter KDFParamP1, valid range is 0 to 32 bytes */
    uint8_t kdfParamP1Len;  //

    /*! Parameter P1 for the key derivation function that is part of ECIES */
    uint8_t kdfParamP1[V2XSE_MAX_KDF_PARAMP1_SIZE];

    /*! Length of the message authentication code, valid range is 8 to 32 bytes */
    uint8_t macLen;

    /*! Length of parameter MacParamP2, valid range is 0 to 32 bytes */
    uint8_t macParamP2Len;

    /*! Parameter P2 for the message authentication code function that is part of ECIES */
    uint8_t macParamP2[V2XSE_MAX_MAC_PARAMP2_SIZE];

    /*! Length of message to be encrypted, maximum size shall depend on length of MAC.
    Valid range is 1 to 105-MAC length, if MAC length is 8 byte then maximum message
    length is 97 bytes, if MAC length is 32 bytes then maximum message length is 73 bytes.
     */
    TypeLen_t  msgLen;
    TypePlainText_t *  pMsgData;

} TypeEncryptEcies_t;

/*!
 *   This structure holds parameters for ECIES-Decrypt functions
 *
 */
typedef struct
{

    /*! Length of parameter KDFParamP1, valid range is 0 to 32 bytes */
    uint8_t kdfParamP1Len;

    /*! Parameter P1 for the key derivation function that is part of ECIES */
    uint8_t kdfParamP1[V2XSE_MAX_KDF_PARAMP1_SIZE];

    /*! Length of the message authentication code, valid range is 8 to 32 bytes */
    uint8_t macLen;

    /*! Length of parameter MacParamP2, valid range is 0 to 32 bytes */
    uint8_t macParamP2Len;

    /*! Parameter P2 for the message authentication code function that is part of ECIES */
    uint8_t macParamP2[V2XSE_MAX_MAC_PARAMP2_SIZE];

    /*! Length of VCT data, valid range is 73 to 169 bytes */
    TypeLen_t  vctLen;

    /*! VCT data- Encrypted data containting V-Ephimeral public key, C-Cipher text and T-Tag */
    TypeVCTData_t *  pVctData;

} TypeDecryptEcies_t;



/*!
 *   This structure holds information of supported features of SE
 *
 */
typedef struct
{

    /*!Maximum Runtime keys supported by applet*/
    uint16_t maxRtKeysAllowed;

    /*!Maximum Base keys supported by applet*/
    uint16_t maxBaKeysAllowed;

    /*!Maximum number of prepared values supported */
    uint8_t numPreparedVal;

    /*!FIPS approved mode indicator */
    uint8_t fipsModeIndicator;

    /*!Proof of possession support indicator */
    uint8_t proofOfPossession;

    /*!Rollback protection status indicator */
    uint8_t rollBackProtection;

    /*!Key derivation support indicator */
    uint8_t rtKeyDerivation;

    /*!Active Applet Instance indicator */
    uint8_t eciesSupport;

    /*!Maximum number of data slots supported by Generic storage applet */
    uint16_t maxDataSlots;
} TypeInformation_t;

/*!
 *   This structure holds the Platform identification information
 *
 */
typedef struct
{
    uint8_t data[V2XSE_PLATFORM_IDENTITY];
} TypePlatformIdentity_t;

/*!
 *   This structure holds the Platform Configuration information
 *
 */
typedef struct
{
    uint8_t data[V2XSE_PLATFORM_CONFIGURATION];

} TypePlatformConfiguration_t;


/*!
 *   This structure holds the Serial number of the chip
 *
 */
typedef struct
{
    uint8_t data[V2XSE_SERIAL_NUMBER];
} TypeChipInformation_t;



/*!
 *   This structure holds the Attack log
 *
 */
typedef struct
{
    uint8_t currAttackCntrStatus;
    uint32_t len;
    uint8_t data[V2XSE_ATTACK_LOG];
} TypeAttackLog_t;


/**
 *
 *   This enumeration data type holds the Information, that shall be used to indicate the applet/applets to be selected during Activation
 *   and also to indicate applet type for which version details have to be retrieved. The activation is done by v2xSe_activate() or
 *   v2xSe_activateWithSecurityLevel().
 */
typedef enum
{
    e_EU /*!To select EU instance of the V2X applet during activation*/,
    e_US /*!To select US instance of the V2X applet during activation*/,
    e_EU_AND_GS/*!To select EU instance of V2X applet and Generic storage applet on two logical channels, during activation*/,
    e_US_AND_GS/*!To select US instance of V2X applet and Generic storage applet on two logical channels, during activation*/,
    e_V2X /*!To indicate applet type to get version of V2X applet(EU/US instance) using v2xSe_getVersion()*/,
    e_GS/*!To indicate applet type to get version of Generic storage applet using v2xSe_getVersion()*/
} appletSelection_t;

/**
 *   This enumeration data type is used to specify the security level to be used for the communication with V2X and GSA applets on SE.
 *
 */
typedef enum
{
    /*!C-MAC*/
    e_channelSecLevel_1 = 1,
    /*!C-DECRYPTION and C-MAC */
    e_channelSecLevel_2 = 2,
    /*!C-MAC and R-MAC */
    e_channelSecLevel_3 = 3,
    /*!C-DECRYPTION, C-MAC and R-MAC */
    e_channelSecLevel_4 = 4,
    /*!C-DECRYPTION, R-ENCRYPTION, C-MAC and R-MAC */
    e_channelSecLevel_5 = 5
} channelSecLevel_t;


/*!
 *   This structure holds the private key in plain text
 */
typedef struct
{
    uint8_t plainKey[V2XSE_MAX_PRIVATE_KEY_SIZE];
} TypePlainTextKey_t;


/*!
 *   This structure holds the Parameters for key injection function
 */


/******************************************************************************
 * EXPORTED FUNCTIONS
 ******************************************************************************/


/*!
 * \brief This function shall enable communication with Card Manager of JCOP(Java Card Open Platform Operating
 *        system)located on V2X-SE.
 *
 * \details   The function shall perform the following actions when called
 *            1. Open SPI channel for communication with V2X-SE
 *            2. Perform SPI T=1 resync using S-Block command of ISO 7816-3
 * If this function is called when V2X-SE status is already "Connected" or "Activated" then it shall result
 * in error, however V2X-SE shall continue to remain in the state earlier to this function call.

 * \pre  V2X-SE should be in init state
 * \return On success return #V2XSE_SUCCESS, if V2X-SE is already in connected state then return #V2XSE_FAILURE_CONNECTED, if V2X-SE is in activated state
 *then return #V2XSE_FAILURE_ACTIVATED and for all other errors return #V2XSE_FAILURE
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_connect(void);



/*!
 *
 * \brief This function shall be used to activate SE to process JCOP, V2X and Generic storage specific commands
 * \details  After successful execution of this function V2X-SE will be in the activated state. It is only from
 *  this state it is possible to perform V2X and Generic storage specific operations.
 *  If Activate is called when V2X-SE is already activated or connected state then it shall result in error, however V2X-SE shall
 *  continue to remain in the state earlier to this function call. JCOP functions are also available in activated state.
 * The function shall perform the following actions when called:
 * 1. Initialize V2X-SE specific parameters on host application processor
 * 2. Initiate Connection to SE via SPI interface
 *    - Open SPI channel for communication with V2X-SE
 *    - Perform SPI T=1 resync using S-Block command
 * 3. Open logical channels, select Applets and card manager(JCOP) on logical channels along with setting up of secure channels
 * for V2X and Generic storage applets.
 * \pre  V2X-SE should be in init state
 * \param [in]    appletId            The applet or applets to be selected for usage. The valid values are
 *                                    #e_EU, #e_US, #e_EU_AND_GS and #e_US_AND_GS.
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_SCP03_KEYFILE_ERROR: missing key-file, invalid key length or invalid number of keys in key-file
 *                                    - #V2XSE_SCP03_SESSIONKEY_ERROR: Session key derivation failure
 *                                    - #V2XSE_SCP03_CARDCRYPTO_ERROR: Card cryptogram verification failure
 *                                    - #V2XSE_SCP03_HOSTCRYPTO_ERROR: Host cryptogram calculation failure
 *                                    - #V2XSE_AUTH_CTR_ERROR: The SCP03 sequence counter has reached the maximum value
 *                                    - #V2XSE_REF_DATA_NOT_FOUND: Reference keys to be used for secure messaging not found
 *                                    - #V2XSE_AUTHENTICATION_FAILED: Authentication of host cryptogram failed
 *                                    - #V2XSE_SECMSG_NOT_SUPPORTED: Secure messaging not supported
 *                                    - #V2XSE_FUNC_NOT_SUPPORTED: Function not supported as per Life cycle
 *                                    - #V2XSE_APP_MISSING: Selected Application/file not found
 * \return On success return #V2XSE_SUCCESS, if V2X-SE is already in activated state then return #V2XSE_FAILURE_ACTIVATED,
 *if V2X-SE is in connected state then return #V2XSE_FAILURE_CONNECTED and for all other errors return #V2XSE_FAILURE
 * \remark Successful activation of V2X-SE is a pre-condition for performing V2X and Generic storage specific operations on V2X-SE
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_activate(appletSelection_t appletId, TypeSW_t *pHsmStatusCode);


/*!
 *
 * \brief This function shall be used to activate SE to process JCOP, V2X and Generic storage specific commands.
 * Unlike the v2xSe_activate(), it is possible to specify the initial security level to be used for mutual
 * authentication specially for the V2X and Generic storage applets.
 * \details  After successful execution of this function V2X-SE will be in the activated state. It is only from
 *  this state it is possible to perform V2X and Generic storage specific operations.
 *  If Activate is called when V2X-SE is already activated or connected state then it shall result in error, however V2X-SE shall
 *  continue to remain in the state earlier to this function call. JCOP functions are also available in activated state.
 * The function shall perform the following actions when called:
 * 1. Initialize V2X-SE specific parameters on host application processor
 * 2. Initiate Connection to SE via SPI interface
 *    - Open SPI channel for communication with V2X-SE
 *    - Perform SPI T=1 resync using S-Block command
 * 3. Open logical channels, select Applets and card manager(JCOP) on logical channels along with setting up of secure channels
 * for V2X and Generic storage applets.
 * \pre  V2X-SE should be in init state
 * \param [in]    appletId            The applet or applets to be selected for usage. The valid values are
 *                                    #e_EU, #e_US, #e_EU_AND_GS and #e_US_AND_GS.
 * \param [in]    securityLevel       The security level to be used for mutual authentication
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_SCP03_KEYFILE_ERROR: missing key-file, invalid key length or invalid number of keys in key-file
 *                                    - #V2XSE_SCP03_SESSIONKEY_ERROR: Session key derivation failure
 *                                    - #V2XSE_SCP03_CARDCRYPTO_ERROR: Card cryptogram verification failure
 *                                    - #V2XSE_SCP03_HOSTCRYPTO_ERROR: Host cryptogram calculation failure
 *                                    - #V2XSE_AUTH_CTR_ERROR: The SCP03 sequence counter has reached the maximum value
 *                                    - #V2XSE_REF_DATA_NOT_FOUND: Reference keys to be used for secure messaging not found
 *                                    - #V2XSE_AUTHENTICATION_FAILED: Authentication of host cryptogram failed
 *                                    - #V2XSE_SECMSG_NOT_SUPPORTED: Secure messaging not supported
 *                                    - #V2XSE_FUNC_NOT_SUPPORTED: Function not supported as per Life cycle
 *                                    - #V2XSE_APP_MISSING: Selected Application/file not found
 * \return On success return #V2XSE_SUCCESS, if V2X-SE is already in activated state then return #V2XSE_FAILURE_ACTIVATED,
 *if V2X-SE is in connected state then return #V2XSE_FAILURE_CONNECTED and for all other errors return #V2XSE_FAILURE
 * \remark Successful activation of V2X-SE is a pre-condition for performing V2X and Generic storage specific operations on V2X-SE
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_activateWithSecurityLevel(appletSelection_t appletId, channelSecLevel_t securityLevel, TypeSW_t *pHsmStatusCode);


/*!
 * \brief This function shall be used to reset V2X-SE
 * \details The function shall perform the following actions when called depending on the state of V2X-SE.
 * It is recommended to use this function to start V2X-SE operation from a clean state.
 * 1. Perform soft reset of V2X-SE, if soft reset is not successful perform hard reset of V2X-SE
 * 2. Close SPI channel with SE if V2X-SE
 * 3. Clear the state of v2x crypto library
 * \pre  This function can be called any time
 * \return On success return #V2XSE_SUCCESS else #V2XSE_FAILURE
 * \remark The actual reset implementation depends on customer platform and it has to be implemented in PAL(Platform Abstraction Layer).
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_reset(void);



/*!
 * \brief This function shall be used to switch V2X-SE into init state
 * \details   The function shall perform the following actions when called depending on the state of V2X-SE
 *            1. Close secure(logical) channels if V2X-SE is in activated state
 *            2. Close SPI channel if V2X-SE is in connected or activated state
 *            3. Clear the state of v2x crypto library
 * \pre V2X-SE should be in connected or activated state
 * \return     On success return #V2XSE_SUCCESS, if V2X-SE is in init state then return #V2XSE_FAILURE_INIT and
 * for all other errors return #V2XSE_FAILURE
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_deactivate(void);


/*! \fn int32_t v2xSe_generateMaEccKeyPair(TypeCurveId_t curveId,TypeSW_t *pHsmStatusCode,
 * TypePublicKey_t *pPublicKeyPlain);
 *
 * \brief  This function shall be used to generate Module Authentication ECC key pair
 * \details   The function shall result in generating Module Authentication(MA) ECC key pair consisting of
 *            ECC private key and ECC public key whose lengths vary depending on ECC curve selected.It is
 *            possible to generate MA key pair only once per Applet(EU and US) per device.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]     curveId             The ID of the ECC curve that must be used to generate ECC key pair
 * \param [out]    pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: Invalid curve ID
 *                                    - #V2XSE_NVRAM_UNCHANGED: MA key is already generated or MA key
 *                                      was generated but storage of key failed
 *
 * \param [out]  pPublicKeyPlain      Public key of the MA ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_KeyManagement
 */

int32_t v2xSe_generateMaEccKeyPair
(
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
);




/*! \fn int32_t v2xSe_getMaEccPublicKey(TypeSW_t *pHsmStatusCode,TypeCurveId_t *pCurveId,
 * TypePublicKey_t *pPublicKeyPlain) ;
 *
 * \brief  This function shall be used to get Module Authentication ECC public key corresponding to the Applet selected
 * \details   The function shall be used to get Module Authentication(MA) public key by calculating the
 *  public key from stored private key.
 * \pre   V2X-SE is in activated state
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error code is:
 *                                    - #V2XSE_NVRAM_UNCHANGED: MA key is not present in NVM
 * \param [out]  pCurveId             The ID of the ECC curve that is associated with the ECC key pair
 * \param [out]  pPublicKeyPlain      Public key of the MA ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_getMaEccPublicKey
(
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);



/*! \fn int32_t v2xSe_createMaSign(TypeHashLength_t hashLength,TypeHash_t *pHashValue,
 *  TypeSW_t *pHsmStatusCode,TypeSignature_t *pSignature);
 *
 * \brief  This function shall be used to create a signature for a hash value of the message
 * \details  The function shall be used to create signature for a hash value of the message using
 *  Module Authentication(MA) private key corresponding to the Applet selected .
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    hashLength         The length of hash which has to be signed
 * \param [in]    pHashValue         The hash of the message to be signed
 * \param [out]   pHsmStatusCode     In case of an error, this code provides detailed information.
 *                                   The function specific error codes are:
 *                                   - #V2XSE_WRONG_DATA: invalid hashLength or hashLength does not
 *                                   correspond to the curve type associated with private key
 *                                   - #V2XSE_NVRAM_UNCHANGED: MA key is not present in NVM
 * \param [out]   pSignature         created signature
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not
 *  activated return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_Signature
 */
int32_t v2xSe_createMaSign
(
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
);



/*! \fn int32_t v2xSe_generateRtEccKeyPair(TypeRtKeyId_t rtKeyId,TypeCurveId_t curveId,
 * TypeSW_t *pHsmStatusCode,TypePublicKey_t *pPublicKeyPlain) ;
 *
 * \brief  This function shall be used to generate Runtime ECC key pair
 * \details  The function shall result in generating Runtime ECC key pair consisting of ECC private
 *  key and ECC public key.The Runtime ECC key pair generation is allowed only for 256 bit curves of
 *  NIST, BP-R1 and BP-T1.
 * \pre V2X-SE is activated in normal operating phase
 *
 * \param [in]    rtKeyId             The ID referring the persistent memory(NVM) slot where the
 *                                    generated private key must be stored
 * \param [in]    curveId             The ID of the ECC curve that must be used to generate the key pair.
 *                                    The valid curve IDs are #V2XSE_CURVE_NISTP256, #V2XSE_CURVE_BP256R1
 *                                    and #V2XSE_CURVE_BP256T1.
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: Invalid rtKeyId or  Invalid curveId
 *                                    - #V2XSE_NVRAM_UNCHANGED :key was generated but storage of key failed
 *                                    - #V2XSE_FILE_FULL : No memory available for key generation
 * \param [out]  pPublicKeyPlain      Public key of the Runtime ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark In case the slot to store the key already contains a private key, the newly created private
 * key overwrites the key already present.
 * \ingroup v2xSe_KeyManagement
 */

int32_t v2xSe_generateRtEccKeyPair
(
    TypeRtKeyId_t rtKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
) ;



/*! \fn int32_t v2xSe_deleteRtEccPrivateKey(TypeRtKeyId_t rtKeyId,TypeSW_t *pHsmStatusCode) ;
 *
 * \brief  This function shall be used to delete Runtime ECC private key.
 * \details  The function shall result in deleting of Runtime Private key from persistent memory(NVM).
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    rtKeyId           The ID referring NVM slot containing Runtime private key that must
 *                                  be deleted
 * \param [out]   pHsmStatusCode    In case of an error, this code provides detailed information.
 *                                  The function specific error code is:
 *                                 - #V2XSE_WRONG_DATA: Invalid rtKeyId or rtKeyId refers to slot
 *                                  that does not contain private key.
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_deleteRtEccPrivateKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
);





/*! \fn int32_t v2xSe_getRtEccPublicKey(TypeRtKeyId_t rtKeyId,TypeSW_t *pHsmStatusCode,
 * TypeCurveId_t *pCurveId,TypePublicKey_t *pPublicKeyPlain) ;
 *
 * \brief  This function shall be used to get Runtime ECC public key
 * \details The function shall be used to get Runtime public key by calculating the public key from
 *  stored private key.
 * \pre V2X-SE is in activated state
 * \param [in]    rtKeyId            The ID referring NVM slot containing the Runtime private key used to
 *                                   calculate the Runtime public key
 * \param [out]   pHsmStatusCode     In case of an error, this code provides detailed information.
 *                                   The function specific error code is:
 *                                   - #V2XSE_WRONG_DATA: Invalid rtKeyId or rtKeyId refers to a slot
 *                                   that does not contain a private key
 * \param [out]  pCurveId            The ID of the ECC curve that is associated with the ECC key pair
 * \param [out]  pPublicKeyPlain     Public key of the Runtime ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_getRtEccPublicKey
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);


/*! \fn int32_t v2xSe_createRtSignLowLatency(TypeHash_t *pHashValue, TypeSW_t *pHsmStatusCode,
 * TypeSignature_t *pSignature, TypeLowlatencyIndicator_t *pFastIndicator);
 *
 * \brief  This function shall be used to create signature for the hash value of a message using Runtime
 * private key.
 * \details  The function shall be used to create signature for the hash value of a message with Runtime private
 * key activated via v2xSe_activateRtKeyForSigning().The function makes use of available
 *  pre-computed values in RAM for signature creation, thereby resulting in low latency signature creation.
 *  In the event of no pre-computed values available in RAM, signature creation request shall result in
 *  pre-computed followed by finalizing the signature process, which shall result in higher latency.
 * \pre V2X-SE is activated in normal operating phase and Runtime key is activated using v2xSe_activateRtKeyForSigning
 * \param [in]    pHashValue         The hash of the message to be signed
 * \param [out]   pHsmStatusCode     In case of an error, this code provides detailed information.
 *                                   The function specific error code is:
 *                                   -  #V2XSE_NVRAM_UNCHANGED: Runtime key to be used for signature creation is
 *                                   not activated
 * \param [out]   pSignature         created signature
 * \param [out]   pFastIndicator     Indicates if the created signature was with already pre-computed values or
 *                                   not.
 *                                  - 1 - pre-computed values used for signature creation
 *                                  - 0 - No pre-computed values used for signature creation
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_Signature
 */
int32_t v2xSe_createRtSignLowLatency
(
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature,
    TypeLowlatencyIndicator_t *pFastIndicator
);



/*! \fn int32_t v2xSe_createRtSign( TypeRtKeyId_t rtKeyId,TypeHash_t *pHashValue,TypeSW_t *pHsmStatusCode,TypeSignature_t *pSignature);
 *
 * \brief  This function shall be used to create signature for the hash value of a message using Runtime
 * private key identified by the key ID.
 * \details  The function shall be used to create signature for the hash value of a message with Runtime private key
 * without using the pre-computed / prepared values. As the function does not make use of pre-computed values, the latency
 * would be higher than v2xSe_createRtSignLowLatency(). The execution of this function shall not have any impact on
 * pre-computed / prepared values or the activated key via v2xSe_activateRtKeyForSigning().

 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    rtKeyId            The ID referring the persistent memory(NVM) slot containing
 *                                   the Runtime private key that must be used
 * \param [in]    pHashValue         The hash of the message to be signed
 * \param [out]   pHsmStatusCode     In case of an error, this code provides detailed information.
 *                                   The function specific error code is:
 *                                   -  #V2XSE_WRONG_DATA: Invalid rtKeyId or rtKeyId refers to slot that does not contain
 *                                    private key.
 * \param [out]   pSignature         created signature
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_Signature
 */


int32_t v2xSe_createRtSign
(
    TypeRtKeyId_t rtKeyId,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature

);



/*! \fn int32_t v2xSe_generateBaEccKeyPair(TypeBaseKeyId_t baseKeyId, TypeCurveId_t curveId,
 * TypeSW_t *pHsmStatusCode, TypePublicKey_t *pPublicKeyPlain) ;
 *
 * \brief   This function shall be used to generate Base ECC key pair
 * \details The function shall result in generating Base ECC key pair consisting of
 *          ECC private key and ECC public key whose lengths vary depending on ECC curve selected.
 * \pre V2X-SE is activated in normal operating phase
 *
 * \param [in]    baseKeyId           The ID referring the persistent memory(NVM) slot where the generated
 *                                    private key must be stored
 * \param [in]    curveId             The ID of the ECC curve that must be used to generate the key pair
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: Invalid baseKeyId or  Invalid curveId
 *                                    - #V2XSE_NVRAM_UNCHANGED: key was generated but storage of key failed
 * \param [out]  pPublicKeyPlain      Public key of the Base ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark In case the slot to store the key already contains a private key, the newly created private key
 * overwrites the key already present.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_generateBaEccKeyPair
(
    TypeBaseKeyId_t baseKeyId,
    TypeCurveId_t curveId,
    TypeSW_t *pHsmStatusCode,
    TypePublicKey_t *pPublicKeyPlain
);



/*! \fn int32_t v2xSe_deleteBaEccPrivateKey(TypeBaseKeyId_t baseKeyId,TypeSW_t *pHsmStatusCode) ;
 *
 * \brief   This function shall be used to delete Base private key.
 * \details   The function shall result in deleting of Base private key from NVM.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    baseKeyId         The ID referring the persistent memory(NVM) slot containing the
 *                                  Base private key that must be deleted
 * \param [out]   pHsmStatusCode    In case of an error, this code provides detailed information.
 *                                  The function specific error codes are:
 *                                  - #V2XSE_WRONG_DATA: Invalid baseKeyId or baseKeyId referes to
 *                                   slot that does not contain private key.
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_deleteBaEccPrivateKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode
);


/*! \fn int32_t v2xSe_getBaEccPublicKey(TypeBaseKeyId_t baseKeyId, TypeSW_t *pHsmStatusCode,
 * TypeCurveId_t *pCurveId, TypePublicKey_t *pPublicKeyPlain) ;
 *
 * \brief  This function shall be used to get Base ECC public key
 * \details  The function shall be used to get Base public key by calculating the public key
 *  from stored private key.
 * \pre   V2X-SE is in activated state
 * \param [in]    baseKeyId         The ID referring the persistent memory(NVM) slot containing the Base
 *                                  private key used to calculate the Base public key
 * \param [out]   pHsmStatusCode    In case of an error, this code provides detailed information.
 *                                  The function specific error codes are:
 *                                  - #V2XSE_WRONG_DATA: Invalid baseKeyId or baseKeyId refers
 *                                  to a slot that does not contain a private key
 * \param [out]   pCurveId          The ID of the ECC curve that is associated with the ECC key pair
 * \param [out]   pPublicKeyPlain   Public key of the Base ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */
int32_t v2xSe_getBaEccPublicKey
(
    TypeBaseKeyId_t baseKeyId,
    TypeSW_t *pHsmStatusCode,
    TypeCurveId_t *pCurveId,
    TypePublicKey_t *pPublicKeyPlain
);


/*!
 * \brief  This function shall be used to create signature for the hash value of a message using
 *  Base private key.
 * \details  The function shall be used to create signature for the hash value of a message using
 *  Base private key. The length of signature shall depend on elliptic curve used.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    baseKeyId          The ID referring the persistent memory(NVM) slot containing
 *                                   the Base private key that must be used
 * \param [in]    hashLength         The length of hash which has to be signed
 * \param [in]    pHashValue         The hash of the message to be signed
 * \param [out]   pHsmStatusCode     In case of an error, this code provides detailed information.
 *                                   The function specific error code is:
 *                                   - #V2XSE_WRONG_DATA: Invalid baseKeyId or invalid hashLength
 *                                    or hashLength does not correspond to the curve type associated
 *                                    with private key or baseKeyId refers to slot that does not contain
 *                                    private key.
 * \param [out]   pSignature         created signature
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_Signature
 */

int32_t v2xSe_createBaSign
(
    TypeBaseKeyId_t baseKeyId,
    TypeHashLength_t hashLength,
    TypeHash_t *pHashValue,
    TypeSW_t *pHsmStatusCode,
    TypeSignature_t *pSignature
);




/*! \fn int32_t v2xSe_deriveRtEccKeyPair(TypeBaseKeyId_t baseKeyId,
 * TypeInt256_t *pFvSign,TypeInt256_t *pRvij, TypeInt256_t *pHvij, TypeRtKeyId_t rtKeyId,TypePubKeyOut_t returnPubKey,
            TypeSW_t *pHsmStatusCode,TypeCurveId_t *pCurveID, TypePublicKey_t *pPublicKeyPlain) ;
 * \brief  This function shall be used to derive Runtime ECC key pair
 * \details   The function shall result in deriving of Runtime ECC key pair from reconstruction values
 * and Base private key. The key derivation should be possible only from Base Ecc key
 * pair belonging to 256 bit elliptic curves supported. This function is supported only in US applet.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    baseKeyId           The ID referring the persistent memory(NVM) slot containing
 *                                    Base key to be used for key derivation
 * \param [in]    pFvSign             The expansion value used in the derivation of the Runtime ECC key
 * \param [in]    pRvij               The private reconstruction value used in the derivation of the
 *                                    Runtime ECC key
 * \param [in]    pHvij               The hash value used in the derivation of the Runtime ECC key
 * \param [in]    rtKeyId             The ID referring the persistent memory(NVM) slot where the
 *                                    generated Runtime private key must be stored
 * \param [in]    returnPubKey        This can be used to indicate SE to return the public key as part of response
 *                                    - #V2XSE_RSP_WITHOUT_PUBKEY:  response will not consist of public key
 *                                    - #V2XSE_RSP_WITH_PUBKEY:  response will consist of public key
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: Invalid value passed as returnPubKey, Invalid baseKeyId or invalid pFvSign
 *                                    or invalid pRvij, or invalid pHvij or invalid rtKeyId or
 *                                    baseKeyId slot does not contain Base private key
 *                                    or baseKeyId refers to private key which is not associated
 *                                    with 256 bit elliptic curve.
 *                                    - #V2XSE_NVRAM_UNCHANGED: key derivation failed or key was generated
 *                                     but storage of key failed
 *                                    - #V2XSE_INS_NOT_SUPPORTED :If key derivation is called in EU applet instance.
 * \param [out]  pCurveID             The ID of the ECC curve that is associated with generated Runtime
 *                                    ecc key pair
 * \param [out]  pPublicKeyPlain      Public key of the Runtime ECC key pair
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark
 *1. The key derivation scheme shall be based on the formula:
 *   runtime key(ij) = ((base key + FvSign(ij)) * Hvij ) + Rvij (modulo n), where n represents the order of the curve.
 *   Notation: Xij indicates the jth value of X for time period i.
 *2. Valid range of FvSign is [0 to 2^(256)-1)]
 *3. Valid range of Rvij is [0 to 2^(256)-1]
 *4. Valid range of Hvij is [1 to n-1] (n = order of the elliptic curve)
 *5. In case the slot to store the key already contains a private key, the newly created private key
 *   overwrites the key already present.
 * \ingroup v2xSe_KeyManagement
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
);




/*! \fn int32_t v2xSe_activateRtKeyForSigning(TypeRtKeyId_t rtKeyId, TypeSW_t *pHsmStatusCode) ;
 * \brief  This function shall be used to activate Runtime ECC private key for signature creation using
 * v2xSe_createRtSignLowLatency()
 * \details   The function shall result in activation of Runtime ECC private key to be used by
 * v2xSe_createRtSignLowLatency(). The activated key shall remain activated until
 * - Deletion or Modification(generation/derivation) of Runtime private key from Runtime key slot
 *  corresponding to activated key
 * - Applet selection(same or different)
 * - Reset of V2X-SE
 * - Successful activation of another key
 *.
 *   On activation of Runtime key having curve domain parameters different than the one used for
 *   preparation(pre-computation), already prepared values shall be invalidated and fresh preparations shall start on
 *idle / v2xSe_createRtSignLowLatency() request with the curve associated to activated key.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    rtKeyId             The ID referring the persistent memory(NVM) slot containing
 *                                    Runtime private key that must be activated
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error code is:
 *                                    - #V2XSE_WRONG_DATA: Invalid rtKeyId or rtKeyId refers
 *                                     to slot that does not contain Runtime private key
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_KeyManagement
 */

int32_t v2xSe_activateRtKeyForSigning
(
    TypeRtKeyId_t rtKeyId,
    TypeSW_t *pHsmStatusCode
);



/*!
 * \brief  This function shall be used to get Applet version details
 * \details The function shall provide details of Applet version.The version shall be in the format: 'XYZ':
 * - X: Indicates V2X-SE project generation (SXA1700 - shall have values 0 & 1 and SXF1800 shall
 *              have value '2')
 * - Y: Patch major version field
 * - Z: Patch minor version field
 *         All fields are presented as hexadecimal values.
 *
 * \pre V2X-SE is in activated state
 * \param [in]    appletType            The applet type whose version has to be retrieved. The valid values are #e_V2X and #e_GS.
 * \param [out]   pHsmStatusCode        In case of an error, this code provides detailed information.
 *                                      - #V2XSE_WRONG_DATA: Invalid appletType
 *                                      - #V2XSE_INACTIVE_CHANNEL: Generic storage applet version is requested
 *                                        while Generic storage applet was not selected as part of v2xSe_activate().
 * \param [out]  pVersion               Version details of the firmware
 *
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 *
 * \remark
 * 1. Both EU and US applet will have the same version number
 * 2. Validation of input parameter shall be done by V2X Crypto Library
 *
 * \ingroup v2xSe_DeviceManagement
 */

int32_t v2xSe_getAppletVersion
(
    appletSelection_t appletType,
    TypeSW_t *pHsmStatusCode,
    TypeVersion_t *pVersion
);



/*! \fn int32_t v2xSe_getRandomNumber(TypeLen_t length, TypeSW_t *pHsmStatusCode,
 *  TypeRandomNumber_t *pRandomNumber) ;
 * \brief  This function shall be used to get random number
 * \details The function shall be used to get random number from true random number generator.
 * \pre V2X-SE is in activated state
 * \param [in]    length              The length of the random number in bytes, valid range is
 *                                    [1 to #V2XSE_MAX_RND_NUM_SIZE]
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: Invalid length
 * \param [out]   pRandomNumber       The generated random number
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_UTILITY
 */

int32_t v2xSe_getRandomNumber
(
    TypeLen_t length,
    TypeSW_t *pHsmStatusCode,
    TypeRandomNumber_t *pRandomNumber
);



/*!
 *
 * \brief  This function shall be used to get details of V2X-SE configuration
 * \pre V2X-SE is in activated state
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error code is: None
 * \param [out]   pInfo               The structure containing configuration details about Applet,
 *                                    - Maximum Runtime keys allowed
 *                                    - Maximum Base keys allowed
 *                                    - Maximum number of prepared(pre-computed)values supported
 *                                    - FIPS approved Mode indicator: Status of self-test, firmware integrity test and key pairwise consistency check
 *                                      represented in same order in last 3 bits of a byte
 *                                    - Proof of Possession support: 0 if disabled and 1 if enabled
 *                                    - Roll back protection support: 0 if disabled and 1 if enabled
 *                                    - Key derivation support: 0 if disabled and 1 if enabled
 *                                    - ECIES support : 0 if disabled and 1 if enabled
 *                                    - Maximum Data storage slots supported by Generic storage applet: supported slots if Generic storage applet
 *                                      is selected and 0 if Generic storage applet is not selected
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 *
 * \remark
 * 1. The reported values could be different for EU and US applet.
 * 2. The FIPS Approved mode indicator will indicate if JCOP on V2X SE is operating in Approved mode or not.
 *    If self test, firmware integrity test and pairwise consistency check are enabled then it shall be considered as FIPS
 *    approved mode of JCOP.
 * 3. The Maximum keys and maximum data storage slots allowed indicates support by Applet, does not necessarily mean
 *    complete storage is possible on SE.The storage is always dependent on the memory available on SE.
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getSeInfo
(
    TypeSW_t *pHsmStatusCode,
    TypeInformation_t *pInfo
);


/*!
 * \brief  This function shall provide version details of V2X Crypto API
 * \details The version shall be in the format: 'XYZ':
 *         - X: Indicates V2X-SE project generation(SXF1700 - shall have values 0 & 1 and SXF1800
 *           shall have value '2')
 *         - Y: Patch major version field
 *         - Z: Patch minor version field
 *            All fields are presented as hexadecimal values
 * \param [out]  pVersion             Version number of the V2X SE access library
 * \return On success return #V2XSE_SUCCESS and on failure #V2XSE_FAILURE .
 * \ingroup v2xSe_DeviceManagement
 */

int32_t v2xSe_getCryptoLibVersion
(
    TypeVersion_t *pVersion
);



/*!
 * \brief  This function shall be used to get Platform Identification information.
 * The Platform Identifier shall indicate to the user which version of OS(JCOP) and hardware is being dealt with.
 * \details  This function shall be used to get information related to Platform identification .
 *            The Platform Identifier identifies the type of platform -combination of HW and OS.
 *            The Platform Identifier shall not be used to identify a single chip as it is same for
 *            given version. The identification data is of 16 bytes length. The platform identifier
 *            information shall be accessible without any authentication.
 * \pre V2X-SE should be in connected or activated state
 * \param [out]  pHsmStatusCode       This code indicates whether the function succeeded or failed.
 *                                     The function specific error code is: None
 * \param [out]  pPlatformIdentifier   Pointer to structure containing Platform identification information
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in connected or activated
 *  state return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getPlatformInfo(TypeSW_t *pHsmStatusCode,TypePlatformIdentity_t *pPlatformIdentifier);




/*!
 * \brief  This function shall be used to get details of Trust Provisioning profile preloaded on the SE.
 * \details This function along with platform identifier shall uniquely identify a product.
 *          It shall be possible to access platform configuration information without any authentication.
 *          The configuration identifier consists of:
 *         - 0x00-(RFU)
 *         - 3bytes Card Identifier (ASCII coded Fabkey short-form)
 * \pre V2X-SE should be connected or activated state
 * \param [out]  pHsmStatusCode       This code indicates whether the function succeeded or failed.
 *                                    The function specific error code is: None
 * \param [out]  pPlatformConfig      Pointer to structure containing Platform Configuration information
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in
 * connected state return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getPlatformConfig(TypeSW_t *pHsmStatusCode,TypePlatformConfiguration_t *pPlatformConfig);


/*!
 * \brief  This function shall be used to get serial number of the chip(SE).
 * \details  The function shall be used to uniquely identify a single chip. Each individual chip has a
 * different Serial Number and is 24 bytes long
 * \pre V2X-SE should be in connected or activated state
 * \param [out]  pHsmStatusCode       This code indicates whether the function succeeded or failed.
 *                                     The function specific error code is: None
 * \param [out]  pChipInfo            Pointer to structure containing Serial number information of the
 *                                    chip
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in
 * connected state return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getChipInfo(TypeSW_t *pHsmStatusCode,TypeChipInformation_t *pChipInfo);


/*!
 *
 * \details  This function shall be used to read attacks logged due to a strong attack.
 * The attack log received is in the encrypted form, decryption and analysis of the log can be performed
 * by NXP only.
 * \pre V2X-SE should be in connected or activated state
 * \param [out]  pHsmStatusCode       This code indicates whether the function succeeded or failed.
 *                                    The function specific error codes are:
 *                                     - #V2XSE_PROCESS_COMP_WITH_WARNING
 * \param [out]  pAttackLog            This field contains
 *                                     - Current attack counter status: If attack counter is zero
 *                                     then current attack status is set to #V2XSE_ATTACK_CNT_ZERO else
 *                                     #V2XSE_ATTACK_CNT_NON_ZERO
 *                                     - Length of the attack log
 *                                     - Attack log encrypted with NXP internal key
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in
 * connected state return #V2XSE_DEVICE_NOT_CONNECTED
 * \remark
 * 1. The attack counter being #V2XSE_ATTACK_CNT_ZERO does not necessarily mean "No Attacks", refer user manual for
 * details about auto decrement of attack counter. This essentially means even when current attack counter status
 * is #V2XSE_ATTACK_CNT_ZERO, attack log could be present.
 * 2. The log needs to be reported back to NXP for detailed analysis.
 *
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getAttackLog(TypeSW_t *pHsmStatusCode,TypeAttackLog_t *pAttackLog);

/*! \fn int32_t v2xSe_encryptUsingEcies (TypeEncryptEcies_t *pEciesData, TypeSW_t *pHsmStatusCode,
 *             TypeLen_t *pVctLen,TypeVCTData_t *pVctData );
 *
 * \brief  This function shall be used to encrypt plain text data using ECIES encryption scheme.
 * \details   The function shall use recipient's ECC public key to encrypt plain text data using
 *  ECIES encryption scheme.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    pEciesData          Pointer to structure containing the following data- ECC Public key of recipient,
 *                                    curve ID associated with public key,KDF-Parameter(P1) length,
 *                                    KDF-Parameter Data, MAC length, MAC-Parameter(P2) Length,
 *                                    MAC-Parameter Data, length of message and message
 *                                    to be encrypted
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    -  #V2XSE_WRONG_DATA: Invalid curve Id or invalid recipient's
 *                                        public key or invalid KDF-Parameter(P1) length or invalid
 *                                        MAC length or invalid MAC-Parameter(P2) Length or invalid
 *                                        message length.
 *                                    -  #V2XSE_KEY_AGREEMENT_ERROR: Error during key agreement
 *                                       (e.g. PublicKey CurveId mismatch)
 *                                    -  #V2XSE_NVRAM_UNCHANGED: Internal error during encryption,
 *                                       message could not be encrypted
 *
 *
 * \param [out]  pVctLen      The length of the encrypted data. The Length of the encrypted data is
 *                            64(V-ephemeral public key)+ Message length + MAC length bytes.
 *                            The length shall be in the range 73 to #V2XSE_MAX_VCT_DATA_SIZE bytes.
 * \param [out]  pVctData     The Encrypted data containing V-ephemeral public key, C-Cipher text and T-Tag
 *                            (message authentication data)
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark   ECIES shall be allowed only with 256 bit elliptic curves supported.
 * \ingroup v2xSe_ECIES
 */

int32_t v2xSe_encryptUsingEcies (TypeEncryptEcies_t *pEciesData, TypeSW_t *pHsmStatusCode,
                                 TypeLen_t *pVctLen,TypeVCTData_t *pVctData );



/*! \fn int32_t v2xSe_decryptUsingRtEcies (TypeRtKeyId_t rtKeyId,
 * TypeDecryptEcies_t *pEciesData,TypeSW_t *pHsmStatusCode, TypeLen_t *pMsgLen,
 * TypePlainText_t *pMsgData );
 *
 * \brief  This function shall be used to decrypt ECIES encrypted data.
 * \details   The function shall be used to decrypt ECIES encrypted data using the Runtime private
 *            key associated with public key that was used for encryption of the original plain text message.
 * \pre V2X-SE is activated in normal operating phase
 * \param [in]    rtKeyId             The ID referring the persistent memory(NVM) slot containing the
 *                                    Runtime private key that must be used
 * \param  [in]   pEciesData          Pointer to structure containing the following data:
 *                                    KDF-Parameter(P1) length, KDF-Parameter Data,
 *                                    MAC length, MAC-Parameter(P2) Length, MAC-Parameter Data,
 *                                    VCT length and VCT data.
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    -  #V2XSE_WRONG_DATA: invalid rtKeyId or invalid KDF-Parameter(P1) length
 *                                       or invalid MAC length or invalid MAC-Parameter(P2) Length or invalid VCT
 *                                       length or rtKeyId refers to slot that does not contain private key
 *                                    -  #V2XSE_NVRAM_UNCHANGED: Runtime key is invalid
 *                                    -  #V2XSE_KEY_AGREEMENT_ERROR : Error during key agreement
 *                                    -  #V2XSE_TAG_CHECK_ERROR : Error during tag checking or calculation
 *
 * \param [out]  pMsgLen      The length of the decrypted data which shall be equal to
 *                            vct length - 64(V-ephemeral public key)- macLen bytes
 * \param [out]  pMsgData     The decrypted data
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark   ECIES shall be allowed only with 256 bit elliptic curves supported.
 * \ingroup v2xSe_ECIES
 */

int32_t v2xSe_decryptUsingRtEcies (TypeRtKeyId_t rtKeyId,
                                   TypeDecryptEcies_t *pEciesData,TypeSW_t *pHsmStatusCode, TypeLen_t *pMsgLen,
                                   TypePlainText_t *pMsgData );

/*! \fn int32_t v2xSe_decryptUsingMaEcies (TypeDecryptEcies_t  *pEciesData,, TypeSW_t *pHsmStatusCode,
 *    TypeLen_t *pMsgLen, TypePlainText_t *pMsgData );
 *
 * \brief  This function shall be used to decrypt ECIES encrypted data.
 * \details   The function shall be used to decrypt ECIES encrypted data using the Module Authentication
 *  private key .
 * \pre V2X-SE is activated in normal operating phase
 * \param  [in]   pEciesData          Pointer to structure containing the following data:
 *                                    KDF-Parameter(P1) length,KDF-Parameter Data, MAC length,
 *                                    MAC-Parameter(P2) Length, MAC-Parameter Data, VCT length and VCT data
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: invalid KDF-Parameter(P1) length or
 *                                       invalid MAC length or invalid MAC-Parameter(P2) Length or
 *                                       invalid VCT length
 *                                    - #V2XSE_NVRAM_UNCHANGED: Module Authentication key is not present
 *                                      or Module Authentication key is invalid(e.g. MA key is of 384 bit)
 *                                    - #V2XSE_KEY_AGREEMENT_ERROR : Error during key agreement
 *                                    - #V2XSE_TAG_CHECK_ERROR : Error during tag checking or calculation
 *
 *
 * \param [out]  pMsgLen              The length of the decrypted data which shall be equal to
 *                                    vct length - 64(V-ephemeral public key)- macLen bytes
 * \param [out]  pMsgData     The decrypted data
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not
 * activated return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark   ECIES shall be allowed only with 256 bit elliptic curves supported.
 * \ingroup v2xSe_ECIES
 */
int32_t v2xSe_decryptUsingMaEcies
(
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
);



/*! \fn int32_t v2xSe_decryptUsingBaEcies(TypeBaseKeyId_t baseKeyId, TypeDecryptEcies_t  *pEciesData,
 *  TypeSW_t *pHsmStatusCode, TypeLen_t *pMsgLen, TypePlainText_t *pMsgData );
 *
 * \brief  This function shall be used to decrypt ECIES encrypted data.
 * \details   The function shall be used to decrypt ECIES encrypted data using the Base private key
 *            associated with public key that was used for encryption of the orginal plain text message.
 * \pre V2X-SE is activated in normal operating phase
 *  \param [in]   baseKeyId           The ID referring the persistent memory(NVM) slot containing the
 *                                    Base private key that must be used
 * \param  [in]   pEciesData          Pointer to structure containing the following data:
 *                                    KDF-Parameter(P1) length, KDF-Parameter Data,
 *                                    MAC length, MAC-Parameter(P2) Length, MAC-Parameter Data,
 *                                    VCT length and VCT data
 * \param [out]   pHsmStatusCode      In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_WRONG_DATA: invalid baseKeyId or invalid KDF-Parameter(P1)
 *                                      length or invalid MAC length or invalid MAC-Parameter(P2) Length or
 *                                      invalid VCT length or baseKeyId refers to slot
 *                                      that does not contain private key
 *                                    - #V2XSE_NVRAM_UNCHANGED: Base key is invalid(e.g. Base key is of 384 bit)
 *                                    - #V2XSE_KEY_AGREEMENT_ERROR : Error during key agreement
 *                                    - #V2XSE_TAG_CHECK_ERROR : Error during tag checking or calculation
 *
 *
 * \param [out]  pMsgLen      The length of the decrypted data which shall be equal to
 *                            vct length - 64(V-ephemeral public key)- macLen bytes
 * \param [out]  pMsgData     The decrypted data
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 *  return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark   ECIES shall be allowed only with 256 bit elliptic curves supported.
 * \ingroup v2xSe_ECIES
 */
int32_t v2xSe_decryptUsingBaEcies
(
    TypeBaseKeyId_t baseKeyId,
    TypeDecryptEcies_t  *pEciesData,
    TypeSW_t *pHsmStatusCode,
    TypeLen_t *pMsgLen,
    TypePlainText_t *pMsgData
);







/*!
 * \fn int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID);
 * \brief This is an utility function to get public key length associated with curve ID
 * \param [in] curveID The ID of the ECC curve that is associated with public key
 * \return On success return length of key in bytes and on failure return #V2XSE_FAILURE
 * \remark
 * 1. ECC curves of 256 bits have Public key of  #V2XSE_256_EC_PUB_KEY bytes
 * 2. ECC curves of 384 bits have Public key of #V2XSE_384_EC_PUB_KEY bytes
 * \ingroup v2xSe_UTILITY
 */
int32_t v2xSe_getKeyLenFromCurveID(TypeCurveId_t curveID);

/*!
 * \fn int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength);
 * \brief This is an utility function to get signature length associated with length of message hash
 * \param [in] hashLength The length of hash that is associated with signature
 * \return On success return length of signature in bytes and on failure return #V2XSE_FAILURE
 * \remark
 * 1. Hash length of 32 bytes corresponds to Signature of #V2XSE_256_EC_COMP_SIGN bytes
 * 2. Hash length of 48 bytes corresponds to Signature of #V2XSE_384_EC_COMP_SIGN bytes
 * \ingroup v2xSe_UTILITY
 */
int32_t v2xSe_getSigLenFromHashLen(TypeHashLength_t hashLength);

/*!
 * \brief This is a device management function to exchange data with SE from Host Application processor
 * \details The function allows the packed data(command APDU) to be sent towards SE and read the response APDU from SE.
 * The main purpose this function is to support debugging and firmware update on SE.
 * \pre V2X-SE should be in connected or activated state, depending on the purpose of using this function
 * \param [in]  pTxBuf               Array containing the packed command APDU to be sent towards SE
 * \param [in]  txLen                Length of complete command to be sent, it includes command APDU header and Data fields
 * \param [out] pRxLen               Length of response data field from SE including the status bytes
 * \param [out] pRxBuf               Array containing response data received from SE. The size of the buffer should be at least #V2XSE_MAX_TX_RX_SIZE bytes.
 * \param [out] pHsmStatusCode       Status bytes returned from SE.
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE, if V2X-SE was not activated or connected
 * return #V2XSE_DEVICE_NOT_CONNECTED
 * \remark
 * 1. This function should not be used unless recommended by NXP.Improper usage could result in irreversible damage to SE
 * 2. This function does not support extended length command APDU(expected length - Le field exceeding 255 bytes)
 *    in which case function shall report #V2XSE_FAILURE
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_sendReceive(uint8_t *pTxBuf, uint16_t txLen,  uint16_t *pRxLen, uint8_t *pRxBuf,TypeSW_t *pHsmStatusCode);





/*!
 * \brief This function shall be used to store data in Generic storage applet
 * \pre V2X-SE is activated and Generic storage applet is selected during activation
 * \param [in]   index          Index associated with the data to be stored
 * \param [in]   length         Length of data to be stored. The valid range is from #V2XSE_MIN_DATA_SIZE_GSA to #V2XSE_MAX_DATA_SIZE_GSA bytes
 * \param [in]   pData          Array containing data to be stored, the size of this array should be at least same as length of data to be stored
 * \param [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                 - #V2XSE_FILE_FULL: free memory is not available
 *                                 - #V2XSE_WRONG_DATA: invalid index or invalid length
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_GenericStorage
 */
int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length, uint8_t  *pData,TypeSW_t *pHsmStatusCode);






/*!
 * \brief This function shall be used to get stored data from Generic storage applet
 * \pre V2X-SE is activated and Generic storage applet is selected during activation
 * \param [in]  index          Index associated with the data to be read from Generic storage applet
 * \param [out] pLength        Length of data retrieved from index specified
 * \param [out] pData          Array containing retrieved data from index specified. If the size of expected data is not known
 *                             then size of this array should be at least #V2XSE_MAX_DATA_SIZE_GSA bytes.
 * \param [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                              The function specific error codes is:
 *                              - #V2XSE_WRONG_DATA: invalid index or no data is available in the index specified
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_GenericStorage
 */
int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength, uint8_t *pData,TypeSW_t *pHsmStatusCode);




/*!
 * \brief This function shall be used to delete data from Generic storage applet
 * \pre V2X-SE is activated and Generic storage applet is selected during activation
 * \param [in]  index           Index associated with data to be deleted
 * \param [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                              The function specific error code is:
 *                              - #V2XSE_WRONG_DATA: invalid index or no data is available in the index specified
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \ingroup v2xSe_GenericStorage
 */
int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode);



/*!
 * \brief This function shall be used to invoke garbage collector
 * \pre V2X-SE is activated in normal operating phase
 * \param [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                              The function specific error codes are none.
 * \return On success return #V2XSE_SUCCESS, on failure #V2XSE_FAILURE and if V2X-SE was not activated
 * return #V2XSE_DEVICE_NOT_CONNECTED.
 * \remark It is recommended to execute this function to get back the memory associated with key or data storage,
 * after having performed significant delete operations. The latency of the function is dependent on the amount of
 * memory marked for trash cleaning and hence it should not be interleaved with critical functions.
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_invokeGarbageCollector(TypeSW_t *pHsmStatusCode);


/*!
 * \brief This is a device management function to get the amount of remaining(free) NVM(Non Volatile Memory) from SE
 * \pre V2X-SE should be in connected or activated state
 * \param [out]  pSize           Size of the remaining NVM of SE, represented in bytes
 * \param  [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                                    The function specific error codes are: None
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in connected
 *  state return #V2XSE_DEVICE_NOT_CONNECTED
 *  \remark This function should be used only as an indication of available memory. The actual amount of generic data or keys
 *  that can be stored is less than reported memory due to overhead caused by meta data.
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getRemainingNvm (uint32_t *pSize, TypeSW_t *pHsmStatusCode);

/*!
 * \brief This function shall be used to end the key injection phase of SE
 * \pre V2X-SE is activated in key injection phase and initial security level used in
 *  v2xSe_activateWithSecurityLevel() is #e_channelSecLevel_5
 * \param  [out] pHsmStatusCode  In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_SECURITY_STATUS_NOT_SATISFIED: Incorrect security level
 *                                    - #V2XSE_FUNC_NOT_SUPPORTED: Function is not supported (Key injection phase is closed)
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in connected
 *  state return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_KeyInjection
 */
int32_t v2xSe_endKeyInjection (TypeSW_t *pHsmStatusCode);

/*!
 * \brief This function shall be used to get phase of SE
 * \pre V2X-SE is in activated state and the initial security level used in v2xSe_activateWithSecurityLevel() / v2xSe_activate()
 *  is #e_channelSecLevel_5
 * \param  [out] pPhaseInfo     The pointer indicating the V2X SE phase. When the function is executed successfully, the value
 *                              shall mean:
 *                                  - #V2XSE_KEY_INJECTION_PHASE: V2X SE is in key injection phase
 *                                  - #V2XSE_NORMAL_OPERATING_PHASE: V2X SE is in normal operating phase
 * \param  [out] pHsmStatusCode In case of an error, this code provides detailed information.
 *                                    The function specific error codes are:
 *                                    - #V2XSE_SECURITY_STATUS_NOT_SATISFIED: Incorrect security level
 * \return On success return #V2XSE_SUCCESS, on failure return #V2XSE_FAILURE and if V2X-SE is not in connected
 *  state return #V2XSE_DEVICE_NOT_CONNECTED
 * \ingroup v2xSe_DeviceManagement
 */
int32_t v2xSe_getSePhase (uint8_t *pPhaseInfo, TypeSW_t *pHsmStatusCode);
/******************************************************************************
 * DOXYGEN MAIN PAGE CONTENTS
 *****************************************************************************/

/*! \mainpage V2X Crypto API
 * \section Revision_History Revision History
 * Revision | Date                  | Description
 * ---------|-----------------------|-----------------
 * 3.7      | 20190401              | Documentation update for error code 0x6F00 and removal of duplicate error definitions
 * 3.6      | 20190116              | v2xSe_sendReceive() description modification: Length parameter includes status bytes
 * 3.5      | 20181211              | Removal of key injection functions
 * 3.4      | 20180827              | Addition of key injection functions
 * 3.3      | 20180802              | Update of description in ecies and reset functions, extension of TypeAttackLog_t structure element, support of v2xSe_invokeGarbageCollector()in V2X applet, doxygen main page documentation update
 * 3.2      | 20180406              | Correct of error code definition, Modification of of error code for v2xSe_getAttackLog(), removal of internal authentication function, Removal of TLV based reporting of response
 * 3.1      | 20180223              | Addition of internal authentication function.Update of secure messaging section and precondition for JCOP specific functions.Change in functionality of v2xSe_activate(),v2xSe_connect() and v2xSe_deactivate().
 * 3.0      | 20180125              | Additional error codes included in decrypt using ecies functions, function to invoke garbage collector added
 * 2.9      | 20180110              | Generic Storage functions and associated data types added
 * 2.8      | 20171202              | v2xSe_generateRtEccKeyPair() description updated to indicate support for only 256 bit ECC curves
 * 2.7      | 20171128              | Removed typedef for v2xSe_sendReceive(), added error precedence section, added details for error reporting
 * 2.6      | 20170914              | Updated v2xSe_createRtSign(), v2xSe_getSeInfo(), v2xSe_deriveRtEccKeyPair() and renamed Base key related functions.
 * 2.5      | 20170816              | Removed key activation part from v2xSe_createRtSign()
 * 2.4      | 20170811              | Modification of v2xSe_deriveRtEccKeyPair(), v2xSe_getSeInfo() and removal of v2xSe_isVirgin()
 * 2.3      | 20170807              | Modification of v2xSe_getSeInfo(), v2xSe_deriveRtEccKeyPair() and utility functions
 * 2.2      | 20170801              | Structure for getSeInfo updated - includes all parameters
 * 2.1      | 20170727              | Review rework, update of getSeInfo function
 * 2.0      | 20170726              | Change of Functions to accommodate evolving V2X Standards
 * 1.0      | 20170713              | Function names modified for Pseudo and Caterpillar key, Error code added for generatePsEccKeyPair function
 * 0.9      | 20170626              | Explicit mention of minimum size of message, length for sendReceive is now uint16_t type
 * 0.8      | 20170623              | Parameter corrected for v2xSe_decryptUsingEcies
 * 0.7      | 20170616              | Modified Pseudo Signature function description to indicate pseudo key being used is activated via a function
 * 0.6      | 20170517              | Activate function parameter change, v2xSe_getWrapperVersion name changed to v2xSe_getCryptoLibVersion
 * 0.5      | 20170404              | Removed: Decompression and Reconstruction function, Activate function updated
 * 0.4      | 20170404              | Removed setChannelSecurity function, additional field added for getSeConfig function
 * 0.3      | 20170323              | Added more information in structure used for ECIES
 * 0.2      | 20170320              | Update after rework of review comments
 * 0.1      | 20170317              | Initial version for review
 *
 * \section Introduction
 * This document provides detailed description of API supported by V2X Crypto library on host.
 * Typical functionalities performed by V2X Crypto  are:
 * - \ref v2xSe_DeviceManagement : Initialization, versioning, firmware updates, phase of SE
 * - \ref v2xSe_KeyManagement :    Key generation, derivation, activation, public key calculation,
 *                                 and key deletion
 * - \ref v2xSe_Signature :        Signature creation and verification
 * - \ref v2xSe_ECIES :            Encryption and decryption of data using ECIES
 * - \ref v2xSe_UTILITY :          Random number generation, get key and signature lengths from curve ID and hash length
 * - \ref v2xSe_GenericStorage :    Store, retrieve and delete data

 * \section Key_types Key types
 * The ECC keys that are generated and stored in persistent memory are:
 * - Module Authentication key  - Only one key per region for lifetime of SE. The keys are used for ECIES and ECDSA schemes.
 *                                It is not possible to modify the keys once generated.
 * - Base key                   - Depending on available memory, the number of keys could be up to 10K. The keys are used
 *                                for run-time key derivation, ECDSA signing and ECIES schemes. It is possible to update or delete
 *                                these keys.
 * - Runtime keys               - Depending on available memory, the number of keys could be up to 10K,
 *                                these keys are for ECDSA signing and ECIES schemes. It is possible to update or
 *                                delete these keys.
 * \remark: Base key and Runtime keys together can be maximum of 10K on the SE
 *
 *
 * \section Supported_elliptical_curves Supported elliptic curves
 * The elliptic curves supported by V2X-SE shall be referred via "Curve IDs" as indicated below:
 * Curve ID | Identifier            | Curve
 * ---------|-----------------------|-----------------
 * 0        | #V2XSE_CURVE_NISTP256 | NIST256P
 * 1        | #V2XSE_CURVE_BP256R1  | BrainpoolP256r1
 * 2        | #V2XSE_CURVE_BP256T1  | BrainpoolP256t1
 * 3        | #V2XSE_CURVE_NISTP384 | NIST384P
 * 4        | #V2XSE_CURVE_BP384R1  | BrainpoolP384r1
 * 5        | #V2XSE_CURVE_BP384T1  | BrainpoolP384t1
 *
 * \section Curves_and_associated_key_lengths  Curves and associated key lengths
 * - 256 bit curve(NIST256P, BrainpoolP256r1, BrainpoolP256t1): Private key shall be of 32 bytes length and
 *   Public key of 64 bytes length
 * - 384 bit curve(NIST384P, BrainpoolP384r1, BrainpoolP384t1): Private key shall be of 48 bytes length and
     Public key of 96 bytes length

 * Except Runtime ECC keys, it shall be possible to generate all other key types with 256 bit and 384 bit
 * curve. Runtime ECC keys can only be generated/derived with 256 bit ECC curve.
 *\section LifeCycle Phases of V2X-SE
 * The functionalities supported by V2X-SE depends on the phase in which V2X-SE is currently in.
 * The phase can be determined by v2xSe_getSePhase().
 * \subsection KEY_INJECTION_PHASE Key injection phase
 * In this phase, the private keys of all key types - MA, Base and Runtime keys shall be allowed to be injected into V2X-SE.
 * This phase requires the highest level of security #e_channelSecLevel_5 to be used for communication
 * with V2X-SE. During this phase the following limited set of functionalities can be accessed:
 * 1. V2X specific functions related to key injection
 *  - v2xSe_endKeyInjection()
 * 2. V2X specific functions not related to key injection
 *  - v2xSe_getAppletVersion()
 *  - v2xSe_getSeInfo()
 *  - v2xSe_getRandomNumber()
 *  - v2xSe_getMaEccPublicKey()
 *  - v2xSe_getRtEccPublicKey()
 *  - v2xSe_getBaEccPublicKey()
 *  - v2xSe_storeData()
 *  - v2xSe_getData()
 *  - v2xSe_deleteData()
 *  - v2xSe_getSePhase()
 * 3. All JCOP specific functions
 *  - v2xSe_getPlatformInfo()
 *  - v2xSe_getPlatformConfig()
 *  - v2xSe_getChipInfo()
 *  - v2xSe_getAttackLog()
 * \subsection NORMAL_PHASE Normal operating phase
 * This phase of V2X-SE shall  be entered only upon closing the key injection phase by v2xSe_endKeyInjection().
 * The movement from key injection phase to normal phase is irreversible. During this phase the complete set of V2X Crypto API functions
 * (except key injection functions)would be accessible. The restriction of initial security level to be at #e_channelSecLevel_5
 * does not apply in this phase. This essentially means, the initial security level could be any of the supported security levels
 * defined. Please refer user manual for more details on secure channel and associated security levels.
 * \section Signature  Signature
 * The length of created signature shall vary(0x41 bytes or 0x61 bytes) depending on the ECC curve associated
 * with keys. The signature shall consist of compressed R.y[0] along with r and s part of signature. The R.y[0] is the bit '0' of MSB byte of Y coordinate
 * which shall be used for fast signature verification.
 *
 * \section Hash Hash Lengths
 * - 256 bit elliptic curve: Hash length shall be 32 bytes
 * - 384 bit elliptic curve: Hash length shall be 48 bytes
 *
 * \section APDU Application protocol data unit (APDU)
 * V2X-SE shall adhere to APDU format specified in ISO7816-4 T=1 protocol specification.
 * The error indicated via status bytes SW1 and SW2 shall be as per this specification.
 * This section is not required to be considered for usage of functionalities supported by V2X Crypto Library, however
 * could be used to analyze the SPI transfers.
 * \subsection APDU_TYPES APDU types
 * - Short length APDUs: The number of bytes in command data field and response data field do not exceed 255 bytes.
 * In this case, LC and LE fields are represented in one byte each.
 * - Extended length APDUs: The number of bytes in command data field or response data field exceed 255 bytes.
 * In this case, LC shall be represented in three bytes, first byte being 0x00 and next two bytes representing
 * length of command data field and LE field shall be represented in two bytes representing length of expected
 * response.
 * \remark V2X-SE supports short length APDUs for command and response while extended length is supported only for command.
 * \subsection APDU_Endianness APDU_Endianness
 * The endianness at APDU level is big endian for all fields. That means that the most significant byte (MSB)
 *  will be transferred first (array index 0).
 *
 *
 * \subsection CLA   CLA byte coding
 *
 * CLA  | description
 * -----|-----------------------
 * 0x80 | No Secure Messaging
 * 0x84 | Secure Messaging with C-MAC as minimum
 *
 * \subsection INS   INS byte coding range
 *
 * INS  | description
 * -----|-----------------------
 * 0x00 | Device Management
 * 0x10 | MA Key Management
 * 0x20 | Base Key Management
 * 0x30 | Runtime Key Management
 * 0x40 | ECIES
 * 0x50 | Signature generation
 * 0x60 | Utility function
 * 0x80 | Generic Storage functions
 *
 * \subsection P1_P2_coding  P1 & P2 coding
 * P1 and P2 are set as zeros for V2X applet and for GSA these fields are used to encode command specific information.
 * In case of V2X applet, the values of these two fields are ignored.
 *
 * \section TPDU Transport protocol data unit (TPDU)
 * V2X-SE shall adhere to TPDU format defined by SPI T=1 protocol specification version 3.1.
 * The endianness at TPDU level is big endian for all fields. That means that the most significant byte
 * (MSB) will be transferred first (array index 0)
 *
 *\section Error_codes Error Codes and Function returns
 *\subsection common_error_codes Common error codes associated with HSM Status code
 *
 * Value  | Identifier | Description
 * -------|-------------------------------------|-------------------
 * 0x9000 | #V2XSE_NO_ERROR | The function completed successfully
 * 0x6E00 | #V2XSE_CLA_NOT_SUPPORTED | CLA value not supported
 * 0x6D00 | #V2XSE_INS_NOT_SUPPORTED | INS value not supported
 * 0x6700 | #V2XSE_WRONG_LENGTH | Invalid length specified as part of Lc or Le fields
 * 0x6A80 | #V2XSE_WRONG_DATA | Command data field contains wrong data
 * 0x6400 | #V2XSE_NVRAM_UNCHANGED | Internal execution error and the NVRAM is unchanged
 * 0x6F00 | #V2XSE_NO_PRECISE_DIAGNOSIS | Generic error when exception occurred but no precise diagnosis is available or when private key is not valid, for example when injected private key is out of the range("1 to n-1" where n is order of the elliptic curve)
 * 0x6985 | #V2XSE_CONDITIONS_NOT_SATISFIED | Condition of use not satisfied
 * 0x6A84 | #V2XSE_FILE_FULL | No more memory available
 * 0x6581 | #V2XSE_MEMORY_FAILURE | EEPROM errors, one or more cells defective
 * 0x6982 | #V2XSE_SECURITY_STATUS_NOT_SATISFIED | Security of command not satisfied, could be due to secure channel specific errors or security domain associated with applets is locked
 * 0x6310 | #V2XSE_PROCESS_COMP_WITH_WARNING | Process completed with warning
 * 0x6A88 | #V2XSE_REF_DATA_NOT_FOUND | Reference keys to be used for secure messaging not found
 * 0x6300 | #V2XSE_AUTHENTICATION_FAILED | Authentication of host cryptogram failed
 * 0x6882 | #V2XSE_SECMSG_NOT_SUPPORTED | Secure messaging not supported
 * 0x6A81 | #V2XSE_FUNC_NOT_SUPPORTED | Function not supported as per Life cycle
 * 0x6A82 | #V2XSE_APP_MISSING | Selected Application/file not found
 * 0x66A5 | #V2XSE_RESTRICTED_MODE | Card has entered restricted mode
 * 0x6999 | #V2XSE_SSD_LOCKED | Security domain locked
 * 0x6F01 | #V2XSE_KEY_AGREEMENT_ERROR | Error during key agreement step of ECIES function
 * 0x6F02 | #V2XSE_TAG_CHECK_ERROR | Error during key tag checking or tag calculation step of ECIES function
 * 0x6F03 | #V2XSE_SCP03_KEYFILE_ERROR | Error associated with key file - missing file, invalid key length or invalid number of keys
 * 0x6F04 | #V2XSE_SCP03_SESSIONKEY_ERROR | Session key derivation failed
 * 0x6F05 | #V2XSE_SCP03_CARDCRYPTO_ERROR | Card cryptogram verification failed
 * 0x6F06 | #V2XSE_SCP03_HOSTCRYPTO_ERROR | Host cryptogram calculation failed
 * 0x6F07 | #V2XSE_AUTH_CTR_ERROR | SCP03 sequence counter has reached maximum value
 * 0x6F08 | #V2XSE_FAILURE_CHALLENGE_ERROR | Invalid or old host challenge
 * 0x6881 | #V2XSE_INACTIVE_CHANNEL | Logical channel is inactive or not supported
 * 0x0000 | #V2XSE_UNDEFINED_ERROR | Undefined error occurred (for example, fatal communication error)
 *
 *\subsection States V2X-SE States
 * The following states are visible to the user of V2X Crypto API
 *
 * INIT: This is the initial state after starting the application or after  v2xSe_reset() or v2xSe_deactivate(). During any state transition
 * if there is an error, the state will be set to INIT by host SW.

 * CONNECTED: The state transition from INIT to CONNECTED state is triggered by v2xSe_connect().
 * It opens SPI T=1 channel between Host and SE. This state can be used to access JCOP specific functions.
 * This state is also used for JCOP and Applet update process.
 *
 * ACTIVATED: The state transition from INIT to ACTIVATED state is triggered by v2xSe_activate().
 * SPI T=1 channel is opened between HOST and SE. The key activities done during this state transition
 * are set up of logical channels, selection of Applet & JCOP, set up of secure channel session for
 * the logical channels used by applets(V2X, Generic storage). Successful activation of SE is a pre-condition for processing of all
 * V2X and generic storage specific commands from HOST AP. JCOP specific functions are also accesible from this state.

 * The user visible states of V2X-SE and their state transitions are captured in the below diagram.
 *
 * \image html userVisibleStates.png "State transitions"
 * \image latex userVisibleStates.png "State transitions"
 * \remark
 * - The transitions resulting in error response are captured in red color
 * - v2xSe_deactivate() should be called before exiting the application
 * - It should be ensured that v2xSe_activate() is called from init state
 *  -During the valid(other than red colored ones) state transition, if any error occurs then
 *   error state is entered, it is recommended to use v2xSe_reset() or follow the
 *   recovery procedure mentioned in user manual
 *
 *\subsection CommonFunctionReturn Common function return values
 * value  | identifier     | description
 * -------|----------------|----------------------------------------
 *  0     | #V2XSE_SUCCESS | The function completed successfully
 * -1     | #V2XSE_FAILURE | The function executed with failure
 * -2     | #V2XSE_DEVICE_NOT_CONNECTED | The function was not executed because of missing v2xSe_connect() or v2xSe_activate()
 * -3     | #V2XSE_FAILURE_CONNECTED | The function is not allowed in connected state of SE
 * -4     | #V2XSE_FAILURE_ACTIVATED | The function is not allowed in activated state of SE
 * -5     | #V2XSE_FAILURE_INIT | The function is not allowed in init state of SE
 *
 *Refer below table for details of function return and HSM status codes in different scenarios
 * States                | Commands following the Action     | Function Return          | HSM Status code
 * ----------------------|-----------------------------------|--------------------------|---------------------
 * INIT                  |JCOP specific                      |V2XSE_NOT_CONNECTED       |V2XSE_UNDEFINED_ERROR
 * INIT                  |Applet specific                    |V2XSE_NOT_CONNECTED       |V2XSE_UNDEFINED_ERROR
 * CONNECTED             |JCOP specific                      |V2XSE_SUCCESS             |V2XSE_SW_NO_ERROR
 * CONNECTED             |Applet specific                    |V2XSE_FAILURE             |V2XSE_INS_NOT_SUPPORTED / V2XSE_INACTIVE_CHANNEL
 * ACTIVATED             |JCOP specific                      |V2XSE_SUCCESS             |V2XSE_SW_NO_ERROR
 * ACTIVATED             |Applet specific                    |V2XSE_SUCCESS             |V2XSE_SW_NO_ERROR
 *
 *\remark If the function return is #V2XSE_FAILURE and HSM status code is #V2XSE_UNDEFINED_ERROR, it is recommended
 *to follow recovery procedure mentioned in user manual.

 *\subsection Error_Precedence Error Precedence in V2X Crypto API
 *There is no check done by V2X Crypto library for correctness of the input and output function parameters.
 *In all functions supported(where ever applicable), the error reported by SE firmware through status bytes
 * is captured in output variable "HSM Status code" without further modification. As the APDU is encapsulated
 * within the TPDU, the correctness of TPDU is checked by firmware on SE followed by correctness of APDU command and then
 * individual parameter of command data field. It is important to note that correctness of LE field
 * of the command is not checked by firmware on SE. The function return is #V2XSE_SUCCESS only when
 * the status bytes returned by firmware on SE has the value #V2XSE_NO_ERROR.
 *
 *
 * \section API V2X Crypto API
 *
 * \subsection Endianness Endianness
 * - V2X Crypto library supports only little-Endian architecture.
 * - The endianness of standard types like int, short will dependent on the processor architecture.
 * - Big-Endian is used for byte arrays unless specified otherwise. That means that the most significant
 *   byte (MSB) will be at array index 0.
 *
 *
 * \subsection Abbreviation Abbreviations and acronyms
 *
 * abbreviation | description
 * -------------|------------------------------------------------
 * V2X          | Vehicle to "X"(Vehicle or Road side unit)
 * SE           | Secure Element
 * ECIES        | Elliptic Curve Integrated Encryption Scheme
 * ECDSA        | Elliptic Curve Digital Signature Algorithm
 * EN           | Enrollment
 * MA           | Module Authentication
 * SPI          | Serial Peripheral Interface
 * SCP          | Secure Channel Protocol
 * KDF          | Key Derivation Function
 * MAC          | Message Authentication code
 * JCOP         | Java Card Open Platform operating system
 * NVM          | Non Volatile Memory
 *
 *
 * \section References  Referred documents
 * -# JCOP4.0 user manual: Internal document
 * -# ISO/IEC International Standard 7816: "Identification cards - Integrated circuit(s) cards with
 *   contacts - Part 4: Interindustry commands for interchange", 2005
 * -# GlobalPlatform Card Technology Secure Channel Protocol 03,Card Specification v2.2 Amendment D
 * -# GlobalPlatform Card Specification Version 2.2.1
 *
 *
 * \section CopyRight Copyright Information
 * (c) NXP B.V. 2017 All rights reserved.
 * All rights reserved. Reproduction in whole or in part is prohibited without the prior written consent of the
 * copyright owner.The information presented in this document does not form part of any quotation or contract,
 * is believed to be accurate and reliable and maybe changed without notice. No liability will be accepted by
 * the publisher for any consequence of its use. Publication thereof does not convey nor imply any license under
 * patent- or other industrial or intellectual property rights.
 * \subsection Disclaimer
 * - General - Information in this document is believed to be accurate and reliable. However, NXP does not give
 *  any representations or warranties, expressed or implied, as to the accuracy or completeness of such
 *  information and shall have no liability for the consequences of use of such information.
 * - Right to make changes - NXP reserves the right to make changes to information published in this document,
 *  including without limitation software, specifications and product descriptions, at any time and without
 *  notice. This document supersedes and replaces all information supplied prior to the publication hereof.
 * - Suitability for use - NXP products, including software are not designed, authorized or warranted to be
 *   suitable for use in medical, military, aircraft, space or life support equipment, nor in applications
 *   where failure or malfunction of a NXP product including software can reasonably be expected to result
 *   in personal injury, death or severe property or environmental damage. NXP accepts no liability for
 *   inclusion and/or use of NXP products including software in such equipment or applications and therefore
 *   such inclusion and/or use is for the customer's own risk.
 * - Applications - Applications that are described herein for any of these products are for illustrative
 *   purposes only. NXP makes no representation or warranty that such applications will be suitable for the
 *   specified use without further testing or modification.
 *
 */


/*!
 * \defgroup v2xSe_DeviceManagement Device Management
 * \brief Device Management functions
 *
 * \defgroup v2xSe_KeyManagement Key Management
 * \brief Key Management functions
 *
 * \defgroup v2xSe_Signature Signature
 * \brief Signature generation functions
 *
 * \defgroup v2xSe_ECIES ECIES
 * \brief ECIES encryption and decryption functions
 *
 * \defgroup v2xSe_GenericStorage Generic data storage
 * \brief Functions to store and read generic data from the V2X-SE
 *
 * \defgroup v2xSe_UTILITY Utility
 * \brief Functions to get key length from curve ID and get signature length from hash length
 *
 *
 * \defgroup v2xSe_KeyInjection Key Injection
 * \brief Key injection functions
 */


#endif
