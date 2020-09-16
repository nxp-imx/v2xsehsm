/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * Copyright 2019-2020 NXP
 */

/*
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
 * @file trace.h
 *
 * @brief LTTng trace definitions for v2xsehsm adaptation layer
 *
 */

#if !defined(TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
/** Include this file once, or more if required by LTTng framework */
#define TRACE_H

/* Need to define ENABLE_LTTNG in compiler options to enable tracing */
#ifdef ENABLE_LTTNG

/** Name of tracepoint provider, used by LTTng framework */
#define TRACEPOINT_PROVIDER v2xsehsm
/** Name of this file, used by LTTng framework */
#define TRACEPOINT_INCLUDE "./trace.h"

#include <lttng/tracepoint.h>


/* Profiling IDs for v2xSe API calls: format 0x01xx */

/** Profiling ID for v2xSe_connect */
#define PROFILE_ID_V2XSE_CONNECT				0x0101
/** Profiling ID for v2xSe_activate */
#define PROFILE_ID_V2XSE_ACTIVATE				0x0102
/** Profiling ID for v2xSe_activateWithSecurityLevel */
#define PROFILE_ID_V2XSE_ACTIVATEWITHSECURITYLEVEL		0x0103
/** Profiling ID for v2xSe_reset */
#define PROFILE_ID_V2XSE_RESET					0x0104
/** Profiling ID for v2xSe_deactivate */
#define PROFILE_ID_V2XSE_DEACTIVATE				0x0105
/** Profiling ID for v2xSe_disconnect */
#define PROFILE_ID_V2XSE_DISCONNECT				0x0106
/** Profiling ID for v2xSe_generateMaEccKeyPair */
#define PROFILE_ID_V2XSE_GENERATEMAECCKEYPAIR			0x0107
/** Profiling ID for v2xSe_getMaEccPublicKey */
#define PROFILE_ID_V2XSE_GETMAECCPUBLICKEY			0x0108
/** Profiling ID for v2xSe_createMaSign */
#define PROFILE_ID_V2XSE_CREATEMASIGN				0x0109
/** Profiling ID for v2xSe_generateRtEccKeyPair */
#define PROFILE_ID_V2XSE_GENERATERTECCKEYPAIR			0x010A
/** Profiling ID for v2xSe_deleteRtEccPrivateKey */
#define PROFILE_ID_V2XSE_DELETERTECCPRIVATEKEY			0x010B
/** Profiling ID for v2xSe_getRtEccPublicKey */
#define PROFILE_ID_V2XSE_GETRTECCPUBLICKEY			0x010C
/** Profiling ID for v2xSe_createRtSignLowLatency */
#define PROFILE_ID_V2XSE_CREATERTSIGNLOWLATENCY			0x010D
/** Profiling ID for v2xSe_createRtSign */
#define PROFILE_ID_V2XSE_CREATERTSIGN				0x010E
/** Profiling ID for v2xSe_generateBaEccKeyPair */
#define PROFILE_ID_V2XSE_GENERATEBAECCKEYPAIR			0x010F
/** Profiling ID for v2xSe_deleteBaEccPrivateKey */
#define PROFILE_ID_V2XSE_DELETEBAECCPRIVATEKEY			0x0110
/** Profiling ID for v2xSe_getBaEccPublicKey */
#define PROFILE_ID_V2XSE_GETBAECCPUBLICKEY			0x0111
/** Profiling ID for v2xSe_createBaSign */
#define PROFILE_ID_V2XSE_CREATEBASIGN				0x0112
/** Profiling ID for v2xSe_deriveRtEccKeyPair */
#define PROFILE_ID_V2XSE_DERIVERTECCKEYPAIR			0x0113
/** Profiling ID for v2xSe_activateRtKeyForSigning */
#define PROFILE_ID_V2XSE_ACTIVATERTKEYFORSIGNING		0x0114
/** Profiling ID for v2xSe_getAppletVersion */
#define PROFILE_ID_V2XSE_GETAPPLETVERSION			0x0115
/** Profiling ID for v2xSe_getRandomNumber */
#define PROFILE_ID_V2XSE_GETRANDOMNUMBER			0x0116
/** Profiling ID for v2xSe_getSeInfo */
#define PROFILE_ID_V2XSE_GETSEINFO				0x0117
/** Profiling ID for v2xSe_getCryptoLibVersion */
#define PROFILE_ID_V2XSE_GETCRYPTOLIBVERSION			0x0118
/** Profiling ID for v2xSe_getPlatformInfo */
#define PROFILE_ID_V2XSE_GETPLATFORMINFO			0x0119
/** Profiling ID for v2xSe_getPlatformConfig */
#define PROFILE_ID_V2XSE_GETPLATFORMCONFIG			0x011A
/** Profiling ID for v2xSe_getChipInfo */
#define PROFILE_ID_V2XSE_GETCHIPINFO				0x011B
/** Profiling ID for v2xSe_getAttackLog */
#define PROFILE_ID_V2XSE_GETATTACKLOG				0x011C
/** Profiling ID for v2xSe_encryptUsingEcies */
#define PROFILE_ID_V2XSE_ENCRYPTUSINGECIES			0x011D
/** Profiling ID for v2xSe_decryptUsingRtEcies */
#define PROFILE_ID_V2XSE_DECRYPYUSINGRTECIES			0x011E
/** Profiling ID for v2xSe_decryptUsingMaEcies */
#define PROFILE_ID_V2XSE_DECRYPTUSINGMAECIES			0x011F
/** Profiling ID for v2xSe_decryptUsingBaEcies */
#define PROFILE_ID_V2XSE_DECRYPTUSINGBAECIES			0x0120
/** Profiling ID for v2xSe_getKeyLenFromCurveID */
#define PROFILE_ID_V2XSE_GETKEYLENFROMCURVEID			0x0121
/** Profiling ID for v2xSe_getSigLenFromHashLen */
#define PROFILE_ID_V2XSE_GETSIGLENFROMHASHLEN			0x0122
/** Profiling ID for v2xSe_sendReceive */
#define PROFILE_ID_V2XSE_SENDRECEIVE				0x0123
/** Profiling ID for v2xSe_storeData */
#define PROFILE_ID_V2XSE_STOREDATA				0x0124
/** Profiling ID for v2xSe_getData */
#define PROFILE_ID_V2XSE_GETDATA				0x0125
/** Profiling ID for v2xSe_deleteData */
#define PROFILE_ID_V2XSE_DELETEDATA				0x0126
/** Profiling ID for v2xSe_invokeGarbageCollector */
#define PROFILE_ID_V2XSE_INVOKEGARBAGECOLLECTOR			0x0127
/** Profiling ID for v2xSe_getRemainingNvm */
#define PROFILE_ID_V2XSE_GETREMAININGNVM			0x0128
/** Profiling ID for v2xSe_endKeyInjection */
#define PROFILE_ID_V2XSE_ENDKEYINJECTION			0x0129
/** Profiling ID for v2xSe_getSePhase */
#define PROFILE_ID_V2XSE_GETSEPHASE				0x012A
/** Profiling ID for v2xSe_getKekPublicKey */
#define PROFILE_ID_V2XSE_GETKEKPUBLICKEY			0x012B
/** Profiling ID for v2xSe_injectMaEccPrivateKey */
#define PROFILE_ID_V2XSE_INJECTMAECCPRIVATEKEY			0x012C
/** Profiling ID for v2xSe_injectRtEccPrivateKey */
#define PROFILE_ID_V2XSE_INJECTRTECCPRIVATEKEY			0x012D
/** Profiling ID for v2xSe_injectBaEccPrivateKey */
#define PROFILE_ID_V2XSE_INJECTBAECCPRIVATEKEY			0x012E
/** Profiling ID for v2xSe_generateRtSymmetricKey */
#define PROFILE_ID_V2XSE_GENERATERTSYMMETRICKEY			0x012F
/** Profiling ID for v2xSe_deleteRtRtSymmetricKey */
#define PROFILE_ID_V2XSE_DELETERTSYMMETRICKEY			0x0130
/** Profiling ID for v2xSe_encryptUsingRtCipher */
#define PROFILE_ID_V2XSE_ENCRYPTUSINGRTCIPHER			0x0131
/** Profiling ID for v2xSe_decryptUsingRtCipher */
#define PROFILE_ID_V2XSE_DECRYPYUSINGRTCIPHER			0x0132
/** Profiling ID for v2xSe_encryptUsingSm2Eces */
#define PROFILE_ID_V2XSE_ENCRYPTUSINGSM2ECES			0x0133
/** Profiling ID for v2xSe_decryptUsingRtSm2Eces */
#define PROFILE_ID_V2XSE_DECRYPTUSINGRTSM2ECES			0x0134
/** Profiling ID for v2xSe_decryptUsingMaSm2Eces */
#define PROFILE_ID_V2XSE_DECRYPTUSINGMASM2ECES			0x0135
/** Profiling ID for v2xSe_decryptUsingBaSm2Eces */
#define PROFILE_ID_V2XSE_DECRYPTUSINGBASM2ECES			0x0136
/** Prodiling ID for v2xSe_sm2_get_z */
#define PROFILE_ID_V2XSE_SM2_GET_Z				0x0137

/* Profiling IDs for HSM API calls: format 0x02xx */

/** Profiling ID for hsm_open_session */
#define PROFILE_ID_HSM_OPEN_SESSION				0x0201
/** Profiling ID for hsm_close_session */
#define PROFILE_ID_HSM_CLOSE_SESSION				0x0202
/** Profiling ID for hsm_open_key_store_service */
#define PROFILE_ID_HSM_OPEN_KEY_STORE_SERVICE			0x0203
/** Profiling ID for hsm_close_key_store_service */
#define PROFILE_ID_HSM_CLOSE_KEY_STORE_SERVICE			0x0204
/** Profiling ID for hsm_generate_key */
#define PROFILE_ID_HSM_GENERATE_KEY				0x0205
/** Profiling ID for hsm_manage_key */
#define PROFILE_ID_HSM_MANAGE_KEY				0x0206
/** Profiling ID for hsm_manage_key_group */
#define PROFILE_ID_HSM_MANAGE_KEY_GROUP				0x0207
/** Profiling ID for hsm_open_key_management_service */
#define PROFILE_ID_HSM_OPEN_KEY_MANAGEMENT_SERVICE		0x0208
/** Profiling ID for hsm_butterfly_key_expansion */
#define PROFILE_ID_HSM_BUTTERFLY_KEY_EXPANSION			0x0209
/** Profiling ID for hsm_close_key_management_service */
#define PROFILE_ID_HSM_CLOSE_KEY_MANAGEMENT_SERVICE		0x020A
/** Profiling ID for hsm_open_cipher_service */
#define PROFILE_ID_HSM_OPEN_CIPHER_SERVICE			0x020B
/** Profiling ID for hsm_cipher_one_go */
#define PROFILE_ID_HSM_CIPHER_ONE_GO				0x020C
/** Profiling ID for hsm_ecies_decryption */
#define PROFILE_ID_HSM_ECIES_DECRYPTION				0x020D
/** Profiling ID for hsm_open_signature_generation_service */
#define PROFILE_ID_HSM_OPEN_SIGNATURE_GENERATION_SERVICE	0x020E
/** Profiling ID for hsm_close_cipher_service */
#define PROFILE_ID_HSM_CLOSE_CIPHER_SERVICE			0x020F
/** Profiling ID for hsm_generate_signature */
#define PROFILE_ID_HSM_GENERATE_SIGNATURE			0x0210
/** Profiling ID for hsm_prepare_signature */
#define PROFILE_ID_HSM_PREPARE_SIGNATURE			0x0211
/** Profiling ID for hsm_open_signature_verification_service */
#define PROFILE_ID_HSM_OPEN_SIGNATURE_VERIFICATION_SERVICE	0x0212
/** Profiling ID for hsm_verify_signature */
#define PROFILE_ID_HSM_VERIFY_SIGNATURE				0x0213
/** Profiling ID for hsm_import_public_key */
#define PROFILE_ID_HSM_IMPORT_PUBLIC_KEY			0x0214
/** Profiling ID for hsm_close_signature_verification_service */
#define PROFILE_ID_HSM_CLOSE_SIGNATURE_VERIFICATION_SERVICE	0x0215
/** Profiling ID for hsm_open_rng_service */
#define PROFILE_ID_HSM_OPEN_RNG_SERVICE				0x0216
/** Profiling ID for hsm_close_rng_service */
#define PROFILE_ID_HSM_CLOSE_RNG_SERVICE			0x0217
/** Profiling ID for hsm_get_random */
#define PROFILE_ID_HSM_GET_RANDOM				0x0218
/** Profiling ID for hsm_open_hash_service */
#define PROFILE_ID_HSM_OPEN_HASH_SERVICE			0x0219
/** Profiling ID for hsm_close_hash_service */
#define PROFILE_ID_HSM_CLOSE_HASH_SERVICE			0x021A
/** Profiling ID for hsm_hash_one_go */
#define PROFILE_ID_HSM_HASH_ONE_GO				0x021B
/** Profiling ID for hsm_pub_key_reconstruction */
#define PROFILE_ID_HSM_PUB_KEY_RECONSTRUCTION			0x021C
/** Profiling ID for hsm_pub_key_decompression */
#define PROFILE_ID_HSM_PUB_KEY_DECOMPRESSION			0x021D
/** Profiling ID for hsm_close_signature_generation_service */
#define PROFILE_ID_HSM_CLOSE_SIGNATURE_GENERATION_SERVICE	0x021E
/** Profiling ID for hsm_ecies_encryption */
#define PROFILE_ID_HSM_ECIES_ENCRYPTION				0x021F
/** Profiling ID for hsm_pub_key_recovery */
#define PROFILE_ID_HSM_PUB_KEY_RECOVERY				0x0220
/** Profiling ID for hsm_export_root_key_encryption_key */
#define PROFILE_ID_HSM_EXPORT_ROOT_KEY_ENCRYPTION_KEY		0x0221
/** Profiling ID for hsm_open_sm2_eces_service */
#define PROFILE_ID_HSM_OPEN_SM2_ECES_SERVICE			0x0222
/** Profiling ID for hsm_close_sm2_eces_service */
#define PROFILE_ID_HSM_CLOSE_SM2_ECES_SERVICE			0x0223
/** Profiling ID for hsm_sm2_eces_encryption */
#define PROFILE_ID_HSM_SM2_ECES_ENCRYPTION			0x0224
/** Profiling ID for hsm_sm2_eces_encryption */
#define PROFILE_ID_HSM_SM2_ECES_DECRYPTION			0x0225

/* Profiling IDs for system calls: format 0x03xx */

/** Profiling ID for open */
#define PROFILE_ID_SYSTEM_OPEN					0x0301
/** Profiling ID for read */
#define PROFILE_ID_SYSTEM_READ					0x0302
/** Profiling ID for write */
#define PROFILE_ID_SYSTEM_WRITE					0x0303
/** Profiling ID for close */
#define PROFILE_ID_SYSTEM_CLOSE					0x0304
/** Profiling ID for fstat */
#define PROFILE_ID_SYSTEM_FSTAT					0x0305
/** Profiling ID for remove */
#define PROFILE_ID_SYSTEM_REMOVE				0x0306
/** Profiling ID for opendir */
#define PROFILE_ID_SYSTEM_OPENDIR				0x0307
/** Profiling ID for readdir */
#define PROFILE_ID_SYSTEM_READDIR				0x0308
/** Profiling ID for closedir */
#define PROFILE_ID_SYSTEM_CLOSEDIR				0x0309
/** Profiling ID for mkdir */
#define PROFILE_ID_SYSTEM_MKDIR					0x030A

/** Tracepoint at entry to v2xSe API call */
#define TRACE_API_ENTRY(function) tracepoint(v2xsehsm, apiEntry, function)
/** Tracepoint at exit from v2xSe API call */
#define TRACE_API_EXIT(function) tracepoint(v2xsehsm, apiExit, function)
/** Tracepoint when calling hsm API */
#define TRACE_HSM_CALL(function) tracepoint(v2xsehsm, hsmCall, function)
/** Tracepoint when returning from hsm API call */
#define TRACE_HSM_RETURN(function) tracepoint(v2xsehsm, hsmReturn, function)
/** Tracepoint when calling system call */
#define TRACE_SYSTEM_CALL(function) tracepoint(v2xsehsm, systemCall, function)
/** Tracepoint when returning from system call */
#define TRACE_SYSTEM_RETURN(function) \
		tracepoint(v2xsehsm, systemReturn, function)

/** Class of profiling trace points for API calls */
TRACEPOINT_EVENT_CLASS(
	v2xsehsm,
	profiling_class,
	TP_ARGS(
		int32_t, apiFunctionID
	),
	TP_FIELDS(
		ctf_integer(int32_t, apiFunctionID, apiFunctionID)
	)
)

/** Event to log API entry */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	apiEntry,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)

/** Event to log API exit */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	apiExit,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)

/** Event to log HSM call */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	hsmCall,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)

/** Event to log HSM return */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	hsmReturn,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)

/** Event to log system call */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	systemCall,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)

/** Event to log system return */
TRACEPOINT_EVENT_INSTANCE(
	v2xsehsm,
	profiling_class,
	systemReturn,
	TP_ARGS(
		int32_t, apiFunctionID
	)
)


#include <lttng/tracepoint-event.h>


#else
/* Trace disabled */
/** Tracepoint at entry to v2xSe API call */
#define TRACE_API_ENTRY(function)
/** Tracepoint at exit from v2xSe API call */
#define TRACE_API_EXIT(function)
/** Tracepoint when calling hsm API */
#define TRACE_HSM_CALL(function)
/** Tracepoint when returning from hsm API call */
#define TRACE_HSM_RETURN(function)
/** Tracepoint when calling system call */
#define TRACE_SYSTEM_CALL(function)
/** Tracepoint when returning from system call */
#define TRACE_SYSTEM_RETURN(function)
#endif

#endif
