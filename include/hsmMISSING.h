
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
 * @file hsmMISSING.h
 *
 * @brief Header file for missing features in current HSM implementation
 *
 */

#ifndef HSMMISSING_H
#define HSMMISSING_H

/** Flag to indicate public key calculation not yet available */
#define STUB_CALC_PUBKEY
/** Flag to indicate random number generation not yet supported */
#define STUB_RNG
/** Flag to indicate butterfly key derivation not supported */
#define STUB_BUTTERFLY
/** Flag to indicate prepare/finalize for fast signature not supported */
#define STUB_PREPARE_FINALIZE
/** Flag single keystore supported, EU & US use same id/nonce */
#define SINGLE_KEYSTORE
/** Flag to indicate BrainpoolT1 not yet supported - code uses R1 instead */
#define NO_BP_T1
/**
 * Flag to indicate that keys cannot be deleted
 *  - will cause buildup of keystore keys over time
 */
#define NO_KEY_DELETION


#ifdef STUB_CALC_PUBKEY
/** Parameter type for stub calc pub key function */
typedef uint8_t hsm_op_calc_pubkey_flags_t;
/** Structure for not yet implemented generate public key API */
typedef struct {
	/** key handle pointer */
	uint32_t *key_identifier;
	/** size out output public key */
	uint16_t out_size;
	/** flags to create or update key */
	hsm_op_calc_pubkey_flags_t flags;
	/** reserved */
	uint16_t reserved;
	/** type of key to generate */
	hsm_key_type_t key_type;
	/** extra key type info */
	hsm_key_type_ext_t key_type_ext;
	/** info whether permanent key or not */
	hsm_key_info_t key_info;
	/** pointer to location to write generated public key */
	uint8_t *output_key;
} op_calc_pubkey_args_t;

/**
 *
 * @brief Calculate public key from specified private key
 *
 * This function needs to be imlemented in the HSM.  This is a placeholder
 * until the real function is available.
 *
 * @param key_management_hdl handle of key management service
 * @param args structure containing parameters for operation
 *
 * @return HSM_NO_ERROR
 *
 */
hsm_err_t hsm_calculate_public_key(hsm_hdl_t key_management_hdl,
						op_calc_pubkey_args_t *args);
#endif


#ifdef STUB_RNG
/** Replace missing hsm call with stub function */
#define hsm_open_rng_service STUB_open_rng_service
/** Replace missing hsm call with stub function */
#define hsm_get_random STUB_get_random
/** Replace missing hsm call with stub function */
#define hsm_close_rng_service STUB_close_rng_service
/**
 *
 * @brief Simulate rng service open
 *
 * This function accepts the parameters requiried for hsm_open_rng_service
 * so that there is no warning message indicating rng variables not used.
 * RNG is not yet supported by seco_libs
 *
 * @param session_hdl handle of hsm session
 * @param args structure containing parameters for operation
 * @param rng_hdl handle for rng service opened
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_open_rng_service(hsm_hdl_t session_hdl,
				open_svc_rng_args_t *args, hsm_hdl_t *rng_hdl);
/**
 *
 * @brief Simulate rng generation
 *
 * This function provides a different number each time, waiting for real
 * RNG support by seco_libs
 *
 * @param rng_hdl handle for rng service
 * @param args structure containing parameters for operation
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args);
/**
 *
 * @brief Simulate rng service close
 *
 * This function accepts the parameters requiried for hsm_close_rng_service
 * so that there is no warning message indicating rng variables not used.
 * RNG is not yet supported by seco_libs
 *
 * @param rng_hdl handle for rng service to close
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_close_rng_service(hsm_hdl_t rng_hdl);
#endif

#ifdef STUB_BUTTERFLY
/** Replace failing hsm call with stub function */
#define hsm_butterfly_key_expansion STUB_butterfly_key_expansion
/**
 *
 * @brief Simulate butterfly key derivation
 *
 * This function generates a random key, waiting for true butterfly
 * derivation to be available in the hsm
 *
 * @param key_management_hdl handle for key management service
 * @param args structure containing parameters for operation
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
						op_butt_key_exp_args_t *args);
#endif

#ifdef STUB_PREPARE_FINALIZE
/** Replace failing hsm call with stub function */
#define hsm_prepare_signature STUB_prepare_signature
/** Replace failing hsm call with stub function */
#define hsm_finalize_signature STUB_finalize_signature
/**
 *
 * @brief Simulate fast signature preparation
 *
 * This function does nothing, waiting for true fast signature
 * preparation to be available in the hsm
 *
 * @param signature_gen_hdl handle for signature generation service
 * @param args structure containing parameters for operation
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_prepare_signature(hsm_hdl_t signature_gen_hdl,
	op_prepare_sign_args_t *args);
/**
 *
 * @brief Simulate fast signature finalization
 *
 * This function does nothing, waiting for true fast signature
 * finalization to be available in the hsm
 *
 * @param signature_gen_hdl handle for signature generation service
 * @param args structure containing parameters for operation
 *
 * @return HSM_NO_ERROR if no error
 *
 */
hsm_err_t STUB_finalize_signature(hsm_hdl_t signature_gen_hdl,
	op_finalize_sign_args_t *args);
#endif

#endif
