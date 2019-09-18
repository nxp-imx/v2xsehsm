
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
