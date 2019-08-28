
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
 * @file hsmMISSING.c
 *
 * @brief Implementation of missing features in current HSM implementation
 *
 */

#include <string.h>
#include "v2xsehsm.h"

#ifdef STUB_CALC_PUBKEY
hsm_err_t hsm_calculate_public_key(hsm_hdl_t key_management_hdl,
						op_calc_pubkey_args_t *args)
{
	return HSM_NO_ERROR;
}
#endif

#ifdef STUB_RNG
hsm_err_t STUB_open_rng_service(hsm_hdl_t session_hdl,
				open_svc_rng_args_t *args, hsm_hdl_t *rng_hdl)
{
	if (!rng_hdl)
		return HSM_GENERAL_ERROR;
	*rng_hdl = 0x2626;
	return HSM_NO_ERROR;
}

hsm_err_t STUB_close_rng_service(hsm_hdl_t rng_hdl)
{
	if (rng_hdl != 0x2626)
		return HSM_GENERAL_ERROR;
	return HSM_NO_ERROR;
}

hsm_err_t STUB_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args)
{
	static uint8_t notVeryRandNum = 2;

	if (rng_hdl != 0x2626)
		return HSM_GENERAL_ERROR;
	if (!args)
		return HSM_GENERAL_ERROR;
	*(args->output) = notVeryRandNum++;
	return HSM_NO_ERROR;
}
#endif

#ifdef STUB_BUTTERFLY
hsm_err_t STUB_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
						op_butt_key_exp_args_t *args)
{

	op_generate_key_args_t gen_args;

	memset(&gen_args, 0, sizeof(gen_args));
	gen_args.key_identifier = args->dest_key_identifier;
	gen_args.out_size = args->output_size;
	gen_args.flags = args->flags;
	gen_args.key_type = args->key_type;
	gen_args.out_key = args->output;
	return hsm_generate_key(hsmKeyMgmtHandle, &gen_args);
}
#endif

#ifdef STUB_PREPARE_FINALIZE
hsm_err_t STUB_prepare_signature(hsm_hdl_t signature_gen_hdl,
	op_prepare_sign_args_t *args)
{
	return HSM_NO_ERROR;
}

hsm_err_t STUB_finalize_signature(hsm_hdl_t signature_gen_hdl,
	op_finalize_sign_args_t *args)
{
	return HSM_NO_ERROR;
}
#endif
