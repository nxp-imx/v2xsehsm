
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
 * @file nvm.h
 *
 * @brief Header file for non volatile memory emulation
 *
 */

#ifndef NVM_H
#define NVM_H

/** Max absolute patch name expected for filesystem access */
#define MAX_FILENAME_SIZE	128

/** NVM fs name for phase variable */
#define V2XSE_PHASE_NAME	"v2xsePhase"
/** NVM fs name for MA curve ID */
#define MA_CURVEID_NAME		"maCurveId"
/** NVM fs name for MA key handle */
#define MA_KEYHANDLE_NAME	"maKeyHandle"
/** NVM fs name for BA curve ID */
#define BA_CURVEID_NAME		"baCurveId"
/** NVM fs name for BA key handle */
#define BA_KEYHANDLE_NAME	"baKeyHandle"
/** NVM fs name for RT curve ID */
#define RT_CURVEID_NAME		"rtCurveId"
/** NVM fs name for RT key handle */
#define RT_KEYHANDLE_NAME	"rtKeyHandle"
/** Used to delete nvm variables at applet root level */
#define ROOT_LEVEL_NAME		""

int nvm_init(void);
int nvm_update_array_data(char *name, int index, uint8_t *data, TypeLen_t size);
int nvm_delete_array_data(char *name, int index);
int nvm_load_generic_data(int index, uint8_t *data, TypeLen_t *size);
int nvm_update_generic_data(int index, uint8_t *data, TypeLen_t size);
int nvm_delete_generic_data(int index);
int nvm_update_var(char *name, uint8_t *data, TypeLen_t size);
int nvm_delete_var(char *name);
int nvm_retrieve_ma_key_handle(uint32_t *handle, TypeCurveId_t *id);
int nvm_retrieve_rt_key_handle(TypeRtKeyId_t index, uint32_t *handle,
							TypeCurveId_t *id);
int nvm_retrieve_ba_key_handle(TypeBaseKeyId_t index, uint32_t *handle,
							TypeCurveId_t *id);

#endif
