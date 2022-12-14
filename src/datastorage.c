
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
 * @file datastorage.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer data storage API
 *
 */

#include <stddef.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Store generic data in NVM
 * @ingroup datastorage
 *
 * This function stores generic data in NVM in the specified slot.  For this
 * system, it is stored in plaintext in the filesystem.   The data must be
 * between 1 and 239 bytes long. If data already exists in the specified
 * slot, it is overwritten.
 *
 * @param index slot to use to store generic data
 * @param length length of generic data to store
 * @param pData pointer to generic data to store
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_storeData(TypeGsDataIndex_t index, TypeLen_t length,
				uint8_t  *pData,TypeSW_t *pHsmStatusCode)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_STOREDATA);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval)) {

		if ((v2xseAppletId != e_EU_AND_GS) &&
			(v2xseAppletId != e_US_AND_GS) &&
			(v2xseAppletId != e_CN_AND_GS)) {
			*pHsmStatusCode = V2XSE_INS_NOT_SUPPORTED;
		} else if (!pData || (length < V2XSE_MIN_DATA_SIZE_GSA) ||
				(length > V2XSE_MAX_DATA_SIZE_GSA) ||
				(index > (NUM_STORAGE_SLOTS-1))) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_update_generic_data(index, pData, length)
								== -1) {
			*pHsmStatusCode = V2XSE_FILE_FULL;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_STOREDATA);
	return retval;
}

/**
 *
 * @brief Retrieve generic data from NVM
 * @ingroup datastorage
 *
 * This function retrieves generic data in NVM from the specified slot.
 *
 * @param index slot to retrieve generic data from
 * @param pLength pointer to location to write length of generic data retrieved
 * @param pData pointer to location to write generic data retrieved
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getData(TypeGsDataIndex_t index, TypeLen_t *pLength,
				uint8_t *pData,TypeSW_t *pHsmStatusCode)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETDATA);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval)) {

		if ((v2xseAppletId != e_EU_AND_GS) &&
			(v2xseAppletId != e_US_AND_GS) &&
			(v2xseAppletId != e_CN_AND_GS)) {
			*pHsmStatusCode = V2XSE_INS_NOT_SUPPORTED;
		} else if (!pData || (!pLength) ||
					(index > (NUM_STORAGE_SLOTS-1))) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_load_generic_data(index, pData, pLength)
								== -1) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETDATA);
	return retval;
}

/**
 *
 * @brief Delete generic data from NVM
 * @ingroup datastorage
 *
 * This function deletes generic data in NVM from the specified slot.
 *
 * @param index slot to delete generic data from
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_deleteData(TypeGsDataIndex_t index, TypeSW_t *pHsmStatusCode)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_DELETEDATA);

	if (!setupDefaultStatusCode(pHsmStatusCode) &&
			!enforceActivatedState(pHsmStatusCode, &retval)) {

		if ((v2xseAppletId != e_EU_AND_GS) &&
			(v2xseAppletId != e_US_AND_GS) &&
			(v2xseAppletId != e_CN_AND_GS)) {
			*pHsmStatusCode = V2XSE_INS_NOT_SUPPORTED;
		} else if (index > (NUM_STORAGE_SLOTS-1)) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else if (nvm_delete_generic_data(index) == -1) {
			*pHsmStatusCode = V2XSE_WRONG_DATA;
		} else {
			*pHsmStatusCode = V2XSE_NO_ERROR;
			retval = V2XSE_SUCCESS;
		}
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_DELETEDATA);
	return retval;
}

/**
 *
 * @brief Retrieve amount of available NVM
 * @ingroup devicemanagement
 *
 * This function returns the amount of available NVM.  As this system only
 * simulates NVM and actually uses the filesystem to store nvm data, for the
 * moment this function simply returns a fixed value.  This may be changed in
 * the future if needed.
 *
 * @param pSize pointer to location to write the amount of available nvm
 * @param pHsmStatusCode pointer to location to write extended result code
 *
 * @return V2XSE_SUCCESS if no error, non-zero on error
 *
 */
int32_t v2xSe_getRemainingNvm (uint32_t *pSize, TypeSW_t *pHsmStatusCode)
{
	int32_t retval = V2XSE_FAILURE;

	TRACE_API_ENTRY(PROFILE_ID_V2XSE_GETREMAININGNVM);
	if (!setupDefaultStatusCode(pHsmStatusCode) &&
				!enforceNotInitState(&retval) &&
				(pSize != NULL)) {

		/* For now, return fixed value 2MB */
		*pSize = 2 * 1024 * 1024;

		*pHsmStatusCode = V2XSE_NO_ERROR;
		retval = V2XSE_SUCCESS;
	}
	TRACE_API_EXIT(PROFILE_ID_V2XSE_GETREMAININGNVM);
	return retval;
}
