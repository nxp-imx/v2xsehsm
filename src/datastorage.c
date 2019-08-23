
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file datastorage.c
 *
 * @brief Implementation of V2X SE to HSM adaptation layer data storage API
 *
 */

#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Store generic data in NVM
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (!pData || (length < V2XSE_MIN_DATA_SIZE_GSA) ||
			(length > V2XSE_MAX_DATA_SIZE_GSA) ||
			(index > (NUM_STORAGE_SLOTS-1))) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (nvm_update_generic_data(index, pData, length) == -1) {
		*pHsmStatusCode = V2XSE_FILE_FULL;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve generic data from NVM
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (!pData || (!pLength) || (index > (NUM_STORAGE_SLOTS-1))) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	if (nvm_load_generic_data(index, pData, pLength) == -1) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_FAILURE;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Delete generic data from NVM
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_ACTIVATED();

	if ((v2xseAppletId != e_EU_AND_GS) &&
		(v2xseAppletId != e_US_AND_GS)) {
		*pHsmStatusCode = V2XSE_INACTIVE_CHANNEL;
		return V2XSE_FAILURE;
	}
	if (index > (NUM_STORAGE_SLOTS-1)) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	if (nvm_delete_generic_data(index) == -1) {
		*pHsmStatusCode = V2XSE_WRONG_DATA;
		return V2XSE_DEVICE_NOT_CONNECTED;
	}
	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}

/**
 *
 * @brief Retrieve amount of available NVM
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
	VERIFY_STATUS_CODE_PTR();
	ENFORCE_STATE_NOT_INIT();
	ENFORCE_POINTER_NOT_NULL(pSize);

	/* For now, return fixed value 2MB */
	*pSize = 2 * 1024 * 1024;

	*pHsmStatusCode = V2XSE_NO_ERROR;
	return V2XSE_SUCCESS;
}
