
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
 * @file nvm.c
 *
 * @brief Non volatile memory emulation
 *
 */

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Read data for an nvm entry from the filesystem
 *
 * This function reads an nvm entry from the filesystem up to the given
 * size to the specified location.  If the file containting the entry is
 * too long, no data is returned (entry must be corrupted).  May return
 * fewer bytes than requested, which is a valid case for generic data.
 *
 * @param name Path & filename expected to contain nvm entry
 * @param data Pointer to location where the data read will be stored
 * @param size Max size of data to be read
 *
 * @return Number of bytes read, 0 in case of ERROR
 *
 */
static int32_t nvm_raw_load(char *name, uint8_t *data, TypeLen_t size)
{
	int32_t fd;
	int32_t numread = -1;
	struct stat fileInfo;
	int32_t fstatret;

	TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_OPEN);
	fd = open(name, O_RDONLY);
	TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_OPEN);
	if (fd != -1) {
		/* Check length is as expected before use */
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_FSTAT);
		fstatret = fstat(fd, &fileInfo);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_FSTAT);
		if (fstatret != -1) {
			if (fileInfo.st_size <= size) {
				TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_READ);
				numread = read(fd, data, size);
				TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_READ);
			}
		}
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_CLOSE);
		close(fd);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_CLOSE);
	}
	return numread;
}

/**
 *
 * @brief Write data to an nvm entry in the filesystem
 *
 * This function writes data to an nvm entry in the filesystem.  If the
 * file containing the entry already exists, it is overwritten.
 *
 * @param name Path & filename to write nvm data
 * @param data Pointer to location where the data will be read from
 * @param size Size of data to be stored
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
static int32_t nvm_raw_update(char *name, uint8_t *data, TypeLen_t size)
{
	int32_t fd;
	int32_t retval = -1;
	int32_t writeret;

	TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_OPEN);
	fd = open(name, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_OPEN);
	if (fd != -1) {
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_WRITE);
		writeret = write(fd, data, size);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_WRITE);
		if (writeret == size)
			retval = 0;
		close(fd);
	}
	return retval;
}

/**
 *
 * @brief Delete data for an nvm entry in the filesystem
 *
 * This function deletes a file in the filesystem.  It is used to delete
 * nvm data, but can be used to delete any file.
 *
 * @param name Path & filename to delete
  *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
static int32_t nvm_raw_delete(char *name)
{
	int32_t retval = 0;
	int32_t removeret;

	TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_REMOVE);
	removeret = remove(name);
	TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_REMOVE);
	if (removeret)
		retval = -1;

	return retval;
}

/**
 *
 * @brief Read data for an nvm variable from the filesystem
 *
 * This function reads an nvm variable for the current applet from the
 * filesystem. An error is returned if the file size does not match the
 * expected size of the variable.  The variable name is appended to the
 * storage path given by the global variable appletVarStoragePath to know
 * the path to the current applet's data in the filesystem.
 *
 * @param name Variable name
 * @param data Pointer to location where the data read will be stored
 * @param size Size of data to be read
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
static int32_t nvm_load_var(char *name, uint8_t *data, TypeLen_t size)
{
	int32_t retval = 0;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								name) < 0) {
		retval = -1;
	} else {
		if (nvm_raw_load(filename, data, size) != size)
			retval = -1;
	}

	return retval;
}

/**
 *
 * @brief Update data for an nvm variable in the filesystem
 *
 * This function updates an nvm variable for the current applet in the
 * filesystem. If a file containing the variable already exists, it is
 * overwritten.  The variable name is appended to the storage path given by
 * the global variable appletVarStoragePath to know the path to the current
 * applet's data in the filesystem.
 *
 * @param name Variable name
 * @param data Pointer to location of the data to be stored
 * @param size Size of data to be stored
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_update_var(char *name, uint8_t *data, TypeLen_t size)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
						name) < 0)
		retval = -1;
	else
		retval = nvm_raw_update(filename, data, size);

	return retval;
}

/**
 *
 * @brief Delete data for an nvm variable in the filesystem
 *
 * This function deletes an nvm variable for the current applet from the
 * filesystem. The variable name is appended to the storage path given by
 * the global variable appletVarStoragePath to know the path to the current
 * applet's data in the filesystem.
 *
 * @param name Variable name
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_delete_var(char *name)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								name) < 0)
		retval = -1;
	else
		retval = nvm_raw_delete(filename);

	return retval;
}

/**
 *
 * @brief Read data for an nvm array element from the filesystem
 *
 * This function reads an nvm array element for the current applet from the
 * filesystem. An error is returned if the file size does not match the
 * expected size of the array element.  The array name and element index
 * are combined in a string and passed to nvm_load_var.
 *
 * @param name Array name
 * @param index The array element index
 * @param data Pointer to location where the loaded data will be stored
 * @param size Size of data to be loaded
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
static int32_t nvm_load_array_data(char *name, uint32_t index, uint8_t *data,
								TypeLen_t size)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index) < 0)
		retval = -1;
	else
		retval = nvm_load_var(filename, data, size);

	return retval;
}

/**
 *
 * @brief Update data for an nvm array element in the filesystem
 *
 * This function updates an nvm array element for the current applet in the
 * filesystem. If a file containing the array element already exists, it is
 * overwritten.  The array name and element index are combined in a string
 * and passed to nvm_update_var.
 *
 * @param name Array name
 * @param index The array element index
 * @param data Pointer to the  data to be stored
 * @param size Size of data to be stored
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_update_array_data(char *name, uint32_t index, uint8_t *data,
								TypeLen_t size)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index) < 0)
		retval = -1;
	else
		retval = nvm_update_var(filename, data, size);

	return retval;
}

/**
 *
 * @brief Delete data for an nvm array element from the filesystem
 *
 * This function deletes an nvm array element for the current applet from the
 * filesystem. The array name and element index are combined in a string
 * and passed to nvm_delete_var.
 *
 * @param name Array name
 * @param index The array element index
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_delete_array_data(char *name, uint32_t index)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index) < 0)
		retval = -1;
	else
		retval = nvm_delete_var(filename);

	return retval;
}

/**
 *
 * @brief Empty an nvm directory from the filesystem
 *
 * This function deletes all entries in an nvm directory.  It goes through
 * the directory and deletes all regular files.  If the name passed is
 * empty, all entries in the nvm root for the current applet are removed.
 * If a name is supplied, all entries for the specified array are removed.
 *
 * @param name subdirectory name, may be empty string
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
static int32_t nvm_empty_dir(char *name)
{
	DIR *arrayDir;
	struct dirent *arrayEntry;
	int32_t retval = -1;
	int32_t fileErr = 0;
	int32_t sysretval;
	char dirName[MAX_FILENAME_SIZE];
	char fileName[MAX_FILENAME_SIZE];

	do {
		if (snprintf(dirName, MAX_FILENAME_SIZE, "%s%s",
					appletVarStoragePath, name) < 0)
			break;

		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_OPENDIR);
		arrayDir = opendir(dirName);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_OPENDIR);
		if (!arrayDir)
			break;

		/* Clear errno to detect diff between end of list and error */
		errno = 0;
		do {
			TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_READDIR);
			arrayEntry = readdir(arrayDir);
			TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_READDIR);
			if (arrayEntry == NULL)
				break;
			if (arrayEntry->d_type == DT_REG) {
				if (snprintf(fileName, MAX_FILENAME_SIZE,
					"%s/%s", dirName, arrayEntry->d_name)
								< 0) {
					fileErr = 1;
				} else {
					TRACE_SYSTEM_CALL(
						PROFILE_ID_SYSTEM_REMOVE);
					sysretval = remove(fileName);
					TRACE_SYSTEM_RETURN(
						PROFILE_ID_SYSTEM_REMOVE);
					if (sysretval)
						fileErr = 1;
				}
			}
		} while (1);
		if (errno)
			fileErr = 1;
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_CLOSEDIR);
		sysretval = closedir(arrayDir);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_CLOSEDIR);
		if (sysretval)
			break;
		if (!fileErr)
			retval = 0;
	} while (0);
	return retval;
}

/**
 *
 * @brief Read data for a generic data item from the filesystem
 *
 * This function reads a generic data item from the filesystem. An error is
 * returned if the size of the data is not from 1 - 239 bytes.  The index
 * value is appended to the generic data storage path to generate the
 * path to the item in the filesystem.
 *
 * @param index Generic data slot number
 * @param data Pointer to location where the data read will be stored
 * @param size Pointer to location where size of data read will be stored
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_load_generic_data(uint32_t index, uint8_t *data, TypeLen_t *size)
{
	int32_t retval = 0;
	char filename[MAX_FILENAME_SIZE];
	int32_t sizeread;

	if (snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d",
								index) < 0) {
		retval = -1;
	} else {
		sizeread = nvm_raw_load(filename, data,
						V2XSE_MAX_DATA_SIZE_GSA);
		if (sizeread < (int32_t)V2XSE_MIN_DATA_SIZE_GSA)
			retval = -1;
		else
			*size = sizeread;
	}

	return retval;
}

/**
 *
 * @brief Update data for a generic data item in the filesystem
 *
 * This function updates a generic data item in the filesystem. An error is
 * returned if the size of the data is not from 1 - 239 bytes.  The index
 * value is appended to the generic data storage path to generate the
 * path to the item in the filesystem.
 *
 * @param index Generic data slot number
 * @param data Pointer to location where the data read will be stored
 * @param size Pointer to location where size of data read will be stored
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_update_generic_data(uint32_t index, uint8_t *data, TypeLen_t size)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if ((size > V2XSE_MAX_DATA_SIZE_GSA) || !size)
		retval = -1;
	else if (snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d",
								index) < 0)
		retval = -1;
	else
		retval = nvm_raw_update(filename, data, size);

	return retval;
}

/**
 *
 * @brief Delete data for a generic data item from the filesystem
 *
 * This function deletes a generic data item from the filesystem. The index
 * value is appended to the generic data storage path to generate the
 * path to the item in the filesystem.
 *
 * @param index Generic data slot number
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_delete_generic_data(uint32_t index)
{
	int32_t retval;
	char filename[MAX_FILENAME_SIZE];

	if (snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d",
								index) < 0)
		retval = -1;
	else
		retval = nvm_raw_delete(filename);

	return retval;
}

/**
 *
 * @brief Retrieve key handle and curveId for MA key
 *
 * This function retrives the Module Authentication key handle.  If the value
 * in memory is non-zero, then the handle has already been loaded from NVM
 * and is returned immediately.  Otherwise the key handle is loaded from
 * NVM, if present. An error is flagged if the key handle or curveId are
 * not in NVM, or the curveId is invalid.
 *
 * @param handle Pointer to location where MA key handle will be written
 * @param id Pointer to location where MA curveId will be written
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_retrieve_ma_key_handle(uint32_t *handle, TypeCurveId_t *id)
{
	int32_t retval = -1;

	if (maKeyHandle) {
		/* Key already in memory, return info */
		*handle = maKeyHandle;
		*id = maCurveId;
		retval = 0;
	} else {
		/*
		 * Key not in memory, check if in NVM and load if it is.
		 * Verify that curveId is valid, may have been changed in fs.
		 * This is done by calling convertCurveId and verifying that it
		 * returns a non-zero (ie valid) keyid - the returned keyid
		 * value is not used.
		 */
		if (!nvm_load_var(MA_KEYHANDLE_NAME, (uint8_t *)handle,
							sizeof(*handle)) &&
				!nvm_load_var(MA_CURVEID_NAME, id,
							sizeof(*id)) &&
				convertCurveId(*id)) {
			/* Save values for fast reply next time */
			maKeyHandle = *handle;
			maCurveId = *id;
			retval = 0;
		}
	}
	return retval;
}

/**
 *
 * @brief Retrieve key handle and curveId/symmetricKeyId for an RT key
 *
 * This function retrives a runtime key handle in the specified slot.  If the
 * value in memory is non-zero, then the handle has already been loaded from
 * NVM and is returned immediately.  Otherwise the key handle is loaded from
 * NVM, if present. An error is flagged if the key handle or curveId/
 * symmetricKeyId  are not in NVM, or the curveId/symmetricKeyId  is invalid.
 *
 * @param index slot containing requested RT key
 * @param handle Pointer to location where RT key handle will be written
 * @param id Pointer to location where RT curveId/symmetricKeyId will be written
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_retrieve_rt_key_handle(TypeRtKeyId_t index, uint32_t *handle,
							uint8_t *id)
{
	int32_t retval = -1;

	if (rtKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = rtKeyHandle[index];
		*id = rtCurveId[index];
		retval = 0;
	} else {
		/*
		 * Key not in memory, check if in NVM and load if it is.
		 * Verify that curveId is valid, may have been changed in fs.
		 * This is done by calling convertCurveId for ECC curves - or
		 * convertSymmetricKeyId for symmetric keys - and verifying that
		 * it returns a non-zero (ie valid) keyid - the returned keyid
		 * value is not used.
		 */
		if (!nvm_load_array_data(RT_KEYHANDLE_NAME, index,
					(uint8_t *)handle, sizeof(*handle)) &&
				!nvm_load_array_data(RT_CURVEID_NAME, index,
					id, sizeof(*id)) &&
				(convertCurveId(*id) || convertSymmetricKeyId(*id))) {
			/* Save values for fast reply next time */
			rtKeyHandle[index] = *handle;
			rtCurveId[index] = *id;
			retval = 0;
		}
	}
	return retval;
}

/**
 *
 * @brief Retrieve key handle and curveId for a BA key
 *
 * This function retrives a base key handle in the specified slot.  If the
 * value in memory is non-zero, then the handle has already been loaded from
 * NVM and is returned immediately.  Otherwise the key handle is loaded from
 * NVM, if present. An error is flagged if the key handle or curveId are
 * not in NVM, or the curveId is invalid.
 *
 * @param index slot containing requested BA key
 * @param handle Pointer to location where BA key handle will be written
 * @param id Pointer to location where BA curveId will be written
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int32_t nvm_retrieve_ba_key_handle(TypeBaseKeyId_t index, uint32_t *handle,
							TypeCurveId_t *id)
{
	int32_t retval = -1;

	if (baKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = baKeyHandle[index];
		*id = baCurveId[index];
		retval = 0;
	} else {
		/*
		 * Key not in memory, check if in NVM and load if it is.
		 * Verify that curveId is valid, may have been changed in fs.
		 * This is done by calling convertCurveId and verifying that it
		 * returns a non-zero (ie valid) keyid - the returned keyid
		 * value is not used.
		 */
		if (!nvm_load_array_data(BA_KEYHANDLE_NAME, index,
					(uint8_t *)handle, sizeof(*handle)) &&
				!nvm_load_array_data(BA_CURVEID_NAME, index,
					id, sizeof(*id)) &&
				convertCurveId(*id)) {
			/* Save values for fast reply next time */
			baKeyHandle[index] = *handle;
			baCurveId[index] = *id;
			retval = 0;
		}
	}
	return retval;
}

/**
 *
 * @brief Create storage for the given array in NVM storage
 *
 * This function creates a directory in the current applet's NVM storage
 * area in the filesystem.  This directory can be used to store the
 * arrays elements.  The variable name is appended to the storage path
 * given by the global variable appletVarStoragePath to know the path to the
 * current applet's data in the filesystem.
 *
 * @param arrayname Name of the array to create a directory for
 *
 * @return 0 if created or already exists, non-zero otherwise
 *
 */
static int32_t var_mkdir(char *arrayname)
{
	char filename[MAX_FILENAME_SIZE];
	int32_t retval;

	if (snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
							arrayname) < 0) {
		retval = -1;
	} else {
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_MKDIR);
		retval = mkdir(filename, 0700);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_MKDIR);
		/* Ignore error if already exists */
		if ((retval == -1) && (errno == EEXIST))
			retval = 0;
	}

	return retval;
}

/**
 *
 * @brief Clear nvm entries in filesystem for the current applet
 *
 * This function clears the current applet's non-volatile entries.  The
 * global variable appletVarStoragePath is used to know the path to the
 * current applet's data in the filesystem.  The variables stored
 * in that directory and known subdirectories are deleted.
 *
 * @return 0 if OK, non-zero if ERROR
 *
 */
static int32_t nvm_clear(void)
{
	int32_t retval = 0;

	if (nvm_empty_dir(ROOT_LEVEL_NAME))
		retval = -1;
	if (nvm_empty_dir(BA_CURVEID_NAME))
		retval = -1;
	if (nvm_empty_dir(BA_KEYHANDLE_NAME))
		retval = -1;
	if (nvm_empty_dir(RT_CURVEID_NAME))
		retval = -1;
	if (nvm_empty_dir(RT_KEYHANDLE_NAME))
		retval = -1;

	return retval;
}

/**
 *
 * @brief Initialize NVM storage for applet use
 *
 * This function initializes NVM storage, and readies the variables that
 * can be loaded from NVM.  The directories for generic storage and the
 * variables for the current applet are created if they do not already
 * exist.  If the applet's phase variable is missing or invalid, all storage
 * for the applet is cleared.  All key handles are set to 0, so that they
 * will be loaded from NVM on the next use.
 *
 * @return 0 if initialized OK, non-zero otherwise
 *
 */
int32_t nvm_init(void)
{
	int32_t phaseValid;
	int32_t retval = -1;
	int32_t mkdirret;

	do {
		/* Make sure top level storage directory exists */
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_MKDIR);
		mkdirret = mkdir(COMMON_STORAGE_PATH, 0700);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_MKDIR);
		if (mkdirret) {
			if (errno != EEXIST)
				break;
		}

		/* Make sure applet specific storage directory exists */
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_MKDIR);
		mkdirret = mkdir(appletVarStoragePath, 0700);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_MKDIR);
		if (mkdirret) {
			if (errno != EEXIST)
				break;
		}

		/* Make sure generic storage directory exists */
		TRACE_SYSTEM_CALL(PROFILE_ID_SYSTEM_MKDIR);
		mkdirret = mkdir(GENERIC_STORAGE_PATH, 0700);
		TRACE_SYSTEM_RETURN(PROFILE_ID_SYSTEM_MKDIR);
		if (mkdirret) {
			if (errno != EEXIST)
				break;
		}

		/* Make sure rt key handle & curve directories exist */
		if (var_mkdir(RT_KEYHANDLE_NAME))
			break;
		if (var_mkdir(RT_CURVEID_NAME))
			break;

		/* Make sure ba key handle & curve directories exist */
		if (var_mkdir(BA_KEYHANDLE_NAME))
			break;
		if (var_mkdir(BA_CURVEID_NAME))
			break;

		/* Verify phase variable is valid */
		phaseValid = 0;
		if (!nvm_load_var(V2XSE_PHASE_NAME, &v2xsePhase,
							sizeof(v2xsePhase))) {
			if ((v2xsePhase == V2XSE_KEY_INJECTION_PHASE) ||
				(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {
				phaseValid = 1;
			}

		}
		if (!phaseValid) {
			/* If phase not valid, clear all data & create phase */
			if (!nvm_clear()) {
				v2xsePhase = V2XSE_NORMAL_OPERATING_PHASE;
				if (!nvm_update_var(V2XSE_PHASE_NAME,
						&v2xsePhase,
							sizeof(v2xsePhase)))
					phaseValid = 1;
			}
		}

		/*
		 * Key handles: initialize all to zero, will try to load from
		 * filesystem on first use
		 */
		if (phaseValid) {
			maKeyHandle = 0;
			memset(rtKeyHandle, 0, sizeof(rtKeyHandle));
			memset(baKeyHandle, 0, sizeof(baKeyHandle));
			retval = 0;
		}
	} while (0);
	return retval;
}
