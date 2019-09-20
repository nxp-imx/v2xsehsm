
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
 * @file nvm.c
 *
 * @brief Non volatile memory emulation
 *
 */

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "v2xsehsm.h"
#include "nvm.h"

/**
 *
 * @brief Clear nvm entries in filesystem for the current applet
 *
 * This function clears the current applet's non-volatile entries.  The
 * global variable appletVarStoragePath is used to know the path to the
 * current applet's data in the filesystem.
 *
 * @return 0 if OK, non-zero if ERROR
 *
 */
static int nvm_clear(void)
{
	char clearCmd[MAX_FILENAME_SIZE];

	/* Clear all NVM data for appropriate applet */
	snprintf(clearCmd, MAX_FILENAME_SIZE, "rm -rf %s*", appletVarStoragePath);
	return system(clearCmd);
}

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
static int nvm_raw_load(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	int numread;
	struct stat fileInfo;

	/* Check length as expected before use */
	if (stat(name, &fileInfo) == -1)
		return 0;
	if (fileInfo.st_size > size)
		return 0;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		return 0;

	numread = read(fd, data, size);
	close(fd);
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
static int nvm_raw_update(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	int retval = -1;

	fd = open(name, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd != -1) {
		if (write(fd, data, size) == size)
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
static int nvm_raw_delete(char* name)
{
	if (access(name, F_OK))
		return -1;

	return remove(name);
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
static int nvm_load_var(char* name, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	if (nvm_raw_load(filename, data, size) != size)
		return -1;
	return 0;
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
int nvm_update_var(char* name, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	return nvm_raw_update(filename, data, size);
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
static int nvm_delete_var(char* name)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	return nvm_raw_delete(filename);
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
static int nvm_load_array_data(char* name, int index, uint8_t* data,
								TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_load_var(filename, data, size);
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
int nvm_update_array_data(char* name, int index, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_update_var(filename, data, size);
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
int nvm_delete_array_data(char* name, int index)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_delete_var(filename);
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
int nvm_load_generic_data(int index, uint8_t* data, TypeLen_t* size)
{
	char filename[MAX_FILENAME_SIZE];
	int sizeread;

	snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d", index);
	sizeread = nvm_raw_load(filename, data, V2XSE_MAX_DATA_SIZE_GSA);
	if (sizeread < V2XSE_MIN_DATA_SIZE_GSA)
		return -1;

	*size = sizeread;
	return 0;
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
int nvm_update_generic_data(int index, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	if ((size > V2XSE_MAX_DATA_SIZE_GSA) || !size)
		return -1;

	snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d", index);
	return nvm_raw_update(filename, data, size);
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
int nvm_delete_generic_data(int index)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d", index);

	return nvm_raw_delete(filename);
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
int nvm_retrieve_ma_key_handle(uint32_t* handle, TypeCurveId_t* id)
{
	if (maKeyHandle) {
		/* Key already in memory, return info */
		*handle = maKeyHandle;
		*id = maCurveId;
		return 0;
	}

	/* Key not in memory, check if in NVM and load if it is */
	if (nvm_load_var("maKeyHandle", (uint8_t*)handle, sizeof(*handle)))
		return -1;

	if (nvm_load_var("maCurveId", id, sizeof(*id)))
		return -1;

	/*
	 * Verify that curveId is valid, may have been changed in fs.
	 * This is done by calling convertCurveId and verifying that it
	 * returns a non-zero (ie valid) keyid - the returned keyid value
	 * is not used.
	 */
	if (!convertCurveId(*id))
		return -1;

	/* Save values for fast reply next time */
	maKeyHandle = *handle;
	maCurveId = *id;

	return 0;
}

/**
 *
 * @brief Retrieve key handle and curveId for an RT key
 *
 * This function retrives a runtime key handle in the specified slot.  If the
 * value in memory is non-zero, then the handle has already been loaded from
 * NVM and is returned immediately.  Otherwise the key handle is loaded from
 * NVM, if present. An error is flagged if the key handle or curveId are
 * not in NVM, or the curveId is invalid.
 *
 * @param index slot containing requested RT key
 * @param handle Pointer to location where RT key handle will be written
 * @param id Pointer to location where RT curveId will be written
 *
 * @return 0 if OK, -1 in case of ERROR
 *
 */
int nvm_retrieve_rt_key_handle(int index, uint32_t* handle, TypeCurveId_t* id)
{
	if (rtKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = rtKeyHandle[index];
		*id = rtCurveId[index];
		return 0;
	}

	/* Key not in memory, check if in NVM and load if it is */
	if (nvm_load_array_data("rtKeyHandle", index, (uint8_t*)handle,
							sizeof(*handle)))
		return -1;

	if (nvm_load_array_data("rtCurveId", index, id, sizeof(*id)))
		return -1;

	/*
	 * Verify that curveId is valid, may have been changed in fs.
	 * This is done by calling convertCurveId and verifying that it
	 * returns a non-zero (ie valid) keyid - the returned keyid value
	 * is not used.
	 */
	if (!convertCurveId(*id))
		return -1;

	/* Save values for fast reply next time */
	rtKeyHandle[index] = *handle;
	rtCurveId[index] = *id;

	return 0;
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
int nvm_retrieve_ba_key_handle(int index, uint32_t* handle, TypeCurveId_t* id)
{
	if (baKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = baKeyHandle[index];
		*id = baCurveId[index];
		return 0;
	}

	/* Key not in memory, check if in NVM and load if it is */
	if (nvm_load_array_data("baKeyHandle", index, (uint8_t*)handle,
							sizeof(*handle)))
		return -1;

	if (nvm_load_array_data("baCurveId", index, id, sizeof(*id)))
		return -1;

	/*
	 * Verify that curveId is valid, may have been changed in fs.
	 * This is done by calling convertCurveId and verifying that it
	 * returns a non-zero (ie valid) keyid - the returned keyid value
	 * is not used.
	 */
	if (!convertCurveId(*id))
		return -1;

	/* Save values for fast reply next time */
	baKeyHandle[index] = *handle;
	baCurveId[index] = *id;

	return 0;
}

/**
 *
 * @brief Check if the given variable is present in NVM storage
 *
 * This function checks if the given variable is present in NVM storage for
 * the current applet.  The variable name is appended to the storage path
 * given by the global variable appletVarStoragePath to know the path to the
 * current applet's data in the filesystem.
 *
 * @param varname Name of variable to check
 *
 * @return 0 if present, non-zero otherwise
 *
 */
static int var_present(char* varname)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								varname);
	return !access(filename, F_OK);

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
 * @return 0 if created OK, non-zero otherwise
 *
 */
static int var_mkdir(char* arrayname)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								arrayname);
	return mkdir(filename, 0700);

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
 * @return 0 if created OK, non-zero otherwise
 *
 */
int nvm_init(void)
{
	int phaseValid;

	/* Verify top level storage directory exists, create if not */
	if (access(COMMON_STORAGE_PATH, F_OK)) {
		if (mkdir(COMMON_STORAGE_PATH, 0700)) {
			return -1;
		}
	}

	/* Verify applet specific storage directory exists, create if not */
	if (access(appletVarStoragePath, F_OK)) {
		if (mkdir(appletVarStoragePath, 0700)) {
			return -1;
		}
	}
	/* Verify phase variable is valid, create if not and clear all data */
	phaseValid = 0;
	if (var_present("v2xsePhase")) {
		if (!nvm_load_var("v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase))) {
			if ((v2xsePhase == V2XSE_KEY_INJECTION_PHASE) ||
				(v2xsePhase == V2XSE_NORMAL_OPERATING_PHASE)) {
					phaseValid = 1;
			}
		}
	}
	if (!phaseValid) {
		if (nvm_clear())
			return -1;
		v2xsePhase = V2XSE_KEY_INJECTION_PHASE;
		if (nvm_update_var("v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase)))
			return -1;
	}

	/* Verify generic storage directory exists, create if not */
	if (access(GENERIC_STORAGE_PATH, F_OK)) {
		if (mkdir(GENERIC_STORAGE_PATH, 0700)) {
			return -1;
		}
	}

	/* Verify rt key handle & curve directories exist, create if not */
	if (!var_present("rtKeyHandle")) {
		if (var_mkdir("rtKeyHandle")) {
			return -1;
		}
	}
	if (!var_present("rtCurveId")) {
		if (var_mkdir("rtCurveId")) {
			return -1;
		}
	}

	/* Verify ba key handle & curve directories exist, create if not */
	if (!var_present("baKeyHandle")) {
		if (var_mkdir("baKeyHandle")) {
			return -1;
		}
	}
	if (!var_present("baCurveId")) {
		if (var_mkdir("baCurveId")) {
			return -1;
		}
	}

	/*
	 * Key handles: initialize all to zero, will try to load from
	 * filesystem on first use
	 */
	maKeyHandle = 0;
	memset(rtKeyHandle, 0, sizeof(rtKeyHandle));
	memset(baKeyHandle, 0, sizeof(baKeyHandle));

	return 0;
}
