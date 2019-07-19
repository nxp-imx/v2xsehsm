
#ifndef NVM_H
#define NVM_H

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "adaptlib.h"
#include "nvm.h"

static int nvm_clear(void)
{
	char clearCmd[MAX_FILENAME_SIZE];

	/* Clear all NVM data for appropriate applet */
	snprintf(clearCmd, MAX_FILENAME_SIZE, "rm -rf %s*", appletVarStoragePath);
	return system(clearCmd);
}

static int nvm_raw_load(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	int numread;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		return -1;
	numread = read(fd, data, size);
	close(fd);
	return numread;
}

static int nvm_raw_update(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;

	fd = open(name, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd == -1)
		return -1;
	if (write(fd, data, size) == -1)
		return -1;
	close(fd);
	return 0;
}

static int nvm_raw_delete(char* name)
{
	if (access(name, F_OK))
		return -1;

	return remove(name);
}

static int nvm_load_var(char* name, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	if (nvm_raw_load(filename, data, size) != size)
		return -1;
	return 0;
}

int nvm_update_var(char* name, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	return nvm_raw_update(filename, data, size);
}

static int nvm_delete_var(char* name)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
									name);
	return nvm_raw_delete(filename);
}

static int nvm_load_array_data(char* name, int index, uint8_t* data,
								TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_load_var(filename, data, size);
}

int nvm_update_array_data(char* name, int index, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_update_var(filename, data, size);
}

int nvm_delete_array_data(char* name, int index)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s/%d", name, index);
	return nvm_delete_var(filename);
}

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

int nvm_update_generic_data(int index, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d", index);
	return nvm_raw_update(filename, data, size);
}


int nvm_delete_generic_data(int index)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, GENERIC_STORAGE_PATH"%d", index);

	return nvm_raw_delete(filename);
}


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

	return 0;
}

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

	return 0;
}

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

	return 0;
}

static int var_access(char* varname, int mode)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								varname);
	return access(filename, mode);

}

static int var_mkdir(char* varname, int mode)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, "%s%s", appletVarStoragePath,
								varname);
	return mkdir(filename, mode);

}
int nvm_init(void)
{
	int i;

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
	/* Verify phase variable exists, create if not and clear all data */
	if (var_access("v2xsePhase", F_OK)) {

		if (nvm_clear())
			return -1;
		v2xsePhase = V2XSE_KEY_INJECTION_PHASE;
		nvm_update_var("v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase));
	} else {
		if (nvm_load_var("v2xsePhase", &v2xsePhase, sizeof(v2xsePhase)))
			return -1;
	}

	/* Verify generic storage directory exists, create if not */
	if (access(GENERIC_STORAGE_PATH, F_OK)) {
		if (mkdir(GENERIC_STORAGE_PATH, 0700)) {
			return -1;
		}
	}

	/* Verify rt key handle & curve directories exist, create if not */
	if (var_access("rtKeyHandle", F_OK)) {
		if (var_mkdir("rtKeyHandle", 0700)) {
			return -1;
		}
	}
	if (var_access("rtCurveId", F_OK)) {
		if (var_mkdir("rtCurveId", 0700)) {
			return -1;
		}
	}

	/* Verify ba key handle & curve directories exist, create if not */
	if (var_access("baKeyHandle", F_OK)) {
		if (var_mkdir("baKeyHandle", 0700)) {
			return -1;
		}
	}
	if (var_access("baCurveId", F_OK)) {
		if (var_mkdir("baCurveId", 0700)) {
			return -1;
		}
	}

	/* Load key_store_nonce - set to 0 if it does not exist */
	if (nvm_load_var("key_store_nonce", (uint8_t*)&key_store_nonce,
						sizeof(key_store_nonce)))
		key_store_nonce = 0;

	/*
	 * Key handles: initialize all to zero, will try to load from
	 * filesystem on first use
	 */
	maKeyHandle = 0;
	for(i = 0; i < NUM_STORAGE_SLOTS; i++) {
		rtKeyHandle[i] = 0;
		baKeyHandle[i] = 0;
	}

	return 0;
}

#endif
