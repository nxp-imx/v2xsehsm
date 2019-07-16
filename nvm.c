
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include "adaptlib.h"
#include "nvm.h"

static int nvm_clear(void) {
	/* TODO: clear all existing data */
	return 0;
}

static int nvm_raw_load(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	int numread;
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"%s", name);
	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return -1;
	numread = read(fd, data, size);
	close(fd);
	return numread;
}

int nvm_load_var(char* name, uint8_t* data, TypeLen_t size)
{
	if (nvm_raw_load(name, data, size) != size)
		return -1;
	return 0;
}

int nvm_update_var(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"%s", name);
	fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd == -1)
		return -1;
	if (write(fd, data, size) == -1)
		return -1;
	close(fd);
	return 0;
}

int nvm_delete_var(char* name)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"%s", name);
	if (access(filename, F_OK))
		return -1;

	return remove(filename);
}

int nvm_load_array_data(char* name, int index, uint8_t* data, TypeLen_t size)
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

/* Generic data requires separate read function as data length is variable */
int nvm_retrieve_generic_data(int index, uint8_t* data, TypeLen_t* size)
{
	char filename[MAX_FILENAME_SIZE];
	int sizeread;

	snprintf(filename, MAX_FILENAME_SIZE, "genericStorage/%d", index);
	sizeread = nvm_raw_load(filename, data, V2XSE_MAX_DATA_SIZE_GSA);
	if (sizeread < V2XSE_MIN_DATA_SIZE_GSA)
		return -1;

	*size = sizeread;
	return 0;
}

int nvm_retrieve_rt_key_handle(int index, uint32_t* handle, TypeCurveId_t* id)
{
	char filename[MAX_FILENAME_SIZE];

	if (rtKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = rtKeyHandle[index];
		*id = rtCurveId[index];
		return 0;
	}

	/* Key not in memory, check if in NVM and load if it is */
	snprintf(filename, MAX_FILENAME_SIZE, "rtKeyHandle/%d",	index);
	if (nvm_load_var(filename, (uint8_t*)handle, sizeof(*handle)))
		return -1;

	snprintf(filename, MAX_FILENAME_SIZE, "rtCurveId/%d", index);
	if (nvm_load_var(filename, id, sizeof(*id)))
		return -1;

	return 0;
}

int nvm_retrieve_ba_key_handle(int index, uint32_t* handle, TypeCurveId_t* id)
{
	char filename[MAX_FILENAME_SIZE];

	if (baKeyHandle[index]) {
		/* Key already in memory, return info */
		*handle = baKeyHandle[index];
		*id = baCurveId[index];
		return 0;
	}

	/* Key not in memory, check if in NVM and load if it is */
	snprintf(filename, MAX_FILENAME_SIZE, "baKeyHandle/%d",	index);
	if (nvm_load_var(filename, (uint8_t*)handle, sizeof(*handle)))
		return -1;

	snprintf(filename, MAX_FILENAME_SIZE, "baCurveId/%d", index);
	if (nvm_load_var(filename, id, sizeof(*id)))
		return -1;

	return 0;
}

int nvm_init(void)
{
	int i;

	/* Verify storage directory exists, create if not */
	if (access(STORAGE_PATH, F_OK)) {
		if (mkdir(STORAGE_PATH, 0700)) {
			return -1;
		}
	}

	/* Verify phase variable exists, create if not and clear all data */
	if (access(STORAGE_PATH"v2xsePhase", F_OK)) {
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
	if (access(STORAGE_PATH"genericStorage", F_OK)) {
		if (mkdir(STORAGE_PATH"genericStorage", 0700)) {
			return -1;
		}
	}

	/* Verify rt key handle & curve directories exist, create if not */
	if (access(STORAGE_PATH"rtKeyHandle", F_OK)) {
		if (mkdir(STORAGE_PATH"rtKeyHandle", 0700)) {
			return -1;
		}
	}
	if (access(STORAGE_PATH"rtCurveId", F_OK)) {
		if (mkdir(STORAGE_PATH"rtCurveId", 0700)) {
			return -1;
		}
	}

	/* Verify ba key handle & curve directories exist, create if not */
	if (access(STORAGE_PATH"baKeyHandle", F_OK)) {
		if (mkdir(STORAGE_PATH"baKeyHandle", 0700)) {
			return -1;
		}
	}
	if (access(STORAGE_PATH"baCurveId", F_OK)) {
		if (mkdir(STORAGE_PATH"baCurveId", 0700)) {
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
