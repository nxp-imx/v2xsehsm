
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

int nvm_load_var(char* name, uint8_t* data, TypeLen_t size)
{
	int fd;
	int retval;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		return -1;
	retval = read(fd, data, size);
	close(fd);
	return retval;
}

int nvm_update_generic_data(int index, uint8_t* data, TypeLen_t size)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"genericStorage/%d",
									index);
	return nvm_update_var(filename, data, size);
}

int nvm_retrieve_generic_data(int index, uint8_t* data, TypeLen_t* size)
{
	char filename[MAX_FILENAME_SIZE];
	int sizeread;

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"genericStorage/%d",
									index);
	sizeread = nvm_load_var(filename, data, V2XSE_MAX_DATA_SIZE_GSA);
	if (sizeread < V2XSE_MIN_DATA_SIZE_GSA)
		return -1;

	*size = sizeread;
	return 0;
}

int nvm_delete_generic_data(int index)
{
	char filename[MAX_FILENAME_SIZE];

	snprintf(filename, MAX_FILENAME_SIZE, STORAGE_PATH"genericStorage/%d",
									index);
	if (access(filename, F_OK))
		return -1;

	return remove(filename);
}

int nvm_update_var(char* name, uint8_t* data, TypeLen_t size)
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

int nvm_load(void)
{
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
		nvm_update_var(STORAGE_PATH"v2xsePhase", &v2xsePhase,
							sizeof(v2xsePhase));
	} else {
		if (nvm_load_var(STORAGE_PATH"v2xsePhase", &v2xsePhase,
				sizeof(v2xsePhase)) != sizeof(v2xsePhase))
			return -1;
	}

	/* Verify storage directory exists, create if not */
	if (access(STORAGE_PATH"genericStorage", F_OK)) {
		if (mkdir(STORAGE_PATH"genericStorage", 0700)) {
			return -1;
		}
	}

	return 0;
}
