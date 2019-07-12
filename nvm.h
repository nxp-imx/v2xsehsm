
#include "adaptlib.h"

#define MAX_FILENAME_SIZE	128

int nvm_load(void);
int nvm_update_generic_data(int index, uint8_t* data, TypeLen_t size);
int nvm_retrieve_generic_data(int index, uint8_t* data, TypeLen_t* size);
int nvm_delete_generic_data(int index);
int nvm_update_var(char* name, uint8_t* data, TypeLen_t size);
