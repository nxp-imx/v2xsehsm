
#define MAX_FILENAME_SIZE	128

int nvm_init(void);
int nvm_update_array_data(char* name, int index, uint8_t* data, TypeLen_t size);
int nvm_delete_array_data(char* name, int index);
int nvm_load_generic_data(int index, uint8_t* data, TypeLen_t* size);
int nvm_update_generic_data(int index, uint8_t* data, TypeLen_t size);
int nvm_delete_generic_data(int index);
int nvm_update_var(char* name, uint8_t* data, TypeLen_t size);
int nvm_retrieve_ma_key_handle(uint32_t* handle, TypeCurveId_t* id);
int nvm_retrieve_rt_key_handle(int index, uint32_t* handle, TypeCurveId_t* id);
int nvm_retrieve_ba_key_handle(int index, uint32_t* handle, TypeCurveId_t* id);
