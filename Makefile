
LIB_NAME=v2x_hsm_adaptation

C_SOURCE=adaptlib.c

$(LIB_NAME): $(C_SOURCE)
	$(CC) -c -o $(LIB_NAME).o $(C_SOURCE)
	ar rcs $(LIB_NAME).a $(LIB_NAME).o
