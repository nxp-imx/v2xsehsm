
LIB_NAME = v2x_hsm_adaptation.a
C_OBJ = adaptlib.o nvm.o ../hsmstub/hsmstub.a
C_HEADERS = adaptlib.h nvm.h ../hsmstub/hsmstub.h

all: $(LIB_NAME)

.PHONY : clean
clean:
	rm *.o *.a

%.o: %.c $(C_HEADERS)
	$(CC) -c -Wall $< -o $@

$(LIB_NAME): $(C_OBJ) $(C_HEADERS)
	ar rcs $(LIB_NAME) $(C_OBJ)
