
LIB_NAME = libv2xhsm.a
C_OBJ = adaptlib.o nvm.o
C_HEADERS = adaptlib.h nvm.h ../hsmstub/hsmstub.h

all: $(LIB_NAME)

.PHONY : clean
clean:
	rm -f *.o *.a

%.o: %.c $(C_HEADERS) ../hsmstub/libhsmstub.a
	$(CC) -c -Wall $< -o $@ -L../hsmstub -lhsmstub

$(LIB_NAME): $(C_OBJ) $(C_HEADERS)
	ar rcs $(LIB_NAME) $(C_OBJ)
