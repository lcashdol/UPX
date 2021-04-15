MAKE=gmake
CC=gcc
CFLAGS = -Wall -ggdb -O2 -D DEBUG=0 $(DEFS)

all	: 
	make 	upx_dec	

upx_dec	: upx_dec.o
	$(CC) -O2 -o upx_dec upx_dec.o

clean	: 
	@echo "Cleaning up src files."
	@rm -f src/*.o $(ARCH)-$(SYS)/httpd
 	
arch	:
	@echo "Making archive."
	@./lcs