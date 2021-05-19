# UPX Fixer

Some C code to repair corrupt p_info header on UPX! packed malware.

```
$ make
make 	upx_dec	
make[1]: Entering directory '/home/larry/code/UPX'
gcc -Wall -ggdb -O2 -D DEBUG=0    -c -o upx_dec.o upx_dec.c
gcc -O2 -o upx_dec upx_dec.o
make[1]: Leaving directory '/home/larry/code/UPX'
```


![alt text](https://raw.githubusercontent.com/lcashdol/UPX/main/upx_dec.jpg "upx_dec output")
