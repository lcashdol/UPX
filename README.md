# UPX

Some C code to repair corrupt p_info header on UPX! packed malware.
```
larry@0v3rfl0w:~/code/UPX$ file 496
496: ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped
larry@0v3rfl0w:~/code/UPX$ upx -d 496
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: 496: CantUnpackException: file header corrupted

Unpacked 1 file: 0 ok, 1 error.
larry@0v3rfl0w:~/code/UPX$ ./upx_dec 496
UPX! Packed Binary un-corruptor v1.0


4/15/2021 Larry Cashdollar - Akamai SIRT


Reading from file 496 
Found UPX! Header Position 120
00000000
Found UPX! Header Position 134962
Found UPX! Header Position 134972
UPX! p_filesize :0x10 0x6f 0x05 0x00 
Header Position:128
File Size Position:134996
Correcting Header.... 
45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 08 00 01 00 00 
00 c8 03 42 00 34 00 00 00 00 00 00 00 07 10 00 00 34 00 20 00 02 
00 28 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 40 00 00 00 40 
00 ee 0d 02 00 ee 0d 02 00 05 00 00 00 00 00 01 00 01 00 00 00 00 
00 00 00 00 00 43 00 00 00 43 00 00 00 00 00 68 ba 08 00 06 00 00 
00 00 00 01 00 8d c0 e9 b2 55 50 58 21 30 0a 0d 1e 00 00 00 00 10 
6f 05 00 10 6f 05 00 94 00 00 00 5d 
Total bytes read 135008

Writing file 496.fixed
larry@0v3rfl0w:~/code/UPX$ upx -d 496.fixed 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    356908 <-    135008   37.83%  linux/mipsel   496.fixed

Unpacked 1 file.
```
