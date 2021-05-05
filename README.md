# UPX Fixer

Some C code to repair corrupt p_info header on UPX! packed malware.
```
+=====================================================================================+
|                       UPX! Corrupt Header Fixer v1.0                                |
|                                                                                     |
|                       Larry W. Cashdollar, 4/20/2021                                |
|                                                                                     |
+=====================================================================================+
Reading File :Mozi.m
Found UPX! Header Position at 120 00000000
Found UPX! Header Position at 108763 
Found UPX! Header Position at 108772 
UPX! p_filesize :0x00 0x04 0x0f 0x7c 
Header Position:128
File Size Position:108796
Correcting Header.... 
45 4c 46 01 02 01 00 00 00 00 00 00 00 00 00 00 02 00 08 00 00 00 
01 00 11 9d e8 00 00 00 34 00 00 00 00 00 00 10 07 00 34 00 20 00 
02 00 28 00 00 00 00 00 00 00 01 00 00 00 00 00 10 00 00 00 10 00 
00 00 01 a7 a3 00 01 a7 a3 00 00 00 05 00 01 00 00 00 00 00 01 00 
00 de 24 00 49 de 24 00 49 de 24 00 00 00 00 00 00 00 00 00 00 00 
06 00 01 00 00 c8 cd a5 93 55 50 58 21 09 dc 0d 89 00 00 00 00 00 
04 0f 7c 00 04 0f 7c 00 00 00 94 00 
Total bytes read 108808

Writing file Mozi.m.fixed
0.00 %
9.19 %
18.38 %
27.57 %
36.76 %
45.95 %
55.14 %
64.33 %
73.52 %
82.71 %
91.91 %
Done

larry@0v3rfl0w:~/code/UPX$ upx -d Mozi.m.fixed 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    356908 <-    135008   37.83%  linux/mipsel   Mozi.m.fixed

Unpacked 1 file.

```
