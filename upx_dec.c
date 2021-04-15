#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/*https://vcodispot.com/corrupted-upx-packed-elf-repair/*/
/*https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/*/
unsigned char data[2560000];
long int size;
long int header;
int total = 0;

int
main (int argc, char **argv)
{

  int x = 0, head = 0, z;
  int fd;
  int byte = 1;

  printf
    ("UPX Packed Binary Decorruptor v0.1\n\n\nAkamai SIRT\n\n\nReading from file %s \n",
     argv[1]);
  fd = open (argv[1], O_RDONLY);
  while (byte)
    {
      byte = read (fd, &data[x], 1);
//printf("Location : Byte:%.2x\n",c);
      x++;
      total++;
    }
  close (fd);
//search for UPX! headers then find p_sizeinfo
  for (x = 0; x <= total; x++)
    {
      if (data[x] == 0x55 && data[x + 1] == 0x50 && data[x + 2] == 0x58
	  && data[x + 3] == 0x21)
	{
	  head++;
	  printf ("Found UPX! Header Position %d\n", x);

	  if (head == 1)
	    {
		    header = x+8;
	      for (z = 0; z < 4; z++)
		{
		  printf ("%.2x", data[(x + 8) + z]);
		 // header[z] = (x + 8)+z;
		}
	      printf ("\n");

	    }

	  if (head == 3)
	    {
	      printf ("UPX! p_filesize\n");

	      size = x+24;
// position header 1 is 8 bytes
// position header 3 is 20 bytes
	      for (z = 0; z < 4; z++)
		{
		  printf ("%.2x", data[(x + 24) + z]);
                  //size[z] = data[(x+24)+z];
		}
	      printf ("\n");
	    }
	}
//printf("%x %c %d \n",data[x],data[x],x);
//printf("%x",data[x]);
    }
//printf("\n");
  printf("%ld\n",header);
  printf("%ld\n",size);

  for (x = 0; x < 4; x++) {
          //copy bytes from the size position over the nulled out p_info header
	  data[(header+4)+x] = data[size+x];
	  data[(header+8)+x] = data[size+x];
  }
printf("Corrected Header \n");
for (x = 0; x<=header+4;x++) {
	printf("%.2x",data[x]);
}	


  printf ("\nTotal bytes read %d\n", total);


FILE *ffile;
 ffile = fopen("newbin","wb");
 fwrite(&data,total,1,ffile);

}
