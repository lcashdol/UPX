#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/*https://vcodispot.com/corrupted-upx-packed-elf-repair/*/
/*https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/*/


extern int errno;

void print_usage (char *arg);

int
main (int argc, char **argv)
{
struct stat stats;
unsigned char *data;
long int size=0;
long int header=0;
int total = 0, x = 0, head = 0, z=0, fd=0, fout=0;
char filename[256];

  if (argc < 2)
    print_usage (argv[0]);

  printf
    ("######################################################################################################\n# UPX! Packed Binary un-corruptor v1.0\n\n\n4/15/2021 Larry Cashdollar - Akamai SIRT\n\n\nReading from file %s \n",
     argv[1]);

if (stat(argv[1], &stats) == 0)
    {

data = malloc(stats.st_size * sizeof(char));

} else {
      fprintf(stderr, "Error %s %s\n", argv[1], strerror( errno ));
      exit (0);
}

  fd = open (argv[1], O_RDONLY);
  if (fd < 0)
    {
      fprintf(stderr, "Error %s %s\n", argv[1], strerror( errno ));
      exit (0);
    }
  while (read (fd, &data[total], 1))
    {
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
	  printf ("Found UPX! Header Position at %d ", x);

	  if (head == 1)
	    {
	      header = x + 8;
	      for (z = 0; z < 4; z++)
		{
		  printf ("%.2x", data[(x + 8) + z]);
		}
	      printf ("\n");

	    }

          if (head == 2) printf("\n");

	  if (head == 3)
	    {
	      printf ("\nUPX! p_filesize :");

	      size = x + 24;
// position header 1 is 8 bytes
// position header 3 is 20 bytes
	      for (z = 0; z < 4; z++)
		{
		  printf ("0x%.2x ", data[(x + 24) + z]);
		}
	      printf ("\n");
	    }
	}
    }
  printf ("Header Position:%ld\n", header);
  printf ("File Size Position:%ld\n", size);

  printf ("Correcting Header.... \n");
  for (x = 0; x < 4; x++)
    {
      //copy bytes from the size position over the nulled out p_info header
      data[(header + 4) + x] = data[size + x];
      data[(header + 8) + x] = data[size + x];
    }

  //print out fixed header
  for (x = 1; x <= header + 16; x++)
    {
      printf ("%.2x ", data[x]);
      if ((x % 22) == 0 && x != 0)
	printf ("\n");
    }

  snprintf (filename, 249, "%s.fixed", argv[1]);
  fout = open (filename, O_WRONLY | O_CREAT |O_TRUNC,0644);

  if (!fout) {
      fprintf(stderr, "Error %s %s\n", filename, strerror( errno ));
      exit (0);
  }

  printf ("\nTotal bytes read %d\n\nWriting file %s\n", total, filename);
  total=0;
  while (total < stats.st_size)
    {
      write (fout, &data[total], 1);
      float percent=0.0, t=total,s=stats.st_size;
      percent = (t/s) * 100;
      if (total % 10000 == 0) printf("%.2f %%\n",percent);
      total++;
    }
    printf("Done\n");
  close (fout);
  free(data);
  return 0;
}


void
print_usage (char *arg)
{
  printf ("To attempt to repair a corruptted UPX packed malware sample.\n\n");
  printf ("Usage: %s filename\n", arg);
  exit (0);
}
