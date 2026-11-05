#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>



/*Code here is based on research published by these fellow researcher's articles

  https://vcodispot.com/corrupted-upx-packed-elf-repair
  https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware*/

void print_usage (char *arg);
void print_banner (char *arg);

#define MAXWIDTH 24
#define COLOR "\033[1;33m"
#define CLEAR "\033[0m"

/* UPX >= v10 PackHeader: 32 bytes, "UPX!" + version/format/method/level, the
   adler/length fields, u_file_size at +24, and header_checksum as the last
   byte (= sum of bytes 4..30, mod 251).  On ELF packs it is followed by a
   4-byte overlay_offset (the offset of p_info).  UPX's canUnpack() only scans
   the last ~8 KB of the file, skipping trailing zero bytes, and expects the
   PackHeader + overlay_offset at the very end.  Appending junk after them
   (and optionally planting a decoy "UPX!" before the real header) makes
   "upx -d" fail with "header corrupted 1" even though every header is intact. */
#define PH_SIZE 32
#define PH_TRAILER 4

static int
ph_checksum_ok (const unsigned char *p)
{
  unsigned c = 0;
  int i;
  for (i = 4; i < PH_SIZE - 1; i++)
    c += p[i];
  return (c % 251) == p[PH_SIZE - 1];
}

/* Offset of the last PackHeader whose version (>= 10) and checksum validate,
   or -1.  The header checksum rejects decoy/garbage "UPX!" matches. */
static long
find_packheader (const unsigned char *d, long total)
{
  long x, found = -1;
  for (x = 0; x + PH_SIZE + PH_TRAILER <= total; x++)
    if (d[x] == 0x55 && d[x + 1] == 0x50 && d[x + 2] == 0x58 && d[x + 3] == 0x21
	&& d[x + 4] >= 10 && d[x + 4] < 0xff && ph_checksum_ok (d + x))
      found = x;
  return found;
}

int
main (int argc, char **argv)
{
  struct stat stats;
  unsigned char *data = NULL;
  unsigned char p_info[5], f_size[5];
  long int size = -1;
  long int header = -1, missing_magic = 0;
  long int ph_off = -1, out_len = 0;
  int tail_fix = 0, pinfo_stage = 1;
  int total = 0, x = 0, i = 0, head = 0, z = 0, fd = 0, ret = 0, fout = 0, compare =
    0;
  char filename[256];

  if (argc < 2)
    print_usage (argv[0]);

  print_banner (argv[1]);
  if (stat (argv[1], &stats) == 0)
    {
      data = malloc ((stats.st_size + 1) * sizeof (char));
      if (data == NULL)
	{
	  fprintf (stderr, "Error allocating %ld bytes: %s\n",
		    (long) (stats.st_size + 1), strerror (errno));
	  exit (0);
	}
    }
  else
    {
      fprintf (stderr, "Error %s %s\n", argv[1], strerror (errno));
      exit (0);
    }
  //initialize array (also guarantees a zero sentinel byte at data[stats.st_size]).
  for (x = 0; x <= stats.st_size; x++)
    data[x] = 0;

  fd = open (argv[1], O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "Error %s %s\n", argv[1], strerror (errno));
      free (data);
      exit (0);
    }
  // Read the whole file in one call instead of one syscall per byte.
  total = read (fd, data, stats.st_size);
  if (total < 0)
    {
      fprintf (stderr, "Error reading %s: %s\n", argv[1], strerror (errno));
      close (fd);
      free (data);
      exit (0);
    }
  close (fd);

  //search for UPX! headers then find p_sizeinfo
  //
  //Bounded to x + 4 <= total so the 4-byte magic comparisons below never
  //read past the last byte actually read from the file -- corrupted/
  //truncated samples (the whole point of this tool) can otherwise walk
  //a few bytes off the end of the allocation.
  for (x = 0; x + 4 <= total; x++)
    {

      if (DEBUG)
	{
	  printf ("%.2x ", data[x]);
	  if ((x % MAXWIDTH) == 0 && x != 0)
	    printf ("\n");
	}

      //if there are 4 trailing arguments after the filename, treat them as
      //hex bytes (argv[2..5]) and compare below
      if (argc > 5)
	{
	  int want[4];
	  int j;
	  for (j = 0; j < 4; j++)
	    want[j] = (int) strtol (argv[2 + j], NULL, 16);

	  if (data[x] == want[0] && data[x + 1] == want[1]
	      && data[x + 2] == want[2] && data[x + 3] == want[3])
	    {
	      printf ("Found UPX corrupted header user supplied hexidecimal fixing.\n");
	      for (i = x; i <= (x + 3); i++)
		{
		  printf ("%x", data[i]);
		}
	      printf ("->");

	      data[x] = 0x55;
	      data[x + 1] = 0x50;
	      data[x + 2] = 0x58;
	      data[x + 3] = 0x21;
	      missing_magic++;
	      for (i = x; i <= (x + 3); i++)
		{
		  printf ("%x", data[i]);
		}
	      printf ("\n");
	    }
	}

      if (data[x] == 0x59 && data[x + 1] == 0x54 && data[x + 2] == 0x53
	  && data[x + 3] == 0x99)	//look for UPX that has been replaced with YTS.
	{

	  printf ("Found UPX corrupted header (YTS.) fixing.\n");
	  for (i = x; i <= (x + 3); i++)
	    {
	      printf ("%x", data[i]);
	    }
	  printf ("->");

	  data[x] = 0x55;
	  data[x + 1] = 0x50;
	  data[x + 2] = 0x58;
	  data[x + 3] = 0x21;
	  missing_magic++;
	  for (i = x; i <= (x + 3); i++)
	    {
	      printf ("%x", data[i]);
	    }
	  printf ("\n");
	}

      if (data[x] == 0x55 && data[x + 1] == 0x55 && data[x + 2] == 0x55 && data[x + 3] == 0x21)	//look for UPX that has been replaced with UUU!.
	{

	  printf ("Found UPX corrupted header (UUU!) fixing.\n");
	  printf (COLOR);
	  for (i = x; i <= (x + 3); i++)
	    {
	      printf ("%c", data[i]);
	    }
	  printf (CLEAR);
	  printf ("->");

	  data[x] = 0x55;
	  data[x + 1] = 0x50;
	  data[x + 2] = 0x58;
	  data[x + 3] = 0x21;
	  missing_magic++;
	  for (i = x; i <= (x + 3); i++)
	    {
	      printf ("%c", data[i]);
	    }
	  printf ("\n");
	}

      // The corrupted-magic fixups above patch data[x..x+3] to a clean "UPX!"
      // in place, so this check fires in the *same* pass for headers we just
      // repaired, not only for ones that were already intact.
      if (data[x] == 0x55 && data[x + 1] == 0x50 && data[x + 2] == 0x58
	  && data[x + 3] == 0x21)
	{
	  head++;
	  printf ("Found UPX! Header Position at %d ", x);

	  if (head == 1)
	    {
	      header = x + 8;
	      for (z = 0; z < 4 && (x + 8 + z) < total; z++)
		{
		  printf ("%.2x", data[(x + 8) + z]);
		}
	      printf ("\n");

	    }

	  if (head == 2)
	    printf ("\n");

	  if (head == 3)
	    {
	      printf ("\nUPX! p_filesize :");

	      size = x + 24;
	      // position header 1 is 8 bytes
	      // position header 3 is 20 bytes
	      if (size + 4 <= total)
		{
		  for (z = 0; z < 4; z++)
		    {
		      printf ("0x%.2x ", data[size + z]);
		    }
		}
	      else
		{
		  printf ("(truncated -- not enough bytes left in file)");
		}
	      printf ("\n");
	    }
	  if (head == 4)
	    {
	      printf ("\nFound 4th UPX! Header, using p_filesize :");

	      size = x + 24;
	      if (size + 4 <= total)
		{
		  for (z = 0; z < 4; z++)
		    {
		      printf ("0x%.2x ", data[size + z]);
		    }
		}
	      else
		{
		  printf ("(truncated -- not enough bytes left in file)");
		}
	      printf (" Instead. \n");
	    }
	}
    }


  // Variant 3: junk appended after the PackHeader + overlay_offset.  Find the
  // real PackHeader (validated by its header_checksum, which also rejects any
  // decoy "UPX!" planted before it) and trim everything after the 4-byte
  // overlay_offset.  Trailing zero bytes are left alone: UPX skips those itself.
  out_len = total;
  ph_off = find_packheader (data, total);
  if (ph_off >= 0)
    {
      long tail = ph_off + PH_SIZE + PH_TRAILER;
      long ov;
      int be = (total > 5 && data[0] == 0x7f && data[1] == 'E'
		&& data[2] == 'L' && data[3] == 'F' && data[5] == 2);
      const unsigned char *o = data + ph_off + PH_SIZE;
      ov = be ? (((long) o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3])
	: (((long) o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0]);

      printf ("Found valid PackHeader (checksum ok) at %ld, overlay_offset 0x%lx",
	      ph_off, ov);
      if (ov >= 0 && ov + 12 <= ph_off
	  && memcmp (data + ov + 4, data + ph_off + 24, 4) == 0)
	printf (" -> p_info.p_filesize matches u_file_size\n");
      else
	printf (" (does not point at a matching p_info; continuing anyway)\n");

      for (z = (int) tail; z < total && data[z] == 0; z++)
	;
      if (z < total)
	{
	  tail_fix = 1;
	  out_len = tail;
	  printf ("Found %ld junk bytes after the PackHeader/overlay_offset; "
		  "trimming file to %ld bytes.\n", (long) total - tail, tail);
	}
    }

  if (head < 3 && missing_magic < 3)
    {
      if (!tail_fix)
	{
	  printf ("Missing required UPX Headers. Found %d.\n.\n", head);
	  free (data);
	  exit (0);
	}
      pinfo_stage = 0;		// only the tail needs repair
    }

  // header/size are byte offsets computed from wherever the magic was found;
  // on a badly truncated sample they can end up pointing past the data we
  // actually read, which would turn the fixups below into an OOB read/write.
  if (pinfo_stage
      && (header < 0 || size < 0 || header + 16 > total - 1
	  || size + 3 > total - 1))
    {
      if (!tail_fix)
	{
	  fprintf (stderr,
		   "Header/size offsets fall outside the file -- sample is too truncated to fix safely.\n");
	  free (data);
	  exit (0);
	}
      pinfo_stage = 0;
    }

  // Prefer the checksum-validated PackHeader for p_filesize over the Nth
  // "UPX!" occurrence (decoy magics can shift the count).
  if (pinfo_stage && ph_off >= 0 && size != ph_off + 24
      && ph_off + 28 <= total)
    {
      printf ("Using validated PackHeader u_file_size at %ld (was %ld).\n",
	      ph_off + 24, size);
      size = ph_off + 24;
    }

  if (pinfo_stage)
    {
  printf ("Header Position:%ld\n", header);
  printf ("File Size Position:%ld\n", size);

  for (x = 0; x < 4; x++)
    {
      // lets check these vaules out first
      p_info[x] = data[(header + 4) + x];
      f_size[x] = data[size + x];
    }
  f_size[4] = '\0';
  p_info[4] = '\0';
// compare values to see if they differ

  for (z = 0; z < 4; z++)
    {
      printf ("0x%.2x compare 0x%.2x \n", f_size[z], p_info[z]);
      if (f_size[z] == p_info[z])
	compare++;
    }

  if (compare == 4 && missing_magic == 0 && !tail_fix)
    {
      printf ("File doesn't appear to be corrupted\n");
      free (data);
      exit (0);
    }

  printf ("\n");
  if (missing_magic == 0 && compare != 4)
    {
      printf ("Correcting Header.... \n");
      for (x = 0; x < 4; x++)
	{
	  //copy bytes from the size position over the nulled out p_info header
	  data[(header + 4) + x] = data[size + x];
	  data[(header + 8) + x] = data[size + x];
	}
    }

  //print out fixed header
  for (x = 1; x <= header + 16; x++)
    {
      if (x == (header + 4))
	printf (COLOR);		//printf("\033[0;31m");
      printf ("%.2x ", data[x]);
      if ((x % MAXWIDTH) == 0 && x != 0)
	printf ("\n");
      if (x == (header + 12))
	printf (CLEAR);
    }
    }				// pinfo_stage

  snprintf (filename, 249, "%s.fixed", argv[1]);
  fout = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);

  if (fout < 0)
    {
      fprintf (stderr, "Error %s %s\n", filename, strerror (errno));
      free (data);
      exit (0);
    }

  printf ("\nTotal bytes read %d\n\nWriting %ld bytes to file %s ->", total,
	  out_len, filename);
  total = 0;
  while (total < out_len)
    {
      ret = write (fout, &data[total], 1);
      if (ret < 0)
	{
	  fprintf (stderr, "Error in writing file !\n");
	  fprintf (stderr, "Error %s %s\n", filename, strerror (errno));
	  close (fout);
	  free (data);
	  exit (0);
	}
      total++;
    }
  printf (" Done\n");
  close (fout);
  free (data);
  return 0;
}


void
print_usage (char *arg)
{
  printf ("To attempt to repair a corruptted UPX packed malware sample.\n\n");
  printf ("Usage: %s filename [byte1 byte2 byte3 byte4]\n", arg);
  printf ("  byte1-4 (optional, hex): a custom 4-byte corrupted magic to look for\n");
  printf ("  instead of/in addition to the built-in YTS./UUU! variants, e.g.:\n");
  printf ("    %s sample.bin 0x99 0x54 0x53 0x99\n", arg);
  exit (0);
}


void
print_banner (char *arg)
{

  printf
    ("+===========================================================================+\n");
  printf
    ("|                       UPX! Corrupt Header Fixer v1.3                      |\n");
  printf
    ("|                       Larry W. Cashdollar, 2/8/2023                       |\n");
  printf
    ("+===========================================================================+\n");
  printf ("Reading File :%s\n", arg);
}
