#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

#include "utility.h"

void die (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  fprintf (stderr, "\n");
  exit (1);
}


void *xmalloc (size_t size)
{
  void *rv;
  if (size == 0)
    return NULL;
  rv = malloc (size);
  if (rv == NULL)
    die ("out-of-memory allocating %u bytes", (unsigned) size);
  return rv;
}

void *xrealloc (void *a, size_t size)
{
  void *rv;
  if (size == 0)
    {
      free (a);
      return NULL;
    }
  if (a == NULL)
    return xmalloc (size);
  rv = realloc (a, size);
  if (rv == NULL)
    die ("out-of-memory re-allocating %u bytes", (unsigned) size);
  return rv;
}

char *xstrdup (const char *str)
{
  if (str == NULL)
    return NULL;
  return strcpy (xmalloc (strlen (str) + 1), str);
}

char *peek_next_token (char *buf)
{
  while (*buf && !isspace (*buf))
    buf++;
  while (*buf && isspace (*buf))
    buf++;
  return buf;
}

int is_whitespace (const char *text)
{
  while (*text != 0)
    {
      if (!isspace (*text))
        return 0;
      text++;
    }
  return 1;
}

void chomp_trailing_whitespace (char *buf)
{
  unsigned len = strlen (buf);
  while (len > 0)
    {
      if (!isspace (buf[len-1]))
        break;
      len--;
    }
  buf[len] = 0;
}

int starts_with (const char *str, const char *prefix)
{
  return memcmp (str, prefix, strlen (prefix)) == 0;
}

void dump_buf_32(uint32_t* buf, size_t buf_size){
  size_t i;
  for (i = 0; i < buf_size; i++)
    {
      if (i > 0) fprintf(stderr, ":");
      fprintf(stderr, "%08X", buf[i]);
    }
  fprintf(stderr, "\n");
}

void dump_buf(uint8_t* buf, size_t buf_size){
  size_t i;
  for (i = 0; i < buf_size; i++)
    {
      if(i > 0 && i%8 == 0) fprintf(stderr, "\n");
      else if (i > 0) fprintf(stderr, ":");
      fprintf(stderr, "%02X", buf[i]);
      
    }
  fprintf(stderr, "\n");
}
