#ifndef _UTILITY_H
#define _UTILITY_H

#include <stdio.h>
#include <stdint.h>

void die (const char *format, ...);

void *xmalloc (size_t size);

void *xrealloc (void *a, size_t size);

char *xstrdup (const char *str);

char *peek_next_token (char *buf);

int is_whitespace (const char *text);


void chomp_trailing_whitespace (char *buf);

int starts_with (const char *str, const char *prefix);

void dump_buf_32(uint32_t* buf, size_t buf_size);
void dump_buf(uint8_t* buf, size_t buf_size);

#endif
