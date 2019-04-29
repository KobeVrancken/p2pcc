#include <stdio.h>

//#define ATTESTATION_DEBUG 1
#define KMGMT_DEBUG 1

int puts(const char *str);

int printf(const char* format, ...);

int printf_prefix(const char* format, ...);

void dump_buf(void* buffer, size_t size);
