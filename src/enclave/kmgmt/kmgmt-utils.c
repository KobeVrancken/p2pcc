#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <stdio.h>  
#include <string.h>

#include "kmgmt-utils.h"
#include "kmgmt_t.h"
/*********/
/* UTILS */
/*********/

//These utility functions are meant for debugging and have been implemented in a quick and dirty way
//Don't ever use them.
const char print_prefix[] = "[ENC] ";

int printf_prefix(const char* format, ...){
  char buffer[1024];
  snprintf(buffer, sizeof(buffer), "%s", print_prefix);
  va_list args;
  va_start( args, format );
  vsnprintf(buffer+strlen(buffer), 1024-strlen(buffer), format, args);
  ocall_print_string(buffer);
  va_end( args );
  return 0;
}

int printf(const char* format, ...){
  char buffer[1024];
  snprintf(buffer, sizeof(buffer), "%s", "");
  va_list args;
  va_start( args, format );
  vsnprintf(buffer+strlen(buffer), 1024-strlen(buffer), format, args);
  ocall_print_string(buffer);
  va_end( args );
  return 0;
}

//Prevent gcc from optimizing printf call in puts to another puts, creating infinite recursion
static int printf_no_opt(const char* format, ...){
  char buffer[1024];
  snprintf(buffer, sizeof(buffer), "%s", "");
  va_list args;
  va_start( args, format );
  vsnprintf(buffer+strlen(buffer), 1024-strlen(buffer), format, args);
  ocall_print_string(buffer);
  va_end( args );
  return 0;
}

int puts(const char *str){
  return printf_no_opt("%s\n", str);
}

int putchar(int ch){
  return printf_no_opt("%c", ch);
}

void dump_buf(void* buffer, size_t size){
  int i;
  for(i = 0; i < size; i++){
     if(i % 8 == 0 && i > 0) printf("\n");
     else if (i > 0) printf(":");
     printf("%02X", ((uint8_t*) buffer)[i]);
  }
  printf("\n");
}
