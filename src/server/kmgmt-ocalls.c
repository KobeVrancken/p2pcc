#include "kmgmt-ocalls.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void ocall_print_string(const char *str) {
  printf("%s", str);
  fflush(stdout);
}

int execute_shell_command(const char* command, int ret_val[1]){
  int pid = fork();
  if(pid == -1) return -1;
  if(pid == 0){
    FILE *fp;
    char path[1035];

    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == NULL) {
      printf("Failed to run command\n" );
      ret_val[0] = -1;
      exit(1);
    }else{
      ret_val[0] = 0;
    }

    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
      printf("%s", path);
    }

    /* close */
    pclose(fp);
    exit(0);
  } else {
    return 0;
  }
}

void ocall_sleep(unsigned int seconds, int ret_val[1]){
  ret_val[0] = sleep(seconds);
}
