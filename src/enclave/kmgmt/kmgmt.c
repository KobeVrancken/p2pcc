#include <assert.h>
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <stdio.h>  
#include "kmgmt_t.h"
#include "kmgmt-utils.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_dh.h"
#include "string.h"


int attest_enclave(char* mrenclave, uint32_t mrenclave_length);


int create_and_attest_distcc_enclave(char* mrenclave, uint32_t mrenclave_length){
  //At this point we normally spawn the distcc enclave using Graphene. Temporarily removed until
  //the distcc modification code is added to the repo
 char spawn_distcc_command[] = "echo 'Spawning distcc enclave...'";
 
 int ret_val[1];
 int ret = execute_shell_command(spawn_distcc_command, ret_val);
 if(ret == -1){
    printf_prefix("Execute failed\n");
    return -1;
 }
 if(attest_enclave(mrenclave, mrenclave_length)){
   printf_prefix("Local attestation of Graphene enclave failed!");
   return -2;
 }
 
  return 0;
}

int attest_enclave(char* mrenclave, uint32_t mrenclave_length){
  //TODO implement local attestation procedure with Graphene enclave here
  //Afterwards, encrypt all communication with the graphene enclave using the local attestation key
  //Currently, we simply ignore this and pass the symmetric key to an unverified distcc graphene enclave,
  //which could be maliciously spawned by the OS.
  return 0;
}


int execute_decrypted_command(uint8_t *p_command, uint32_t command_size, uint8_t *p_result, uint32_t result_size){
  //The key mgmt enclave only knows one command at the moment, which is the SPAWN ENCLAVE command
  //This command spawns a new session on behalf of the attestor, establishes a secure session with
  //the new enclave and provisions it with the provided symmetric key. It replies with the PORT
  //on which the newly spawned enclave will be listening for communication
  char* init_protocol = "MRENCLAVE ";
  if(strncmp((char*) p_command, init_protocol, strlen(init_protocol)) == 0){
    size_t prefix_size = strlen(init_protocol);
    char* mrenclave = ((char*) p_command)+prefix_size;
    size_t mrenclave_length = command_size - prefix_size;

#ifdef KMGMT_DEBUG
    printf_prefix("Received MRENCLAVE (%s) \n", mrenclave);
#endif
    if(create_and_attest_distcc_enclave(mrenclave, mrenclave_length)){
      printf_prefix("Failed to start distcc enclave\n");
      return -2;
    };
    //This responds with PORT 3306 since this is where we spawn the Graphene enclave
    char response[] = "PORT 3306";
    if(sizeof(response) >= result_size){
      printf_prefix("Not enough memory in response buffer\n");
      return -3;
    }
    memcpy(p_result,&response,sizeof(response));
    return 0;
  }else{
    printf_prefix("Did not understand received command (%s). Aborting.\n", p_command);
    return -1;
  }
}
 
