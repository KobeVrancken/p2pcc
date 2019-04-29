#include "kmgmt-untrusted.h"

#include <limits.h>

#include <sgx_urts.h>
#include <sgx_ukey_exchange.h>
#include <sgx_uae_service.h>


#include <utils/sgx-errors.h>

#include <utils/utility.h>
#include <kmgmt_u.h>

//TODO clean up decently if attestation fails
#define SGX_CHECK_NORET(ret) if(!(ret == SGX_SUCCESS)){print_error_message(ret); \
    fprintf(stderr,"Failed on line %d in function %s.\n", __LINE__, __FUNCTION__);}

#define SGX_CHECK_RET(ret) if(!(ret == SGX_SUCCESS)){print_error_message(ret);\
    fprintf(stderr,"Failed on line %d in function %s.\n", __LINE__, __FUNCTION__);return -1;}

#define SGX_CHECK_CLEAN(ret) if(!(ret == SGX_SUCCESS)){print_error_message(ret);\
    fprintf(stderr,"Failed on line %d in function %s.\n", __LINE__, __FUNCTION__);kmgmt_clean_session();}

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

sgx_enclave_id_t enclave_id = 0;
sgx_ra_context_t context = INT_MAX;
uint32_t extended_epid_group_id = 0;

sgx_ra_msg1_t* msg1_raw = NULL;

int start_key_enclave(char* path)
{
  sgx_status_t ret;
  ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
  SGX_CHECK_RET(ret);
  int launch_token_update = 0;
  sgx_launch_token_t launch_token = {0};
  memset(&launch_token, 0, sizeof(sgx_launch_token_t));

  ret = sgx_create_enclave(path,
                           SGX_DEBUG_FLAG,
                           &launch_token,
                           &launch_token_update,
                           &enclave_id, NULL);
  SGX_CHECK_RET(ret);
  return 0;
}


sgx_ec256_public_t ga_bak;

//Fills 
int kmgmt_att_get_msg1(sgx_ra_msg1_t* msg1){
  sgx_status_t ret, status;
  if(enclave_id <= 0){
    fprintf(stderr, "%s", "Key management enclave not loaded. Cannot start attestation.\n");
    return -1;
  }
  
  if(msg1 == NULL){
    fprintf(stderr, "%s", "No buffer provided to store msg1.\n");
    return -2;
  }
  
  ret = kmgmt_enclave_init_ra(enclave_id,
                                  &status,
			          0,
                                  &context);
  SGX_CHECK_RET(ret);
  SGX_CHECK_RET(status);
 
  ret = sgx_ra_get_msg1(context, enclave_id, kmgmt_sgx_ra_get_ga,
			msg1);
 
  SGX_CHECK_CLEAN(ret);
 
  return ret;
}


int kmgmt_att_get_msg3(const sgx_ra_msg2_t* msg2, sgx_ra_msg3_t** msg3, uint32_t* msg3_size){
  
  sgx_status_t ret;

  
  ret = sgx_ra_proc_msg2(context,
			 enclave_id,
			 kmgmt_sgx_ra_proc_msg2_trusted,
			 kmgmt_sgx_ra_get_msg3_trusted,
			 msg2,
			 sizeof(sgx_ra_msg2_t),
			 msg3,
			 msg3_size);

  if(!msg3){
    fprintf(stderr, "%s\n", "Failed to call sgx_ra_proc_msg2\n");
    return -1;
  }
  SGX_CHECK_RET(ret);
  
  return ret;
}

int kmgmt_att_verify_result()
{
  //TODO implement this verification 
  
  return 0;
  
}

int execute_command(uint8_t* command, size_t command_size, uint8_t* command_mac, uint8_t* response, uint32_t response_size, uint8_t* response_mac){
  sgx_status_t status;
  sgx_status_t ret;
  ret = kmgmt_execute_command(enclave_id, &status, context, command, command_size, command_mac, response, response_size, response_mac);
  return (int) status;
}

int kmgmt_clean_session(){
  //TODO implement
  return 0;
 
}
