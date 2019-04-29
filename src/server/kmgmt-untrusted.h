#ifndef _KMGMT_UNTRUSTED_H
#define _KMGMT_UNTRUSTED_H

#include <sgx_ukey_exchange.h>


int start_key_enclave(char* path);

int kmgmt_att_get_msg1(sgx_ra_msg1_t* msg1);

int kmgmt_att_get_msg3(const sgx_ra_msg2_t* msg2, sgx_ra_msg3_t** msg3, uint32_t* msg3_size);

int execute_command(uint8_t* command, size_t command_size, uint8_t* command_mac, uint8_t* response, uint32_t response_size, uint8_t* response_mac); 

int kmgmt_clean_session();

#endif
