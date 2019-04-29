

#ifndef CLIENT_ATTESTATION_H
#define CLIENT_ATTESTATION_H

#include <sgx_ukey_exchange.h>

int client_att_get_msg2(const sgx_ra_msg1_t* msg1, sgx_ra_msg2_t* msg2);

int client_att_get_result(const sgx_ra_msg3_t* msg3, const uint32_t quote_size, uint8_t* result);

int encrypt_message(const uint8_t* message, const size_t message_size, uint8_t* encrypted_buffer, uint8_t* mac);

#endif
