/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdarg.h>     /* va_list, va_start, va_arg, va_end */
#include <stdio.h>  
#include "kmgmt_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_dh.h"
#include "string.h"
#include "kmgmt-utils.h"

#ifndef ISV_ENCLAVE_HEADER
#define ISV_ENCLAVE_HEADER

//Warning: Same key as used in sample code SDK. Use different key for real applications!
const sgx_ec256_public_t g_sp_pub_key = {
  {
  0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
  0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
  0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
  0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
  },
  {
  0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
  0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
  0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
  0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
  }

};


/***************************/
/* ATTESTATION SAMPLE CODE */
/***************************/

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context) {
  // isv enclave call to trusted key exchange library.
  sgx_status_t ret;
  if (b_pse) {
    int busy_retry_times = 2;
    do {
      ret = sgx_create_pse_session();
    } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
      return ret;
  }
  ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
  //dump_buf(&g_sp_pub_key.gx, sizeof(&g_sp_pub_key.gx));
  //dump_buf(&g_sp_pub_key.gy, sizeof(&g_sp_pub_key.gy));
  if (b_pse) {
    sgx_close_pse_session();
    return ret;
  }
  return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context) {
  sgx_status_t ret;
  ret = sgx_ra_close(context);
  return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t *p_message,
                                   size_t message_size,
                                   uint8_t *p_mac,
                                   size_t mac_size) {
  sgx_status_t ret;
  sgx_ec_key_128bit_t mk_key;

  if (mac_size != sizeof(sgx_mac_t)) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  if (message_size > UINT32_MAX) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  do {
    uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
    if (SGX_SUCCESS != ret) {
      break;
    }
    ret = sgx_rijndael128_cmac_msg(&mk_key,
                                   p_message,
                                   (uint32_t) message_size,
                                   &mac);
    if (SGX_SUCCESS != ret) {
      break;
    }
    if (0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
      ret = SGX_ERROR_MAC_MISMATCH;
      break;
    }

  } while (0);

  return ret;
}

int execute_decrypted_command(uint8_t *p_command, uint32_t command_size, uint8_t *p_result, uint32_t result_size);

sgx_status_t execute_command(
    sgx_ra_context_t context,
    uint8_t *p_command,
    uint32_t command_size,
    uint8_t *p_gcm_mac,
    uint8_t *p_result,
    uint32_t result_size,
    uint8_t *p_result_gcm_mac) {
  sgx_status_t ret = SGX_SUCCESS;
  sgx_ec_key_128bit_t sk_key;
 ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
 if(ret != SGX_SUCCESS) return ret;

#ifdef ATTESTATION_DEBUG
  printf_prefix("Received encrypted command (size %d). \n", command_size);
#endif
  
  uint8_t aes_gcm_iv[12] = {0};

  uint8_t *p_decrypted_command = (uint8_t *) malloc(command_size);

  ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                   p_command,
                                   command_size,
                                   p_decrypted_command,
                                   &aes_gcm_iv[0],
                                   12,
                                   NULL,
                                   0,
                                   (const sgx_aes_gcm_128bit_tag_t *)
                                       (p_gcm_mac));

  if(ret != SGX_SUCCESS) return ret;
  
#ifdef ATTESTATION_DEBUG
  printf_prefix("Successfully decrypted command\n");
#endif
  
  uint8_t *p_temp_result = (uint8_t *) malloc(result_size);
  if(p_temp_result == NULL) return SGX_ERROR_OUT_OF_MEMORY;
  
  execute_decrypted_command(p_decrypted_command, command_size, p_temp_result, result_size);
  //TODO IV!
  memset(aes_gcm_iv, 0, sizeof(aes_gcm_iv));

  ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                   p_temp_result,
                                   result_size,
                                   p_result,
                                   &aes_gcm_iv[0],
                                   12,
                                   NULL,
                                   0,
                                   (sgx_aes_gcm_128bit_tag_t *) p_result_gcm_mac);
  free(p_temp_result);
  free(p_decrypted_command);
  return ret;
}

#endif
