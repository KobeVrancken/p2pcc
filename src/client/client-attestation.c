#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>

#include <utils/sgx-errors.h>
#include <utils/utility.h>
#include <sgx_tcrypto.h>
#include <sgx_quote.h>
#include <sgx_tkey_exchange.h>

#define SGX_CHECK_RET(ret) if(!(ret == SGX_SUCCESS)){print_error_message(ret); \
    fprintf(stderr,"Failed on line %d in function %s.\n", __LINE__, __FUNCTION__);return -1;}

//This is the default key included in SGX RA code sample. Don't ever use this anywhere in real
//applications!
sgx_ec256_private_t client_private_key = {
    {   
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
    }
};

int g_sp_credentials = 0;
int g_authentication_token = 0;
sgx_spid_t g_spid;
sgx_ec256_signature_t sign_gb_ga;
uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

uint8_t g_secret[8] = {0x74, 0x65, 0x73, 0x74, 0x73, 0x74, 0x72, 0};;

void* memset_s( void *dest, size_t destsz __attribute__((unused)), int ch, size_t count ){
  return memset(dest, ch, count);
};

//This is a temporarily implemented horrible RNG to be able to reproduce debugging
//Never use this in real applications!!
sgx_status_t sgx_read_rand(unsigned char *seq,
			   size_t length_in_bytes)
{
  for (unsigned int i = 0; i < length_in_bytes; i++) {
    seq[i] = rand();
  }
  return SGX_SUCCESS;
}

//From SGX SDK
int consttime_memequal(const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = b1, *c2 = b2;
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	 * Map 0 to 1 and [1, 256) to 0 using only constant-time
	 * arithmetic.
	 *
	 * This is not simply `!res' because although many CPUs support
	 * branchless conditional moves and many compilers will take
	 * advantage of them, certain compilers generate branches on
	 * certain CPUs for `!res'.
	 */
	return (1 & ((res - 1) >> 8));
}

typedef struct _sgx_key_db
{
  sgx_ec256_public_t             g_a;
  sgx_ec256_public_t             g_b;
  sgx_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
  sgx_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
  sgx_ec_key_128bit_t      sk_key;// Shared secret key for encryption
  sgx_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
  sgx_ec256_private_t            b;
  sgx_ps_sec_prop_desc_t   ps_sec_prop;
}sgx_key_db;
static sgx_key_db key_db; 

typedef enum _derive_key_type_t
  {
   DERIVE_KEY_SMK = 0,
   DERIVE_KEY_SK,
   DERIVE_KEY_MK,
   DERIVE_KEY_VK,
  } derive_key_type_t;

const char str_SMK[] = "SMK";
const char str_SK[] = "SK";
const char str_MK[] = "MK";
const char str_VK[] = "VK";

#define SGX_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)
#define QUOTE_LINKABLE_SIGNATURE   1
const uint16_t AES_CMAC_KDF_ID = 0x0001;

int derive_key(
	       const sgx_ec256_dh_shared_t *p_shared_key,
	       uint8_t key_id,
	       sgx_ec_key_128bit_t *derived_key) {
  sgx_status_t ret = SGX_SUCCESS;
  uint8_t cmac_key[SGX_CMAC_KEY_SIZE];
  sgx_ec_key_128bit_t key_derive_key;

  memset(&cmac_key, 0, SGX_CMAC_KEY_SIZE);

  ret = sgx_rijndael128_cmac_msg(
				 (sgx_cmac_128bit_key_t *) &cmac_key,
				 (uint8_t *) p_shared_key,
				 sizeof(sgx_ec256_dh_shared_t),
				 (sgx_cmac_128bit_tag_t *) &key_derive_key);

  SGX_CHECK_RET(ret);
  
  const char *label = NULL;
  uint32_t label_length = 0;
  switch (key_id) {
  case DERIVE_KEY_SMK:
    label = str_SMK;
    label_length = sizeof(str_SMK) - 1;
    break;
  case DERIVE_KEY_SK:
    label = str_SK;
    label_length = sizeof(str_SK) - 1;
    break;
  case DERIVE_KEY_MK:
    label = str_MK;
    label_length = sizeof(str_MK) - 1;
    break;
  case DERIVE_KEY_VK:
    label = str_VK;
    label_length = sizeof(str_VK) - 1;
    break;
  default:
    memset(&key_derive_key, 0, sizeof(key_derive_key));
    return -1;
    break;
  }
  uint32_t derivation_buffer_length = SGX_DERIVATION_BUFFER_SIZE(label_length);
  uint8_t *p_derivation_buffer = (uint8_t *) malloc(derivation_buffer_length);
  if (p_derivation_buffer == NULL) {
    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_derive_key, 0, sizeof(key_derive_key));
    return -1;
  }
  memset(p_derivation_buffer, 0, derivation_buffer_length);

  p_derivation_buffer[0] = 0x01;
  memcpy(&p_derivation_buffer[1], label, label_length);
  uint16_t *key_len = (uint16_t *) (&(p_derivation_buffer[derivation_buffer_length - 2]));
  *key_len = 0x0080;


  ret = sgx_rijndael128_cmac_msg(
				 (sgx_cmac_128bit_key_t *) &key_derive_key,
				 p_derivation_buffer,
				 derivation_buffer_length,
				 (sgx_cmac_128bit_tag_t *) derived_key);
  free(p_derivation_buffer);
  // memset here can be optimized away by compiler, so please use memset_s on
  // windows for production code and similar functions on other OSes.
  memset(&key_derive_key, 0, sizeof(key_derive_key));
  if (ret != SGX_SUCCESS) {
    return -1;
  }
  return 0;
}

int client_att_get_msg2(const sgx_ra_msg1_t* msg1, sgx_ra_msg2_t* msg2) {

  sgx_status_t ret = SGX_SUCCESS;

  key_db.g_a = msg1->g_a;
 
  //TODO include revocation list
  uint8_t *sig_rl __attribute__((unused));
  uint32_t sig_rl_size = 0;
  msg2->sig_rl_size = sig_rl_size;

  sgx_ecc_state_handle_t ecc_state = NULL;
 
  // Generate the Service providers ECCDH key pair.
  ret = sgx_ecc256_open_context(&ecc_state);
  SGX_CHECK_RET(ret);
  
  sgx_ec256_public_t pub_key = {{0},
				{0}};
  sgx_ec256_private_t priv_key = {{0}};
  ret = sgx_ecc256_create_key_pair(&priv_key, &pub_key,
				   ecc_state);

  SGX_CHECK_RET(ret);

  //Save the keys
  key_db.b = priv_key;
  key_db.g_b = pub_key;

  // Generate the client/SP shared secret
  sgx_ec256_dh_shared_t dh_key = {{0}};
  ret = sgx_ecc256_compute_shared_dhkey(&priv_key,
					&key_db.g_a,
					&dh_key,
					ecc_state);
  SGX_CHECK_RET(ret);
  
  // smk is only needed for msg2 generation.
  int derive_ret = derive_key(&dh_key, DERIVE_KEY_SMK,
			      &key_db.smk_key);

  SGX_CHECK_RET(derive_ret);
  
  //The rest of the keys are the shared secrets for future communication.
  derive_ret = derive_key(&dh_key, DERIVE_KEY_MK,
  &key_db.mk_key);
  SGX_CHECK_RET(derive_ret);
  
  derive_ret = derive_key(&dh_key, DERIVE_KEY_SK,
  &key_db.sk_key);
  SGX_CHECK_RET(derive_ret);
  
  derive_ret = derive_key(&dh_key, DERIVE_KEY_VK,
  &key_db.vk_key);
  SGX_CHECK_RET(derive_ret);

  msg2->g_b = key_db.g_b;
  msg2->spid = g_spid;
  msg2->quote_type = QUOTE_LINKABLE_SIGNATURE;
  msg2->kdf_id = AES_CMAC_KDF_ID;

  // The service provider is responsible for selecting the proper EPID
  // signature type and to understand the implications of the choice!
  // Create gb_ga
  sgx_ec256_public_t gb_ga[2];

  gb_ga[0] = key_db.g_b;
  gb_ga[1] = key_db.g_a;

  // Sign gb_ga
  ret = sgx_ecdsa_sign((uint8_t *) &gb_ga, sizeof(gb_ga),
		       (sgx_ec256_private_t *) &client_private_key,
		       &sign_gb_ga,
		       ecc_state);
  SGX_CHECK_RET(ret);
  msg2->sign_gb_ga = sign_gb_ga;

  uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
  sgx_ra_msg2_t tmp_msg2;
  memcpy(&tmp_msg2.g_b, &key_db.g_b, sizeof(sgx_ec256_public_t));
  memcpy(&tmp_msg2.spid, &g_spid, sizeof(sgx_spid_t));
  tmp_msg2.quote_type = msg2->quote_type;
  tmp_msg2.kdf_id = msg2->kdf_id;
  memcpy(&tmp_msg2.sign_gb_ga, &sign_gb_ga, sizeof(sgx_ec256_signature_t));
  
  ret = sgx_rijndael128_cmac_msg(&key_db.smk_key,
				 (uint8_t *) &tmp_msg2, cmac_size, &mac);
  SGX_CHECK_RET(ret);

  memcpy(msg2->mac, mac, SGX_CMAC_MAC_SIZE);

  if (ecc_state) {
    sgx_ecc256_close_context(ecc_state);
  }
  return 0;
}

int client_att_get_result(const sgx_ra_msg3_t* msg3, size_t quote_size, uint8_t* result) {
  int ret = 0;
  uint8_t *p_msg3_cmaced = NULL;
  sgx_quote_t *p_quote = NULL;
  sgx_sha_state_handle_t sha_handle = NULL;
  sgx_report_data_t report_data = {0};

  size_t msg3_size = sizeof(sgx_ra_msg3_t)+quote_size;

  if(!msg3){
    if(!msg3) fprintf(stderr, "No message 3 received\n");
    return -1;
  }
 
  // Compare g_a in message 3 with local g_a.
  if(memcmp(&key_db.g_a, &msg3->g_a, sizeof(sgx_ec256_public_t))){
    fprintf(stderr, "g_a did not match\n");
    return -2;
  }

  //Make sure that msg3_size is bigger than sample_mac_t.
  uint32_t mac_size = msg3_size - sizeof(sgx_mac_t);
  p_msg3_cmaced = ((uint8_t*) msg3) + sizeof(sgx_mac_t);

  // Verify the message mac using SMK
  sgx_cmac_128bit_tag_t mac = {0};
  ret = sgx_rijndael128_cmac_msg(&key_db.smk_key,
				 p_msg3_cmaced,
				 mac_size,
				 &mac);
  SGX_CHECK_RET(ret);

  // In real implementation, should use a time safe version of memcmp here,
  // in order to avoid side channel attack.
  ret = memcmp(&msg3->mac, &mac, sizeof(mac));
  SGX_CHECK_RET(ret);
  
  memcpy(&key_db.ps_sec_prop, &msg3->ps_sec_prop, sizeof(key_db.ps_sec_prop));

  p_quote = (sgx_quote_t *) msg3->quote;

  // Check the quote version if needed. Only check the Quote.version field if the enclave
  // identity fields have changed or the size of the quote has changed.  The version may
  // change without affecting the legacy fields or size of the quote structure.
  //if(p_quote->version < ACCEPTED_QUOTE_VERSION)
  //{
  //    fprintf(stderr,"\nError, quote version is too old.", __FUNCTION__);
  //    ret = SP_QUOTE_VERSION_ERROR;
  //    break;
  //}

  // Verify the report_data in the Quote matches the expected value.
  // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
  // The second 32 bytes of report_data are set to zero.
  ret = sgx_sha256_init(&sha_handle);
  SGX_CHECK_RET(ret);
  ret = sgx_sha256_update((uint8_t *) &(key_db.g_a), sizeof(key_db.g_a), sha_handle);
  SGX_CHECK_RET(ret);

  ret = sgx_sha256_update((uint8_t *) &(key_db.g_b), sizeof(key_db.g_b), sha_handle);
  SGX_CHECK_RET(ret);

  ret = sgx_sha256_update((uint8_t *) &(key_db.vk_key), sizeof(key_db.vk_key), sha_handle);
  SGX_CHECK_RET(ret);

  ret = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *) &report_data);
  SGX_CHECK_RET(ret);

  ret = memcmp((uint8_t *) &report_data,(uint8_t *) &(p_quote->report_body.report_data), sizeof(report_data));
  SGX_CHECK_RET(ret);

  return 0;
}

//TODO use counter for IV (GCM MODE). This is unsafe!

int encrypt_message(const uint8_t* message, const size_t message_size, uint8_t* encrypted_buffer, uint8_t* mac){
  uint8_t aes_gcm_iv[12] = {0};
  sgx_status_t ret;
  ret = sgx_rijndael128GCM_encrypt(&key_db.sk_key,
                                   message,
                                   message_size,
                                   encrypted_buffer,
                                   &aes_gcm_iv[0],
                                   12,
                                   NULL,
                                   0,
                                   (sgx_aes_gcm_128bit_tag_t *) mac);

  if(ret != SGX_SUCCESS) return -1;
  return 0;
}
