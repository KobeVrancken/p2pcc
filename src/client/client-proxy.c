//Original source for socket code: https://www.geeksforgeeks.org/socket-programming-cc/
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utils/utility.h>
#include <utils/constants.h>
#include "client-attestation.h"

int main(int argc, char**argv)
{
  int ret;
  if(argc != 3){
    die("usage: client-proxy PORT IP\n");
  }

  //TODO unsafe user input parsing!
  unsigned int port = atoi(argv[2]);

  //TODO randomness disabled! Implement RDRAND instead of pseudo-random same seed!
  //Giving a warning message again as a reminder to never use this.
  srand(0);
  fprintf(stderr, "Warning: randomness with same seed enabled for testing! Don't use this!\n");

  //Start sockets
  int sock = 0;
  size_t bytes;
  struct sockaddr_in serv_addr; 
  uint8_t buffer[P2PSGX_MAX_MESSAGE_SIZE] = {0}; 
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  { 
    die("Socket creation error\n"); 
  } 
  memset(&serv_addr, '0', sizeof(serv_addr)); 
  serv_addr.sin_family = AF_INET; 
  serv_addr.sin_port = htons(port); 

  //TODO unsafe user input!
  if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)  
  { 
    die("Invalid IP address \n"); 
  } 

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
  { 
    printf("Connection Failed \n"); 
    return -1; 
  }

  //Connected to key mgmt enclave server
  //Start executing client protocol
  
  uint8_t init = INIT_PROTOCOL;

  if((bytes = write(sock, &init, sizeof(uint8_t))) != sizeof(uint8_t)){
    die("Couldn't send initial message\n");
  }

#ifdef RA_DEBUG
  printf("Sent INIT PROTOCOL\n");
#endif
  
  if((bytes = read(sock, buffer, P2PSGX_MAX_MESSAGE_SIZE)) != sizeof(sgx_ra_msg1_t)){
    die("Read %d/%d bytes.\nFailed to read msg1\n", bytes, sizeof(sgx_ra_msg1_t));
  }

#ifdef RA_DEBUG
  printf("Succesfully received message 1!\n");
  dump_buf(buffer, sizeof(sgx_ra_msg1_t));
#endif

  sgx_ra_msg2_t message2;
  if((ret = client_att_get_msg2((sgx_ra_msg1_t*) buffer, &message2))){
    die("Failed to create msg2 from msg1: error code %d\n", ret);
  }

  if((bytes = write(sock , &message2 , sizeof(message2))) != sizeof(message2)){
    die("Did not manage to write message 2.\n");
  }

#ifdef RA_DEBUG
  printf("Replied with message 2:\n");
  dump_buf((uint8_t*) &message2, sizeof(message2));
#endif


  if((bytes = read(sock, buffer, sizeof(sgx_ra_msg3_t))) != sizeof(sgx_ra_msg3_t)){
    die("Read %d/%d bytes.\nFailed to read msg3\n", bytes, sizeof(sgx_ra_msg3_t));
  }

#ifdef RA_DEBUG
  printf("Succesfully received message 3!\n");
  dump_buf(buffer, sizeof(sgx_ra_msg3_t));
#endif

  sgx_ra_msg3_t msg3;
  memcpy(&msg3, buffer, sizeof(sgx_ra_msg3_t));
  
  if((bytes = read(sock, buffer, sizeof(uint32_t))) != sizeof(uint32_t)){
    die("Read %d/%d bytes.\nFailed to read quote size.\n", bytes, sizeof(uint32_t));
  }
  uint32_t quote_size = *((uint32_t*) buffer);

#ifdef RA_DEBUG
  printf("Succesfully received quote size: %d\n", quote_size);
#endif
  
  if((bytes = read(sock, buffer, quote_size) != quote_size)){
    die("Read %d/%d bytes.\nFailed to read quote size.\n", bytes, quote_size);
  }

#ifdef RA_DEBUG
  printf("Succesfully received quote!\n");
  dump_buf(buffer, quote_size);
#endif

  uint8_t* msg3_full_buf = xmalloc(sizeof(sgx_ra_msg3_t) + quote_size);
  memcpy(msg3_full_buf, &msg3, sizeof(sgx_ra_msg3_t));
  memcpy(msg3_full_buf+sizeof(sgx_ra_msg3_t), buffer, quote_size);

  uint8_t result[100];

  if((ret = client_att_get_result((sgx_ra_msg3_t*) msg3_full_buf, quote_size, (uint8_t*) &result))){
    die("Failed to verify msg3: error code %d\n", ret);
  };

#ifdef RA_DEBUG
  printf("Attestation succeeded!\n");
#endif

  free(msg3_full_buf);

  //Send request to key mgmt enclave to spawn daemon enclave.
  //Provide MRENCLAVE that needs to be verified by key enclave.
  //Leaking length
  //Maybe read MRENCLAVE from argv
  char* measurement = "MRENCLAVE THISISAFAKEMRENCLAVE";

  uint8_t plaintext_buffer[P2PSGX_CRYPTO_MESSAGE_SIZE];
  uint8_t mac[SGX_CMAC_MAC_SIZE];
  uint8_t encrypted_buffer[P2PSGX_CRYPTO_MESSAGE_SIZE];

  strncpy((char*) plaintext_buffer, measurement, P2PSGX_CRYPTO_MESSAGE_SIZE-SGX_CMAC_MAC_SIZE);
  encrypt_message(plaintext_buffer, P2PSGX_CRYPTO_MESSAGE_SIZE, (uint8_t*) &encrypted_buffer, (uint8_t*) &mac);
 
  if((bytes = write(sock , encrypted_buffer, P2PSGX_CRYPTO_MESSAGE_SIZE)) != P2PSGX_CRYPTO_MESSAGE_SIZE){
    die("Did not manage to write MRENCLAVE \n");
  }

#ifdef RA_DEBUG
  printf("Sent MRENCLAVE (first 128 bytes shown):\n");
  dump_buf((uint8_t*) encrypted_buffer, 128);
#endif
 
  if((bytes = write(sock , mac, SGX_CMAC_MAC_SIZE)) != SGX_CMAC_MAC_SIZE){
    die("Did not manage to write MAC for MRENCLAVE \n");
  }

#ifdef RA_DEBUG
  printf("Sent MRENCLAVE MAC:\n");
  dump_buf((uint8_t*) mac, SGX_CMAC_MAC_SIZE);
#endif

  //TODO receive and decrypt PORT message, start listening to the same local port forward all communications
  //to this remote PORT encrypted with the symmetric key
  
  return 0;
}
