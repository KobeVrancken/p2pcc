//Original source for socket code; https://www.geeksforgeeks.org/socket-programming-cc/

#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 

#include <utils/utility.h>
#include <utils/constants.h>

#include "kmgmt-untrusted.h"

int main(int argc, char**argv)
{
  if(argc != 2){
    die("usage: server PORT\n");
  }

  //TODO unsafe user input parsing!
  unsigned int port = atoi(argv[1]);

  if(start_key_enclave(ENCLAVE_PATH)){
    fprintf(stderr, "Failed to start key enclave. Aborting.\n");
    exit(-1);
  }

  int server_fd, sock;
  size_t bytes;
  struct sockaddr_in address; 
  int opt = 1; 
  int addrlen = sizeof(address); 
  uint8_t buffer[P2PSGX_MAX_MESSAGE_SIZE] = {0}; 
       
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
  { 
      die("Couldn't create socket.\n"); 
  } 
       
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
		 &opt, sizeof(opt))) 
  { 
    die("Set sock opt call failed.\n");
  } 
  address.sin_family = AF_INET; 
  address.sin_addr.s_addr = INADDR_ANY; 
  address.sin_port = htons( port ); 
       
  if (bind(server_fd, (struct sockaddr *)&address,  
	   sizeof(address))<0) 
  { 
      die("Could not bind to port %d\n", port); 
  } 
  if (listen(server_fd, 1) < 0) //1 for backlog param: don't let other connections wait, refuse them 
  { 
    die("Could not listen on port %d\n", port); 
  } 

  if ((sock = accept(server_fd, (struct sockaddr *)&address,  
			   (socklen_t*)&addrlen))<0) 
  { 
    die("Failed accepting connection from client\n"); 
  } 

  //Key mgmt enclave started and connected to client.
  //Ready to start attestation protocol
  bytes = read(sock , buffer, P2PSGX_MAX_MESSAGE_SIZE);

  uint8_t init = INIT_PROTOCOL;
  if(bytes != sizeof(init) || init != buffer[0]){
    die("Did not receive init protocol message!\n");
  }

#ifdef RA_DEBUG
  printf("Succesfully received INIT PROTOCOL\n");
#endif

  sgx_ra_msg1_t message1;
  kmgmt_att_get_msg1(&message1);
  if((bytes = write(sock , &message1 , sizeof(message1))) != sizeof(message1)){
    die("Did not manage to write message 1\n");
  };

#ifdef RA_DEBUG
  printf("Replied with message 1:\n");
  dump_buf((uint8_t*) &message1, sizeof(message1));
#endif

  if((bytes = read(sock, buffer, P2PSGX_MAX_MESSAGE_SIZE)) != sizeof(sgx_ra_msg2_t)){
    die("Read %d/%d bytes.\nFailed to read msg2\n", bytes, sizeof(sgx_ra_msg2_t));
  }

#ifdef RA_DEBUG
  printf("Succesfully received message 2!\n");
  dump_buf(buffer, sizeof(sgx_ra_msg2_t));
#endif

  sgx_ra_msg3_t* message3;
  uint32_t message3_size_plus_quote;
  if(kmgmt_att_get_msg3((sgx_ra_msg2_t*) &buffer, &message3, &message3_size_plus_quote)){
    die("Failed to generate message 3 from message 2\n");
  }
  
  if((bytes = write(sock , message3 , sizeof(sgx_ra_msg3_t))) != sizeof(sgx_ra_msg3_t)){
    die("Did not manage to write message 3.\n");
  }

#ifdef RA_DEBUG
  printf("Replied with message 3:\n");
  dump_buf((uint8_t*) message3, sizeof(sgx_ra_msg3_t));
#endif

  uint32_t quote_size = message3_size_plus_quote - sizeof(sgx_ra_msg3_t);
  if((bytes = write(sock , &quote_size, sizeof(uint32_t))) != sizeof(uint32_t)){
    die("Did not manage to write quote size.\n");
  }

#ifdef RA_DEBUG
  printf("Replied with quote size: %d\n", quote_size);
#endif

  if((bytes = write(sock , (uint8_t*) message3+sizeof(sgx_ra_msg3_t) , quote_size)) != quote_size){
    die("Did not manage to write quote.\n");
  }

#ifdef RA_DEBUG
  printf("Replied with message quote (first 128 bytes shown):\n");
  dump_buf((uint8_t*) message3+sizeof(sgx_ra_msg3_t), 128);
#endif

 uint8_t encrypted_buffer[P2PSGX_CRYPTO_MESSAGE_SIZE]; 
 uint8_t mac[SGX_CMAC_MAC_SIZE];
 
  if((bytes = read(sock, encrypted_buffer, P2PSGX_CRYPTO_MESSAGE_SIZE)) != P2PSGX_CRYPTO_MESSAGE_SIZE){
    die("Read %d/%d bytes.\nFailed to read encrypted message\n", bytes, P2PSGX_CRYPTO_MESSAGE_SIZE);
  }

#ifdef RA_DEBUG
  printf("Succesfully received MRENCLAVE (first 128 bytes shown)!\n");
  dump_buf(encrypted_buffer, 128);
#endif
 
  if((bytes = read(sock, mac, SGX_CMAC_MAC_SIZE)) != SGX_CMAC_MAC_SIZE){
    die("Read %d/%d bytes.\nFailed to read encrypted message\n", bytes, SGX_CMAC_MAC_SIZE);
  }

#ifdef RA_DEBUG
  printf("Succesfully received MAC!\n");
  dump_buf(mac, SGX_CMAC_MAC_SIZE);
#endif

  uint8_t response[P2PSGX_CRYPTO_MESSAGE_SIZE];
  uint8_t response_mac[SGX_CMAC_MAC_SIZE];
  //Provide info about enclave that needs to be spawned by the kmgmt enclave
  int ret;
  if((ret = execute_command((uint8_t*) encrypted_buffer,
			P2PSGX_CRYPTO_MESSAGE_SIZE,
			mac,
			response,
			P2PSGX_CRYPTO_MESSAGE_SIZE,
				 response_mac))){
    die("Failed to execute command: %d", ret);
  };
  
  printf("Finished without errors!\n");
  return 0; 
 
}
