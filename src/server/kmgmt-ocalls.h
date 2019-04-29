#ifndef UNTRUSTED_H
#define UNTRUSTED_H

#include <stdio.h>
#include <stdint.h>

void ocall_print_string(const char *str);
void send_receive_message(const char *enclave_location,
                          uint8_t *send_buffer,
                          size_t send_buffer_size,
                          uint8_t *response_buffer,
                          size_t response_buffer_size);
#endif

