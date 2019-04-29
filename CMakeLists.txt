cmake_minimum_required(VERSION 2.8)
project(sgx_cmake)

set(SERVER_EXE server)
set(CLIENT_EXE client-proxy)
set(ATTESTOR_EXE local_attestor)
set(KEY_ENCLAVE kmgmt)
set(KEY_ENCLAVE_DIR src/enclave/kmgmt/)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

find_library(SGX_TCRYPTO
  NAMES sgx_tcrypto
  HINTS ${SGX_LIBRARY_DIR})

find_library(SGX_TSERVICE
  NAMES sgx_tservice
  HINTS ${SGX_LIBRARY_DIR})

find_library(SGX_TRTS
  NAMES sgx_trts
  HINTS ${SGX_LIBRARY_DIR})


include_directories(/usr/local/include src src/shared /opt/intel/sgxsdk/include build/)

#Locals
file(GLOB_RECURSE SHARED_SOURCES "src/shared/*.c")
file(GLOB_RECURSE CLIENT_SOURCES "src/client/*.c")
file(GLOB_RECURSE SERVER_SOURCES "src/server/*.c")
file(GLOB_RECURSE ATTESTOR_SOURCES "src/enclave/attestor/*.c")

file(GLOB_RECURSE KMGMT_ENCLAVE_SOURCES "${KEY_ENCLAVE_DIR}/*.c")
file(GLOB_RECURSE KMGMT_ENCLAVE_EDL "${KEY_ENCLAVE_DIR}/edl/kmgmt.edl")

add_executable(${CLIENT_EXE} ${SHARED_SOURCES} ${CLIENT_SOURCES})
#link_directories($(SGX_LIBRARY_DIR))
target_link_libraries(${CLIENT_EXE} ${SGX_TCRYPTO})

#Key Enclave
#include_directories(/opt/intel/sgxsdk/include)


add_enclave_library(${KEY_ENCLAVE}
  SRCS ${KMGMT_ENCLAVE_SOURCES}
  EDL ${KMGMT_ENCLAVE_EDL}
  EDL_SEARCH_PATHS "${KEY_ENCLAVE_DIR}/edl"
  USE_PREFIX
  LDSCRIPT "${KEY_ENCLAVE_DIR}/conf/kmgmt.lds")

enclave_sign(${KEY_ENCLAVE} OUTPUT ${KEY_ENCLAVE}.signed.so KEY ${KEY_ENCLAVE_DIR}/keys/signing_private_key.pem CONFIG ${KEY_ENCLAVE_DIR}/conf/kmgmt.config.xml)


#Local attestor
#add_executable(${ATTESTOR_EXE} ${ATTESTOR_SOURCES})
#target_link_libraries(${ATTESTOR_EXE} ${SGX_TSERVICE} ${SGX_TCRYPTO} ${SGX_TRTS})


add_untrusted_executable(${SERVER_EXE}
  SRCS ${SHARED_SOURCES} ${SERVER_SOURCES}
  USE_PREFIX
  EDL ${KMGMT_ENCLAVE_EDL}
  EDL_SEARCH_PATHS "${KEY_ENCLAVE_DIR}/edl"
)
#target_link_libraries(${SERVER_EXE})

