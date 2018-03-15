#pragma once
#include <cstring>
#include <stdarg.h>
#include <stdio.h>  
#define BUF_LEN 100
char savedString[BUF_LEN] = "Default Enclave savedText";
int savedInt = 5;
//

#include "Enclave_t.h"
#include "sgx_trts.h"
#include <cstring>
#include <stdarg.h>
#include <stdio.h>  
#include "sgx_tcrypto.h"
#include "sgx_ecp_types.h"



// generate EC key pair 
void ecall_generateECKeyPair(sgx_ec256_private_t * pPrivate, sgx_ec256_public_t * pPublic, sgx_ecc_state_handle_t *handle);
// sign message using ECC256 :ECDSA 
void ecall_ECDSAsignMessage(sgx_ec256_private_t *p_private, sgx_ecc_state_handle_t * ecc_handle, sgx_ec256_signature_t *p_signature, uint8_t * p_data, size_t p_dataSize);
// verify signature message using ECC256 :ECDSA 
void ecall_ECDSAverifyMessage(sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, sgx_ecc_state_handle_t * ecc_handle, uint8_t * p_data, size_t p_dataSize, uint8_t * p_result);
// encrypt data using AES-GCM rijndael128GXM
void ecall_encrypt_rijndael128GCM(sgx_ec256_private_t * p_key,
	const uint8_t *p_data, 
	uint32_t p_data_len, 
	uint8_t *p_dst, 
	const uint8_t *p_iv, 
	uint8_t* p_out_mac);
// decrypt data using AES-GCM rijndael128GXM
void ecall_decrypt_rijndael128GCM(sgx_ec256_private_t *p_key,
	const uint8_t *p_data,
	uint32_t p_data_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint8_t* p_in_mac);

void ecall_sum_array(int *arr, size_t size, int * result);
void ecall_sum_values(int arr[5], int * result);
void enclaveChangeBuffer(char * buf, size_t len);
void enclaveStringSave(char * input, size_t len);
int enclaveLoadInt();
void setSecretValue(int * value);
