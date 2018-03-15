#include "Enclave_t.h"
#include "sgx_trts.h"
#include <cstring>
#include <stdarg.h>
#include <stdio.h>  
#include "sgx_tcrypto.h"
#include "sgx_ecp_types.h"
#include "Enclave.h"



// generate EC key pair 
void ecall_generateECKeyPair(sgx_ec256_private_t * pPrivate,sgx_ec256_public_t * pPublic, sgx_ecc_state_handle_t *handle)
{
	ocall_print_string("Generating key pair!\n");
	sgx_status_t status = sgx_ecc256_open_context(handle);
	if (status) {
		ocall_print_string("Some error 1 \n");
	}
	status = sgx_ecc256_create_key_pair(pPrivate, pPublic, *handle);
	if (status) {
		ocall_print_string("Some error 2 \n");
	}
	else {
		ocall_print_string("[enclave:] no errors \n");
	}
}

// sign message using ECC256 :ECDSA 
void ecall_ECDSAsignMessage(sgx_ec256_private_t *p_private, sgx_ecc_state_handle_t * ecc_handle, sgx_ec256_signature_t *p_signature, uint8_t * p_data, size_t p_dataSize) {
	ocall_print_string("Signing message!\n");
	sgx_status_t status = sgx_ecc256_open_context(ecc_handle); 
	if (status) {
		ocall_print_string("Some error 1 \n");
	}
	status = sgx_ecdsa_sign(p_data, p_dataSize, p_private, p_signature, *ecc_handle);
	if (status) {
		ocall_print_string("Some error 2 \n");
	}
}

void ecall_ECDSAverifyMessage(sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, sgx_ecc_state_handle_t * ecc_handle, uint8_t * p_data, size_t p_dataSize, uint8_t * p_result) {
	ocall_print_string("Verifying signature! \n");
	uint8_t result;
	sgx_status_t status = sgx_ecc256_open_context(ecc_handle);
	if (status) {
		ocall_print_string("Some error 1 \n");
	}
	status = sgx_ecdsa_verify(p_data,p_dataSize, p_public, p_signature, &result, *ecc_handle);
	*p_result = result;
	if (status) {
		ocall_print_string("Some error 2 \n");
	}
	if (SGX_EC_VALID == result) {
		ocall_print_string("The signature's match! \n");
	}
	else if (SGX_EC_INVALID_SIGNATURE == result) {
		ocall_print_string("The signature's DONT match! \n");
	}
	else {
		ocall_print_string("underfined error \n");
	}
}

uint8_t ccc[16];
// encrypt data 
void ecall_encrypt_rijndael128GCM(sgx_ec256_private_t * p_key,
	const uint8_t *p_data, 
	uint32_t p_data_len, 
	uint8_t *p_dst, 
	const uint8_t *p_iv,  
	uint8_t* p_out_mac)
{
	sgx_status_t status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *)p_key->r, 
		p_data, p_data_len, p_dst, p_iv, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)p_out_mac);
}

// decrypt data 
void ecall_decrypt_rijndael128GCM(sgx_ec256_private_t *p_key,
	const uint8_t *p_data,
	uint32_t p_data_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint8_t* p_in_mac) 
{
	sgx_status_t status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*) p_key->r, 
		p_data, p_data_len,p_dst,p_iv,12,NULL,0, (sgx_aes_gcm_128bit_tag_t *)p_in_mac);
	switch (status) {
	case SGX_SUCCESS: 
	{
		ocall_print_string("\nSGX_SUCCESS\n");
		break;
	}
	case SGX_ERROR_INVALID_PARAMETER:
	{
		ocall_print_string("\nSGX_ERROR_INVALID_PARAMETER\n");
		break;
	}
	case SGX_ERROR_MAC_MISMATCH: 
	{
		ocall_print_string("\nSGX_ERROR_MAC_MISMATCH\n");
		break;
	}
	case SGX_ERROR_OUT_OF_MEMORY:
	{
		ocall_print_string("\nSGX_ERROR_OUT_OF_MEMORY\n");
		break;
	}
	case SGX_ERROR_UNEXPECTED:
	{
		ocall_print_string("\nSGX_ERROR_UNEXPECTED\n");
		break;
	}
	}

}
/*
ret = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *)g.secret, crypt, length, clear,
iv, 12, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)crypt_mac);
*/

void ecall_sum_array(int *arr, size_t size, int * result) {
	int sum = 0; 
	for (int i = 0; i < size; ++i) {
		sum += arr[i];
	}
	*result = sum;
}
void ecall_sum_values(int arr[5], int * result) {
	int sum = 0;
	for (int i = 0; i < 5; ++i) {
		sum += arr[i];
	}
	*result = sum;
}

void enclaveChangeBuffer(char * buf, size_t len)
{
	const char * secret = "Hello Enclave!";
	if (len > strlen(secret) + 1)
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
	else
	{
		memcpy(buf, "false", strlen("false") + 1);
	}
}

void enclaveStringSave(char * input, size_t len) 
{
	if (strlen(input) + 1 < BUF_LEN)
	{
		memcpy(savedString,input, strlen(input) + 1);
	}
	else 
	{
		memcpy(input, "false", strlen("fasle") + 1);
	}
}

int enclaveLoadInt() {
	char num = (savedInt + '0');
	char buf[BUF_LEN] = {num , '\n' };
	ocall_print_string(buf);
	return savedInt;
}

void setSecretValue(int * value) 
{
	*value = savedInt;
}
