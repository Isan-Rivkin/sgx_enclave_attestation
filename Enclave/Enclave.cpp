#include "Enclave_t.h"
#include "sgx_trts.h"
#include <cstring>
#include <stdarg.h>
#include <stdio.h>  
#include "sgx_tcrypto.h"
#include "sgx_ecp_types.h"
//
//sgx_ecc_param_t context;
//sgx_ecc_state_handle_t * ecc_handle;
//sgx_status_t status;
//sgx_ec256_private_t key;
//sgx_ec256_private_t * tPrivate = &key;
//sgx_ec256_public_t  pub;
//sgx_ec256_public_t * tPublic = &pub;
//
//
///// new 
//sgx_ecc_state_handle_t handle;
//sgx_ec256_private_t sk;
//sgx_ec256_public_t pk;

// PROBLEM : the ecc_gandle context is null as seen inside the debbuger break point #21
void ecall_test(sgx_ec256_private_t * pPrivate,sgx_ec256_public_t * pPublic, sgx_ecc_state_handle_t *handle)
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
void ecall_ECDSAsignMessage(sgx_ec256_private_t *p_private, sgx_ecc_state_handle_t * ecc_handle, sgx_ec256_signature_t *p_signature) {
	ocall_print_string("Signing message!\n");
	uint8_t data = 's'; // the data 
	sgx_status_t status = sgx_ecc256_open_context(ecc_handle); 
	if (status) {
		ocall_print_string("Some error 1 \n");
	}
	status = sgx_ecdsa_sign(&data, sizeof(data), p_private, p_signature, *ecc_handle);
	if (status) {
		ocall_print_string("Some error 2 \n");
	}
}
void ecall_ECDSAverifyMessage(sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, sgx_ecc_state_handle_t * ecc_handle) {
	ocall_print_string("Verifying signature! \n");
	uint8_t data = 's';
	uint8_t result;
	sgx_status_t status = sgx_ecc256_open_context(ecc_handle);
	if (status) {
		ocall_print_string("Some error 1 \n");
	}
	status = sgx_ecdsa_verify(&data, sizeof(data), p_public, p_signature, &result, *ecc_handle);
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
#define BUF_LEN 100
char savedString[BUF_LEN] = "Default Enclave savedText";
int savedInt = 5;

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
