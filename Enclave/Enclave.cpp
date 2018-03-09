#include "Enclave_t.h"
#include "sgx_trts.h"
#include <cstring>
#include <stdarg.h>
#include <stdio.h>  
#include "sgx_tcrypto.h"


sgx_ecc_state_handle_t * ecc_handle;
sgx_status_t status;
sgx_ec256_private_t * pPrivate;
//sgx_ec256_public_t * pPublic;
void ecall_generate_ecc_key_pair(sgx_ec256_public_t * pPublic)
{
	ocall_print_string("Generated key pair!\n");

	// create curve context 
	status = sgx_ecc256_open_context(ecc_handle);
	// generate key pair 
	status = sgx_ecc256_create_key_pair(pPrivate,pPublic,ecc_handle);
	// destroy created curve
	status = sgx_ecc256_close_context(ecc_handle);
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
