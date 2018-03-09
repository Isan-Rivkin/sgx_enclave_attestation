
#define ENCLAVE_FILE "Enclave.signed.dll"
#define BUF_LEN 100
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <cstring>
#include <iostream>
//crpyto 
#include "sgx_tcrypto.h"


void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}

int main() 
{
	sgx_enclave_id_t eid; 
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int savedInt =0, updated = 0;
	int * enclaveValue = &savedInt;
	// test params 
	char buffer[BUF_LEN] = "Hello World!";

	// create enclave 
	ret = sgx_create_enclave(TEXT(ENCLAVE_FILE), SGX_DEBUG_FLAG, &token, &updated, &eid, nullptr);
	if (ret != SGX_SUCCESS) 
	{
		std::cout << " Error #" << ret << " failed to create enclave." << std::endl;
	}
	// generate key pair 
	sgx_ec256_private_t * pPrivate;
	sgx_ec256_public_t  pub;
	sgx_ec256_public_t * pPublic = &pub;
	int a[2] = { 0 };
	uint8_t gy[SGX_ECP256_KEY_SIZE];
	ecall_generate_ecc_key_pair(eid,pPublic);
	std::cout << pPublic->gx << std::endl;
	std::cout << pPublic->gy << std::endl;
	//for (int i = 0; i < SGX_ECP256_KEY_SIZE; ++i) {
	//	std::cout << pPublic->gx[i] << std::endl;
	//	std::cout << pPublic->gy[i] << std::endl;
	//}

	// change buffer 
	std::cout << "Buffer before change: " << buffer << std::endl;
	enclaveChangeBuffer(eid, buffer, BUF_LEN);
	std::cout << "Buffer after change " << buffer << std::endl;
	// get int value 
	std::cout << "Before int = " << *enclaveValue << std::endl;
	savedInt = enclaveLoadInt(eid,enclaveValue);
	std::cout << "After enclave int = " << *enclaveValue << ","<< savedInt << std::endl;
	setSecretValue(eid, enclaveValue);
	std::cout << "After enclave int = " << *enclaveValue << "," << savedInt << std::endl;
	// sum values 
	int arr[6] = { 0,1,2,3,4,100 };
	int sumInt = 0;
	int *sumPtr = &sumInt;
	ecall_sum_array(eid, arr, 6, sumPtr);
	//ecall_sum_values(eid,arr, sumPtr);
	std::cout << "The sum is = " << *sumPtr << std::endl;
	//destroy enclave 
	if (SGX_SUCCESS != sgx_destroy_enclave(eid)) 
	{
		std::cout << "Error failed to destroy enclave" << std::endl;
	}

	getchar();
	return 0;	
}