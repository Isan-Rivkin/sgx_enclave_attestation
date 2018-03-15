
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
	sgx_ec256_public_t * tempPublic = &pub;
	// generate ecc256 key pairs 
	sgx_ecc_state_handle_t ecc_state = NULL;
	sgx_ec256_private_t sk;
	sgx_ec256_public_t pk;
	sgx_status_t status = ecall_generateECKeyPair(eid,&sk,&pk, &ecc_state);
	if (status != SGX_SUCCESS){ 
		std::cout << "\n Error %d while generate ecc key pair. \n" << std::endl;
	}
	sgx_ec256_private_t sk2 = sk;
	// sign a message using ECDSA 
	ecc_state = nullptr;
	sgx_ec256_signature_t signature;
	uint8_t d = 's';
	uint8_t res;
	uint8_t * p_result = &res;
	uint8_t * p_data = &d;
	size_t p_dataSize = sizeof(d);
	ecall_ECDSAsignMessage(eid, &sk, &ecc_state,&signature, p_data,p_dataSize);
	// verify a message using ECDSA 
	ecc_state = nullptr;
	ecall_ECDSAverifyMessage(eid, &pk, &signature, &ecc_state, p_data, p_dataSize, p_result);
	// encrypt data 
	uint8_t enc;
	uint8_t * p_encrypted = &enc;
	uint8_t crypt_mac[16];
	uint8_t i;
	uint8_t iv[12];
	p_data[p_dataSize] = '\0';
	std::cout << "Original message: " << p_data << std::endl;
	for (int j = 0; j < 12; ++j) {
		i = rand() % 256;
		iv[j] = i;
	}
	ecall_encrypt_rijndael128GCM(eid, &sk, p_data, p_dataSize, p_encrypted, iv, crypt_mac);
	
	std::cout << "Encrypted message: ";
	for (int j = 0; j < p_dataSize; j++)
		std::cout << std::hex << int(p_encrypted[j]) << " ";
	std::cout << std::dec << std::endl;

	// decrypt data 
	ecall_decrypt_rijndael128GCM(eid, &sk,p_encrypted, p_dataSize, p_data, iv, crypt_mac);
	std::cout << "Decrypted Message:" << p_data << std::endl;
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