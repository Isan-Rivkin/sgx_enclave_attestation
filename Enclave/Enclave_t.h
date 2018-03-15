#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_sum_array(int* arr, size_t size, int* result);
void ecall_generateECKeyPair(sgx_ec256_private_t* pPrivate, sgx_ec256_public_t* pPublic, sgx_ecc_state_handle_t* handle);
void ecall_ECDSAsignMessage(sgx_ec256_private_t* p_private, sgx_ecc_state_handle_t* ecc_handle, sgx_ec256_signature_t* p_signature, uint8_t* p_data, size_t p_dataSize);
void ecall_ECDSAverifyMessage(sgx_ec256_public_t* p_public, sgx_ec256_signature_t* p_signature, sgx_ecc_state_handle_t* ecc_handle, uint8_t* p_data, size_t p_dataSize, uint8_t* p_result);
void ecall_encrypt_rijndael128GCM(sgx_ec256_private_t* p_key, const uint8_t* p_data, uint32_t p_data_len, uint8_t* p_dst, const uint8_t* p_iv, uint8_t* p_out_mac);
void ecall_decrypt_rijndael128GCM(sgx_ec256_private_t* p_key, const uint8_t* p_data, uint32_t p_data_len, uint8_t* p_dst, const uint8_t* p_iv, uint8_t* p_in_mac);
void ecall_sum_values(int arr[5], int* result);
void enclaveChangeBuffer(char* buf, size_t len);
void enclaveStringSave(char* input, size_t len);
int enclaveLoadInt();
void setSecretValue(int* value);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
