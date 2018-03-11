#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_sum_array(sgx_enclave_id_t eid, int* arr, size_t size, int* result);
sgx_status_t ecall_test(sgx_enclave_id_t eid, sgx_ec256_private_t* pPrivate, sgx_ec256_public_t* pPublic, sgx_ecc_state_handle_t* handle);
sgx_status_t ecall_ECDSAsignMessage(sgx_enclave_id_t eid, sgx_ec256_private_t* p_private, sgx_ecc_state_handle_t* ecc_handle, sgx_ec256_signature_t* p_signature);
sgx_status_t ecall_ECDSAverifyMessage(sgx_enclave_id_t eid, sgx_ec256_public_t* p_public, sgx_ec256_signature_t* p_signature, sgx_ecc_state_handle_t* ecc_handle);
sgx_status_t ecall_sum_values(sgx_enclave_id_t eid, int arr[5], int* result);
sgx_status_t enclaveChangeBuffer(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t enclaveStringSave(sgx_enclave_id_t eid, char* input, size_t len);
sgx_status_t enclaveLoadInt(sgx_enclave_id_t eid, int* retval);
sgx_status_t setSecretValue(sgx_enclave_id_t eid, int* value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
