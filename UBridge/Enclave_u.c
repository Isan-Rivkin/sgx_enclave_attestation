#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_sum_array_t {
	int* ms_arr;
	size_t ms_size;
	int* ms_result;
} ms_ecall_sum_array_t;

typedef struct ms_ecall_generateECKeyPair_t {
	sgx_ec256_private_t* ms_pPrivate;
	sgx_ec256_public_t* ms_pPublic;
	sgx_ecc_state_handle_t* ms_handle;
} ms_ecall_generateECKeyPair_t;

typedef struct ms_ecall_ECDSAsignMessage_t {
	sgx_ec256_private_t* ms_p_private;
	sgx_ecc_state_handle_t* ms_ecc_handle;
	sgx_ec256_signature_t* ms_p_signature;
	uint8_t* ms_p_data;
	size_t ms_p_dataSize;
} ms_ecall_ECDSAsignMessage_t;

typedef struct ms_ecall_ECDSAverifyMessage_t {
	sgx_ec256_public_t* ms_p_public;
	sgx_ec256_signature_t* ms_p_signature;
	sgx_ecc_state_handle_t* ms_ecc_handle;
	uint8_t* ms_p_data;
	size_t ms_p_dataSize;
	uint8_t* ms_p_result;
} ms_ecall_ECDSAverifyMessage_t;

typedef struct ms_ecall_encrypt_rijndael128GCM_t {
	sgx_ec256_private_t* ms_p_key;
	uint8_t* ms_p_data;
	uint32_t ms_p_data_len;
	uint8_t* ms_p_dst;
	uint8_t* ms_p_iv;
	uint8_t* ms_p_out_mac;
} ms_ecall_encrypt_rijndael128GCM_t;

typedef struct ms_ecall_decrypt_rijndael128GCM_t {
	sgx_ec256_private_t* ms_p_key;
	uint8_t* ms_p_data;
	uint32_t ms_p_data_len;
	uint8_t* ms_p_dst;
	uint8_t* ms_p_iv;
	uint8_t* ms_p_in_mac;
} ms_ecall_decrypt_rijndael128GCM_t;

typedef struct ms_ecall_sum_values_t {
	int* ms_arr;
	int* ms_result;
} ms_ecall_sum_values_t;

typedef struct ms_enclaveChangeBuffer_t {
	char* ms_buf;
	size_t ms_len;
} ms_enclaveChangeBuffer_t;

typedef struct ms_enclaveStringSave_t {
	char* ms_input;
	size_t ms_len;
} ms_enclaveStringSave_t;

typedef struct ms_enclaveLoadInt_t {
	int ms_retval;
} ms_enclaveLoadInt_t;

typedef struct ms_setSecretValue_t {
	int* ms_value;
} ms_setSecretValue_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)(uintptr_t)Enclave_ocall_print_string,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_sum_array(sgx_enclave_id_t eid, int* arr, size_t size, int* result)
{
	sgx_status_t status;
	ms_ecall_sum_array_t ms;
	ms.ms_arr = arr;
	ms.ms_size = size;
	ms.ms_result = result;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_generateECKeyPair(sgx_enclave_id_t eid, sgx_ec256_private_t* pPrivate, sgx_ec256_public_t* pPublic, sgx_ecc_state_handle_t* handle)
{
	sgx_status_t status;
	ms_ecall_generateECKeyPair_t ms;
	ms.ms_pPrivate = pPrivate;
	ms.ms_pPublic = pPublic;
	ms.ms_handle = handle;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_ECDSAsignMessage(sgx_enclave_id_t eid, sgx_ec256_private_t* p_private, sgx_ecc_state_handle_t* ecc_handle, sgx_ec256_signature_t* p_signature, uint8_t* p_data, size_t p_dataSize)
{
	sgx_status_t status;
	ms_ecall_ECDSAsignMessage_t ms;
	ms.ms_p_private = p_private;
	ms.ms_ecc_handle = ecc_handle;
	ms.ms_p_signature = p_signature;
	ms.ms_p_data = p_data;
	ms.ms_p_dataSize = p_dataSize;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_ECDSAverifyMessage(sgx_enclave_id_t eid, sgx_ec256_public_t* p_public, sgx_ec256_signature_t* p_signature, sgx_ecc_state_handle_t* ecc_handle, uint8_t* p_data, size_t p_dataSize, uint8_t* p_result)
{
	sgx_status_t status;
	ms_ecall_ECDSAverifyMessage_t ms;
	ms.ms_p_public = p_public;
	ms.ms_p_signature = p_signature;
	ms.ms_ecc_handle = ecc_handle;
	ms.ms_p_data = p_data;
	ms.ms_p_dataSize = p_dataSize;
	ms.ms_p_result = p_result;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_encrypt_rijndael128GCM(sgx_enclave_id_t eid, sgx_ec256_private_t* p_key, const uint8_t* p_data, uint32_t p_data_len, uint8_t* p_dst, const uint8_t* p_iv, uint8_t* p_out_mac)
{
	sgx_status_t status;
	ms_ecall_encrypt_rijndael128GCM_t ms;
	ms.ms_p_key = p_key;
	ms.ms_p_data = (uint8_t*)p_data;
	ms.ms_p_data_len = p_data_len;
	ms.ms_p_dst = p_dst;
	ms.ms_p_iv = (uint8_t*)p_iv;
	ms.ms_p_out_mac = p_out_mac;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_decrypt_rijndael128GCM(sgx_enclave_id_t eid, sgx_ec256_private_t* p_key, const uint8_t* p_data, uint32_t p_data_len, uint8_t* p_dst, const uint8_t* p_iv, uint8_t* p_in_mac)
{
	sgx_status_t status;
	ms_ecall_decrypt_rijndael128GCM_t ms;
	ms.ms_p_key = p_key;
	ms.ms_p_data = (uint8_t*)p_data;
	ms.ms_p_data_len = p_data_len;
	ms.ms_p_dst = p_dst;
	ms.ms_p_iv = (uint8_t*)p_iv;
	ms.ms_p_in_mac = p_in_mac;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_sum_values(sgx_enclave_id_t eid, int arr[5], int* result)
{
	sgx_status_t status;
	ms_ecall_sum_values_t ms;
	ms.ms_arr = (int*)arr;
	ms.ms_result = result;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclaveChangeBuffer(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_enclaveChangeBuffer_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclaveStringSave(sgx_enclave_id_t eid, char* input, size_t len)
{
	sgx_status_t status;
	ms_enclaveStringSave_t ms;
	ms.ms_input = input;
	ms.ms_len = len;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclaveLoadInt(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclaveLoadInt_t ms;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t setSecretValue(sgx_enclave_id_t eid, int* value)
{
	sgx_status_t status;
	ms_setSecretValue_t ms;
	ms.ms_value = value;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

