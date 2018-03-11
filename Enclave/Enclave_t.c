#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_sum_array_t {
	int* ms_arr;
	size_t ms_size;
	int* ms_result;
} ms_ecall_sum_array_t;

typedef struct ms_ecall_test_t {
	sgx_ec256_private_t* ms_pPrivate;
	sgx_ec256_public_t* ms_pPublic;
	sgx_ecc_state_handle_t* ms_handle;
} ms_ecall_test_t;

typedef struct ms_ecall_ECDSAsignMessage_t {
	sgx_ec256_private_t* ms_p_private;
	sgx_ecc_state_handle_t* ms_ecc_handle;
	sgx_ec256_signature_t* ms_p_signature;
} ms_ecall_ECDSAsignMessage_t;

typedef struct ms_ecall_ECDSAverifyMessage_t {
	sgx_ec256_public_t* ms_p_public;
	sgx_ec256_signature_t* ms_p_signature;
	sgx_ecc_state_handle_t* ms_ecc_handle;
} ms_ecall_ECDSAverifyMessage_t;

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_sum_array(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sum_array_t));
	ms_ecall_sum_array_t* ms = SGX_CAST(ms_ecall_sum_array_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _tmp_size = ms->ms_size;
	size_t _len_arr = _tmp_size * sizeof(*_tmp_arr);
	int* _in_arr = NULL;
	int* _tmp_result = ms->ms_result;
	size_t _len_result = sizeof(*_tmp_result);
	int* _in_result = NULL;

	if (sizeof(*_tmp_arr) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_arr))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	if (_tmp_result != NULL && _len_result != 0) {
		_in_result = (int*)malloc(_len_result);
		if (_in_result == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_result, _tmp_result, _len_result);
	}

	ecall_sum_array(_in_arr, _tmp_size, _in_result);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}
	if (_in_result) {
		memcpy(_tmp_result, _in_result, _len_result);
		free(_in_result);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_t));
	ms_ecall_test_t* ms = SGX_CAST(ms_ecall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_private_t* _tmp_pPrivate = ms->ms_pPrivate;
	size_t _len_pPrivate = sizeof(*_tmp_pPrivate);
	sgx_ec256_private_t* _in_pPrivate = NULL;
	sgx_ec256_public_t* _tmp_pPublic = ms->ms_pPublic;
	size_t _len_pPublic = sizeof(*_tmp_pPublic);
	sgx_ec256_public_t* _in_pPublic = NULL;
	sgx_ecc_state_handle_t* _tmp_handle = ms->ms_handle;
	size_t _len_handle = sizeof(*_tmp_handle);
	sgx_ecc_state_handle_t* _in_handle = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pPrivate, _len_pPrivate);
	CHECK_UNIQUE_POINTER(_tmp_pPublic, _len_pPublic);
	CHECK_UNIQUE_POINTER(_tmp_handle, _len_handle);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_pPrivate != NULL && _len_pPrivate != 0) {
		_in_pPrivate = (sgx_ec256_private_t*)malloc(_len_pPrivate);
		if (_in_pPrivate == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_pPrivate, _tmp_pPrivate, _len_pPrivate);
	}
	if (_tmp_pPublic != NULL && _len_pPublic != 0) {
		_in_pPublic = (sgx_ec256_public_t*)malloc(_len_pPublic);
		if (_in_pPublic == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_pPublic, _tmp_pPublic, _len_pPublic);
	}
	if (_tmp_handle != NULL && _len_handle != 0) {
		_in_handle = (sgx_ecc_state_handle_t*)malloc(_len_handle);
		if (_in_handle == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_handle, _tmp_handle, _len_handle);
	}

	ecall_test(_in_pPrivate, _in_pPublic, _in_handle);
err:
	if (_in_pPrivate) {
		memcpy(_tmp_pPrivate, _in_pPrivate, _len_pPrivate);
		free(_in_pPrivate);
	}
	if (_in_pPublic) {
		memcpy(_tmp_pPublic, _in_pPublic, _len_pPublic);
		free(_in_pPublic);
	}
	if (_in_handle) {
		memcpy(_tmp_handle, _in_handle, _len_handle);
		free(_in_handle);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ECDSAsignMessage(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ECDSAsignMessage_t));
	ms_ecall_ECDSAsignMessage_t* ms = SGX_CAST(ms_ecall_ECDSAsignMessage_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_private_t* _tmp_p_private = ms->ms_p_private;
	size_t _len_p_private = sizeof(*_tmp_p_private);
	sgx_ec256_private_t* _in_p_private = NULL;
	sgx_ecc_state_handle_t* _tmp_ecc_handle = ms->ms_ecc_handle;
	size_t _len_ecc_handle = sizeof(*_tmp_ecc_handle);
	sgx_ecc_state_handle_t* _in_ecc_handle = NULL;
	sgx_ec256_signature_t* _tmp_p_signature = ms->ms_p_signature;
	size_t _len_p_signature = sizeof(*_tmp_p_signature);
	sgx_ec256_signature_t* _in_p_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_private, _len_p_private);
	CHECK_UNIQUE_POINTER(_tmp_ecc_handle, _len_ecc_handle);
	CHECK_UNIQUE_POINTER(_tmp_p_signature, _len_p_signature);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_p_private != NULL && _len_p_private != 0) {
		_in_p_private = (sgx_ec256_private_t*)malloc(_len_p_private);
		if (_in_p_private == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_private, _tmp_p_private, _len_p_private);
	}
	if (_tmp_ecc_handle != NULL && _len_ecc_handle != 0) {
		_in_ecc_handle = (sgx_ecc_state_handle_t*)malloc(_len_ecc_handle);
		if (_in_ecc_handle == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ecc_handle, _tmp_ecc_handle, _len_ecc_handle);
	}
	if (_tmp_p_signature != NULL && _len_p_signature != 0) {
		_in_p_signature = (sgx_ec256_signature_t*)malloc(_len_p_signature);
		if (_in_p_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_signature, _tmp_p_signature, _len_p_signature);
	}

	ecall_ECDSAsignMessage(_in_p_private, _in_ecc_handle, _in_p_signature);
err:
	if (_in_p_private) {
		memcpy(_tmp_p_private, _in_p_private, _len_p_private);
		free(_in_p_private);
	}
	if (_in_ecc_handle) {
		memcpy(_tmp_ecc_handle, _in_ecc_handle, _len_ecc_handle);
		free(_in_ecc_handle);
	}
	if (_in_p_signature) {
		memcpy(_tmp_p_signature, _in_p_signature, _len_p_signature);
		free(_in_p_signature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ECDSAverifyMessage(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ECDSAverifyMessage_t));
	ms_ecall_ECDSAverifyMessage_t* ms = SGX_CAST(ms_ecall_ECDSAverifyMessage_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_p_public = ms->ms_p_public;
	size_t _len_p_public = sizeof(*_tmp_p_public);
	sgx_ec256_public_t* _in_p_public = NULL;
	sgx_ec256_signature_t* _tmp_p_signature = ms->ms_p_signature;
	size_t _len_p_signature = sizeof(*_tmp_p_signature);
	sgx_ec256_signature_t* _in_p_signature = NULL;
	sgx_ecc_state_handle_t* _tmp_ecc_handle = ms->ms_ecc_handle;
	size_t _len_ecc_handle = sizeof(*_tmp_ecc_handle);
	sgx_ecc_state_handle_t* _in_ecc_handle = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_public, _len_p_public);
	CHECK_UNIQUE_POINTER(_tmp_p_signature, _len_p_signature);
	CHECK_UNIQUE_POINTER(_tmp_ecc_handle, _len_ecc_handle);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_p_public != NULL && _len_p_public != 0) {
		_in_p_public = (sgx_ec256_public_t*)malloc(_len_p_public);
		if (_in_p_public == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_public, _tmp_p_public, _len_p_public);
	}
	if (_tmp_p_signature != NULL && _len_p_signature != 0) {
		_in_p_signature = (sgx_ec256_signature_t*)malloc(_len_p_signature);
		if (_in_p_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_signature, _tmp_p_signature, _len_p_signature);
	}
	if (_tmp_ecc_handle != NULL && _len_ecc_handle != 0) {
		_in_ecc_handle = (sgx_ecc_state_handle_t*)malloc(_len_ecc_handle);
		if (_in_ecc_handle == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ecc_handle, _tmp_ecc_handle, _len_ecc_handle);
	}

	ecall_ECDSAverifyMessage(_in_p_public, _in_p_signature, _in_ecc_handle);
err:
	if (_in_p_public) {
		memcpy(_tmp_p_public, _in_p_public, _len_p_public);
		free(_in_p_public);
	}
	if (_in_p_signature) {
		memcpy(_tmp_p_signature, _in_p_signature, _len_p_signature);
		free(_in_p_signature);
	}
	if (_in_ecc_handle) {
		memcpy(_tmp_ecc_handle, _in_ecc_handle, _len_ecc_handle);
		free(_in_ecc_handle);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sum_values(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sum_values_t));
	ms_ecall_sum_values_t* ms = SGX_CAST(ms_ecall_sum_values_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 5 * sizeof(*_tmp_arr);
	int* _in_arr = NULL;
	int* _tmp_result = ms->ms_result;
	size_t _len_result = sizeof(*_tmp_result);
	int* _in_result = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_arr, _tmp_arr, _len_arr);
	}
	if (_tmp_result != NULL && _len_result != 0) {
		_in_result = (int*)malloc(_len_result);
		if (_in_result == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_result, _tmp_result, _len_result);
	}

	ecall_sum_values(_in_arr, _in_result);
err:
	if (_in_arr) {
		memcpy(_tmp_arr, _in_arr, _len_arr);
		free(_in_arr);
	}
	if (_in_result) {
		memcpy(_tmp_result, _in_result, _len_result);
		free(_in_result);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveChangeBuffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveChangeBuffer_t));
	ms_enclaveChangeBuffer_t* ms = SGX_CAST(ms_enclaveChangeBuffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}

	enclaveChangeBuffer(_in_buf, _tmp_len);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveStringSave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveStringSave_t));
	ms_enclaveStringSave_t* ms = SGX_CAST(ms_enclaveStringSave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_input = ms->ms_input;
	size_t _tmp_len = ms->ms_len;
	size_t _len_input = _tmp_len;
	char* _in_input = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		_in_input = (char*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}

	enclaveStringSave(_in_input, _tmp_len);
err:
	if (_in_input) free(_in_input);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveLoadInt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveLoadInt_t));
	ms_enclaveLoadInt_t* ms = SGX_CAST(ms_enclaveLoadInt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	//
	// fence after pointer checks
	//
	_mm_lfence();


	ms->ms_retval = enclaveLoadInt();


	return status;
}

static sgx_status_t SGX_CDECL sgx_setSecretValue(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setSecretValue_t));
	ms_setSecretValue_t* ms = SGX_CAST(ms_setSecretValue_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_value = ms->ms_value;
	size_t _len_value = sizeof(*_tmp_value);
	int* _in_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);


	//
	// fence after pointer checks
	//
	_mm_lfence();

	if (_tmp_value != NULL && _len_value != 0) {
		_in_value = (int*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_value, _tmp_value, _len_value);
	}

	setSecretValue(_in_value);
err:
	if (_in_value) {
		memcpy(_tmp_value, _in_value, _len_value);
		free(_in_value);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_ecall_sum_array, 0},
		{(void*)(uintptr_t)sgx_ecall_test, 0},
		{(void*)(uintptr_t)sgx_ecall_ECDSAsignMessage, 0},
		{(void*)(uintptr_t)sgx_ecall_ECDSAverifyMessage, 0},
		{(void*)(uintptr_t)sgx_ecall_sum_values, 0},
		{(void*)(uintptr_t)sgx_enclaveChangeBuffer, 0},
		{(void*)(uintptr_t)sgx_enclaveStringSave, 0},
		{(void*)(uintptr_t)sgx_enclaveLoadInt, 0},
		{(void*)(uintptr_t)sgx_setSecretValue, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][9];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
