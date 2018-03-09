#include "sgx_trts.h"

#include "Enclave_t.h"
#include <limits>
#include <cmath>

void ecall_module(int * value)
{
	*value = 5000;
}
