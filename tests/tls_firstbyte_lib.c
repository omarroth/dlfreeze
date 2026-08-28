#include <stdint.h>

static __thread unsigned char tls_first
    __attribute__((section(".dlfreeze_tls_first"), aligned(1))) = 0x4b;
static __thread uintptr_t tls_page_aligned
    __attribute__((aligned(4096))) = (uintptr_t)0xabcdefu;

uintptr_t dlfreeze_tls_first_address(void)
{
    return (uintptr_t)&tls_first;
}

uintptr_t dlfreeze_tls_aligned_address(void)
{
    return (uintptr_t)&tls_page_aligned;
}

int dlfreeze_tls_values_valid(void)
{
    int valid = tls_first == 0x4b &&
                tls_page_aligned == (uintptr_t)0xabcdefu;

    tls_first++;
    tls_page_aligned++;
    return valid && tls_first == 0x4c &&
           tls_page_aligned == (uintptr_t)0xabcdf0u;
}
