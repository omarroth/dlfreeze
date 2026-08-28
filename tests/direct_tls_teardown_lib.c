#include <stdint.h>

__thread unsigned char direct_tls_teardown_area[1024 * 1024]
    __attribute__((aligned(8192)));

int direct_tls_teardown_touch(unsigned int value)
{
    direct_tls_teardown_area[0] = (unsigned char)value;
    direct_tls_teardown_area[sizeof(direct_tls_teardown_area) - 1] =
        (unsigned char)(value ^ 0x5aU);
    return direct_tls_teardown_area[0] == (unsigned char)value &&
           direct_tls_teardown_area[sizeof(direct_tls_teardown_area) - 1] ==
               (unsigned char)(value ^ 0x5aU) &&
           (uintptr_t)direct_tls_teardown_area % 8192 == 0;
}
