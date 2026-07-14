#include <stdint.h>

/* Keep the private compatibility hook internal in production while testing
 * its exact success contract.  Dead-section elimination discards the rest of
 * the direct loader from this small helper. */
#include "../src/loader.c"

static void succeed(void *argument)
{
    *(int *)argument = 1;
}

int main(void)
{
    struct dlfreeze_dl_exception exception = {
        (const char *)(uintptr_t)1,
        (const char *)(uintptr_t)2,
        (char *)(uintptr_t)3,
    };
    int called = 0;

    if (stub_dl_catch_exception(&exception, succeed, &called) != 0 ||
        !called || exception.objname != NULL || exception.errstring != NULL ||
        exception.message_buffer != NULL)
        return 1;
    return 0;
}
