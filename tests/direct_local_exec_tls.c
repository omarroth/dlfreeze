#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#ifndef TEST_TLS_ALIGNMENT
#define TEST_TLS_ALIGNMENT 16
#endif

static const char initial_text[] = "local-exec-template";
struct local_state {
    uint64_t marker;
    const char *text;
    uint64_t guard[4];
};

/* These accesses have link-time-fixed TP offsets, including in PIE. Moving
 * the executable's TLS image cannot be repaired through its DTV entry. */
static _Thread_local volatile struct local_state state
    __attribute__((tls_model("local-exec"), aligned(TEST_TLS_ALIGNMENT))) = {
        UINT64_C(0x123456789abcdef0), initial_text,
        {UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211),
         UINT64_C(0x13579bdf2468ace0), UINT64_C(0xfedcba9876543210)}
    };
static _Thread_local volatile unsigned char zero_fill[48]
    __attribute__((tls_model("local-exec")));
static int constructor_ok;

static int template_ok(void)
{
    if ((uintptr_t)&state % TEST_TLS_ALIGNMENT != 0 ||
        state.marker != UINT64_C(0x123456789abcdef0) ||
        state.text != initial_text ||
        state.guard[0] != UINT64_C(0x1122334455667788) ||
        state.guard[1] != UINT64_C(0x8877665544332211) ||
        state.guard[2] != UINT64_C(0x13579bdf2468ace0) ||
        state.guard[3] != UINT64_C(0xfedcba9876543210))
        return 0;
    for (size_t i = 0; i < sizeof(zero_fill); i++)
        if (zero_fill[i] != 0)
            return 0;
    return 1;
}

__attribute__((constructor)) static void check_constructor(void)
{
    constructor_ok = template_ok();
}

static void *worker(void *unused)
{
    (void)unused;
    if (!template_ok())
        return (void *)(uintptr_t)1;
    state.marker = 72;
    state.text = NULL;
    zero_fill[sizeof(zero_fill) - 1] = 19;
    return NULL;
}

int main(void)
{
    if (!constructor_ok || !template_ok())
        return 1;
    state.marker = 93;
    zero_fill[0] = 7;
    for (unsigned i = 0; i < 2; i++) {
        pthread_t thread;
        void *result;

        if (pthread_create(&thread, NULL, worker, NULL) != 0 ||
            pthread_join(thread, &result) != 0 || result != NULL)
            return 2;
        if (state.marker != 93 || state.text != initial_text ||
            zero_fill[0] != 7 || zero_fill[sizeof(zero_fill) - 1] != 0)
            return 3;
    }
    puts("local-exec-tls-ok");
    return 0;
}
