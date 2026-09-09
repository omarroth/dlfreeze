#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS 0x5005
#endif
#ifndef ARCH_SHSTK_SHSTK
#define ARCH_SHSTK_SHSTK UINT64_C(1)
#endif

#define GNU_PROPERTY_X86_FEATURE_1_SHSTK UINT32_C(2)
#define GLIBC_X86_TCB_FEATURE_1_OFFSET 72

struct cet_state {
    uint32_t kernel_shstk;
    uint32_t tcb_shstk;
};

static int read_cet_state(struct cet_state *state)
{
    unsigned long long kernel_features = 0;
    uint32_t tcb_features;
    long status;

    if (!state)
        return -1;
    errno = 0;
    status = syscall(SYS_arch_prctl, ARCH_SHSTK_STATUS,
                     &kernel_features);
    if (status < 0 && errno != EINVAL && errno != ENOSYS &&
        errno != EOPNOTSUPP)
        return -1;
    __asm__ volatile("movl %%fs:%c1,%0"
                     : "=r"(tcb_features)
                     : "i"(GLIBC_X86_TCB_FEATURE_1_OFFSET));
    state->kernel_shstk = status == 0 &&
        (kernel_features & ARCH_SHSTK_SHSTK) != 0
            ? GNU_PROPERTY_X86_FEATURE_1_SHSTK : 0;
    state->tcb_shstk =
        tcb_features & GNU_PROPERTY_X86_FEATURE_1_SHSTK;
    return state->kernel_shstk == state->tcb_shstk ? 0 : -1;
}

static void *thread_main(void *opaque)
{
    struct cet_state *state = opaque;

    return (void *)(uintptr_t)(read_cet_state(state) != 0);
}

int main(int argc, char **argv)
{
    struct cet_state main_before;
    struct cet_state child;
    struct cet_state main_after;
    pthread_t thread;
    void *thread_result = NULL;
    void *handle;

    if (argc != 2 || read_cet_state(&main_before) != 0)
        return 70;
    if (pthread_create(&thread, NULL, thread_main, &child) != 0 ||
        pthread_join(thread, &thread_result) != 0 || thread_result != NULL)
        return 71;
    if (child.kernel_shstk != main_before.kernel_shstk ||
        child.tcb_shstk != main_before.tcb_shstk)
        return 72;

    /* NPTL's multiple_threads bit remains set after join.  A strict active
     * target must reject this legacy DSO; an inactive target may admit it.
     * Comparing the normalized native/direct outcome checks both cases. */
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (read_cet_state(&main_after) != 0)
        return 73;
    printf("before=%u/%u child=%u/%u dlopen=%u after=%u/%u\n",
           main_before.kernel_shstk, main_before.tcb_shstk,
           child.kernel_shstk, child.tcb_shstk, handle != NULL,
           main_after.kernel_shstk, main_after.tcb_shstk);
    if (handle && dlclose(handle) != 0)
        return 74;
    return 0;
}
