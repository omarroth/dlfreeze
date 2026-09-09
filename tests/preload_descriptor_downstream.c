#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../include/linux_syscalls.h"

enum descriptor_mock_kind {
    DESCRIPTOR_MOCK_NONE = 0,
    DESCRIPTOR_MOCK_CLOSE = 1,
    DESCRIPTOR_MOCK_DUP = 2,
    DESCRIPTOR_MOCK_DUP2 = 3,
    DESCRIPTOR_MOCK_DUP3 = 4,
    DESCRIPTOR_MOCK_CLOSE_RANGE = 5,
    DESCRIPTOR_MOCK_CLOSEFROM = 6,
    DESCRIPTOR_MOCK_CLOSE_FORK = 7,
    DESCRIPTOR_MOCK_CLOSE_RANGE_FAIL = 8,
    DESCRIPTOR_MOCK_CLOSE_FAIL = 9,
};

static int (*next_close)(int);
static int (*next_dup)(int);
static int (*next_dup2)(int, int);
static int (*next_dup3)(int, int, int);
static int (*next_close_range)(unsigned int, unsigned int, int);
static void (*next_closefrom)(int);
static atomic_int armed_kind;
static atomic_int observed_calls;
static atomic_int callback_failed;
static unsigned int expected_first;
static unsigned int expected_last;
static int expected_flags;
static pid_t fork_child;
static _Thread_local int returned_in_fork_child;

static void resolve_next_symbols(void) __attribute__((constructor));

static void resolve_next_symbols(void)
{
    next_close = dlsym(RTLD_NEXT, "close");
    next_dup = dlsym(RTLD_NEXT, "dup");
    next_dup2 = dlsym(RTLD_NEXT, "dup2");
    next_dup3 = dlsym(RTLD_NEXT, "dup3");
    next_close_range = dlsym(RTLD_NEXT, "close_range");
    next_closefrom = dlsym(RTLD_NEXT, "closefrom");
}

void dlfreeze_descriptor_mock_arm(int kind, unsigned int first,
                                  unsigned int last, int flags)
{
    expected_first = first;
    expected_last = last;
    expected_flags = flags;
    fork_child = -1;
    returned_in_fork_child = 0;
    atomic_store_explicit(&observed_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&callback_failed, 0, memory_order_relaxed);
    atomic_store_explicit(&armed_kind, kind, memory_order_release);
}

int dlfreeze_descriptor_mock_status(void)
{
    return atomic_load_explicit(&armed_kind, memory_order_acquire) == 0 &&
           atomic_load_explicit(&observed_calls, memory_order_relaxed) == 1 &&
           atomic_load_explicit(&callback_failed, memory_order_relaxed) == 0;
}

pid_t dlfreeze_descriptor_mock_fork_child(void)
{
    return fork_child;
}

int dlfreeze_descriptor_mock_returned_in_child(void)
{
    return returned_in_fork_child;
}

static int consume_arm(int kind)
{
    int expected = kind;

    if (!atomic_compare_exchange_strong_explicit(
            &armed_kind, &expected, DESCRIPTOR_MOCK_NONE,
            memory_order_acq_rel, memory_order_acquire))
        return 0;
    atomic_fetch_add_explicit(&observed_calls, 1, memory_order_relaxed);
    return 1;
}

static void *trace_worker(void *unused)
{
    const char *path = getenv("DLFREEZE_DESCRIPTOR_TEST_INPUT");
    struct stat status;

    (void)unused;
    if (!path || stat(path, &status) != 0 || !S_ISREG(status.st_mode))
        atomic_store_explicit(&callback_failed, 1, memory_order_relaxed);
    return NULL;
}

static void run_joined_trace_callback(void)
{
    pthread_t worker;

    if (pthread_create(&worker, NULL, trace_worker, NULL) != 0) {
        atomic_store_explicit(&callback_failed, 1, memory_order_relaxed);
        return;
    }
    if (pthread_join(worker, NULL) != 0)
        atomic_store_explicit(&callback_failed, 1, memory_order_relaxed);
}

int close(int fd)
{
    int armed = consume_arm(DESCRIPTOR_MOCK_CLOSE);
    int fork_armed = 0;
    int fail_armed = 0;

    if (!armed)
        fork_armed = consume_arm(DESCRIPTOR_MOCK_CLOSE_FORK);
    if (!armed && !fork_armed)
        fail_armed = consume_arm(DESCRIPTOR_MOCK_CLOSE_FAIL);
    if (armed)
        run_joined_trace_callback();
    if (fail_armed) {
        run_joined_trace_callback();
        errno = EINTR;
        return -1;
    }
    if (fork_armed) {
        pid_t child = fork();

        if (child < 0) {
            atomic_store_explicit(&callback_failed, 1,
                                  memory_order_relaxed);
        } else if (child == 0) {
            returned_in_fork_child = 1;
        } else {
            fork_child = child;
        }
    }
    return next_close ? next_close(fd) : (int)syscall(SYS_close, fd);
}

int dup(int oldfd)
{
    if (consume_arm(DESCRIPTOR_MOCK_DUP))
        run_joined_trace_callback();
    return next_dup ? next_dup(oldfd) : (int)syscall(SYS_dup, oldfd);
}

int dup2(int oldfd, int newfd)
{
    if (consume_arm(DESCRIPTOR_MOCK_DUP2))
        run_joined_trace_callback();
    if (next_dup2)
        return next_dup2(oldfd, newfd);
#if defined(SYS_dup2)
    return (int)syscall(SYS_dup2, oldfd, newfd);
#elif defined(SYS_dup3)
    if (oldfd == newfd) {
        if (syscall(SYS_fcntl, oldfd, 1) < 0)
            return -1;
        return newfd;
    }
    return (int)syscall(SYS_dup3, oldfd, newfd, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int dup3(int oldfd, int newfd, int flags)
{
    if (consume_arm(DESCRIPTOR_MOCK_DUP3))
        run_joined_trace_callback();
    if (next_dup3)
        return next_dup3(oldfd, newfd, flags);
#if defined(SYS_dup3)
    return (int)syscall(SYS_dup3, oldfd, newfd, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int close_range(unsigned int first, unsigned int last, int flags)
{
    if (consume_arm(DESCRIPTOR_MOCK_CLOSE_RANGE_FAIL)) {
        run_joined_trace_callback();
        if (first != expected_first || last != expected_last ||
            flags != expected_flags)
            atomic_store_explicit(&callback_failed, 1,
                                  memory_order_relaxed);
        errno = EPERM;
        return -1;
    }
    if (consume_arm(DESCRIPTOR_MOCK_CLOSE_RANGE)) {
        run_joined_trace_callback();
        if (first != expected_first || last != expected_last ||
            flags != expected_flags) {
            atomic_store_explicit(&callback_failed, 1,
                                  memory_order_relaxed);
            errno = EPERM;
            return -1;
        }
    }
    if (next_close_range)
        return next_close_range(first, last, flags);
#if defined(SYS_close_range)
    return (int)syscall(SYS_close_range, first, last, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

void closefrom(int lowfd)
{
    if (consume_arm(DESCRIPTOR_MOCK_CLOSEFROM))
        run_joined_trace_callback();
    if (next_closefrom) {
        next_closefrom(lowfd);
        return;
    }
    if (lowfd < 0)
        lowfd = 0;
#if defined(SYS_close_range)
    if (syscall(SYS_close_range, (unsigned int)lowfd, UINT32_MAX, 0) == 0)
        return;
#endif
    {
        long maximum = sysconf(_SC_OPEN_MAX);

        if (maximum < 0)
            maximum = 1024;
        for (long fd = lowfd; fd < maximum; fd++)
            (void)syscall(SYS_close, (int)fd);
    }
}
