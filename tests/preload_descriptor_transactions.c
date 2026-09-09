#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../include/linux_syscalls.h"

#if defined(__has_include)
# if __has_include(<linux/filter.h>) && \
     __has_include(<linux/seccomp.h>) && __has_include(<sys/prctl.h>)
#  define DLFREEZE_TEST_HAVE_SECCOMP_HEADERS 1
# endif
#endif
#ifndef DLFREEZE_TEST_HAVE_SECCOMP_HEADERS
# define DLFREEZE_TEST_HAVE_SECCOMP_HEADERS 0
#endif
#if DLFREEZE_TEST_HAVE_SECCOMP_HEADERS
# include <linux/filter.h>
# include <linux/seccomp.h>
# include <sys/prctl.h>
#endif

enum descriptor_mock_kind {
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

typedef void (*mock_arm_fn)(int, unsigned int, unsigned int, int);
typedef int (*mock_status_fn)(void);
typedef pid_t (*mock_child_fn)(void);
typedef int (*mock_in_child_fn)(void);
typedef int (*close_range_fn)(unsigned int, unsigned int, int);
typedef void (*closefrom_fn)(int);

static mock_arm_fn mock_arm;
static mock_status_fn mock_status;
static mock_child_fn mock_child;
static mock_in_child_fn mock_in_child;

static int find_trace_fd(const char *trace_path)
{
    char proc_path[64];
    char target[PATH_MAX];
    size_t path_length = strlen(trace_path);

    for (int fd = 3; fd < 4096; fd++) {
        int length = snprintf(proc_path, sizeof(proc_path),
                              "/proc/self/fd/%d", fd);
        ssize_t target_length;

        if (length < 0 || (size_t)length >= sizeof(proc_path))
            return -1;
        target_length = readlink(proc_path, target, sizeof(target) - 1);
        if (target_length < 0)
            continue;
        if ((size_t)target_length >= sizeof(target) - 1)
            return -1;
        target[target_length] = '\0';
        if (strcmp(target, trace_path) == 0 ||
            ((size_t)target_length == path_length +
                                      sizeof(" (deleted)") - 1 &&
             memcmp(target, trace_path, path_length) == 0 &&
             strcmp(target + path_length, " (deleted)") == 0))
            return fd;
    }
    return -1;
}

static int count_trace_fds(const char *trace_path)
{
    char proc_path[64];
    char target[PATH_MAX];
    size_t path_length = strlen(trace_path);
    int count = 0;

    for (int fd = 3; fd < 4096; fd++) {
        int length = snprintf(proc_path, sizeof(proc_path),
                              "/proc/self/fd/%d", fd);
        ssize_t target_length;

        if (length < 0 || (size_t)length >= sizeof(proc_path))
            return -1;
        target_length = readlink(proc_path, target, sizeof(target) - 1);
        if (target_length < 0)
            continue;
        if ((size_t)target_length >= sizeof(target) - 1)
            return -1;
        target[target_length] = '\0';
        if (strcmp(target, trace_path) == 0 ||
            ((size_t)target_length == path_length +
                                      sizeof(" (deleted)") - 1 &&
             memcmp(target, trace_path, path_length) == 0 &&
             strcmp(target + path_length, " (deleted)") == 0))
            count++;
    }
    return count;
}

static int arm_and_check(int kind, unsigned int first, unsigned int last,
                         int flags)
{
    mock_arm(kind, first, last, flags);
    return 1;
}

static int run_callbacks(const char *file_trace_path)
{
    close_range_fn traced_close_range =
        (close_range_fn)dlsym(RTLD_DEFAULT, "close_range");
    closefrom_fn traced_closefrom =
        (closefrom_fn)dlsym(RTLD_DEFAULT, "closefrom");
    int app_fd;
    int duplicated;
    int destination;
    int trace_fd;
    int high_fd;
    int status;

    mock_arm = (mock_arm_fn)dlsym(RTLD_DEFAULT,
                                  "dlfreeze_descriptor_mock_arm");
    mock_status = (mock_status_fn)dlsym(
        RTLD_DEFAULT, "dlfreeze_descriptor_mock_status");
    mock_child = (mock_child_fn)dlsym(
        RTLD_DEFAULT, "dlfreeze_descriptor_mock_fork_child");
    mock_in_child = (mock_in_child_fn)dlsym(
        RTLD_DEFAULT, "dlfreeze_descriptor_mock_returned_in_child");
    if (!traced_close_range || !traced_closefrom || !mock_arm ||
        !mock_status || !mock_child || !mock_in_child)
        return 77;

    app_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (app_fd < 0 || !arm_and_check(DESCRIPTOR_MOCK_CLOSE, 0, 0, 0) ||
        close(app_fd) != 0 || !mock_status())
        return 10;

    if (!arm_and_check(DESCRIPTOR_MOCK_DUP, 0, 0, 0) ||
        (duplicated = dup(STDIN_FILENO)) < 0 || !mock_status())
        return 11;
    if (close(duplicated) != 0)
        return 12;

    destination = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (destination < 0 ||
        !arm_and_check(DESCRIPTOR_MOCK_DUP2, 0, 0, 0) ||
        dup2(STDIN_FILENO, destination) != destination || !mock_status())
        return 13;
    if (close(destination) != 0)
        return 14;

    destination = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (destination < 0 ||
        !arm_and_check(DESCRIPTOR_MOCK_DUP3, 0, 0, O_CLOEXEC) ||
        dup3(STDIN_FILENO, destination, O_CLOEXEC) != destination ||
        !mock_status())
        return 15;
    if (close(destination) != 0)
        return 16;

    trace_fd = find_trace_fd(file_trace_path);
    if (trace_fd < 3 || count_trace_fds(file_trace_path) != 1)
        return 17;
    if (!arm_and_check(DESCRIPTOR_MOCK_CLOSE_FAIL, 0, 0, 0))
        return 18;
    errno = 0;
    if (close(trace_fd) != -1 || errno != EINTR || !mock_status() ||
        find_trace_fd(file_trace_path) != trace_fd ||
        count_trace_fds(file_trace_path) != 1)
        return 19;
    if (!arm_and_check(DESCRIPTOR_MOCK_CLOSE_RANGE_FAIL,
                       (unsigned int)trace_fd,
                       (unsigned int)trace_fd, 0))
        return 20;
    errno = 0;
    if (traced_close_range((unsigned int)trace_fd,
                           (unsigned int)trace_fd, 0) != -1 ||
        errno != EPERM || !mock_status() ||
        find_trace_fd(file_trace_path) != trace_fd ||
        count_trace_fds(file_trace_path) != 1)
        return 21;
    if (!arm_and_check(DESCRIPTOR_MOCK_CLOSE_RANGE,
                       (unsigned int)trace_fd,
                       (unsigned int)trace_fd, 0) ||
        traced_close_range((unsigned int)trace_fd,
                           (unsigned int)trace_fd, 0) != 0 ||
        !mock_status() || find_trace_fd(file_trace_path) < 0)
        return 22;

    app_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (app_fd < 0)
        return 23;
    high_fd = fcntl(app_fd, F_DUPFD_CLOEXEC, 256);
    (void)close(app_fd);
    if (high_fd < 256)
        return 77;
    if (!arm_and_check(DESCRIPTOR_MOCK_CLOSEFROM, 100, UINT_MAX, 0))
        return 24;
    traced_closefrom(100);
    errno = 0;
    if (!mock_status() || fcntl(high_fd, F_GETFD) != -1 || errno != EBADF)
        return 25;

    app_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (app_fd < 0 ||
        !arm_and_check(DESCRIPTOR_MOCK_CLOSE_FORK, 0, 0, 0) ||
        close(app_fd) != 0)
        return 26;
    if (mock_in_child())
        _exit(0);
    if (!mock_status() || mock_child() <= 0 ||
        waitpid(mock_child(), &status, 0) != mock_child() ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 27;

    puts("descriptor-transactions-ok");
    return 0;
}

static int install_close_range_eperm_filter(void)
{
#if DLFREEZE_TEST_HAVE_SECCOMP_HEADERS && \
    defined(SYS_close_range) && defined(SYS_seccomp)
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close_range, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) /
                                sizeof(instructions[0])),
        .filter = instructions,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return 0;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
#else
    return 0;
#endif
}

static int run_closefrom_eperm(void)
{
    closefrom_fn traced_closefrom =
        (closefrom_fn)dlsym(RTLD_DEFAULT, "closefrom");
    struct rlimit limit;
    int base_fd;
    int high_fd;

    if (!traced_closefrom)
        return 77;
    base_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (base_fd < 0)
        return 30;
    high_fd = fcntl(base_fd, F_DUPFD_CLOEXEC, 256);
    (void)close(base_fd);
    if (high_fd < 256 || getrlimit(RLIMIT_NOFILE, &limit) != 0 ||
        limit.rlim_cur <= 128)
        return 77;
    limit.rlim_cur = 128;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0 ||
        !install_close_range_eperm_filter())
        return 77;

    traced_closefrom(100);
    errno = 0;
    if (fcntl(high_fd, F_GETFD) != -1 || errno != EBADF)
        return 31;
    puts("descriptor-closefrom-eperm-ok");
    return 0;
}

static int run_segmented_eperm(void)
{
    close_range_fn traced_close_range =
        (close_range_fn)dlsym(RTLD_DEFAULT, "close_range");

    if (!traced_close_range || !install_close_range_eperm_filter())
        return 77;
    errno = 0;
    if (traced_close_range(3, UINT_MAX, 0) != -1 || errno != EPERM)
        return 40;
    puts("descriptor-segmented-eperm-ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    if (strcmp(argv[1], "callbacks") == 0 && argc == 3)
        return run_callbacks(argv[2]);
    if (strcmp(argv[1], "closefrom-eperm") == 0 && argc == 2)
        return run_closefrom_eperm();
    if (strcmp(argv[1], "segmented-eperm") == 0 && argc == 2)
        return run_segmented_eperm();
    return 2;
}
