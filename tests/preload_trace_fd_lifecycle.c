#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

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

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif

typedef int (*close_range_fn)(unsigned int, unsigned int, int);
typedef void (*closefrom_fn)(int);

static close_range_fn traced_close_range;
static const char *traced_input;
static const char *traced_trace_path;
static const char *replacement_path;
static atomic_int stress_failed;
static atomic_int unshare_worker_ready;
static atomic_int unshare_worker_release;
static int unshare_trace_fd;

static void record_stress_failure(int code)
{
    int expected = 0;

    (void)atomic_compare_exchange_strong_explicit(
        &stress_failed, &expected, code,
        memory_order_relaxed, memory_order_relaxed);
}

static int trace_input(void)
{
    char byte;
    int fd = open(traced_input, O_RDONLY | O_CLOEXEC);
    int ok = fd >= 0 && read(fd, &byte, 1) == 1;

    if (fd >= 0)
        (void)close(fd);
    return ok;
}

static int find_trace_fd(const char *trace_path)
{
    char proc_path[64];
    char target[PATH_MAX];
    size_t path_length = strlen(trace_path);

    for (int fd = 3; fd < 1024; fd++) {
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

static int find_trace_fd_during_rehome(const char *trace_path)
{
    for (unsigned int attempt = 0; attempt < 1024; attempt++) {
        int fd = find_trace_fd(trace_path);

        if (fd >= 0)
            return fd;
        sched_yield();
    }
    return -1;
}

static void *stress_writer(void *unused)
{
    (void)unused;
    for (unsigned int iteration = 0; iteration < 1000; iteration++) {
        struct stat status;

        if (stat(traced_input, &status) != 0 || !S_ISREG(status.st_mode)) {
            record_stress_failure(1);
            break;
        }
    }
    return NULL;
}

static void *stress_closer(void *unused)
{
    (void)unused;
    for (unsigned int iteration = 0; iteration < 4000; iteration++) {
        if (traced_close_range(3, UINT_MAX, 0) < 0) {
            record_stress_failure(2);
            break;
        }
    }
    return NULL;
}

static void *stress_replacer(void *unused)
{
    (void)unused;
    for (unsigned int iteration = 0; iteration < 128; iteration++) {
        int trace_fd = find_trace_fd_during_rehome(traced_trace_path);

        if (trace_fd < 0) {
            record_stress_failure(3);
            break;
        }
        if (iteration % 3 == 0) {
            /* A concurrent broad close_range may close this stale observed
             * number after the helper has moved its stream elsewhere. */
            if (close(trace_fd) != 0 && errno != EBADF) {
                record_stress_failure(4);
            }
        } else if (iteration % 3 == 1) {
            if (dup2(STDIN_FILENO, trace_fd) != trace_fd ||
                (close(trace_fd) != 0 && errno != EBADF)) {
                record_stress_failure(5);
            }
        } else {
            if (dup3(STDIN_FILENO, trace_fd, O_CLOEXEC) != trace_fd ||
                (close(trace_fd) != 0 && errno != EBADF)) {
                record_stress_failure(6);
            }
        }
        if (atomic_load_explicit(&stress_failed,
                                 memory_order_relaxed) != 0)
            break;
    }
    return NULL;
}

static void *unshare_worker(void *unused)
{
    static const char marker[] = "application-worker-ok\n";
    struct stat status;
    int app_fd;

    (void)unused;
    atomic_store_explicit(&unshare_worker_ready, 1,
                          memory_order_release);
    while (!atomic_load_explicit(&unshare_worker_release,
                                 memory_order_acquire))
        sched_yield();

    /* This thread retained the pre-split fd table.  The stream descriptor
     * must still be present here, but process-global trace publication has
     * been disabled, so ordinary close/reuse and a traced open are safe. */
    if (fstat(unshare_trace_fd, &status) != 0 ||
        !S_ISREG(status.st_mode) || !trace_input() ||
        close(unshare_trace_fd) != 0) {
        atomic_store_explicit(&stress_failed, 1,
                              memory_order_relaxed);
        return NULL;
    }
    app_fd = open(replacement_path,
                  O_WRONLY | O_APPEND | O_CLOEXEC);
    if (app_fd < 0 ||
        (app_fd != unshare_trace_fd &&
         dup2(app_fd, unshare_trace_fd) != unshare_trace_fd)) {
        if (app_fd >= 0)
            (void)close(app_fd);
        atomic_store_explicit(&stress_failed, 1,
                              memory_order_relaxed);
        return NULL;
    }
    if (app_fd != unshare_trace_fd)
        (void)close(app_fd);
    if (write(unshare_trace_fd, marker, sizeof(marker) - 1) !=
            (ssize_t)(sizeof(marker) - 1) ||
        close(unshare_trace_fd) != 0)
        atomic_store_explicit(&stress_failed, 1,
                              memory_order_relaxed);
    return NULL;
}

static int run_unshare(const char *trace_path)
{
    static const char marker[] = "application-main-ok\n";
    pthread_t worker;
    int app_fd;

    unshare_trace_fd = find_trace_fd(trace_path);
    if (unshare_trace_fd < 0)
        return 20;
    if (pthread_create(&worker, NULL, unshare_worker, NULL) != 0)
        return 21;
    while (!atomic_load_explicit(&unshare_worker_ready,
                                 memory_order_acquire))
        sched_yield();

    errno = 0;
    if (traced_close_range((unsigned int)unshare_trace_fd,
                           (unsigned int)unshare_trace_fd,
                           CLOSE_RANGE_UNSHARE) < 0) {
        int result_errno = errno;

        atomic_store_explicit(&unshare_worker_release, 1,
                              memory_order_release);
        (void)pthread_join(worker, NULL);
        if (result_errno == ENOSYS || result_errno == EINVAL)
            return 77;
        return 22;
    }
    errno = 0;
    if (fcntl(unshare_trace_fd, F_GETFD) != -1 || errno != EBADF)
        return 23;

    app_fd = open(replacement_path,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (app_fd < 0 ||
        (app_fd != unshare_trace_fd &&
         dup2(app_fd, unshare_trace_fd) != unshare_trace_fd))
        return 24;
    if (app_fd != unshare_trace_fd)
        (void)close(app_fd);
    if (write(unshare_trace_fd, marker, sizeof(marker) - 1) !=
            (ssize_t)(sizeof(marker) - 1) ||
        close(unshare_trace_fd) != 0 || !trace_input())
        return 25;

    atomic_store_explicit(&unshare_worker_release, 1,
                          memory_order_release);
    if (pthread_join(worker, NULL) != 0 ||
        atomic_load_explicit(&stress_failed,
                             memory_order_relaxed) != 0)
        return 26;
    puts("trace-fd-unshare-ok");
    return 0;
}

static int run_ordinary(const char *trace_path)
{
    static const char marker[] = "application-dup-ok\n";
    closefrom_fn traced_closefrom;
    pthread_t writers[4];
    pthread_t closer;
    pthread_t replacer;
    int app_fd;
    int trace_fd;

    traced_closefrom = (closefrom_fn)dlsym(RTLD_DEFAULT, "closefrom");
    if (!traced_closefrom)
        return 77;

    if (fcntl(STDIN_FILENO, F_GETFD) < 0) {
        app_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (app_fd < 0 || dup2(app_fd, STDIN_FILENO) != STDIN_FILENO)
            return 19;
        if (app_fd != STDIN_FILENO)
            (void)close(app_fd);
    }

    trace_fd = find_trace_fd(trace_path);
    if (trace_fd < 0)
        return 3;

    errno = 0;
    if (traced_close_range(9, 8, 0) != -1 || errno != EINVAL)
        return 4;
    if (!trace_input())
        return 5;

    app_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (app_fd < 3)
        return 8;
    traced_closefrom(3);
    errno = 0;
    if (fcntl(app_fd, F_GETFD) != -1 || errno != EBADF ||
        fcntl(trace_fd, F_GETFD) < 0 || !trace_input())
        return 9;

    /* Replacing the writer's descriptor number must first rehome the stream;
     * the destination is then an ordinary application descriptor. */
    app_fd = open(replacement_path,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (app_fd < 0)
        return 10;
    trace_fd = find_trace_fd(trace_path);
    if (trace_fd < 0 || dup2(app_fd, trace_fd) != trace_fd)
        return 11;
    if (app_fd != trace_fd && close(app_fd) != 0)
        return 12;
    if (write(trace_fd, marker, sizeof(marker) - 1) !=
            (ssize_t)(sizeof(marker) - 1) ||
        close(trace_fd) != 0 || !trace_input())
        return 13;

    for (size_t index = 0; index < sizeof(writers) / sizeof(writers[0]);
         index++) {
        if (pthread_create(&writers[index], NULL, stress_writer, NULL) != 0)
            return 14;
    }
    if (pthread_create(&closer, NULL, stress_closer, NULL) != 0)
        return 15;
    if (pthread_create(&replacer, NULL, stress_replacer, NULL) != 0)
        return 18;
    for (size_t index = 0; index < sizeof(writers) / sizeof(writers[0]);
         index++) {
        if (pthread_join(writers[index], NULL) != 0)
            return 16;
    }
    if (pthread_join(closer, NULL) != 0 ||
        pthread_join(replacer, NULL) != 0 ||
        atomic_load_explicit(&stress_failed, memory_order_relaxed) != 0 ||
        !trace_input()) {
        fprintf(stderr, "stress-failure=%d\n",
                atomic_load_explicit(&stress_failed,
                                     memory_order_relaxed));
        return 17;
    }

    puts("trace-fd-lifecycle-ok");
    return 0;
}

static int install_close_range_enosys_filter(void)
{
#if DLFREEZE_TEST_HAVE_SECCOMP_HEADERS && \
    defined(SYS_close_range) && defined(SYS_seccomp)
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close_range, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
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

static int run_closefrom_enosys(const char *trace_path)
{
    closefrom_fn traced_closefrom =
        (closefrom_fn)dlsym(RTLD_DEFAULT, "closefrom");
    struct rlimit limit;
    int base_fd;
    int high_fd;
    int trace_fd;

    if (!traced_closefrom)
        return 77;
    trace_fd = find_trace_fd(trace_path);
    if (trace_fd < 0)
        return 30;
    base_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (base_fd < 0)
        return 31;
    high_fd = fcntl(base_fd, F_DUPFD_CLOEXEC, 256);
    (void)close(base_fd);
    if (high_fd < 256)
        return 77;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur <= 64)
        return 77;
    limit.rlim_cur = 64;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0 ||
        !install_close_range_enosys_filter())
        return 77;

    traced_closefrom(3);
    errno = 0;
    if (fcntl(high_fd, F_GETFD) != -1 || errno != EBADF ||
        fcntl(trace_fd, F_GETFD) < 0 || !trace_input())
        return 32;
    puts("trace-closefrom-enosys-ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5)
        return 2;
    traced_input = argv[3];
    traced_trace_path = argv[2];
    replacement_path = argv[4];
    traced_close_range = (close_range_fn)dlsym(RTLD_DEFAULT,
                                                "close_range");
    if (!traced_close_range)
        return 77;
    if (strcmp(argv[1], "ordinary") == 0)
        return run_ordinary(argv[2]);
    if (strcmp(argv[1], "unshare") == 0)
        return run_unshare(argv[2]);
    if (strcmp(argv[1], "closefrom-enosys") == 0)
        return run_closefrom_enosys(argv[2]);
    return 2;
}
