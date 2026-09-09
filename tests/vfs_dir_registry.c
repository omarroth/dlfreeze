#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int same_node(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_rdev == right->st_rdev &&
           left->st_mode == right->st_mode &&
           left->st_size == right->st_size;
}

struct worker_args {
    const char *directory;
    const char *file;
    const char *scratch;
    atomic_int *failed;
    int frozen;
};

static int directory_has_files(DIR *directory)
{
    struct dirent *entry;
    int first = 0;
    int second = 0;

    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "first.txt") == 0)
            first = 1;
        if (strcmp(entry->d_name, "second.txt") == 0)
            second = 1;
    }
    return errno == 0 && first && second;
}

static int check_seek_contract(DIR *directory)
{
    struct dirent *entry;
    char following[256];
    long position;

    rewinddir(directory);
    entry = readdir(directory);
    if (!entry)
        return 0;
    position = telldir(directory);
    if (position < 0)
        return 0;
    entry = readdir(directory);
    if (!entry)
        following[0] = '\0';
    else {
        size_t length = strlen(entry->d_name);

        if (length >= sizeof(following))
            return 0;
        memcpy(following, entry->d_name, length + 1);
    }
    seekdir(directory, position);
    entry = readdir(directory);
    if (!entry)
        return following[0] == '\0';
    return strcmp(entry->d_name, following) == 0;
}

static int check_directory(const struct worker_args *args)
{
    char byte = '\0';
    DIR *directory;
    int descriptor;
    int file;
    int ok;

    directory = opendir(args->directory);
    if (!directory)
        return 0;
    descriptor = dirfd(directory);
    if (descriptor < 0 ||
        (file = openat(descriptor, "first.txt", O_RDONLY | O_CLOEXEC)) < 0 ||
        read(file, &byte, 1) != 1 || byte != '1' || close(file) != 0) {
        closedir(directory);
        return 0;
    }
    ok = check_seek_contract(directory);
    rewinddir(directory);
    ok = ok && directory_has_files(directory);
    if (closedir(directory) != 0)
        ok = 0;
    if (!ok)
        return 0;

    descriptor = open(args->directory,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0)
        return 0;
    directory = fdopendir(descriptor);
    if (!directory) {
        close(descriptor);
        return 0;
    }
    ok = dirfd(directory) == descriptor && directory_has_files(directory);
    if (closedir(directory) != 0)
        ok = 0;
    return ok;
}

static void *worker(void *opaque)
{
    struct worker_args *args = opaque;

    for (int iteration = 0; iteration < 32; iteration++) {
        if (!check_directory(args)) {
            atomic_store_explicit(args->failed, 1, memory_order_relaxed);
            break;
        }
    }
    return NULL;
}

static int check_real_directory(const struct worker_args *args)
{
    char real_directory[PATH_MAX];
    DIR *directory;
    struct dirent *entry;
    long position;
    int descriptor;
    int length;
    int ok = 0;

    length = snprintf(real_directory, sizeof(real_directory),
                      "%s/real-dir-XXXXXX", args->scratch);
    if (length < 0 || (size_t)length >= sizeof(real_directory) ||
        !mkdtemp(real_directory))
        return 0;
    directory = opendir(real_directory);
    if (!directory)
        goto out;
    descriptor = dirfd(directory);
    entry = readdir(directory);
    position = telldir(directory);
    if (descriptor < 0 || !entry || position < 0)
        goto out;
    seekdir(directory, position);
    rewinddir(directory);
    entry = readdir(directory);
    ok = entry != NULL;

out:
    if (directory && closedir(directory) != 0)
        ok = 0;
    if (rmdir(real_directory) != 0)
        ok = 0;
    return ok;
}

static int check_forked_handle(const struct worker_args *args)
{
    DIR *directory = opendir(args->directory);
    pid_t child;
    int status;
    int parent_ok;

    if (!directory)
        return 0;
    child = fork();
    if (child < 0) {
        closedir(directory);
        return 0;
    }
    if (child == 0) {
        int ok;

        rewinddir(directory);
        ok = directory_has_files(directory) && closedir(directory) == 0;
        _exit(ok ? 0 : 1);
    }
    /* fork(2) preserves the open file description, including its directory
     * offset.  A parent and child racing readdir() on the inherited stream
     * therefore have no portable per-process iteration order.  First prove
     * that the child can consume and close its inherited DIR, then reset the
     * still-live parent stream and exercise it independently. */
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        closedir(directory);
        return 0;
    }
    rewinddir(directory);
    parent_ok = directory_has_files(directory) && closedir(directory) == 0;
    return parent_ok;
}

static int check_replaced_synthetic_dirfd(const struct worker_args *args)
{
    DIR *virtual_directory = NULL;
    int virtual_fd = -1;
    int real_fd = -1;
    int probe_fd = -1;
    int ok = 0;

    virtual_directory = opendir(args->directory);
    if (!virtual_directory)
        goto out;
    virtual_fd = dirfd(virtual_directory);
    /* Bypass the interposed dup API so registry validation, rather than
     * wrapper propagation, must reject the replacement descriptor. */
    real_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (virtual_fd < 0 || real_fd < 0 || real_fd == virtual_fd)
        goto out;
    if (syscall(SYS_dup3, real_fd, virtual_fd, 0) != virtual_fd)
        goto out;
    if (close(real_fd) != 0)
        goto out;
    real_fd = -1;

    /* first.txt exists in the captured directory, but not in the real
     * directory now installed at the same descriptor number.  A stale VFS
     * provenance record would incorrectly serve the captured byte here. */
    errno = 0;
    probe_fd = openat(virtual_fd, "first.txt", O_RDONLY | O_CLOEXEC);
    if (probe_fd >= 0 || errno != ENOENT)
        goto out;
    ok = 1;

out:
    if (probe_fd >= 0)
        close(probe_fd);
    if (real_fd >= 0)
        close(real_fd);
    if (virtual_directory && closedir(virtual_directory) != 0)
        ok = 0;
    return ok;
}

static int check_directory_descriptor_flags(const struct worker_args *args)
{
    int descriptor;
    int descriptor_flags;
    int status_flags;

    descriptor = open(args->directory, O_RDONLY);
    if (descriptor < 0)
        return 0;
    descriptor_flags = fcntl(descriptor, F_GETFD);
    status_flags = fcntl(descriptor, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) != 0 ||
        (status_flags & O_ACCMODE) != O_RDONLY || close(descriptor) != 0)
        return 0;

    descriptor = open(args->directory,
                      O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (descriptor < 0)
        return 0;
    descriptor_flags = fcntl(descriptor, F_GETFD);
    status_flags = fcntl(descriptor, F_GETFL);
    if (descriptor_flags < 0 || status_flags < 0 ||
        (descriptor_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_NONBLOCK) == 0 || close(descriptor) != 0)
        return 0;

#ifdef O_PATH
    {
        DIR *path_directory;
        int path_descriptor;

        descriptor = open(args->directory, O_PATH | O_CLOEXEC);
        if (descriptor < 0)
            return 0;
        path_descriptor = descriptor;
        descriptor_flags = fcntl(descriptor, F_GETFD);
        status_flags = fcntl(descriptor, F_GETFL);
        if (descriptor_flags < 0 || status_flags < 0 ||
            (descriptor_flags & FD_CLOEXEC) == 0 ||
            (status_flags & O_PATH) != O_PATH)
            return 0;

        /* libc versions reject an O_PATH descriptor at either fdopendir() or
         * the first readdir().  Both timings implement the same contract.  On
         * early rejection fdopendir leaves ownership with us; on late
         * rejection the DIR stream owns the descriptor and closedir consumes
         * it. */
        errno = 0;
        path_directory = fdopendir(descriptor);
        if (!path_directory) {
            if (errno != EBADF || close(descriptor) != 0)
                return 0;
        } else {
            errno = 0;
            if (readdir(path_directory) != NULL || errno != EBADF) {
                closedir(path_directory);
                return 0;
            }
            if (closedir(path_directory) != 0)
                return 0;
            errno = 0;
            if (fcntl(path_descriptor, F_GETFD) != -1 || errno != EBADF)
                return 0;
        }
    }
#endif
    return 1;
}

static int openat_has_byte(int directory_fd, const char *name, char expected)
{
    char byte = '\0';
    int descriptor = openat(directory_fd, name, O_RDONLY | O_CLOEXEC);
    int ok;

    if (descriptor < 0)
        return 0;
    ok = read(descriptor, &byte, 1) == 1 && byte == expected;
    if (close(descriptor) != 0)
        ok = 0;
    return ok;
}

static int check_identity_coherence(const struct worker_args *args)
{
    char first_path[PATH_MAX];
    struct stat first_status;
    struct stat second_status;
    struct stat directory_status;
    struct stat descriptor_status;
    struct stat empty_status;
    DIR *directory = NULL;
    struct dirent *entry;
    int descriptor = -1;
    int duplicate = -1;
    int found_first = 0;
    int ok = 0;

    if (snprintf(first_path, sizeof(first_path), "%s/first.txt",
                 args->directory) < 0 ||
        stat(first_path, &first_status) < 0 ||
        stat(args->file, &second_status) < 0 ||
        stat(args->directory, &directory_status) < 0 ||
        (first_status.st_dev == second_status.st_dev &&
         first_status.st_ino == second_status.st_ino) ||
        (first_status.st_dev == directory_status.st_dev &&
         first_status.st_ino == directory_status.st_ino))
        goto out;

    descriptor = open(first_path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &descriptor_status) < 0 ||
        !same_node(&first_status, &descriptor_status) ||
        (args->frozen &&
         (fstatat(descriptor, "", &empty_status, AT_EMPTY_PATH) < 0 ||
          !same_node(&first_status, &empty_status))))
        goto out;
    duplicate = dup(descriptor);
    if (duplicate < 0 || fstat(duplicate, &descriptor_status) < 0 ||
        !same_node(&first_status, &descriptor_status) ||
        close(duplicate) != 0)
        goto out;
    duplicate = -1;
#ifdef F_DUPFD_CLOEXEC
    duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
#else
    duplicate = fcntl(descriptor, F_DUPFD, 3);
#endif
    if (duplicate < 0 || fstat(duplicate, &descriptor_status) < 0 ||
        !same_node(&first_status, &descriptor_status) ||
        close(duplicate) != 0)
        goto out;
    duplicate = -1;
    if (close(descriptor) != 0)
        goto out;
    descriptor = -1;

    descriptor = open(args->directory,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &descriptor_status) < 0 ||
        !same_node(&directory_status, &descriptor_status) ||
        (args->frozen &&
         (fstatat(descriptor, "", &empty_status, AT_EMPTY_PATH) < 0 ||
          !same_node(&directory_status, &empty_status))) ||
        close(descriptor) != 0)
        goto out;
    descriptor = -1;

    directory = opendir(args->directory);
    if (!directory)
        goto out;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "first.txt") == 0) {
            if (entry->d_ino != first_status.st_ino)
                goto out;
            found_first++;
        }
    }
    if (errno != 0 || found_first != 1)
        goto out;
    ok = 1;

out:
    if (duplicate >= 0)
        close(duplicate);
    if (descriptor >= 0)
        close(descriptor);
    if (directory && closedir(directory) != 0)
        ok = 0;
    return ok;
}

static int check_raw_regular_fd_reuse(const struct worker_args *args)
{
    char replacement_path[PATH_MAX];
    struct stat expected;
    struct stat actual;
    int source = -1;
    int target = -1;
    int ok = 0;

    if (snprintf(replacement_path, sizeof(replacement_path), "%s/reuse.txt",
                 args->scratch) < 0)
        return 0;
    source = open(replacement_path, O_RDONLY | O_CLOEXEC);
    target = open(args->file, O_RDONLY | O_CLOEXEC);
    if (source < 0 || target < 0 || source == target ||
        fstat(source, &expected) < 0 || syscall(SYS_close, target) != 0)
        goto out;
    if (syscall(SYS_dup3, source, target, O_CLOEXEC) != target ||
        fstat(target, &actual) < 0 || !same_node(&expected, &actual))
        goto out;
    ok = 1;

out:
    if (target >= 0)
        close(target);
    if (source >= 0)
        close(source);
    return ok;
}

static int check_close_range_independence(const struct worker_args *args)
{
#ifdef SYS_close_range
    struct stat expected;
    struct stat actual;
    int descriptor;
    long result;

    if (!args->frozen)
        return 1;
    if (stat(args->file, &expected) < 0 ||
        (descriptor = open(args->file, O_RDONLY | O_CLOEXEC)) < 0)
        return 0;
    result = syscall(SYS_close_range, (unsigned int)descriptor + 1,
                     ~0U, 0U);
    if (result < 0 && errno != ENOSYS) {
        close(descriptor);
        return 0;
    }
    if (fstat(descriptor, &actual) < 0 || !same_node(&expected, &actual)) {
        close(descriptor);
        return 0;
    }
    return close(descriptor) == 0;
#else
    (void)args;
    return 1;
#endif
}

static int check_readlink_contract(const struct worker_args *args)
{
    char first_path[PATH_MAX];
    char negative_path[PATH_MAX];
    char other_path[PATH_MAX];
    char target[PATH_MAX];
    struct stat status;
    ssize_t length;
    int descriptor = -1;
    int probe = -1;
    int ok = 0;

    if (snprintf(first_path, sizeof(first_path), "%s/first.txt",
                 args->directory) < 0 ||
        snprintf(negative_path, sizeof(negative_path), "%s/proc",
                 args->directory) < 0 ||
        snprintf(other_path, sizeof(other_path), "%s/other",
                 args->directory) < 0)
        return 0;
#define EXPECT_READLINK_ERROR(path_value, expected_errno) do {          \
        errno = 0;                                                       \
        if (readlink((path_value), target, sizeof(target)) != -1 ||     \
            errno != (expected_errno))                                  \
            goto out;                                                    \
    } while (0)
    EXPECT_READLINK_ERROR(first_path, EINVAL);
    EXPECT_READLINK_ERROR(args->directory, EINVAL);
    EXPECT_READLINK_ERROR(other_path, EINVAL);
    EXPECT_READLINK_ERROR(negative_path, ENOENT);
#undef EXPECT_READLINK_ERROR

    descriptor = open(args->directory,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0)
        goto out;
    errno = 0;
    if (readlinkat(descriptor, "first.txt", target, sizeof(target)) != -1 ||
        errno != EINVAL)
        goto out;
    errno = 0;
    if (readlinkat(descriptor, "proc", target, sizeof(target)) != -1 ||
        errno != ENOENT)
        goto out;
    if (args->frozen) {
        length = readlinkat(descriptor, "host-link", target,
                            sizeof(target) - 1);
        if (length < 0 || (size_t)length >= sizeof(target))
            goto out;
        target[length] = '\0';
        if (strcmp(target, "/dev/null") != 0)
            goto out;

        errno = 0;
        probe = openat(descriptor, "./first.txt", O_RDONLY | O_CLOEXEC);
        if (probe >= 0 || errno != EINVAL)
            goto out;
        errno = 0;
        if (fstatat(descriptor, "other/../first.txt", &status, 0) != -1 ||
            errno != EINVAL)
            goto out;
        errno = 0;
        if (faccessat(descriptor, "other//third.txt", F_OK, 0) != -1 ||
            errno != EINVAL)
            goto out;
    }
    ok = 1;

out:
    if (probe >= 0)
        close(probe);
    if (descriptor >= 0)
        close(descriptor);
    return ok;
}

static int check_opendir_contract(const struct worker_args *args)
{
    const char *names[] = { "proc", "second.txt" };
    const int errors[] = { ENOENT, ENOTDIR };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[PATH_MAX];
        int length = snprintf(path, sizeof(path), "%s/%s",
                              args->directory, names[i]);
        DIR *directory;

        if (length < 0 || (size_t)length >= sizeof(path))
            return 0;
        errno = 0;
        directory = opendir(path);
        if (directory) {
            closedir(directory);
            return 0;
        }
        if (errno != errors[i])
            return 0;
        errno = 0;
        int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (descriptor >= 0) {
            close(descriptor);
            return 0;
        }
        if (errno != errors[i])
            return 0;
    }
    /* An unrepresentable, existing node outside the selected data scope
     * must not invalidate the trace or become a false missing-file record. */
    errno = 0;
    DIR *special = opendir("/dev/null");
    if (special) {
        closedir(special);
        return 0;
    }
    if (errno != ENOTDIR)
        return 0;
    /* fopen's libc-internal open must not bypass captured directory identity. */
    FILE *stream = fopen(args->directory, "r");
    struct stat status;
    if (!stream)
        return 0;
    int valid = fstat(fileno(stream), &status) == 0 && S_ISDIR(status.st_mode);
    if (fclose(stream) != 0 || !valid)
        return 0;
    return 1;
}

static int check_directory_duplication(const struct worker_args *args)
{
    DIR *directory = NULL;
    int source = -1;
    int duplicate = -1;
    int target = -1;
    int ok = 0;

    directory = opendir(args->directory);
    if (!directory)
        goto out;
    source = dirfd(directory);
    duplicate = dup(source);
    if (source < 0 || duplicate < 0 ||
        !openat_has_byte(duplicate, "first.txt", '1') ||
        close(duplicate) != 0)
        goto out;
    duplicate = -1;

#ifdef F_DUPFD_CLOEXEC
    duplicate = fcntl(source, F_DUPFD_CLOEXEC, 3);
#else
    duplicate = fcntl(source, F_DUPFD, 3);
#endif
    if (duplicate < 0 || !openat_has_byte(duplicate, "second.txt", '2'))
        goto out;
#ifdef F_DUPFD_CLOEXEC
    if ((fcntl(duplicate, F_GETFD) & FD_CLOEXEC) == 0)
        goto out;
#endif
    target = duplicate;
    if (close(duplicate) != 0)
        goto out;
    duplicate = -1;

    if (dup3(source, target, O_CLOEXEC) != target ||
        !openat_has_byte(target, "first.txt", '1') ||
        close(target) != 0)
        goto out;
    target = -1;
    ok = 1;

out:
    if (duplicate >= 0)
        close(duplicate);
    if (target >= 0)
        close(target);
    if (directory && closedir(directory) != 0)
        ok = 0;
    return ok;
}

static int check_virtual_dirfd_replacement(const struct worker_args *args)
{
    char other_path[PATH_MAX];
    DIR *first_directory = NULL;
    DIR *other_directory = NULL;
    int first_fd;
    int other_fd;
    int probe = -1;
    int length;
    int ok = 0;

    length = snprintf(other_path, sizeof(other_path), "%s/other",
                      args->directory);
    if (length < 0 || (size_t)length >= sizeof(other_path))
        return 0;
    first_directory = opendir(args->directory);
    other_directory = opendir(other_path);
    if (!first_directory || !other_directory)
        goto out;
    first_fd = dirfd(first_directory);
    other_fd = dirfd(other_directory);
    if (first_fd < 0 || other_fd < 0 || first_fd == other_fd ||
        dup2(other_fd, first_fd) != first_fd)
        goto out;

    errno = 0;
    probe = openat(first_fd, "first.txt", O_RDONLY | O_CLOEXEC);
    if (probe >= 0 || errno != ENOENT ||
        !openat_has_byte(first_fd, "third.txt", '3'))
        goto out;
    ok = 1;

out:
    if (probe >= 0)
        close(probe);
    if (first_directory && closedir(first_directory) != 0)
        ok = 0;
    if (other_directory && closedir(other_directory) != 0)
        ok = 0;
    return ok;
}

static int check_raw_virtual_dirfd_replacement(
    const struct worker_args *args)
{
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    DIR *first_directory = NULL;
    DIR *second_directory = NULL;
    int first_fd;
    int second_fd;
    int probe = -1;
    int ok = 0;

    if (snprintf(first_path, sizeof(first_path), "%s/other",
                 args->directory) < 0 ||
        snprintf(second_path, sizeof(second_path), "%s/another",
                 args->directory) < 0)
        return 0;
    first_directory = opendir(first_path);
    second_directory = opendir(second_path);
    if (!first_directory || !second_directory)
        goto out;
    first_fd = dirfd(first_directory);
    second_fd = dirfd(second_directory);
    if (first_fd < 0 || second_fd < 0 || first_fd == second_fd ||
        syscall(SYS_dup3, second_fd, first_fd, 0) != first_fd)
        goto out;

    errno = 0;
    probe = openat(first_fd, "third.txt", O_RDONLY | O_CLOEXEC);
    if (probe >= 0 || errno != ENOENT)
        goto out;
    ok = 1;

out:
    if (probe >= 0)
        close(probe);
    if (first_directory && closedir(first_directory) != 0)
        ok = 0;
    if (second_directory && closedir(second_directory) != 0)
        ok = 0;
    return ok;
}

static int check_invalid_virtual_seek(const struct worker_args *args)
{
    DIR *directory;
    struct dirent *entry;
    int descriptor;
    int first = 0;
    int second = 0;
    int other = 0;
    int another = 0;
    int host_only = 0;
    int host_link = 0;
    int ok = 0;

    if (!args->frozen)
        return 1;
    directory = opendir(args->directory);
    if (!directory)
        return 0;
    descriptor = dirfd(directory);
    errno = 0;
    seekdir(directory, 1);
    if (descriptor < 0 || errno != EINVAL) {
        fprintf(stderr, "invalid seek: fd=%d errno=%d\n", descriptor,
                errno);
        goto out;
    }

    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "first.txt") == 0)
            first++;
        else if (strcmp(entry->d_name, "second.txt") == 0)
            second++;
        else if (strcmp(entry->d_name, "other") == 0)
            other++;
        else if (strcmp(entry->d_name, "another") == 0)
            another++;
        else if (strcmp(entry->d_name, "host-only") == 0)
            host_only++;
        else if (strcmp(entry->d_name, "host-link") == 0)
            host_link++;
        else if (strcmp(entry->d_name, ".") != 0 &&
                 strcmp(entry->d_name, "..") != 0)
            goto out;
    }
    if (errno == 0 && first == 1 && second == 1 && other == 1 &&
        another == 1 && host_only == 0 && host_link == 0)
        ok = 1;
    else
        fprintf(stderr,
                "invalid-seek listing: errno=%d first=%d second=%d "
                "other=%d another=%d host-only=%d host-link=%d\n",
                errno, first, second, other, another, host_only,
                host_link);

out:
    if (closedir(directory) != 0)
        ok = 0;
    return ok;
}

int main(int argc, char **argv)
{
    enum { THREAD_COUNT = 8 };
    pthread_t threads[THREAD_COUNT];
    atomic_int failed = 0;
    struct worker_args args;
    char first_path[PATH_MAX];
    char fourth_path[PATH_MAX];
    char negative_path[PATH_MAX];
    char byte;
    int file;
    int opened = 0;

    if (argc != 5)
        return 2;
    args.directory = argv[1];
    args.file = argv[2];
    args.scratch = argv[3];
    args.failed = &failed;
    args.frozen = strcmp(argv[4], "frozen") == 0;
    if (snprintf(first_path, sizeof(first_path), "%s/first.txt",
                 args.directory) < 0 ||
        strlen(first_path) + 1 >= sizeof(first_path))
        return 3;
    if (snprintf(negative_path, sizeof(negative_path), "%s/proc",
                 args.directory) < 0 ||
        strlen(negative_path) + 1 >= sizeof(negative_path))
        return 3;
    if (snprintf(fourth_path, sizeof(fourth_path), "%s/another/fourth.txt",
                 args.directory) < 0 ||
        strlen(fourth_path) + 1 >= sizeof(fourth_path))
        return 3;
    file = open(first_path, O_RDONLY | O_CLOEXEC);
    if (file < 0 || read(file, &byte, 1) != 1 || byte != '1' ||
        close(file) != 0)
        return 3;
    file = open(args.file, O_RDONLY | O_CLOEXEC);
    if (file < 0 || read(file, &byte, 1) != 1 || byte != '2' ||
        close(file) != 0)
        return 3;
    file = open(fourth_path, O_RDONLY | O_CLOEXEC);
    if (file < 0 || read(file, &byte, 1) != 1 || byte != '4' ||
        close(file) != 0)
        return 3;
    errno = 0;
    file = open(negative_path, O_RDONLY | O_CLOEXEC);
    if (file >= 0 || errno != ENOENT) {
        if (file >= 0)
            close(file);
        return 3;
    }
    for (int index = 0; index < THREAD_COUNT; index++) {
        if (pthread_create(&threads[index], NULL, worker, &args) != 0) {
            atomic_store_explicit(&failed, 1, memory_order_relaxed);
            break;
        }
        opened++;
    }
    for (int index = 0; index < opened; index++) {
        if (pthread_join(threads[index], NULL) != 0)
            atomic_store_explicit(&failed, 1, memory_order_relaxed);
    }
    if (atomic_load_explicit(&failed, memory_order_relaxed)) {
        fputs("concurrent directory check failed\n", stderr);
        return 3;
    }
#define REQUIRE_DIRECTORY_CHECK(expression) do {                         \
        if (!(expression)) {                                             \
            fputs(#expression " failed\n", stderr);                    \
            return 3;                                                    \
        }                                                                \
    } while (0)
    REQUIRE_DIRECTORY_CHECK(check_real_directory(&args));
    REQUIRE_DIRECTORY_CHECK(check_forked_handle(&args));
    REQUIRE_DIRECTORY_CHECK(check_replaced_synthetic_dirfd(&args));
    REQUIRE_DIRECTORY_CHECK(check_directory_descriptor_flags(&args));
    REQUIRE_DIRECTORY_CHECK(check_directory_duplication(&args));
    REQUIRE_DIRECTORY_CHECK(check_identity_coherence(&args));
    REQUIRE_DIRECTORY_CHECK(check_raw_regular_fd_reuse(&args));
    REQUIRE_DIRECTORY_CHECK(check_close_range_independence(&args));
    REQUIRE_DIRECTORY_CHECK(check_readlink_contract(&args));
    REQUIRE_DIRECTORY_CHECK(check_opendir_contract(&args));
    REQUIRE_DIRECTORY_CHECK(check_virtual_dirfd_replacement(&args));
    REQUIRE_DIRECTORY_CHECK(check_raw_virtual_dirfd_replacement(&args));
    REQUIRE_DIRECTORY_CHECK(check_invalid_virtual_seek(&args));
#undef REQUIRE_DIRECTORY_CHECK
    puts("vfs-dir-registry-ok");
    return 0;
}
