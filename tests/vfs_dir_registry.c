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
#include <sys/wait.h>
#include <unistd.h>

struct worker_args {
    const char *directory;
    const char *file;
    const char *scratch;
    atomic_int *failed;
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
    rewinddir(directory);
    parent_ok = directory_has_files(directory) && closedir(directory) == 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 0;
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
    /* Every synthetic descriptor uses / as its kernel placeholder.  Replace
     * it with an independently opened description of that exact same inode;
     * stat identity alone cannot detect this substitution. */
    real_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (virtual_fd < 0 || real_fd < 0 || real_fd == virtual_fd)
        goto out;
    if (dup2(real_fd, virtual_fd) != virtual_fd)
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

int main(int argc, char **argv)
{
    enum { THREAD_COUNT = 8 };
    pthread_t threads[THREAD_COUNT];
    atomic_int failed = 0;
    struct worker_args args;
    char first_path[PATH_MAX];
    char byte;
    int file;
    int opened = 0;

    if (argc != 4)
        return 2;
    args.directory = argv[1];
    args.file = argv[2];
    args.scratch = argv[3];
    args.failed = &failed;
    if (snprintf(first_path, sizeof(first_path), "%s/first.txt",
                 args.directory) < 0 ||
        strlen(first_path) + 1 >= sizeof(first_path))
        return 3;
    file = open(first_path, O_RDONLY | O_CLOEXEC);
    if (file < 0 || read(file, &byte, 1) != 1 || byte != '1' ||
        close(file) != 0)
        return 3;
    file = open(args.file, O_RDONLY | O_CLOEXEC);
    if (file < 0 || read(file, &byte, 1) != 1 || byte != '2' ||
        close(file) != 0)
        return 3;
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
    if (atomic_load_explicit(&failed, memory_order_relaxed) ||
        !check_real_directory(&args) || !check_forked_handle(&args) ||
        !check_replaced_synthetic_dirfd(&args) ||
        !check_directory_descriptor_flags(&args) ||
        !check_directory_duplication(&args) ||
        !check_virtual_dirfd_replacement(&args))
        return 3;
    puts("vfs-dir-registry-ok");
    return 0;
}
