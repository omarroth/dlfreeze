#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct worker_args {
    const char *directory;
    const char *file;
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

static int check_real_directory(void)
{
    DIR *directory = opendir("/");
    struct dirent *entry;
    long position;
    int descriptor;

    if (!directory)
        return 0;
    descriptor = dirfd(directory);
    entry = readdir(directory);
    position = telldir(directory);
    if (descriptor < 0 || !entry || position < 0) {
        closedir(directory);
        return 0;
    }
    seekdir(directory, position);
    rewinddir(directory);
    entry = readdir(directory);
    return entry != NULL && closedir(directory) == 0;
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

    if (argc != 3)
        return 2;
    args.directory = argv[1];
    args.file = argv[2];
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
        !check_real_directory() || !check_forked_handle(&args))
        return 3;
    puts("vfs-dir-registry-ok");
    return 0;
}
