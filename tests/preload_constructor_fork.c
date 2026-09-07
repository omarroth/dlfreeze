#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *atfork_library;
static int atfork_child_status = 1;

static void atfork_child(void)
{
    int (*value)(void);
    void *handle = dlopen(atfork_library, RTLD_NOW | RTLD_LOCAL);

    if (!handle)
        return;
    value = (int (*)(void))dlsym(handle, "trace_process_value");
    if (value && value() == 22)
        atfork_child_status = 0;
}

static int read_one(const char *path)
{
    char byte;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int ok = fd >= 0 && read(fd, &byte, 1) == 1;

    if (fd >= 0)
        (void)close(fd);
    return ok;
}

int main(int argc, char **argv)
{
    pid_t (*child_pid)(void);
    int (*is_child)(void);
    void *handle;
    pid_t child;
    int status;

    if (argc != 4)
        return 2;
    atfork_library = argv[2];
    if (pthread_atfork(NULL, NULL, atfork_child) != 0)
        return 3;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 4;
    child_pid = (pid_t (*)(void))dlsym(
        handle, "preload_constructor_child_pid");
    is_child = (int (*)(void))dlsym(
        handle, "preload_constructor_is_child");
    if (!child_pid || !is_child)
        return 5;

    if (is_child()) {
        int child_ok = child_pid() == 0 && atfork_child_status == 0 &&
                       read_one(argv[3]);

        _exit(child_ok ? 0 : 6);
    }
    child = child_pid();
    if (child <= 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 7;
    puts("constructor-fork-ok");
    return 0;
}
