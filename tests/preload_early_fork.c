#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(DLFREEZE_EARLY_FORK_PRELOAD)

static int early_process_status = 1;

static int run_fork_child(const char *library, const char *path)
{
    int (*value)(void);
    void *handle;
    char byte;
    int fd;

    handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 2;
    value = (int (*)(void))dlsym(handle, "trace_process_value");
    if (!value || value() != 22)
        return 3;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 4;
    if (read(fd, &byte, 1) != 1) {
        close(fd);
        return 5;
    }
    close(fd);
    return 0;
}

__attribute__((constructor)) static void run_before_trace_constructor(void)
{
    const char *mode = getenv("DLFREEZE_EARLY_PROCESS_MODE");
    const char *library = getenv("DLFREEZE_EARLY_PROCESS_LIBRARY");
    const char *path = getenv("DLFREEZE_EARLY_PROCESS_FILE");
    const char *child_path = getenv("DLFREEZE_EARLY_PROCESS_CHILD");
    pid_t child;
    int status;

    if (!mode)
        return;
    if (strcmp(mode, "fork") == 0) {
        if (!library || !path)
            return;
        child = fork();
        if (child == 0)
            _exit(run_fork_child(library, path));
    } else if (strcmp(mode, "vfork") == 0) {
        char *const child_argv[] = {(char *)child_path, NULL};
        if (!child_path)
            return;
        child = vfork();
        if (child == 0) {
            /* Exercise the helper's pre-initialization execvp forwarder in a
             * vfork child.  A slash keeps lookup deterministic while still
             * taking the PATH-search API wrapper. */
            execvp(child_path, child_argv);
            _exit(6);
        }
    } else {
        return;
    }
    if (child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0)
        early_process_status = 0;
}

int preload_early_process_status(void)
{
    return early_process_status;
}

#else

int main(void)
{
    int (*status)(void) =
        (int (*)(void))dlsym(RTLD_DEFAULT,
                             "preload_early_process_status");

    return status && status() == 0 ? 0 : 1;
}

#endif
