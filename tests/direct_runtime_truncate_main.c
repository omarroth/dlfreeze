#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int dlfrz_runtime_truncate_ready_fd = -1;
int dlfrz_runtime_truncate_release_fd = -1;

static int transfer_byte(int fd, char *byte, int writing)
{
    ssize_t result;

    do {
        result = writing ? write(fd, byte, 1) : read(fd, byte, 1);
    } while (result < 0 && errno == EINTR);
    return result == 1 ? 0 : -1;
}

static void child_load(const char *path, int ready_fd, int release_fd)
{
    void *handle;
    int (*value)(void);

    dlfrz_runtime_truncate_ready_fd = ready_fd;
    dlfrz_runtime_truncate_release_fd = release_fd;
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        _exit(20);
    value = (int (*)(void))dlsym(handle, "dlfrz_runtime_truncate_value");
    if (!value || value() != 73)
        _exit(21);
    _exit(0);
}

int main(int argc, char **argv)
{
    int ready_pipe[2];
    int release_pipe[2];
    int source_fd = -1;
    int status = 0;
    int release_status;
    pid_t child;
    char byte;

    if (argc != 2 || pipe(ready_pipe) < 0 || pipe(release_pipe) < 0)
        return 2;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 3;
    alarm(15);
    child = fork();
    if (child < 0)
        return 4;
    if (child == 0) {
        close(ready_pipe[0]);
        close(release_pipe[1]);
        child_load(argv[1], ready_pipe[1], release_pipe[0]);
    }

    close(ready_pipe[1]);
    close(release_pipe[0]);
    if (transfer_byte(ready_pipe[0], &byte, 0) == 0)
        source_fd = open(argv[1], O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (source_fd >= 0)
        close(source_fd);
    byte = 'G';
    release_status = transfer_byte(release_pipe[1], &byte, 1);
    close(ready_pipe[0]);
    close(release_pipe[1]);
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return 5;
    }
    alarm(0);

    if (source_fd < 0 || release_status < 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFSIGNALED(status))
            fprintf(stderr, "late DSO child signal=%d\n", WTERMSIG(status));
        else if (WIFEXITED(status))
            fprintf(stderr, "late DSO child exit=%d\n", WEXITSTATUS(status));
        return 1;
    }
    puts("runtime-truncate-snapshot-ok");
    return 0;
}
