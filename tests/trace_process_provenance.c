#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* execveat is a Linux syscall but not every libc exposes a public wrapper.
 * A weak reference lets the same fixture exercise an interposed/native libc
 * entry point when one exists without making that optional API a link-time
 * requirement. */
#if defined(AT_FDCWD)
extern int execveat(int, const char *, char *const[], char *const[], int)
    __attribute__((weak));
#endif

static int load_value(const char *path, int expected)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    int (*value)(void);

    if (!handle)
        return 0;
    value = (int (*)(void))dlsym(handle, "trace_process_value");
    return value && value() == expected;
}

static int read_file(const char *path)
{
    char byte;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int ok = fd >= 0 && read(fd, &byte, 1) == 1;

    if (fd >= 0)
        close(fd);
    return ok;
}

static int leaf(const char *library, const char *input)
{
    return load_value(library, 22) && read_file(input) ? 0 : 1;
}

int main(int argc, char **argv)
{
    pid_t child;
    int status;

    if (argc >= 2 && strcmp(argv[1], "leaf") == 0)
        return argc == 4 ? leaf(argv[2], argv[3]) : 2;
    if (argc >= 2 && strcmp(argv[1], "low-fds") == 0) {
        int descriptors[3];

        if (argc != 2)
            return 2;
        for (int index = 0; index < 3; index++)
            descriptors[index] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        return descriptors[0] == STDIN_FILENO &&
               descriptors[1] == STDOUT_FILENO &&
               descriptors[2] == STDERR_FILENO ? 0 : 6;
    }
    if (argc >= 2 && strcmp(argv[1], "first-fd") == 0) {
        int descriptor;

        if (argc != 2)
            return 2;
        descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
        return descriptor == STDERR_FILENO + 1 ? 0 : 6;
    }
    if (argc >= 2 && strcmp(argv[1], "exec-clean") == 0) {
        if (argc != 5)
            return 2;
        char *const child_argv[] = {
            argv[2], (char *)"leaf", argv[3], argv[4], NULL
        };
        char *const child_env[] = {(char *)"PATH=/usr/bin:/bin", NULL};

        execve(argv[2], child_argv, child_env);
        return 3;
    }
    if (argc >= 2 && strcmp(argv[1], "exec-clean-child") == 0) {
        if (argc != 3)
            return 2;
        char *const child_argv[] = {argv[2], NULL};
        char *const child_env[] = {NULL};

        execve(argv[2], child_argv, child_env);
        return 3;
    }
    if (argc >= 2 && strcmp(argv[1], "failed-exec") == 0) {
        extern char **environ;
        char *const child_argv[] = {(char *)"does-not-exist", NULL};

        if (argc != 3)
            return 2;
        errno = 0;
        if (execve("/dlfreeze-no-such-executable", child_argv, environ) != -1 ||
            errno != ENOENT)
            return 3;
        return load_value(argv[2], 11) ? 0 : 4;
    }
    if (argc >= 2 && strcmp(argv[1], "failed-exec-all") == 0) {
        extern char **environ;
        char *const child_argv[] = {(char *)"does-not-exist", NULL};
        char *const empty_env[] = {NULL};
        int executable = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (argc != 3 || executable < 0)
            return 2;
#define EXPECT_ENOENT(call)                                                   \
        do {                                                                  \
            errno = 0;                                                        \
            if ((call) != -1 || errno != ENOENT)                              \
                return 3;                                                     \
        } while (0)
        EXPECT_ENOENT(execve("/dlfreeze-no-such-executable",
                             child_argv, environ));
        EXPECT_ENOENT(execv("/dlfreeze-no-such-executable", child_argv));
        EXPECT_ENOENT(execvp("dlfreeze-no-such-executable", child_argv));
        EXPECT_ENOENT(execvpe("dlfreeze-no-such-executable", child_argv,
                              empty_env));
        EXPECT_ENOENT(execl("/dlfreeze-no-such-executable",
                            "does-not-exist", (char *)NULL));
        EXPECT_ENOENT(execlp("dlfreeze-no-such-executable",
                             "does-not-exist", (char *)NULL));
        EXPECT_ENOENT(execle("/dlfreeze-no-such-executable",
                             "does-not-exist", (char *)NULL, empty_env));
        errno = 0;
        if (fexecve(executable, child_argv, environ) != -1 ||
            (errno != EACCES && errno != ENOEXEC))
            return 3;
#ifdef AT_FDCWD
        if (execveat)
            EXPECT_ENOENT(execveat(AT_FDCWD,
                                   "/dlfreeze-no-such-executable",
                                   child_argv, environ, 0));
#endif
#undef EXPECT_ENOENT
        close(executable);
        return load_value(argv[2], 11) ? 0 : 4;
    }
    if (argc >= 2 && strcmp(argv[1], "fork") == 0) {
        if (argc != 6)
            return 2;
        child = fork();
        if (child < 0)
            return 3;
        if (child == 0)
            _exit(load_value(argv[3], 22) && read_file(argv[5]) ? 0 : 4);
        if (!load_value(argv[2], 11) || !read_file(argv[4]) ||
            waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            return 5;
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "fork-exec") == 0) {
        if (argc != 7)
            return 2;
        char *const child_argv[] = {
            argv[2], (char *)"leaf", argv[3], argv[4], NULL
        };

        child = fork();
        if (child < 0)
            return 3;
        if (child == 0) {
            execv(argv[2], child_argv);
            _exit(4);
        }
        if (!load_value(argv[5], 11) || !read_file(argv[6]) ||
            waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            return 5;
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "exec") == 0) {
        if (argc != 5)
            return 2;
        char *const child_argv[] = {
            argv[2], (char *)"leaf", argv[3], argv[4], NULL
        };

        execv(argv[2], child_argv);
        return 3;
    }
    if (argc >= 2 && strcmp(argv[1], "replace") == 0) {
        if (argc != 4 || !load_value(argv[2], 11))
            return 2;
        return rename(argv[3], argv[2]) == 0 ? 0 : 3;
    }
    if (argc >= 2 && strcmp(argv[1], "mapped-replace") == 0) {
        if (argc != 5 || setenv("DLFREEZE_TEST_REPLACE_DESTINATION",
                                argv[3], 1) != 0 ||
            setenv("DLFREEZE_TEST_REPLACEMENT", argv[4], 1) != 0)
            return 2;
        return load_value(argv[2], 11) ? 0 : 3;
    }
    if (argc >= 2 && strcmp(argv[1], "daemon") == 0) {
        child = fork();
        if (child < 0)
            return 2;
        if (child == 0) {
            sleep(2);
            _exit(0);
        }
        return 0;
    }
    return 2;
}
