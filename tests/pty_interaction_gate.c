#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT_MS 15000
#define SIGNAL_SETTLE_MS 250
#define MAX_TRANSCRIPT (1024U * 1024U)

static volatile sig_atomic_t signal_count;
static int signal_pipe_write = -1;

static void handle_sigint(int signal_number)
{
    int saved_errno = errno;
    char marker = 'I';

    (void)signal_number;
    if (signal_count < 100)
        signal_count++;
    if (signal_pipe_write >= 0)
        (void)write(signal_pipe_write, &marker, sizeof(marker));
    errno = saved_errno;
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int write_all(int fd, const void *buffer, size_t size)
{
    const unsigned char *cursor = buffer;

    while (size != 0) {
        ssize_t written = write(fd, cursor, size);
        if (written > 0) {
            cursor += written;
            size -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd output = { .fd = fd, .events = POLLOUT };
            if (poll(&output, 1, 1000) > 0)
                continue;
        }
        return -1;
    }
    return 0;
}

static int target_read_line(char *buffer, size_t capacity)
{
    size_t used = 0;

    while (used + 1 < capacity) {
        char byte;
        ssize_t length = read(STDIN_FILENO, &byte, sizeof(byte));

        if (length == 1) {
            buffer[used++] = byte;
            if (byte == '\n')
                break;
            continue;
        }
        if (length < 0 && errno == EINTR)
            continue;
        return -1;
    }
    buffer[used] = '\0';
    return used != 0 && buffer[used - 1] == '\n' ? 0 : -1;
}

static int wait_for_first_sigint(int fd, int timeout_ms)
{
    int64_t deadline = monotonic_milliseconds() + timeout_ms;

    while (signal_count == 0) {
        int64_t now = monotonic_milliseconds();
        int remaining;
        struct pollfd input = { .fd = fd, .events = POLLIN };

        if (now < 0 || now >= deadline)
            return -1;
        remaining = (int)(deadline - now);
        if (poll(&input, 1, remaining) < 0 && errno != EINTR)
            return -1;
        if (input.revents & POLLIN) {
            char markers[32];
            while (read(fd, markers, sizeof(markers)) > 0) {}
        }
    }
    return 0;
}

static void settle_sigint_delivery(int fd)
{
    int64_t deadline = monotonic_milliseconds() + SIGNAL_SETTLE_MS;

    for (;;) {
        int64_t now = monotonic_milliseconds();
        int remaining;
        struct pollfd input = { .fd = fd, .events = POLLIN };

        if (now < 0 || now >= deadline)
            return;
        remaining = (int)(deadline - now);
        if (poll(&input, 1, remaining) < 0 && errno != EINTR)
            return;
        if (input.revents & POLLIN) {
            char markers[32];
            while (read(fd, markers, sizeof(markers)) > 0) {}
        }
    }
}

static int run_target(void)
{
    static const char expected_line[] = "dlfreeze-pty-line\n";
    static const char expected_resume[] = "dlfreeze-pty-resume\n";
    struct termios terminal;
    struct sigaction action;
    char line[128];
    int signal_pipe[2] = { -1, -1 };
    int flags;

    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) ||
        !isatty(STDERR_FILENO)) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR not-a-tty\n");
        return 10;
    }
    if (tcgetpgrp(STDIN_FILENO) != getpgrp()) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR not-foreground\n");
        return 11;
    }
    if (tcgetattr(STDIN_FILENO, &terminal) < 0 ||
        !(terminal.c_lflag & ICANON) || !(terminal.c_lflag & ISIG)) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR terminal-mode\n");
        return 12;
    }

    if (write_all(STDOUT_FILENO, "PTY_GATE_LINE_READY\n", 20) < 0 ||
        target_read_line(line, sizeof(line)) < 0 ||
        strcmp(line, expected_line) != 0) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR line-input\n");
        return 13;
    }
    if (write_all(STDOUT_FILENO, "PTY_GATE_LINE_OK\n", 17) < 0)
        return 14;

    if (pipe(signal_pipe) < 0)
        return 15;
    flags = fcntl(signal_pipe[0], F_GETFL);
    if (flags < 0 || fcntl(signal_pipe[0], F_SETFL, flags | O_NONBLOCK) < 0)
        return 16;
    flags = fcntl(signal_pipe[1], F_GETFL);
    if (flags < 0 || fcntl(signal_pipe[1], F_SETFL, flags | O_NONBLOCK) < 0)
        return 17;
    signal_pipe_write = signal_pipe[1];

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_sigint;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) < 0)
        return 18;

    if (write_all(STDOUT_FILENO, "PTY_GATE_INT_READY\n", 19) < 0)
        return 19;
    if (wait_for_first_sigint(signal_pipe[0], 5000) < 0) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR no-sigint\n");
        return 20;
    }
    settle_sigint_delivery(signal_pipe[0]);
    signal_pipe_write = -1;
    close(signal_pipe[0]);
    close(signal_pipe[1]);

    if (signal_count != 1) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR sigint-count=%d\n",
                (int)signal_count);
        return 21;
    }
    if (write_all(STDOUT_FILENO, "PTY_GATE_STOP_READY\n", 20) < 0 ||
        target_read_line(line, sizeof(line)) < 0 ||
        strcmp(line, expected_resume) != 0) {
        dprintf(STDERR_FILENO, "PTY_GATE_ERROR stop-resume-input\n");
        return 22;
    }
    if (write_all(STDOUT_FILENO, "PTY_GATE_STOP_OK\n", 17) < 0 ||
        write_all(STDOUT_FILENO, "PTY_GATE_OK\n", 12) < 0)
        return 23;
    return 0;
}

static int parse_timeout(void)
{
    const char *value = getenv("PTY_GATE_TIMEOUT_MS");
    char *end = NULL;
    long timeout;

    if (!value || !value[0])
        return DEFAULT_TIMEOUT_MS;
    errno = 0;
    timeout = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || timeout < 1000 ||
        timeout > 120000)
        return DEFAULT_TIMEOUT_MS;
    return (int)timeout;
}

static void terminate_child(pid_t child, int master)
{
    close(master);
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
}

static int configure_slave(int slave)
{
    struct termios terminal;

    if (tcgetattr(slave, &terminal) < 0)
        return -1;
    terminal.c_iflag |= ICRNL;
    terminal.c_oflag |= OPOST | ONLCR;
    terminal.c_lflag |= ICANON | ISIG;
    terminal.c_lflag &= ~(ECHO | ECHONL);
    terminal.c_cc[VINTR] = 3;
    terminal.c_cc[VSUSP] = 26;
    terminal.c_cc[VEOF] = 4;
    terminal.c_cc[VMIN] = 1;
    terminal.c_cc[VTIME] = 0;
    return tcsetattr(slave, TCSANOW, &terminal);
}

static int spawn_pty_child(char **command, int *master_out, pid_t *child_out)
{
    char slave_name[256];
    char start = 'S';
    int start_pipe[2] = { -1, -1 };
    int master;
    int slave;
    pid_t child;

    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 ||
        ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        if (master >= 0)
            close(master);
        return -1;
    }
    slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0 || configure_slave(slave) < 0) {
        if (slave >= 0)
            close(slave);
        close(master);
        return -1;
    }
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0 ||
        pipe(start_pipe) < 0) {
        close(slave);
        close(master);
        return -1;
    }

    child = fork();
    if (child < 0) {
        close(start_pipe[0]);
        close(start_pipe[1]);
        close(slave);
        close(master);
        return -1;
    }
    if (child == 0) {
        struct sigaction default_action;

        close(start_pipe[1]);
        if (setpgid(0, 0) < 0 ||
            read(start_pipe[0], &start, sizeof(start)) != sizeof(start) ||
            dup2(slave, STDIN_FILENO) < 0 ||
            dup2(slave, STDOUT_FILENO) < 0 ||
            dup2(slave, STDERR_FILENO) < 0)
            _exit(126);
        close(start_pipe[0]);
        if (slave > STDERR_FILENO)
            close(slave);
        close(master);
        memset(&default_action, 0, sizeof(default_action));
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        (void)sigaction(SIGHUP, &default_action, NULL);
        execvp(command[0], command);
        dprintf(STDERR_FILENO, "PTY_GATE_DRIVER exec failed: %s\n",
                strerror(errno));
        _exit(127);
    }

    close(start_pipe[0]);
    if ((setpgid(child, child) < 0 && errno != EACCES) ||
        tcsetpgrp(slave, child) < 0 ||
        write_all(start_pipe[1], &start, sizeof(start)) < 0) {
        close(start_pipe[1]);
        close(slave);
        close(master);
        (void)kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        return -1;
    }
    close(start_pipe[1]);
    close(slave);
    *master_out = master;
    *child_out = child;
    return 0;
}

static int run_driver(char **command);

static int run_driver_isolated(char **command)
{
    int status;
    pid_t worker = fork();

    if (worker < 0) {
        fprintf(stderr, "PTY_GATE_DRIVER could not fork controller: %s\n",
                strerror(errno));
        return 1;
    }
    if (worker == 0) {
        (void)signal(SIGHUP, SIG_IGN);
        _exit(run_driver(command));
    }
    while (waitpid(worker, &status, 0) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "PTY_GATE_DRIVER controller wait failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        fprintf(stderr, "PTY_GATE_DRIVER controller killed by signal %d\n",
                WTERMSIG(status));
    return 1;
}

static int run_driver(char **command)
{
    static const char line_ready[] = "PTY_GATE_LINE_READY";
    static const char line_ok[] = "PTY_GATE_LINE_OK";
    static const char int_ready[] = "PTY_GATE_INT_READY";
    static const char stop_ready[] = "PTY_GATE_STOP_READY";
    static const char stop_ok[] = "PTY_GATE_STOP_OK";
    static const char final_ok[] = "PTY_GATE_OK";
    static const char input_line[] = "dlfreeze-pty-line\n";
    static const char resume_line[] = "dlfreeze-pty-resume\n";
    char *transcript;
    size_t used = 0;
    int master = -1;
    int timeout = parse_timeout();
    int state = 0;
    int status = 0;
    int child_done = 0;
    int64_t deadline;
    pid_t child;

    transcript = calloc(MAX_TRANSCRIPT + 1, 1);
    if (!transcript) {
        fprintf(stderr, "PTY_GATE_DRIVER allocation failed\n");
        return 1;
    }
    if (spawn_pty_child(command, &master, &child) < 0) {
        fprintf(stderr, "PTY_GATE_DRIVER could not create controlling PTY: %s\n",
                strerror(errno));
        free(transcript);
        return 1;
    }
    deadline = monotonic_milliseconds() + timeout;

    while (!child_done) {
        struct pollfd input = { .fd = master, .events = POLLIN | POLLHUP };
        int64_t now = monotonic_milliseconds();
        int wait_ms;
        pid_t waited;

        if (now < 0 || now >= deadline) {
            fprintf(stderr,
                    "PTY_GATE_DRIVER timeout (possible background-terminal stop)\n");
            terminate_child(child, master);
            free(transcript);
            return 1;
        }
        wait_ms = (int)(deadline - now);
        if (wait_ms > 100)
            wait_ms = 100;
        if (poll(&input, 1, wait_ms) < 0 && errno != EINTR) {
            fprintf(stderr, "PTY_GATE_DRIVER poll failed: %s\n",
                    strerror(errno));
            terminate_child(child, master);
            free(transcript);
            return 1;
        }
        if (input.revents & (POLLIN | POLLHUP)) {
            char buffer[4096];
            ssize_t length;

            do {
                length = read(master, buffer, sizeof(buffer));
            } while (length < 0 && errno == EINTR);
            if (length > 0) {
                (void)write_all(STDOUT_FILENO, buffer, (size_t)length);
                if (used + (size_t)length > MAX_TRANSCRIPT) {
                    fprintf(stderr, "PTY_GATE_DRIVER transcript limit exceeded\n");
                    terminate_child(child, master);
                    free(transcript);
                    return 1;
                }
                memcpy(transcript + used, buffer, (size_t)length);
                used += (size_t)length;
                transcript[used] = '\0';
            }
        }

        for (;;) {
            if (state == 0 && strstr(transcript, line_ready)) {
                if (write_all(master, input_line, sizeof(input_line) - 1) < 0)
                    state = -1;
                else
                    state = 1;
                continue;
            }
            if (state == 1 && strstr(transcript, line_ok)) {
                state = 2;
                continue;
            }
            if (state == 2 && strstr(transcript, int_ready)) {
                const unsigned char interrupt = 3;
                if (write_all(master, &interrupt, sizeof(interrupt)) < 0)
                    state = -1;
                else
                    state = 3;
                continue;
            }
            if (state == 3 && strstr(transcript, stop_ready)) {
                const unsigned char suspend = 26;
                if (write_all(master, &suspend, sizeof(suspend)) < 0)
                    state = -1;
                else
                    state = 4;
                continue;
            }
            if (state == 5 && strstr(transcript, stop_ok)) {
                state = 6;
                continue;
            }
            if (state == 6 && strstr(transcript, final_ok)) {
                state = 7;
                continue;
            }
            break;
        }
        if (state < 0) {
            fprintf(stderr, "PTY_GATE_DRIVER could not write PTY input\n");
            terminate_child(child, master);
            free(transcript);
            return 1;
        }

        waited = waitpid(child, &status, WNOHANG | WUNTRACED);
        if (waited == child) {
            if (WIFSTOPPED(status)) {
                if (state != 4 ||
                    (WSTOPSIG(status) != SIGTSTP &&
                     WSTOPSIG(status) != SIGSTOP)) {
                    fprintf(stderr,
                            "PTY_GATE_DRIVER unexpected stop signal %d in state %d\n",
                            WSTOPSIG(status), state);
                    terminate_child(child, master);
                    free(transcript);
                    return 1;
                }
                if (kill(-child, SIGCONT) < 0 ||
                    write_all(master, resume_line,
                              sizeof(resume_line) - 1) < 0) {
                    fprintf(stderr,
                            "PTY_GATE_DRIVER could not resume command group\n");
                    terminate_child(child, master);
                    free(transcript);
                    return 1;
                }
                state = 5;
                continue;
            }
            child_done = 1;
        } else if (waited < 0 && errno != EINTR) {
            fprintf(stderr, "PTY_GATE_DRIVER waitpid failed: %s\n",
                    strerror(errno));
            terminate_child(child, master);
            free(transcript);
            return 1;
        }
    }

    close(master);
    free(transcript);
    if (state != 7) {
        fprintf(stderr, "PTY_GATE_DRIVER protocol incomplete (state=%d)\n",
                state);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFEXITED(status))
            fprintf(stderr, "PTY_GATE_DRIVER command exited %d\n",
                    WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            fprintf(stderr, "PTY_GATE_DRIVER command killed by signal %d\n",
                    WTERMSIG(status));
        return 1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --target\n"
            "       %s --run -- command [argument ...]\n",
            program, program);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--target") == 0)
        return run_target();
    if (argc >= 4 && strcmp(argv[1], "--run") == 0 &&
        strcmp(argv[2], "--") == 0)
        return run_driver_isolated(&argv[3]);
    usage(argv[0]);
    return 2;
}
