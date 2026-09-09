#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <string.h>

static int ignored(int signal_number)
{
    struct sigaction action = {0};

    if (sigaction(signal_number, NULL, &action) < 0)
        return 0;
    return action.sa_handler == SIG_IGN;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 64;
    if (strcmp(argv[1], "plain") == 0) {
        puts("crash-handler-no-debug-ok");
        return 0;
    }
    if (strcmp(argv[1], "partial") == 0) {
        /* SIGABRT was the denied transactional slot.  It must remain the
         * inherited SIG_IGN disposition without ever being restored from an
         * uninitialized saved action. */
        if (raise(SIGABRT) != 0 || !ignored(SIGSEGV))
            return 65;
        puts("crash-handler-rollback-ok");
        return 0;
    }
    if (strcmp(argv[1], "ignored") == 0) {
        if (!ignored(SIGSEGV) || !ignored(SIGABRT))
            return 66;
        puts("crash-handler-restore-ok");
        return 0;
    }
    return 67;
}
