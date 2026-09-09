#define _GNU_SOURCE

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__NR_rt_sigaction)
#error "Linux rt_sigaction syscall number is required"
#endif

static int install_filter(const char *policy)
{
    struct sock_filter deny_abrt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 5),
        /* Deny only a capture+install transaction.  A restore has oldact
         * == NULL, so a buggy restore of the failed slot would be allowed
         * and the target's inherited-SIG_IGN check would catch it. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[2]) + sizeof(uint32_t)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_filter trap_all[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {0};

    if (strcmp(policy, "none") == 0)
        return 0;
    if (strcmp(policy, "deny-abrt") == 0) {
        program.len = (unsigned short)(sizeof(deny_abrt) /
                                       sizeof(deny_abrt[0]));
        program.filter = deny_abrt;
    } else if (strcmp(policy, "trap-all") == 0) {
        program.len = (unsigned short)(sizeof(trap_all) /
                                       sizeof(trap_all[0]));
        program.filter = trap_all;
    } else {
        return 64;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return 77;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0)
        return 77;
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction ignored = {0};
    char *target_argv[3];
    int status;

    if (argc != 4)
        return 64;
    if (strcmp(argv[3], "plain") != 0) {
        ignored.sa_handler = SIG_IGN;
        if (sigemptyset(&ignored.sa_mask) < 0 ||
            sigaction(SIGSEGV, &ignored, NULL) < 0 ||
            sigaction(SIGABRT, &ignored, NULL) < 0)
            return 65;
        if (setenv("DLFREEZE_DEBUG", "1", 1) < 0)
            return 66;
    } else if (unsetenv("DLFREEZE_DEBUG") < 0) {
        return 67;
    }

    status = install_filter(argv[1]);
    if (status != 0)
        return status;
    target_argv[0] = argv[2];
    target_argv[1] = argv[3];
    target_argv[2] = NULL;
    execv(argv[2], target_argv);
    return errno == ENOENT ? 127 : 126;
}
