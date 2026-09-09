#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Make every openat observe an absent filesystem entry.  A fully embedded
 * direct artifact must not require the GNU cache merely to establish that no
 * cache-provided tunables apply. */
int main(int argc, char **argv)
{
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 SECCOMP_RET_ERRNO |
                     (ENOENT & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(
            sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };

    if (argc < 2)
        return 2;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
        return 77;
    execv(argv[1], argv + 1);
    return 3;
}
