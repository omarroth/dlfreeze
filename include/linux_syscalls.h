#ifndef DLFRZ_LINUX_SYSCALLS_H
#define DLFRZ_LINUX_SYSCALLS_H

#include <sys/syscall.h>

/* Linux UAPI numbers shared by the two supported ELF architectures. Old
 * libc headers must not hide a syscall implemented by the running kernel. */
#if !defined(SYS_close_range) && \
    (defined(__x86_64__) || defined(__aarch64__))
#define SYS_close_range 436
#endif

#endif
