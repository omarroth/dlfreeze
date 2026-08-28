#define _GNU_SOURCE
#include <dlfcn.h>

extern unsigned int __rseq_flags;
extern unsigned int imported_main_rseq_flags;
extern void imported_audit_preinit(void);
__asm__(".symver imported_main_rseq_flags,"
        "__rseq_flags@GLIBC_2.35");
__asm__(".symver imported_audit_preinit,"
        "_dl_audit_preinit@GLIBC_PRIVATE");

void *plugin_next_dlopen(void)
{
    return dlsym(RTLD_NEXT, "dlopen");
}

void *plugin_next_open(void)
{
    return dlsym(RTLD_NEXT, "open");
}

void *plugin_imported_rseq_flags(void)
{
    return (void *)&__rseq_flags;
}

void *plugin_imported_main_rseq_flags(void)
{
    return (void *)&imported_main_rseq_flags;
}

void *plugin_imported_audit_preinit(void)
{
    return (void *)imported_audit_preinit;
}
