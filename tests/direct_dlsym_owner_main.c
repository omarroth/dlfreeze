#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

typedef void *(*address_fn)(void);

void __monstartup(unsigned long low, unsigned long high)
{
    (void)low;
    (void)high;
}

void _mcleanup(void) {}
unsigned int main_rseq_flags_impl = 88;
__asm__(".symver main_rseq_flags_impl,__rseq_flags@@GLIBC_2.35");
void main_audit_preinit_impl(void) {}
__asm__(".symver main_audit_preinit_impl,"
        "_dl_audit_preinit@@GLIBC_PRIVATE");

int main(int argc, char **argv)
{
    void *caller;
    void *provider;
    address_fn expected_dlopen;
    address_fn expected_open;
    address_fn expected_monstartup;
    address_fn expected_mcleanup;
    address_fn expected_rseq_flags;
    address_fn expected_audit_preinit;
    address_fn next_dlopen;
    address_fn next_open;
    address_fn imported_rseq_flags;
    address_fn imported_main_rseq_flags;
    address_fn imported_audit_preinit;
    void *want_dlopen;
    void *want_open;

    if (argc != 3)
        return 1;
    caller = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!caller)
        return 2;
    provider = dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD);
    if (!provider)
        return 3;
    expected_dlopen = (address_fn)dlsym(provider, "plugin_expected_dlopen");
    expected_open = (address_fn)dlsym(provider, "plugin_expected_open");
    expected_monstartup =
        (address_fn)dlsym(provider, "plugin_expected_monstartup");
    expected_mcleanup =
        (address_fn)dlsym(provider, "plugin_expected_mcleanup");
    expected_rseq_flags =
        (address_fn)dlsym(provider, "plugin_expected_rseq_flags");
    expected_audit_preinit =
        (address_fn)dlsym(provider, "plugin_expected_audit_preinit");
    next_dlopen = (address_fn)dlsym(caller, "plugin_next_dlopen");
    next_open = (address_fn)dlsym(caller, "plugin_next_open");
    imported_rseq_flags =
        (address_fn)dlsym(caller, "plugin_imported_rseq_flags");
    imported_main_rseq_flags =
        (address_fn)dlsym(caller, "plugin_imported_main_rseq_flags");
    imported_audit_preinit =
        (address_fn)dlsym(caller, "plugin_imported_audit_preinit");
    if (!expected_dlopen || !expected_open || !expected_monstartup ||
        !expected_mcleanup || !expected_rseq_flags ||
        !expected_audit_preinit || !next_dlopen || !next_open ||
        !imported_rseq_flags || !imported_main_rseq_flags ||
        !imported_audit_preinit)
        return 4;
    want_dlopen = expected_dlopen();
    want_open = expected_open();
    if (dlsym(provider, "dlopen") != want_dlopen ||
        dlsym(provider, "open") != want_open ||
        dlvsym(provider, "dlopen", "PLUGIN_1") != want_dlopen ||
        dlvsym(provider, "open", "PLUGIN_1") != want_open)
        return 5;
    if (dlsym(provider, "__monstartup") != expected_monstartup() ||
        dlsym(provider, "_mcleanup") != expected_mcleanup() ||
        dlvsym(provider, "__monstartup", "PLUGIN_1") !=
            expected_monstartup() ||
        dlvsym(provider, "_mcleanup", "PLUGIN_1") != expected_mcleanup())
        return 7;
    if (dlsym(RTLD_DEFAULT, "__monstartup") != (void *)__monstartup ||
        dlsym(RTLD_DEFAULT, "_mcleanup") != (void *)_mcleanup)
        return 8;
    if (next_dlopen() != want_dlopen || next_open() != want_open)
        return 6;
    /* These two references exercise ordinary relocation ownership.  The
     * names also have interpreter/private loader shims, but the plugin's
     * selected definitions must retain ELF interposition precedence. */
    if (imported_rseq_flags() != expected_rseq_flags() ||
        *(unsigned int *)imported_rseq_flags() != 77 ||
        imported_main_rseq_flags() != (void *)&main_rseq_flags_impl ||
        *(unsigned int *)imported_main_rseq_flags() != 88 ||
        dlsym(RTLD_DEFAULT, "__rseq_flags") !=
            (void *)&main_rseq_flags_impl ||
        dlvsym(RTLD_DEFAULT, "__rseq_flags", "GLIBC_2.35") !=
            (void *)&main_rseq_flags_impl ||
        imported_audit_preinit() != (void *)main_audit_preinit_impl)
        return 9;
    puts("plugin-owner-ok");
    return 0;
}
