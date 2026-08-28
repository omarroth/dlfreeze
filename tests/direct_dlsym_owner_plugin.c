int plugin_dlopen_impl(void) { return 101; }
int plugin_open_impl(void) { return 202; }
unsigned int __rseq_flags = 77;
unsigned int plugin_compat_rseq_flags = 66;
__asm__(".symver plugin_compat_rseq_flags,__rseq_flags@GLIBC_2.35");
void plugin_monstartup_impl(unsigned long low, unsigned long high)
{
    (void)low;
    (void)high;
}
void plugin_mcleanup_impl(void) {}
void plugin_audit_preinit_impl(void) {}

__asm__(".symver plugin_dlopen_impl,dlopen@@PLUGIN_1");
__asm__(".symver plugin_open_impl,open@@PLUGIN_1");
__asm__(".symver plugin_monstartup_impl,__monstartup@@PLUGIN_1");
__asm__(".symver plugin_mcleanup_impl,_mcleanup@@PLUGIN_1");
__asm__(".symver plugin_audit_preinit_impl,"
        "_dl_audit_preinit@@GLIBC_PRIVATE");

void *plugin_expected_dlopen(void)
{
    return (void *)plugin_dlopen_impl;
}

void *plugin_expected_open(void)
{
    return (void *)plugin_open_impl;
}

void *plugin_expected_monstartup(void)
{
    return (void *)plugin_monstartup_impl;
}

void *plugin_expected_mcleanup(void)
{
    return (void *)plugin_mcleanup_impl;
}

void *plugin_expected_rseq_flags(void)
{
    return (void *)&__rseq_flags;
}

void *plugin_expected_audit_preinit(void)
{
    return (void *)plugin_audit_preinit_impl;
}
