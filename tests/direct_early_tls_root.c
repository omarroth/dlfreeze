#ifndef ROOT_EVENT
#error ROOT_EVENT must name the constructor event
#endif
#ifndef DIRECT_EARLY_HAVE_IFUNC
#define DIRECT_EARLY_HAVE_IFUNC 0
#endif

extern void record_event(char event);
extern int direct_early_tls_read(void);

#if DIRECT_EARLY_HAVE_IFUNC
extern int direct_early_ifunc_ready;

static int direct_early_local_implementation(void)
{
    return 73;
}

static int (*direct_early_local_resolver(void))(void)
{
    /* Native rtld invokes this while servicing dlopen, after main has set
     * the readiness marker.  Running it while merely reserving startup TLS
     * would expose promoted objects before their semantic load point. */
    record_event(direct_early_ifunc_ready ? 'I' : 'X');
    return direct_early_local_implementation;
}

static int direct_early_local_ifunc(void)
    __attribute__((ifunc("direct_early_local_resolver")));

static int (*direct_early_local_pointer)(void) = direct_early_local_ifunc;
#endif

__attribute__((constructor))
static void direct_early_tls_root_init(void)
{
    record_event(direct_early_tls_read() >= 0 ? ROOT_EVENT : 'X');
}

int direct_early_tls_root_read(void)
{
    return direct_early_tls_read();
}

int direct_early_tls_root_ifunc(void)
{
#if DIRECT_EARLY_HAVE_IFUNC
    return direct_early_local_pointer();
#else
    return 73;
#endif
}
