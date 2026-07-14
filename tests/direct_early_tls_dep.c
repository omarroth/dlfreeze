extern void record_event(char event);

__thread int direct_early_tls_value
    __attribute__((tls_model("initial-exec"))) = 41;

__attribute__((constructor))
static void direct_early_tls_dep_init(void)
{
    record_event('D');
}

int direct_early_tls_read(void)
{
    return direct_early_tls_value;
}

int direct_early_tls_exchange(int value)
{
    int previous = direct_early_tls_value;

    direct_early_tls_value = value;
    return previous;
}
