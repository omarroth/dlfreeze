extern void record_event(char event);

__thread int direct_late_static_tls_value
    __attribute__((tls_model("initial-exec"))) = 73;

__attribute__((constructor))
static void direct_late_static_tls_init(void)
{
    record_event('L');
}

int direct_late_static_tls_read(void)
{
    return direct_late_static_tls_value;
}
