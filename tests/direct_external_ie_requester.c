extern __thread int direct_external_ie_value
    __attribute__((tls_model("initial-exec")));

int direct_external_ie_read(void)
{
    return direct_external_ie_value;
}

int direct_external_ie_exchange(int value)
{
    int previous = direct_external_ie_value;

    direct_external_ie_value = value;
    return previous;
}
