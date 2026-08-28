__thread int dlfreeze_runtime_bounds_tls = 37;

int dlfreeze_runtime_bounds_value(void)
{
    return dlfreeze_runtime_bounds_tls + 5;
}
