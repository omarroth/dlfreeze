extern int kernel_premap_lazy_ctor_count;

__attribute__((constructor))
static void kernel_premap_lazy_constructor(void)
{
    kernel_premap_lazy_ctor_count++;
}

int kernel_premap_lazy_value(void)
{
    return 73;
}
