extern __thread unsigned char direct_weak_tlsdesc_missing
    __attribute__((weak));

__attribute__((visibility("default"), noinline))
void *direct_weak_tlsdesc_address(void)
{
    return &direct_weak_tlsdesc_missing;
}
