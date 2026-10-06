#ifdef INDIRECT_DEFAULT_EXPORTS
#define INDIRECT_VISIBILITY
#else
#define INDIRECT_VISIBILITY __attribute__((visibility("protected")))
#endif

INDIRECT_VISIBILITY int indirect_value = 37;

INDIRECT_VISIBILITY int indirect_function(void)
{
    return indirect_value;
}

int (*indirect_function_pointer(void))(void)
{
    return indirect_function;
}

int *indirect_data_pointer(void)
{
    return &indirect_value;
}
