#include <dlfcn.h>
#include <stdio.h>

#ifdef INDIRECT_LATE_LOAD
int main(int argc, char **argv)
{
    void *handle;
    int (*function)(void);
    int (*(*pointer)(void))(void);
    int *(*data_pointer)(void);
    int *value;

    if (argc != 2 || !(handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)))
        return 1;
    function = (int (*)(void))dlsym(handle, "indirect_function");
    pointer = (int (*(*)(void))(void))dlsym(handle, "indirect_function_pointer");
    data_pointer = (int *(*)(void))dlsym(handle, "indirect_data_pointer");
    value = (int *)dlsym(handle, "indirect_value");
    if (!function || !pointer || !data_pointer || !value ||
        function != pointer() || value != data_pointer() ||
        function() != 37 || *value != 37)
        return 2;
    puts("indirect external access identities preserved");
    return 0;
}
#else
extern int indirect_value;
extern int indirect_function(void);
extern int (*indirect_function_pointer(void))(void);
extern int *indirect_data_pointer(void);

int main(void)
{
    if (indirect_function != indirect_function_pointer() ||
        &indirect_value != indirect_data_pointer() ||
        indirect_function() != 37 || indirect_value != 37)
        return 1;
    puts("indirect external access identities preserved");
    return 0;
}
#endif
