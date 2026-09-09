#include <unistd.h>

extern void constructor_binding_hold(int (*entry)(void));

static int answer(void)
{
    return 42;
}

#ifdef TEST_IFUNC
static int (*resolve_answer(void))(void)
{
    return answer;
}
int constructor_binding_answer(void) __attribute__((ifunc("resolve_answer")));
#else
int constructor_binding_answer(void)
{
    return answer();
}
#endif

int constructor_binding_entry(void)
{
    /* getuid cannot be folded away and has not been called by this DSO. */
    if (getuid() == (uid_t)-1)
        return -1;
    return constructor_binding_answer();
}

__attribute__((constructor))
static void initialize(void)
{
    constructor_binding_hold(constructor_binding_entry);
}
