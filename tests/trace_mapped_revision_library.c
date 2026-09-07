#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#ifndef TRACE_VALUE
#define TRACE_VALUE 0
#endif

#ifdef TRACE_REPLACE_ON_LOAD
__attribute__((constructor)) static void replace_loaded_source(void)
{
    const char *destination =
        getenv("DLFREEZE_TEST_REPLACE_DESTINATION");
    const char *replacement = getenv("DLFREEZE_TEST_REPLACEMENT");

    if (destination && replacement)
        (void)rename(replacement, destination);
}
#endif

#ifdef TRACE_EXIT_ON_LOAD
__attribute__((constructor)) static void exit_during_load(void)
{
    _exit(0);
}
#endif

int trace_process_value(void)
{
    return TRACE_VALUE;
}

int trace_mapped_dependency_value(void)
{
    return TRACE_VALUE;
}
