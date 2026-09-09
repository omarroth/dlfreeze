#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) static void rename_loaded_image(void)
{
    const char *source = getenv("DLFREEZE_EXTERNAL_PHDR_RENAME_FROM");
    const char *destination = getenv("DLFREEZE_EXTERNAL_PHDR_RENAME_TO");

    if (source && source[0] && destination && destination[0])
        (void)rename(source, destination);
}

int external_phdr_value(void)
{
    return 73;
}
