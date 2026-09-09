#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static volatile unsigned char bss[192 * 1024];

int main(void)
{
    /* A real allocation also exercises the unchanged native heap region. */
    char *memory = malloc(2 * 1024 * 1024);
    if (!memory) return 1;
    memset(memory, 0x5a, 2 * 1024 * 1024);
    for (size_t i = 0; i < sizeof(bss); i++) if (bss[i]) return 2;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[1024];
        char permissions[5];
        unsigned long long lo, hi;
        while (fgets(line, sizeof(line), maps)) {
            if (sscanf(line, "%llx-%llx %4s", &lo, &hi, permissions) == 3 &&
                !strcmp(permissions, "r--p") &&
                lo >= UINT64_C(0x10000000) && hi <= UINT64_C(0x3f000000) &&
                hi - lo > 65536) return 3;
        }
        fclose(maps);
    }
    free(memory);
    puts("kernel-premap-ok");
    return 0;
}
