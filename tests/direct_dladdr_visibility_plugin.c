__attribute__((aligned(64), section(".data.dladdr_visibility")))
unsigned char loader_dladdr_candidate_a[16];

__attribute__((aligned(64), section(".data.dladdr_visibility")))
unsigned char loader_dladdr_candidate_b[16];

void *loader_dladdr_candidate_a_address(void)
{
    return loader_dladdr_candidate_a;
}

void *loader_dladdr_candidate_b_address(void)
{
    return loader_dladdr_candidate_b;
}
