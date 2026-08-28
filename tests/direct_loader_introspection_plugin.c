__thread int loader_introspection_tls = 73;

__attribute__((aligned(64), section(".data.dladdr_public")))
unsigned char loader_introspection_sized_symbol[16];

__attribute__((visibility("hidden"), aligned(64),
               section(".data.dladdr_hidden")))
unsigned char loader_introspection_hidden_symbol[16];

__attribute__((aligned(64), section(".data.dladdr_local")))
static unsigned char loader_introspection_local_symbol[16];

__asm__(
#if defined(__aarch64__)
    ".pushsection .text.dladdr_zero,\"ax\",%progbits\n"
    ".global loader_introspection_zero_sized_symbol\n"
    ".type loader_introspection_zero_sized_symbol,%function\n"
#else
    ".pushsection .text.dladdr_zero,\"ax\",@progbits\n"
    ".global loader_introspection_zero_sized_symbol\n"
    ".type loader_introspection_zero_sized_symbol,@function\n"
#endif
    "loader_introspection_zero_sized_symbol:\n"
    "ret\n"
    ".size loader_introspection_zero_sized_symbol,0\n"
    ".space 16,0\n"
    ".popsection\n");

/* The smaller symbol deliberately sits inside the larger symbol.  For an
 * address just past the smaller symbol, glibc rejects the smaller candidate
 * by size and retains the containing larger one.  musl selects the nearest
 * candidate first and then clears it by size without falling back. */
__asm__(
#if defined(__aarch64__)
    ".pushsection .data.dladdr_overlap,\"aw\",%progbits\n"
    ".global loader_introspection_wide_symbol\n"
    ".type loader_introspection_wide_symbol,%object\n"
#else
    ".pushsection .data.dladdr_overlap,\"aw\",@progbits\n"
    ".global loader_introspection_wide_symbol\n"
    ".type loader_introspection_wide_symbol,@object\n"
#endif
    "loader_introspection_wide_symbol:\n"
    ".space 16,0\n"
    ".global loader_introspection_short_symbol\n"
#if defined(__aarch64__)
    ".type loader_introspection_short_symbol,%object\n"
#else
    ".type loader_introspection_short_symbol,@object\n"
#endif
    "loader_introspection_short_symbol:\n"
    ".byte 0\n"
    ".size loader_introspection_short_symbol,1\n"
    ".space 47,0\n"
    ".size loader_introspection_wide_symbol,64\n"
    ".popsection\n");

int loader_introspection_value(void)
{
    return 41;
}

int *loader_introspection_tls_address(void)
{
    return &loader_introspection_tls;
}

void *loader_introspection_hidden_address(void)
{
    return loader_introspection_hidden_symbol;
}

void *loader_introspection_local_address(void)
{
    return loader_introspection_local_symbol;
}
