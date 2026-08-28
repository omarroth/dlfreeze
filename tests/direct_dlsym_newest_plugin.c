int ambiguous_v1(void) { return 11; }
int ambiguous_v2(void) { return 22; }

__asm__(".symver ambiguous_v1,ambiguous@NEWEST_1");
__asm__(".symver ambiguous_v2,ambiguous@NEWEST_2");
