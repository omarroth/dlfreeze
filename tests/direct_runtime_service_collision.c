#include <stdio.h>

#if defined(DLFRZ_PTHREAD_OBJECT_COLLISION)
/* Use an assembler name so no host pthread declaration influences the ELF
 * type: this must remain a visible STT_OBJECT collision. */
__attribute__((visibility("default")))
int dlfrz_pthread_key_create_object
    __asm__("pthread_key_create") = 0;
#elif defined(DLFRZ_PTHREAD_FUNCTION_COLLISION)
static int collision_calls;

__attribute__((visibility("default")))
int dlfrz_pthread_atfork_function(void (*prepare)(void),
                                  void (*parent)(void),
                                  void (*child)(void))
    __asm__("pthread_atfork");

int dlfrz_pthread_atfork_function(void (*prepare)(void),
                                  void (*parent)(void),
                                  void (*child)(void))
{
    (void)prepare;
    (void)parent;
    (void)child;
    collision_calls++;
    return 0;
}

/* glibc's loader-private backend must likewise bind __register_atfork from
 * the admitted libc rather than an executable definition with the same ELF
 * name.  Keep both spellings in one fixture so musl and glibc exercise their
 * respective backend without changing the matrix cardinality. */
__attribute__((visibility("default")))
int dlfrz_register_atfork_function(void (*prepare)(void),
                                   void (*parent)(void),
                                   void (*child)(void), void *dso_handle)
    __asm__("__register_atfork");

int dlfrz_register_atfork_function(void (*prepare)(void),
                                   void (*parent)(void),
                                   void (*child)(void), void *dso_handle)
{
    (void)prepare;
    (void)parent;
    (void)child;
    (void)dso_handle;
    collision_calls++;
    return 0;
}
#else
#error "select one runtime-service collision kind"
#endif

int main(void)
{
#if defined(DLFRZ_PTHREAD_FUNCTION_COLLISION)
    if (collision_calls != 0)
        return 73;
    puts("runtime-service-function-collision-ok");
#else
    puts("runtime-service-object-collision-ok");
#endif
    return 0;
}
