#ifndef DLFREEZE_LIBC_SEMANTICS_H
#define DLFREEZE_LIBC_SEMANTICS_H

#include <stdint.h>

static inline int dlfrz_string_starts_with(const char *text,
                                           const char *prefix)
{
    while (*prefix && *text == *prefix) {
        ++text;
        ++prefix;
    }
    return *prefix == '\0';
}

/* musl treats these historical libc-family SONAME prefixes as references to
 * the dynamic linker/libc object itself.  Keep this target-runtime rule in
 * one place so dependency capture and direct replay cannot disagree.  The
 * trailing dot is significant and intentionally also matches versioned
 * names such as libpthread.so.0, exactly as musl's loader does. */
static inline int dlfrz_musl_reserved_soname(const char *name)
{
    const char *suffix;

    /* Do not use fixed-index probes here.  Dependency names come from an
     * untrusted ELF string table, and a valid short name can end immediately
     * before an inaccessible page. */
    if (!name || !dlfrz_string_starts_with(name, "lib"))
        return 0;
    suffix = name + 3;
    return dlfrz_string_starts_with(suffix, "c.") ||
           dlfrz_string_starts_with(suffix, "pthread.") ||
           dlfrz_string_starts_with(suffix, "rt.") ||
           dlfrz_string_starts_with(suffix, "m.") ||
           dlfrz_string_starts_with(suffix, "dl.") ||
           dlfrz_string_starts_with(suffix, "util.") ||
           dlfrz_string_starts_with(suffix, "xnet.");
}

/* Compute the NPTL geometry which direct mode publishes after assigning every
 * startup static-TLS block.  Unlike the native dynamic loader, dlfreeze never
 * reserves optional compatibility surplus: traced initial-exec closures are
 * assigned before startup and a later load needing a new static offset is
 * refused.  TLS_TCB_AT_TP includes the target's struct pthread after the
 * rounded TLS area; TLS_DTV_AT_TP keeps that descriptor before TP and rounds
 * the positive-offset TLS extent only to the architecture's TCB alignment. */
static inline int dlfrz_glibc_used_static_tls_geometry(
    uint64_t used, uint64_t maximum_tls_align, uint64_t tcb_align,
    uint64_t pthread_size, int tcb_at_tp, uint64_t *size_out,
    uint64_t *align_out)
{
    uint64_t public_align;
    uint64_t size_align;
    uint64_t mask;
    uint64_t rounded;

    if (!size_out || !align_out || maximum_tls_align == 0 ||
        (maximum_tls_align & (maximum_tls_align - 1)) != 0 ||
        tcb_align == 0 || (tcb_align & (tcb_align - 1)) != 0)
        return 0;
    public_align = maximum_tls_align < tcb_align
        ? tcb_align : maximum_tls_align;
    size_align = tcb_at_tp ? public_align : tcb_align;
    mask = size_align - 1;
    if (used > UINT64_MAX - mask)
        return 0;
    rounded = (used + mask) & ~mask;
    if (tcb_at_tp) {
        if (pthread_size == 0 || rounded > UINT64_MAX - pthread_size)
            return 0;
        rounded += pthread_size;
    } else if (pthread_size != 0) {
        return 0;
    }
    *size_out = rounded;
    *align_out = public_align;
    return 1;
}

#endif /* DLFREEZE_LIBC_SEMANTICS_H */
