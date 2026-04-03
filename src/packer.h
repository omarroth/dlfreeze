#ifndef DLFREEZE_PACKER_H
#define DLFREEZE_PACKER_H

#include "dep_resolver.h"

struct pack_options {
    const char      *exe_path;        /* original executable           */
    const char      *output_path;     /* frozen output file            */
    const char      *bootstrap_path;  /* statically-linked bootstrap   */
    struct dep_list *deps;            /* resolved dependencies         */
};

/* Create a frozen (self-extracting) ELF binary. */
int pack_frozen(const struct pack_options *opts);

#endif /* DLFREEZE_PACKER_H */
