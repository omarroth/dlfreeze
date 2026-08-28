#ifndef DLFREEZE_CHAIN_SYMBOL
#error "DLFREEZE_CHAIN_SYMBOL must name this fixture's exported function"
#endif

#ifdef DLFREEZE_CHAIN_LEAF
int DLFREEZE_CHAIN_SYMBOL(void)
{
    return 1;
}
#else
#ifndef DLFREEZE_CHAIN_NEXT
#error "DLFREEZE_CHAIN_NEXT must name the next fixture function"
#endif
extern int DLFREEZE_CHAIN_NEXT(void);

int DLFREEZE_CHAIN_SYMBOL(void)
{
    return DLFREEZE_CHAIN_NEXT() + 1;
}
#endif
