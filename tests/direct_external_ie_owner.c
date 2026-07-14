__thread int direct_external_ie_value = 37;

int *direct_external_ie_owner_addr(void)
{
    return &direct_external_ie_value;
}
