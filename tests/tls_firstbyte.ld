/*
 * Put a minimally aligned TLS byte before the normally page-aligned .tdata
 * output section.  The resulting PT_TLS starts at a non-zero residue modulo
 * its p_align, while the later page-aligned symbol forces p_align to 4096.
 * This exercises the ELF "first-byte" TLS layout rule.
 */
SECTIONS
{
  .dlfreeze_tls_first ALIGN(4096) + 0x80 :
  {
    KEEP(*(.dlfreeze_tls_first))
  }
}
INSERT BEFORE .tdata;
