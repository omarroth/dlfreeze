/*
 * Runtime-dlopen parser fixture.  The inert PT_NULL entries make the real
 * program-header count exceed the loader's former fixed stack buffer, while
 * padding after DT_NULL makes PT_DYNAMIC exceed its former fixed buffer.
 */
PHDRS
{
  phdr    PT_PHDR PHDRS;
  text    PT_LOAD FILEHDR PHDRS FLAGS(5);
  data    PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC FLAGS(6);
  tls     PT_TLS FLAGS(4);
  stack   PT_GNU_STACK FLAGS(6);
  null00  PT_NULL;
  null01  PT_NULL;
  null02  PT_NULL;
  null03  PT_NULL;
  null04  PT_NULL;
  null05  PT_NULL;
  null06  PT_NULL;
  null07  PT_NULL;
  null08  PT_NULL;
  null09  PT_NULL;
  null10  PT_NULL;
  null11  PT_NULL;
  null12  PT_NULL;
  null13  PT_NULL;
  null14  PT_NULL;
  null15  PT_NULL;
  null16  PT_NULL;
  null17  PT_NULL;
  null18  PT_NULL;
  null19  PT_NULL;
  null20  PT_NULL;
  null21  PT_NULL;
  null22  PT_NULL;
  null23  PT_NULL;
  null24  PT_NULL;
  null25  PT_NULL;
  null26  PT_NULL;
  null27  PT_NULL;
  null28  PT_NULL;
  null29  PT_NULL;
  null30  PT_NULL;
  null31  PT_NULL;
  null32  PT_NULL;
  null33  PT_NULL;
  null34  PT_NULL;
  null35  PT_NULL;
  null36  PT_NULL;
  null37  PT_NULL;
  null38  PT_NULL;
  null39  PT_NULL;
  null40  PT_NULL;
  null41  PT_NULL;
  null42  PT_NULL;
  null43  PT_NULL;
  null44  PT_NULL;
  null45  PT_NULL;
  null46  PT_NULL;
  null47  PT_NULL;
  null48  PT_NULL;
  null49  PT_NULL;
  null50  PT_NULL;
  null51  PT_NULL;
  null52  PT_NULL;
  null53  PT_NULL;
  null54  PT_NULL;
  null55  PT_NULL;
  null56  PT_NULL;
  null57  PT_NULL;
  null58  PT_NULL;
  null59  PT_NULL;
  null60  PT_NULL;
  null61  PT_NULL;
  null62  PT_NULL;
  null63  PT_NULL;
}

SECTIONS
{
  . = SIZEOF_HEADERS;
  /* Keep allocatable linker-generated notes in the first PT_LOAD.  GNU ld's
   * AArch64 orphan placement can otherwise attach .note.gnu.build-id to the
   * later writable segment while leaving adjacent sections in the text
   * segment, creating overlapping, non-loadable PT_LOAD geometry. */
  .note.gnu.property : { *(.note.gnu.property) } :text
  .note.gnu.build-id : { *(.note.gnu.build-id) } :text
  .hash           : { *(.hash) } :text
  .gnu.hash       : { *(.gnu.hash) } :text
  .dynsym         : { *(.dynsym) } :text
  .dynstr         : { *(.dynstr) } :text
  .gnu.version    : { *(.gnu.version) } :text
  .gnu.version_d  : { *(.gnu.version_d) } :text
  .gnu.version_r  : { *(.gnu.version_r) } :text
  .rela.dyn       : { *(.rela.dyn) } :text
  .rela.plt       : { *(.rela.plt) } :text
  .plt            : { *(.plt) *(.plt.*) } :text
  .text           : { *(.text) *(.text.*) } :text
  .rodata         : { *(.rodata) *(.rodata.*) } :text
  .eh_frame_hdr   : { *(.eh_frame_hdr) } :text
  .eh_frame       : { KEEP(*(.eh_frame)) } :text

  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .tdata          : { *(.tdata) *(.tdata.*) } :data :tls
  .tbss           : { *(.tbss) *(.tbss.*) } :data :tls
  .dynamic        :
  {
    *(.dynamic)
    . = ALIGN(16);
    . += 0x11008;
  } :data :dynamic
  .got            : { *(.got) *(.got.plt) } :data
  .data           : { *(.data) *(.data.*) } :data
  .bss            : { *(.bss) *(.bss.*) *(COMMON) } :data

  /DISCARD/       : { *(.comment) *(.note.GNU-stack) }
}
