/* Architecture-independent ELF64 binding contract. The loader must enforce
 * this even when built against elf.h predating the property definition. */
.section .note.gnu.property,"a",%note
.p2align 3
.long 4
.long 16
.long 5
.asciz "GNU"
.long 0xb0008000
.long 4
.long 1
.long 0

.section .note.GNU-stack,"",%progbits
