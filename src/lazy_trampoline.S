/*
 * Architecture PLT resolver trampolines for the direct loader.
 *
 * These entry points are reached through the target object's native PLT0,
 * not through an ordinary C call.  The stack/register contracts therefore
 * match the platform ELF lazy-binding ABI.  The C helpers validate all
 * object and relocation metadata and return the final branch target.
 */

#if defined(__x86_64__)

	.section .text,"ax",@progbits
	.p2align 4
	.globl dlfreeze_x86_64_lazy_plt_resolver
	.hidden dlfreeze_x86_64_lazy_plt_resolver
	.type dlfreeze_x86_64_lazy_plt_resolver, @function
	.hidden dlfreeze_x86_64_lazy_plt_fixup

/*
 * Native x86-64 PLT0 entry stack:
 *
 *   0(%rsp)   loader object token (GOT[1])
 *   8(%rsp)   DT_JMPREL ordinal
 *  16(%rsp)   original caller return address
 *
 * Preserve every potentially useful caller GPR, including %rax/%al, and
 * the complete kernel-enabled user xstate.  The returned target replaces
 * the no-longer-needed object-token word, allowing the final memory-indirect
 * jump to preserve even %r10 and %r11.  Discarding the two synthetic normal
 * stack words with ADD followed by JMP also preserves CET shadow-stack
 * balance: only the original call's return address remains on both stacks.
 */
dlfreeze_x86_64_lazy_plt_resolver:
	.cfi_startproc
	/* Hide the two words pushed by the PLT from the logical caller frame. */
	.cfi_def_cfa %rsp, 24
	.cfi_offset %rip, -8
	/* ENDBR64, encoded directly so baseline assemblers can build this file. */
	.byte 0xf3, 0x0f, 0x1e, 0xfa

	pushq %rbp
	.cfi_def_cfa_offset 32
	.cfi_offset %rbp, -32
	movq %rsp, %rbp
	.cfi_def_cfa_register %rbp

	/* Fixed save area; %rbp and the incoming stack keep 16-byte alignment. */
	subq $80, %rsp
	movq %rax, -8(%rbp)
	.cfi_offset %rax, -40
	movq %rcx, -16(%rbp)
	.cfi_offset %rcx, -48
	movq %rdx, -24(%rbp)
	.cfi_offset %rdx, -56
	movq %rsi, -32(%rbp)
	.cfi_offset %rsi, -64
	movq %rdi, -40(%rbp)
	.cfi_offset %rdi, -72
	movq %r8, -48(%rbp)
	.cfi_offset %r8, -80
	movq %r9, -56(%rbp)
	.cfi_offset %r9, -88
	movq %r10, -64(%rbp)
	.cfi_offset %r10, -96
	movq %r11, -72(%rbp)
	.cfi_offset %r11, -104

	/* A nonzero size is the publication flag for the admitted XSAVE mask. */
	movl g_x86_64_tlsdesc_xsave_size(%rip), %eax
	testl %eax, %eax
	jz .Lx86_lazy_fxsave

	/* XSAVE requires 64-byte alignment.  The extra 63 bytes cover rounding. */
	addq $63, %rax
	subq %rax, %rsp
	andq $-64, %rsp

	/* XRSTOR requires reserved XSAVE-header bytes to have been zeroed. */
	xorl %eax, %eax
	movq %rax, 512(%rsp)
	movq %rax, 520(%rsp)
	movq %rax, 528(%rsp)
	movq %rax, 536(%rsp)
	movq %rax, 544(%rsp)
	movq %rax, 552(%rsp)
	movq %rax, 560(%rsp)
	movq %rax, 568(%rsp)
	movl g_x86_64_tlsdesc_xsave_mask_low(%rip), %eax
	movl g_x86_64_tlsdesc_xsave_mask_high(%rip), %edx
	xsave64 (%rsp)

	movq 8(%rbp), %rdi
	movq 16(%rbp), %rsi
	call dlfreeze_x86_64_lazy_plt_fixup
	/* GOT[1] has served its purpose; retain the target without a live GPR. */
	movq %rax, 8(%rbp)

	movl g_x86_64_tlsdesc_xsave_mask_low(%rip), %eax
	movl g_x86_64_tlsdesc_xsave_mask_high(%rip), %edx
	xrstor64 (%rsp)
	jmp .Lx86_lazy_restore

.Lx86_lazy_fxsave:
	/* Without OSXSAVE, the ABI-visible state is covered by the legacy image. */
	subq $512, %rsp
	fxsave64 (%rsp)
	movq 8(%rbp), %rdi
	movq 16(%rbp), %rsi
	call dlfreeze_x86_64_lazy_plt_fixup
	movq %rax, 8(%rbp)
	fxrstor64 (%rsp)

.Lx86_lazy_restore:
	movq -72(%rbp), %r11
	.cfi_restore %r11
	movq -64(%rbp), %r10
	.cfi_restore %r10
	movq -56(%rbp), %r9
	.cfi_restore %r9
	movq -48(%rbp), %r8
	.cfi_restore %r8
	movq -40(%rbp), %rdi
	.cfi_restore %rdi
	movq -32(%rbp), %rsi
	.cfi_restore %rsi
	movq -24(%rbp), %rdx
	.cfi_restore %rdx
	movq -16(%rbp), %rcx
	.cfi_restore %rcx
	movq -8(%rbp), %rax
	.cfi_restore %rax

	movq %rbp, %rsp
	.cfi_def_cfa %rsp, 32
	popq %rbp
	.cfi_restore %rbp
	.cfi_def_cfa_offset 24
	addq $16, %rsp
	.cfi_def_cfa_offset 8
	/* The target is in the former GOT[1] word, now 16 bytes below %rsp. */
	jmp *-16(%rsp)
	.cfi_endproc
	.size dlfreeze_x86_64_lazy_plt_resolver, .-dlfreeze_x86_64_lazy_plt_resolver

#elif defined(__aarch64__)

	.section .text,"ax",%progbits
	.p2align 2
	.globl dlfreeze_aarch64_lazy_plt_resolver
	.hidden dlfreeze_aarch64_lazy_plt_resolver
	.type dlfreeze_aarch64_lazy_plt_resolver, %function
	.hidden dlfreeze_aarch64_lazy_plt_fixup

/*
 * Native AArch64 PLT0 entry state:
 *
 *   x16        &GOT[2]
 *   x17        temporary resolver target
 *   [sp, #0]   address of the calling JUMP_SLOT
 *   [sp, #8]   original caller LR
 *
 * This is the base PCS trampoline.  Variant-PCS JUMP_SLOT references must be
 * resolved eagerly because preserving their SVE/SME/ZA state requires the
 * variant's complete (and extensible) register contract.
 */
dlfreeze_aarch64_lazy_plt_resolver:
	.cfi_startproc
	/* The caller's LR was spilled by PLT0 into the second synthetic word. */
	.cfi_def_cfa sp, 16
	.cfi_offset x30, -8
	/* BTI c, encoded directly so older assemblers can build this file. */
	.inst 0xd503245f

	/* 80 bytes for x0-x9 plus 128 bytes for q0-q7. */
	stp x8, x9, [sp, #-208]!
	.cfi_def_cfa_offset 224
	.cfi_offset x8, -224
	.cfi_offset x9, -216
	stp x6, x7, [sp, #16]
	.cfi_offset x6, -208
	.cfi_offset x7, -200
	stp x4, x5, [sp, #32]
	.cfi_offset x4, -192
	.cfi_offset x5, -184
	stp x2, x3, [sp, #48]
	.cfi_offset x2, -176
	.cfi_offset x3, -168
	stp x0, x1, [sp, #64]
	.cfi_offset x0, -160
	.cfi_offset x1, -152

	stp q0, q1, [sp, #80]
	.cfi_offset q0, -144
	.cfi_offset q1, -128
	stp q2, q3, [sp, #112]
	.cfi_offset q2, -112
	.cfi_offset q3, -96
	stp q4, q5, [sp, #144]
	.cfi_offset q4, -80
	.cfi_offset q5, -64
	stp q6, q7, [sp, #176]
	.cfi_offset q6, -48
	.cfi_offset q7, -32

	ldr x0, [x16, #-8]
	ldr x1, [sp, #208]
	bl dlfreeze_aarch64_lazy_plt_fixup
	mov x16, x0

	ldp q0, q1, [sp, #80]
	.cfi_restore q0
	.cfi_restore q1
	ldp q2, q3, [sp, #112]
	.cfi_restore q2
	.cfi_restore q3
	ldp q4, q5, [sp, #144]
	.cfi_restore q4
	.cfi_restore q5
	ldp q6, q7, [sp, #176]
	.cfi_restore q6
	.cfi_restore q7
	ldp x0, x1, [sp, #64]
	.cfi_restore x0
	.cfi_restore x1
	ldp x2, x3, [sp, #48]
	.cfi_restore x2
	.cfi_restore x3
	ldp x4, x5, [sp, #32]
	.cfi_restore x4
	.cfi_restore x5
	ldp x6, x7, [sp, #16]
	.cfi_restore x6
	.cfi_restore x7
	ldp x8, x9, [sp], #208
	.cfi_restore x8
	.cfi_restore x9
	.cfi_def_cfa_offset 16

	/* Remove PLT0's pair, restore the real return link, and tail-branch. */
	ldp x17, x30, [sp], #16
	.cfi_restore x30
	.cfi_def_cfa_offset 0
	br x16
	.cfi_endproc
	.size dlfreeze_aarch64_lazy_plt_resolver, .-dlfreeze_aarch64_lazy_plt_resolver

#else
#error "dlfreeze lazy PLT resolver is implemented only for x86-64 and AArch64"
#endif

	.section .note.GNU-stack,"",%progbits
