    .text
    .file   "Test_26"
    .rodata.cst32
    .p2align    5
CPI0_0:
    .cell 65536 ; not in kernel space
    .text
    .globl  __entry
__entry:
.main:

    add 1000, r0, r1
    shl.s 192, r1, r1

    add @CPI0_0[0], r0, r2

    context.ergs_left r9
    add r9, r0, stack[0]

    far_call r1, r2, @catch_all

    add stack[0], r0, r10
    context.ergs_left r9
    add r9, r0, stack[0]

    ret.ok r0

catch_all:
    ret.panic r0
