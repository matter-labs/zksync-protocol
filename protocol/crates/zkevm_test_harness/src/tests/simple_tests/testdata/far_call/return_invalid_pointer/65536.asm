    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:

    sstore r1, r1

    add 0, r0, r1
    shl.s 136, r1, r1
    ; length 2048
    add 2048, r1, r1
    shl.s 32, r1, r1
    ; start at 128
    add 128, r1, r1
    shl.s 32, r1, r1
    shl.s 32, r1, r1
    add 1, r1, r1

    ret.ok r1
