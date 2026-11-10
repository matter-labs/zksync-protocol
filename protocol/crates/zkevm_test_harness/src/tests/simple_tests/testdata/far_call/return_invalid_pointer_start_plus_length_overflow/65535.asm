    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    ; start = 0xFFFF_FFF0, length = 0x30 => start + length overflows u32
    .cell 4294967280
    .text
    .globl	__entry
__entry:
.main:

    ; Return a fat pointer where start + length overflows.

    sstore r1, r1

    add 48, r0, r3
    shl.s 32, r3, r3
    add @CPI0_0[0], r3, r3
    shl.s 64, r3, r3

    ret.ok r3
