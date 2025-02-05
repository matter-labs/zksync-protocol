    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_1:
    .cell 65536
    .text
    .globl	__entry
__entry:
.main:
    add 10, r0, r2
    sstore r0, r2
    ret.ok r0