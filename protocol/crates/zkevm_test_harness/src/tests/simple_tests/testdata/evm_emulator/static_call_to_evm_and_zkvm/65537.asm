    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    log.swrite r0, r0, r0
    ret.ok r0 ; just return