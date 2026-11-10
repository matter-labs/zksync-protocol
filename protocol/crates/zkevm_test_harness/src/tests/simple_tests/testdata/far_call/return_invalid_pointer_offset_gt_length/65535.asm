    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:

    sstore r1, r1

    add 35, r0, r2
    ptr.shrink r1, r2, r1

    ; Set offset = 2, so offset > length (2 > 1)
    add 2, r0, r2
    ptr.add r1, r2, r1

    add 1, r0, r2
    shl.s 224, r2, r2
    ptr.pack r1, r2, r1

    ret.ok r1
