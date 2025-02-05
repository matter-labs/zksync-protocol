    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_1:
    .cell 65537
    .text
    .globl	__entry
__entry:
.main:
    ; we aren't in static mode since it is EVM environment
    log.swrite r0, r0, r0

    ret.ok r0