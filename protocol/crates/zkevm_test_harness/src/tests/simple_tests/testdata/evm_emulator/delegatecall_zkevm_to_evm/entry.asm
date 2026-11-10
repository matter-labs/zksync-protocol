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
    ; create ABI for far_call
    ; give 60k gas
    add 60000, r1, r1
    shl.s 192, r1, r1
    
    ; we are delegatecalling address 65536 where we have EVM contract

    add @CPI0_1[0], r0, r2
    far_call.delegate r1, r2, @catch_all

    log.sread r0, r0, r5
    ; assert r5 == 10
    sub! 10, r5, r0
    jump.ne @.panic

    ret.ok r0

catch_all:
    ret.panic r0

.panic:
    revert("Invalid value in storage")