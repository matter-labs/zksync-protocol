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

    ; create ABI for far_call
    ; give 40k gas
    add 40000, r1, r1
    shl.s 192, r1, r1
    
    ; we are calling address 65537 which is out of EVM environment in static mode
    ; it will try to access storage and should fail
    add @CPI0_1[0], r0, r2
    far_call.static r1, r2, @expected_panic

    revert("Not panicked!")


expected_panic:
    add r0, r0, r1
    ; create ABI for far_call
    ; give 40k gas
    add 40000, r1, r1
    shl.s 192, r1, r1

    ; we are calling address 65537 which is out of EVM environment in non-static mode
    ; it will try to access storage
    add @CPI0_1[0], r0, r2
    far_call r1, r2, @panic
    
    ret.ok r0

panic:
    ret.panic r0