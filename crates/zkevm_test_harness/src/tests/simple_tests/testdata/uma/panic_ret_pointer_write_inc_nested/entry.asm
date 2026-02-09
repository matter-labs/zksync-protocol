    .text
    .file   "smart_wrapper"
    .rodata.cst32
    .p2align    5
CPI0_0:
    ; Worker address (smart_worker)
    .cell 65537
    .text
    .globl  __entry
__entry:
.main:
    ; smart_wrapper - Catches panic, writes different values based on path
    ;
    ; This contract far_calls the worker (65537) and catches any panic.
    ; The two paths write different values to storage slot 0:
    ; - SUCCESS PATH (circuit only - vulnerable): writes 1
    ; - PANIC PATH (VM, and fixed circuit): writes 2
    ;
    ; This makes the divergence detectable: witness mismatch causes prover panic.

    ; Setup far_call ABI: give worker 200k gas
    add 200000, r0, r1
    shl.s 192, r1, r1

    add @CPI0_0[0], r0, r2
    far_call r1, r2, @exception_handler

    ; SUCCESS PATH (circuit only - vulnerable)
    ; Write 1 to storage slot 0
    add 1, r0, r2
    sstore r0, r2
    ret.ok r0

exception_handler:
    ; PANIC PATH (VM, and fixed circuit)
    ; Write 2 to storage slot 0
    add 2, r0, r2
    sstore r0, r2
    ret.ok r0
