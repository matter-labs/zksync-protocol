        .text
        .file   "ret_panic_heap_growth_entry"
        .rodata.cst32
        .p2align 5
    CPI0_0:
        .cell 800000
        .text
        .globl  __entry
    __entry:
    .main:
        ; Record ergs before far_call for comparison.
        context.ergs_left r3

        ; Build far_call ABI: ergs=10000, forwarding_mode=0 (UseHeap).
        add 10000, r0, r1
        shl.s 192, r1, r1

        ; Call callee at address 800000 (loaded from constant pool
        ; because 800000 > 16-bit immediate limit).
        add @CPI0_0[0], r0, r2
        far_call r1, r2, @on_panic

        ; Should NOT reach here -- callee always panics.
        revert("should have panicked")

    on_panic:
        ; Callee panicked as expected.  Control returns to caller.
        ;
        ; In OOC: caller ergs are preserved (panic zeroed src0, no heap cost).
        ; In IC (buggy): caller ergs drained to 0 by u32::MAX heap growth
        ;   penalty applied to the pre-erasure src0 value.
        ;
        ; The ergs mismatch between OOC witness and IC constraints
        ; makes the batch unprovable.
        ;
        ; Verify we still have ergs (this passes in OOC but the proof
        ; itself will fail if the IC/OOC mismatch exists).
        context.ergs_left r4
        sub.s! r4, r0, r0
        jump.eq @no_ergs_left

        ; Ergs > 0 -- OOC execution is correct.
        ret.ok r0

    no_ergs_left:
        ; If ergs == 0 something went wrong even in OOC.
        revert("ergs drained to zero")
