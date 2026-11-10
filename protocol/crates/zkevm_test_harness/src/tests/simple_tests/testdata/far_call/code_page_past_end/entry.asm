        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; A decommit page outlives the frame that filled it, and a later far call to the same
        ; hash runs from that page, code reads past the end of the bytecode included. The kernel
        ; at 32770 decommits X (65536) the way CodeOracle does, with X's hash straddling the end
        ; of X's code, and returns the hash. X then returns the code word one past its end, which
        ; must hold the last four bytes of the hash.

        ; far call the kernel with 100k gas and no calldata
        add 100000, r0, r1
        shl.s 192, r1, r1
        add 32770, r0, r2
        far_call r1, r2, @fail

        ; expected leftover: the hash's last four bytes at the top of the word
        ld r1, r3
        shl.s 224, r3, r3
        add r3, r0, stack[0]

        ; far call X (address 1 << 16) with 100k gas and no calldata
        add 100000, r0, r1
        shl.s 192, r1, r1
        add 1, r0, r2
        shl.s 16, r2, r2
        far_call r1, r2, @fail

        ld r1, r3
        sub! stack[0], r3, r0
        jump.ne @fail
        ret.ok r0

    fail:
        ret.panic r0
