    .text
    .file   "dst0_dst1_alias_add"
    .rodata.cst32
    .p2align 5
    .text
    .globl  __entry
__entry:
.main:
        ; r2 = 5
        add 5, r0, r2

        add 7, r0, r2

        ; eq flag set iff r2 == 0
        sub.s! 0, r2, r0
        jump.eq @ok

        ; Only the (buggy) OOC path where r2 == 7 reaches here.
        revert("r2 not zero")

ok:
        ret.ok r0
