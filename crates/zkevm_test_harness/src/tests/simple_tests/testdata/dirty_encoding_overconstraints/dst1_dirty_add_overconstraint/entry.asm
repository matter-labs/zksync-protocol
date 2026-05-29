    .text
    .file   "dst1_dirty_add_overconstraint"
    .rodata.cst32
    .p2align 5
    .text
    .globl  __entry
__entry:
.main:
        ; r2 = 5
        add 5, r0, r2

        ; r1 = 7
        ; The test patches this instruction to set dst1_reg_idx = r2 (non-zero).
        add 7, r0, r1

        sub.s! 0, r2, r0
        jump.ne @panic

        ret.ok r0

panic:
        revert("r2 not clobbered")
