        .text
        .file   "user_sets_blob_in_construction_then_static_calls"
        .rodata.cst32
        .p2align 5
    CPI0_0:
        .cell 65537
        .text
        .globl  __entry
    __entry:
    .main:
        ; System call to write blob hash with marker=1
        add 100000, r0, r1
        add 1, r0, r5
        shl.s 56, r5, r5
        add r5, r1, r1
        shl.s 192, r1, r1
        add 32770, r0, r2
        far_call r1, r2, @catch_all

        ; STATIC far call to address with marker=1
        add 100000, r0, r1
        shl.s 192, r1, r1
        add @CPI0_0[0], r0, r2
        far_call.static r1, r2, @catch_all
        ret.ok r0
    catch_all:
        ret.panic r0
