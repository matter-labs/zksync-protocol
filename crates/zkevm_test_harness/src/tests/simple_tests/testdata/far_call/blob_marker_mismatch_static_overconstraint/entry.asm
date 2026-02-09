        .text
        .file   "far_call_blob_marker_mismatch_static_overconstraint"
        .rodata.cst32
        .p2align 5
    CPI0_0:
        .cell 65536
        .text
        .globl  __entry
    __entry:
    .main:
        add 100000, r0, r1
        shl.s 192, r1, r1
        add @CPI0_0[0], r0, r2
        far_call r1, r2, @catch_all
        ret.ok r0
    catch_all:
        ret.panic r0
