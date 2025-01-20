    .text
    .file   "Test_26"
    .rodata.cst32
    .p2align    5
CPI0_0:
    .cell 65537
NOT_U32_MAX:
    .cell 4294963296
    .text
    .globl  __entry
__entry:
.main:

    near_call r0, @get_heap_bound, @panic

    add 500, r0, r1
    near_call r1, @grow_heap_by_far_calling, @continue_after

grow_heap_by_far_calling:
    add 100, r0, r1
    shl.s 96, r1, r1

    ; Length 2^32 
    add @NOT_U32_MAX[0], r1, r1
    shl.s 32, r1, r1

    add stack[0], r1, r1
    add 4050, r1, r1
    shl.s 64, r1, r1

    context.ergs_left r9
    add r9, r0, stack[0]

    ; Call function 65537 with fat pointer
    add @CPI0_0[0], r0, r2
    far_call r1, r2, @panic

continue_after:
    add stack[0], r0, r10
    context.ergs_left r9
    add r9, r0, stack[0]

    shl.s 96, r1, r1

    ret.ok r1

get_heap_bound:
    context.meta r5

    add 1, r0, r7
    shl.s 32, r7, r7
    sub.s 1, r7, r7

    shr.s 64, r5, r6
    and r6, r7, stack[0]

    ret.ok r0
    
panic:
    ret.panic r0
