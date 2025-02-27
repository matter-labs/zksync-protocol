        .text
        .file   "no_growth_on_overflow"
        .rodata.cst32
        .p2align	5
    HUGE_NUMBER:
        .cell 100000000
    HUGE_NUMBER_2:
        .cell 499999968
    U32_MAX:
        .cell 4294967295

        .text
        .globl  __entry
__entry:
        context.ergs_left r8
        add 30, r0, r1
        call r1, @step1, @step2
step1:
        add 1, r0, r5
        shl.s 64, r5, r5
        add @HUGE_NUMBER_2[0], r5, r5
        ld.1 r5, r0
step2:
        ; check ergs cost
        context.ergs_left r1
        sub r8, r1, r1
        sub! 66, r1, r0
        jump.ne @.panic_wrong_cost

        ; check heap size
        context.meta r1
        shr.s 64, r1, r1
        and @U32_MAX[0], r1, r1
        sub! @HUGE_NUMBER[0], r1, r0
        jump.lt @.panic_wrong_heap_size

        ret.ok r0

    .panic_wrong_cost:
        revert("should use 66 ergs")
    
    .panic_wrong_heap_size:
        revert("heap size should not be huge")
