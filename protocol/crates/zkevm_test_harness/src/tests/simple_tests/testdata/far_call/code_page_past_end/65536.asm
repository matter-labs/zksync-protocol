        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
        ; return ABI: 32 bytes of heap starting at 0, 32 << 96
        .cell 2535301200456458802993406410752
        .text
        .globl	__entry
    __entry:
    .main:
        ; Assembled layout: two words of code, a zero word, this constant, the metadata word
        ; that makes the length odd. `@CPI0_0[r1]` with r1 = 2 is word 5, one past the end.
        add 2, r0, r1
        add @CPI0_0[r1], r0, r2
        st.1 r0, r2
        add @CPI0_0[0], r0, r1
        ret.ok r1
