    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    .cell 30272441630670900764332283662402067049651745785153368133042924362431065855
    .cell 30272434434303437454318367229716471635614919446304865000139367529706422272
CPI0_1:
    .cell 65536 
    .text
    .globl	__entry
__entry:
.main:
    add 64, r0, r2
    add @CPI0_0[0], r0, r3
    st.2.inc r2, r3, r2

    add @CPI0_0[1], r0, r3
    st.2 r2, r3

    add 2, r0, r1
    shl.s 32, r1, r1
    ; give 100k gas
    add 100000, r1, r1
    shl.s 96, r1, r1
    add 36, r1, r1
    shl.s 32, r1, r1
    add 64, r1, r1
    shl.s 64, r1, r1

    add @CPI0_1[0], r0, r2

    far_call r1, r2, @panic

    add 1, r0, r2
    shl.s 224, r2, r2
    ptr.pack r1, r2, r1

    ret.panic r0

panic:
    ret.ok r0
