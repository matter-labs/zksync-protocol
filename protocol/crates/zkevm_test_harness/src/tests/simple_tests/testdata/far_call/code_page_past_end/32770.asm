        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
        ; return ABI: 32 bytes of heap starting at 192, (32 << 96) | (192 << 64)
        .cell 2535301203998233665145640321024
        .text
        .globl	__entry
    __entry:
    .main:
        ; this contract sits at the deployer address, so X's versioned hash is in its own storage
        add 1, r0, r1
        shl.s 16, r1, r1
        sload r1, r1

        ; CodeOracle layout: the hash ends four bytes past X's five words of code, so bytes
        ; 160..164 survive the decommit below
        add 132, r0, r2
        st.1 r2, r1
        ; a copy for the caller
        add 192, r0, r2
        st.1 r2, r1

        log.decommit r1, r0, r3

        add @CPI0_0[0], r0, r1
        ret.ok r1
