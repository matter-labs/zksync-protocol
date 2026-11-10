    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_1:
    .cell 904625723324600433130593017022534769871285436503292405573848045861155580197
    .text
    .globl	__entry
CPI0_2:
    .cell 32786
    .text
    .globl	__entry
__entry:
.main:

    ; put data from CPI0_1 into AUX heap (st.2) 
    add 64, r0, r2
    add @CPI0_1[0], r0, r3
 
    log.decommit r3, r0, r0
    
    ret.ok r0