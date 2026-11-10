    .text
    .file   "smart_worker"
    .rodata.cst32
    .p2align    5
CPI0_0:
    ; Callee address (smart_callee)
    .cell 65536
    .text
    .globl  __entry
__entry:
.main:
    ; smart_worker - Triggers the UMA HeapWrite+Increment pointer marker bug
    ;
    ; Flow:
    ; 1) far_call -> callee (65536) which panics
    ; 2) After panic, r1 = {value: 0, is_pointer: true}
    ; 3) st.1.inc r1, r2, r3 - BUG: circuit preserves is_pointer=true, VM clears to false
    ; 4) ptr.add r3, r0, r4 - VM panics (r3.is_pointer=false), circuit continues (r3.is_pointer=true)
    ;
    ; Result:
    ; - VM: panics at ptr.add, caught by wrapper's exception_handler
    ; - Circuit (pre-fix): continues past ptr.add, returns normally to wrapper's success path

    ; Far call to callee which panics
    add 0, r0, r1
    shl.s 192, r1, r1
    add @CPI0_0[0], r0, r2
    far_call r1, r2, @inner_exception

    ; Should not reach here (callee panics)
    ret.ok r0

inner_exception:
    ; After panic, r1 = {value: 0, is_pointer: true}
    add 66, r0, r2

    ; st.1.inc: BUG - circuit preserves is_pointer=true, VM clears to false
    st.1.inc r1, r2, r3

    ; ptr.add: VM panics (r3.is_pointer=false), circuit continues (r3.is_pointer=true)
    ptr.add r3, r0, r4

    ; If we reached here, we're on the circuit-only path (vulnerable behavior)
    ret.ok r0
