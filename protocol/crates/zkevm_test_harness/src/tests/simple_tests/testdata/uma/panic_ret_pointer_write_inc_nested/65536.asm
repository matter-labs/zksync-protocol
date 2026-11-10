    .text
    .file   "smart_callee"
    .text
    .globl  __entry
__entry:
.main:
    ; smart_callee - Panics on runtime calls
    ;
    ; This contract immediately panics when called.
    ; Panic RET from the global frame writes an empty fat pointer to r1 with is_pointer=true.
    ;
    ; This sets up the precondition for the UMA bug:
    ; - r1 = {value: 0, is_pointer: true}

    ret.panic r0
