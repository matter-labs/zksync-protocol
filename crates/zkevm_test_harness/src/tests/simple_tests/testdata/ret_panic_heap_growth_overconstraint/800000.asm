        .text
        .file   "ret_panic_heap_growth_callee"
        .rodata.cst32
        .p2align 5
        .text
        .globl  __entry
    __entry:
    .main:
        ; Construct crafted quasi-fat-pointer in r1:
        ;   bits[64:95]  = start  = 0xFFFFFFFF
        ;   bits[96:127] = length = 0x00000001
        ;   byte[28]     = 0x00   (UseHeap -> do_not_forward_ptr = true)
        ;
        ; start + length = 0xFFFFFFFF + 1 overflows u32
        ;   -> is_non_addressable = true in IC
        ;   -> penalize_heap_overflow = true -> upper_bound = u32::MAX -> ergs = 0
        ;
        ; OOC zeroes src0 before parsing -> growth_cost = 0 -> ergs preserved

        ; Build 0xFFFFFFFF = (1 << 32) - 1
        add     1, r0, r1
        shl.s   32, r1, r1
        sub.s   1, r1, r1
        ; r1 = 0x0000...FFFFFFFF

        ; Shift to start field position (bits 64-95)
        shl.s   64, r1, r1
        ; r1 = 0xFFFFFFFF_00000000_00000000

        ; Build length = 1 at bits 96-127
        add     1, r0, r2
        shl.s   96, r2, r2
        ; r2 = 1 << 96

        ; Combine start and length
        add     r2, r1, r1
        ; r1 = (0xFFFFFFFF << 64) | (1 << 96)
        ;     = start=0xFFFFFFFF, length=1, offset=0, page=0

        ; ret.panic with crafted src0
        ; OOC: zeroes r1 before parsing -> heap growth = 0
        ; IC:  parses original r1 -> start+length overflow -> penalty -> ergs = 0
        ret.panic r1
