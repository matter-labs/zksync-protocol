        .text
        .file   "account_code_storage_shim"
        .rodata.cst32
        .p2align 5
    CPI0_0:
        .cell 65537
    CPI0_1:
        ; 0x02 0x01 ... (BlobSha256Format, marker=1)
        .cell 906392544231311161076231617881117198619499239097192525516383981263113945088
        .text
        .globl  __entry
    __entry:
    .main:
        add @CPI0_0[0], r0, r1
        add @CPI0_1[0], r0, r2
        log.swrite r1, r2, r0
        ret.ok r0
