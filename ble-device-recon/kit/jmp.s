@ jmp.s — 3 个 16 位字的长跳转桩，装在 0x120E32E8
@ b.w 是 Thumb-2 的 32 位编码，占 4 字节，正好和原指令 push {r4,lr} 同宽
    .syntax unified
    .thumb
    .text
    .global jmp
jmp:
    b.w 0x12070670
