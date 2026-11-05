/* 注入代码块的链接脚本：只输出 .text + .rodata，连续放在洞穴起始地址 */
ENTRY(my_handler)

SECTIONS
{
    . = 0x12070200;

    .text : ALIGN(4)
    {
        *(.text)
        *(.text*)
        *(.rodata)
        *(.rodata*)
        . = ALIGN(4);
    }

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.comment)
        *(.note*)
        *(.data*)
        *(.bss*)
        *(COMMON)
    }
}
