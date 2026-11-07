/* motor_hook.ld — 把钩子定位到代码洞里，让 BL 的相对偏移算对
 *
 * 关键：BL/B.W 的编码是**相对当前 PC 的偏移**。如果链接时假定基址为 0，
 * objcopy 出来的二进制里偏移就是错的，运行到真实地址时会跳到垃圾地址上。
 * 必须让链接器知道真实基址，这是手写机器码最容易错的地方。
 *
 * 用法：
 *   arm-none-eabi-as  -mcpu=cortex-m33 -mthumb motor_hook.s -o hook.o
 *   arm-none-eabi-ld  -T motor_hook.ld hook.o -o hook.elf
 *   arm-none-eabi-objcopy -O binary -j .text hook.elf hook.bin
 */
ENTRY(hook)

SECTIONS
{
    /* 代码洞起点：紧邻内置计算器尾部，约 144B 可用 */
    . = 0x12070670;

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
