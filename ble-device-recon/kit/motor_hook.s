@ motor_hook.s — 在 HCPU 核间消息分发器入口插"振一下"的钩子
@
@ 目标：不改 App、不依赖 BLE 协议细节，让设备在收到任意 IPC 消息时振动一次，
@      用来验证"注入链路是否打通"。验证通过后再收窄触发条件。
@
@ 挂载点  0x120E32E8  原指令 10 b5 42 88 = push {r4,lr} + ldrh r2,[r0,#2]，正好 4 字节
@         改写成 b.w hook
@ 代码洞  0x12070670  紧邻内置计算器尾部，约 144B 全零
@ 返回点  0x120E32EC  分发器第 3 条指令
@
@ 为什么用 app_motor_control 而不是 vib_start：
@   app_motor_control 直接 rt_device_control(dev, 0x23, &mode)，无队列、可重入；
@   vib_start 内部 rt_mq_send，在分发上下文里会死锁。
@
@ 构建：
@   arm-none-eabi-as -mcpu=cortex-m55 -mthumb motor_hook.s -o hook.o
@   arm-none-eabi-objcopy -O binary -j .text hook.o hook.bin
@   arm-none-eabi-as -mcpu=cortex-m55 -mthumb jmp.s -o jmp.o
@   arm-none-eabi-objcopy -O binary -j .text jmp.o jmp.bin
@   再用 sifli_fw_patch.py 把 jmp.bin 写进 0x120E32E8、hook.bin 写进 0x12070670

    .syntax unified
    .thumb
    .text

    .set MOTOR,   0x120B3C98        @ app_motor_control(mode): 1=启动 0=停止
    .set RESUME,  0x120E32EC        @ 分发器第 3 条指令
    .set DELAY,   0x00100000        @ 忙等次数，按主频折算实际时长

    .global hook
    .type hook, %function
hook:
    @ ---- 现场保护：必须保持 8 字节栈对齐（push 6 个寄存器 = 24B）
    push    {r0-r3, r7, lr}

    @ ---- 马达开
    movs    r0, #1
    bl      MOTOR

    @ ---- 忙等。分发上下文里不要用 rt_thread_mdelay。
    ldr     r7, =DELAY
1:  subs    r7, r7, #1
    bne     1b

    @ ---- 马达关
    movs    r0, #0
    bl      MOTOR

    @ ---- 还现场（注意 lr 是单独从栈上取的，因为要先恢复原 push 的效果）
    pop     {r0-r3, r7}
    ldr.w   lr, [sp]
    add     sp, sp, #4

    @ ---- 原样补回被 b.w 覆盖掉的两条指令
    push    {r4, lr}
    ldrh    r2, [r0, #2]

    b.w     RESUME

    .ltorg
    .size hook, .-hook
