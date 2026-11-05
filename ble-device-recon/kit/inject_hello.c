/*
 * inject_hello.c — 最小验证：把计算器的 handler 换成"原逻辑 + 一个 HELLO 标签"
 *
 * 目标：证明我们自己编译的 C 代码能在原厂固件的 app 框架里被执行，并且能调通 LVGL。
 *
 * 注入方式（零代码改动）：
 *   Calculator 的注册函数 0x120B0584 只有 4 条有效指令：
 *       push {r7,lr}
 *       ldr  r1, [pc,#0x18]        ; 槽 0x120B05A0 = 0x122199D5 (原 handler)
 *       adr  r0, "Calculator"
 *       movs r2, #0
 *       bl   gui_app_regist_msg_handler_ext
 *   把那个池槽的 4 字节换成 my_handler|1 即可，原 handler 原封不动保留。
 *
 * 策略：先调原 handler（保证计算器界面照常出现），再在 act_scr 上叠加一个标签。
 *   若屏幕出现"计算器 + HELLO"，即证明：我们编译的机器码被执行了，且 LVGL 调用链正确。
 *
 * 地址来源（全部由反汇编语义确认，非符号表猜测）：
 *   0x121A9730  lv_disp_get_scr_act(d)
 *               push {r7,lr}; cbnz r0,+; bl lv_disp_get_default; cbz r0,ret0;
 *               ldr r0,[r0,#0x64]; pop {r7,pc}          ← disp->act_scr
 *   0x121AA9A4  lv_label_create(parent)
 *               handler 里 create(容器) 紧接着 set_text(返回值, 字符串)
 *   0x121AC008  lv_label_set_text(obj, text)
 *               mov r5,r0 (obj) / mov sl,r1 (text)
 *   0x1219EB14  lv_obj_set_pos(obj, x, y)
 *               mov r4,r1 / mov r5,r0
 *
 * 注意：Thumb 函数指针必须置 bit0，否则 blx 会按 ARM 状态跳转 -> HardFault。
 */

#include <stdint.h>

typedef void *(*fn_p1)(void *);
typedef void *(*fn_p2)(void *, int);
typedef void  (*fn_text)(void *, const char *);
typedef void  (*fn_pos)(void *, int, int);
typedef int   (*fn_handler)(int, int, int, int);

#define ORIG_HANDLER  ((fn_handler)0x122199D5)   /* 原计算器 handler */
#define GET_SCR_ACT   ((fn_p1)0x121A9731)
#define LABEL_CREATE  ((fn_p2)0x121AA9A5)
#define LABEL_SET_TXT ((fn_text)0x121AC009)
#define OBJ_SET_POS   ((fn_pos)0x1219EB15)

int my_handler(int msg, int a, int b, int c)
{
    /* 先跑原逻辑：计算器界面照常建立 / 销毁 */
    int r = ORIG_HANDLER(msg, a, b, c);

    /* msg 0 == 建立界面。此时再往根屏幕叠加一个标签 */
    if (msg == 0) {
        void *scr = GET_SCR_ACT(0);
        if (scr) {
            void *lbl = LABEL_CREATE(scr, 0);
            if (lbl) {
                LABEL_SET_TXT(lbl, "HELLO");
                OBJ_SET_POS(lbl, 40, 70);
            }
        }
    }
    return r;
}
