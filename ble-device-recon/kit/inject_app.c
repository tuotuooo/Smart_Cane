/*
 * inject_app.c — 在应用表里新增一个「Hello」应用
 *
 * 思路：不动原有 35 项，把其中一个**图标为 0（菜单里不可见）**的槽位
 *       （Dice，entry[30] @ 0x12324A44）改造成我们自己的应用：
 *         +0x00 id     = 0x10C      （保持不变，避免资源查找失败）
 *         +0x04 icon   = 0x129FDCD8 （借用计算器图标，保证菜单里能看见）
 *         +0x08 name   = "Hello"    （16 字节字段）
 *         +0x18 reg    = hello_regist|1
 *
 * 开机时框架遍历应用表、逐项调用 reg()，于是 hello_regist() 会被执行：
 *   gui_app_regist_msg_handler_ext("Hello", hello_handler, 0)
 * 把我们的 handler 注册进消息框架。点图标 -> 框架发 msg=0 -> 我们画 HELLO。
 *
 * 地址来源（均经反汇编语义确认）：
 *   0x1215A118  gui_app_regist_msg_handler_ext(name, handler, flag)
 *               内部 memcmp 16 字节名字；未命中则新建 0x90 字节注册项
 *   0x121A9730  lv_disp_get_scr_act(disp)
 *   0x121AA9A4  lv_label_create(parent)
 *   0x121AC008  lv_label_set_text(obj, text)
 *   0x1219EB14  lv_obj_set_pos(obj, x, y)
 *
 * 注意：Thumb 函数指针必须置 bit0。
 */

#include <stdint.h>

typedef void *(*fn_p1)(void *);
typedef void *(*fn_p2)(void *, int);
typedef void  (*fn_text)(void *, const char *);
typedef void  (*fn_pos)(void *, int, int);
typedef void  (*fn_reg)(const char *, void *, int);
typedef int   (*fn_handler)(int, int, int, int);

#define GET_SCR_ACT   ((fn_p1)0x121A9731)
#define LABEL_CREATE  ((fn_p2)0x121AA9A5)
#define LABEL_SET_TXT ((fn_text)0x121AC009)
#define OBJ_SET_POS   ((fn_pos)0x1219EB15)
#define APP_REGIST    ((fn_reg)0x1215A119)

static int hello_handler(int msg, int a, int b, int c)
{
    (void)a; (void)b; (void)c;

    if (msg == 0) {                     /* 0 == 建立界面 */
        void *scr = GET_SCR_ACT(0);
        if (scr) {
            void *lbl = LABEL_CREATE(scr, 0);
            if (lbl) {
                LABEL_SET_TXT(lbl, "HELLO");
                OBJ_SET_POS(lbl, 55, 100);
            }
        }
    }
    return 0;
}

/* 开机时被应用表调用，入口必须排在最前面 */
void hello_regist(void)
{
    APP_REGIST("Hello", (void *)hello_handler, 0);
}
