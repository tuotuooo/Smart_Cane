/*
 * calculator.c — 自研计算器（16 键 / 四则运算），零隐藏状态
 *
 * 编译：照 build_app.sh（-Os -mthumb），-Ttext 必须等于实际注入地址。
 * 本模板按 0x120701D0 编排，产物 1140 字节，占 0x120701D0..0x12070643
 * （代码洞上限 0x12070700，后面 0x12070700 起是菜单字符串区）。
 *
 * 挂载：把某个隐藏槽的 reg 字段指向 (t_regist | 1)。
 *       ⚠️ 该槽 name[16] 必须与下面 N_HELLO 的 16 字节完全一致，否则 handler 不登记、
 *          点进去是空白页且不崩溃（memcmp 16 字节，见 surgery §11.3）。
 *
 * 核心思路：不往任何对象字段里写数据。
 *   - 容器       = GET_PARENT(btn)          <- 回调参数直接给
 *   - 显示区 label = *(cont + 0x0C)          <- tail，因为 disp 最先建，而 ll 是 ins_head
 *   - 显示文本    = *(char**)GET_EXT(disp)   <- ext->text @ ext+0x00
 *   - 运算状态    = 显示文本本身（"12+3" 按 = 就地解析求值）
 *
 * 这样彻底避开 user_data：固件把子链表 meta 放在块尾，obj 基址就是 malloc 起始，
 * 所以 obj+0x08/0x0C 直接就是对象指针，不需要再 +8。
 */
#include <stdint.h>

typedef void *(*fn_p1)(void *);
typedef void *(*fn_p2)(void *, int);
typedef void  (*fn_txt)(void *, const char *);
typedef void  (*fn_size)(void *, int, int);
typedef void  (*fn_align)(void *, void *, int, int, int);
typedef void  (*fn_cb)(void *, void *);
typedef void  (*fn_reg)(const char *, void *, int);
typedef int   (*fn_i1)(void *);

#define GET_SCR_ACT  ((fn_p1)0x121A9731)
#define OBJ_CREATE   ((fn_p2)0x121ABE81)   /* 官方建外层容器用的就是它 */
#define BTN_CREATE   ((fn_p2)0x121A3B1D)
#define LABEL_CREATE ((fn_p2)0x121AA9A5)
#define SET_TXT      ((fn_txt)0x121AC009)
#define SET_SIZE     ((fn_size)0x121B1FA1)
#define ALIGN        ((fn_align)0x121B3449)
#define SET_CB       ((fn_cb)0x121ABE25)
#define REGIST       ((fn_reg)0x1215A119)
#define GET_PARENT   ((fn_p1)0x121B2119)
#define GET_EXT      ((fn_p1)0x121B406D)
#define GET_W        ((fn_i1)0x121A9901)
#define GET_H        ((fn_i1)0x121B2C0D)

#define OFF_HEAD 0x08    /* child_ll.head */
#define OFF_TAIL 0x0C    /* child_ll.tail */

/* 官方计算器参数：按键 88x58，列距 94，行距 66，起点 (10,81) */
#define KW   88
#define KH   58
#define CX0  10
#define CY0  81
#define CDX  94
#define CDY  66

#define ALIGN_TL  1      /* LV_ALIGN_IN_TOP_LEFT */
#define ALIGN_CEN 0      /* LV_ALIGN_CENTER */
#define EV_CLICK  7

static const char KS[16][2] = {
    "7", "8", "9", "/",
    "4", "5", "6", "*",
    "1", "2", "3", "-",
    "C", "0", "=", "+"
};

/* ---------------- 数字 -> 字符串 ---------------- */
static char *ntoa(char *p, int v)
{
    char t[14];
    int n = 0;
    unsigned u;

    if (v < 0) { *p++ = '-'; u = (unsigned)(-v); }
    else       { u = (unsigned)v; }
    if (!u) { *p++ = '0'; return p; }
    while (u) { t[n++] = (char)('0' + (int)(u % 10u)); u /= 10u; }
    while (n) *p++ = t[--n];
    return p;
}

static int isd(char c) { return c >= '0' && c <= '9'; }

/* ---------------- 解析 "A op B" ---------------- */
static int ev1(const char *s, int *out)
{
    int a = 0, b = 0;
    int i = 0, nb = 0;
    char op;

    while (isd(s[i])) { a = a * 10 + (s[i] - '0'); i++; }
    if (!s[i]) { *out = a; return 1; }
    op = s[i++];
    while (isd(s[i])) { b = b * 10 + (s[i] - '0'); i++; nb++; }
    if (!nb) return 0;

    switch (op) {
    case '+': *out = a + b; break;
    case '-': *out = a - b; break;
    case '*': *out = a * b; break;
    case '/': if (!b) return 0; *out = a / b; break;
    default:  return 0;
    }
    return 1;
}

/* ---------------- 按键主逻辑 ---------------- */
static void __attribute__((noinline)) key(char kc, void *btn, void *ev)
{
    void *cont, *disp, *ext;
    const char *t;
    char buf[32], *p;
    int i, len, opi, hasop, hasb;
    int v;

    if ((int)ev != EV_CLICK) return;

    cont = GET_PARENT(btn);
    if (!cont) return;
    disp = *(void **)((char *)cont + OFF_TAIL);      /* disp 最先建 -> tail */
    if (!disp) return;
    ext = GET_EXT(disp);
    if (!ext) return;
    t = *(const char **)ext;
    if (!t) t = "0";

    if (kc == 'C') { SET_TXT(disp, "0"); return; }

    len = 0; while (t[len]) len++;

    /* 找最后一个运算符 */
    opi = -1; hasop = 0;
    for (i = 0; i < len; i++) {
        char c = t[i];
        if (c == '+' || c == '-' || c == '*' || c == '/') { opi = i; hasop = 1; }
    }
    hasb = 0;
    if (hasop) {
        for (i = opi + 1; i < len; i++) if (isd(t[i])) { hasb = 1; break; }
    }

    if (kc == '=') {
        if (!ev1(t, &v)) return;
        p = ntoa(buf, v); *p = 0;
        SET_TXT(disp, buf);
        return;
    }

    if (kc == '+' || kc == '-' || kc == '*' || kc == '/') {
        if (hasop && hasb) {                 /* 已有 A op B -> 先算 */
            if (!ev1(t, &v)) return;
            p = ntoa(buf, v);
        } else if (hasop) {                  /* 只有 "A op" -> 换掉运算符 */
            for (i = 0; i < opi; i++) buf[i] = t[i];
            p = buf + opi;
        } else {                             /* 只有 "A" -> 追加运算符 */
            for (i = 0; i < len; i++) buf[i] = t[i];
            p = buf + len;
        }
        *p++ = kc; *p = 0;
        SET_TXT(disp, buf);
        return;
    }

    /* 数字键 */
    if (hasop) {                             /* 追加到第二操作数 */
        if (len - opi - 1 >= 9) return;
        for (i = 0; i < len; i++) buf[i] = t[i];
        buf[len] = kc; buf[len + 1] = 0;
        SET_TXT(disp, buf);
        return;
    }
    if (len == 1 && t[0] == '0') { buf[0] = kc; buf[1] = 0; SET_TXT(disp, buf); return; }
    if (len >= 9) return;
    for (i = 0; i < len; i++) buf[i] = t[i];
    buf[len] = kc; buf[len + 1] = 0;
    SET_TXT(disp, buf);
}

/* ---------------- 16 个按键 thunk ---------------- */
static void k0(void *b, void *e)  { key('7', b, e); }
static void k1(void *b, void *e)  { key('8', b, e); }
static void k2(void *b, void *e)  { key('9', b, e); }
static void k3(void *b, void *e)  { key('/', b, e); }
static void k4(void *b, void *e)  { key('4', b, e); }
static void k5(void *b, void *e)  { key('5', b, e); }
static void k6(void *b, void *e)  { key('6', b, e); }
static void k7(void *b, void *e)  { key('*', b, e); }
static void k8(void *b, void *e)  { key('1', b, e); }
static void k9(void *b, void *e)  { key('2', b, e); }
static void k10(void *b, void *e) { key('3', b, e); }
static void k11(void *b, void *e) { key('-', b, e); }
static void k12(void *b, void *e) { key('C', b, e); }
static void k13(void *b, void *e) { key('0', b, e); }
static void k14(void *b, void *e) { key('=', b, e); }
static void k15(void *b, void *e) { key('+', b, e); }

static void (*const KCBS[16])(void *, void *) = {
    k0, k1, k2, k3, k4, k5, k6, k7,
    k8, k9, k10, k11, k12, k13, k14, k15
};

/* ---------------- 建界面 ---------------- */
static int __attribute__((noinline)) build(void)
{
    void *scr, *cont, *disp, *btn, *kl;
    int w, h, i;

    scr = GET_SCR_ACT(0);
    if (!scr) return 0;

    w = GET_W(0);
    h = GET_H(0);
    if (w < 100) w = 390;
    if (h < 100) h = 450;

    cont = OBJ_CREATE(scr, 0);
    if (!cont) return 0;
    SET_SIZE(cont, w, h);

    disp = LABEL_CREATE(cont, 0);
    if (!disp) return 0;
    SET_TXT(disp, "0");
    ALIGN(disp, cont, ALIGN_TL, 10, 20);

    for (i = 0; i < 16; i++) {
        btn = BTN_CREATE(cont, 0);
        if (!btn) break;
        SET_SIZE(btn, KW, KH);
        ALIGN(btn, cont, ALIGN_TL, CX0 + (i & 3) * CDX, CY0 + (i >> 2) * CDY);

        kl = LABEL_CREATE(btn, 0);
        if (kl) { SET_TXT(kl, KS[i]); ALIGN(kl, btn, ALIGN_CEN, 0, 0); }

        SET_CB(btn, KCBS[i]);
    }
    return 0;
}

static int h_calc(int m, int a, int b, int c)
{
    (void)a; (void)b; (void)c;
    if (m) return 0;
    return build();
}

static const char N_HELLO[16] = "Hello";

void t_regist(void) { REGIST(N_HELLO, (void *)h_calc, 0); }
