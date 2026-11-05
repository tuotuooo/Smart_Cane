# kit —— 往原厂固件里塞自己编译的代码

不改镜像布局、不动启动链路，只做两件事：

1. 把自己编译出的机器码写进镜像里的**填充洞**；
2. 把某个**已有的函数指针 / 表项**改成指向它。

出问题时影响面被限制在"某一个功能异常"，GTX20 刷写通道仍在，能重刷回来。
（不要试图自己编完整固件替换：不带外设初始化的裸镜像 = 没有 BLE、没有画面、没有救砖通道。）

## 文件

| 文件 | 作用 |
|---|---|
| `inject_app.c` | **首选模板**：在应用表里占一个隐藏槽，注册自己的应用（菜单可见、点进去画自己的界面） |
| `inject_hello.c` | 备选模板：只替换某个已有 app 的 handler，原逻辑照跑，再叠一层自己的绘制 |
| `inject_app.ld` | 注入块链接脚本，基址 `0x12070300`，`ENTRY(hello_regist)` |
| `inject.ld` | 同上，基址 `0x120701CC`，供 handler 替换用 |
| `build_app.sh` | 编译 → 链接 → binary → 打印 flash 常量自检（含 thumb 位检查） |
| `build_inject.sh` | 同上，入口名参数化 |

## 构建

```bash
TC="/c/Program Files (x86)/Arm GNU Toolchain arm-none-eabi/14.2 rel1/bin"
cd ble-device-recon/kit
./build_app.sh inject_app.c hello_regist
#   build/inject_app.bin  100 字节
#   脚本会自动列出代码里出现的 flash 地址常量，缺 thumb 位的会标红
```

`-Ttext` / 链接脚本里的 `. = 0xADDR` **必须等于实际注入地址**，否则代码里的绝对常量全错位。
不能用 `--gc-sections`：没有外部引用，整个函数会被删成 0 字节。

## 打补丁 + 刷写

```bash
python ../scripts/sifli_fw_patch.py --image fw.bin -o out.bin \
    --inject 0x12070300=build/inject_app.bin \
    --set 0x12324A60=391FD812 --set 0x12324A5C=...      # 应用表项字段（见 sifli_apptab.py）
python ../scripts/sifli_i18n.py   --image out.bin -o out2.bin \
    --put-str 0x12070400=HELLO --set-addr 0x122933FC=0x12070400
python ../scripts/sifli_fw_pack.py --keys <sifli02目录> --image out2.bin \
    --fw-ver 1001099 -o pkg
python ../scripts/sifli_ota_push.py ...                 # 见 sifli_ota.md §十一
```

更省事的写法：应用表用 `sifli_apptab.py --entry Dice --icon ... --reg ...`，
菜单标签用 `sifli_i18n.py --put-str / --set-addr`，别手算十六进制。

## 三个必踩的坑

1. **函数指针必须带 thumb 位**（`addr | 1`）。少了它 `blx` 按 ARM 态跳转，直接 HardFault。
2. **`--set` 的字节序是内存序**。`0x12070341` 要写成 `41030712`，写成 `41037012`
   就变成 `0x12700341`（镜像外），必崩。打完补丁一定回读校验。
3. **改 `name[16]` 不会改菜单文字**。菜单文字来自 i18n 表（`sifli_i18n.py`），
   `name` 只用于内部匹配。字节全对、现象全错，就是这类。

## 洞在哪

```bash
python ../scripts/sifli_cave.py --image fw.bin --min 256
```

实测这份镜像只有三块：`0x120701CC`(1524B)、`0x12365E29`(951B)、`0x123537C6`(530B)。
第一块在向量表的未使用 IRQ 槽里，硬件永不取指，最干净。放了 HELLO 示例后仍余约 1.2KB。
