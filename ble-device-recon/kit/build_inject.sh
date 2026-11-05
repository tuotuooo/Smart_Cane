#!/usr/bin/env bash
# 构建注入代码块（塞进原厂固件代码洞，不是完整镜像）
#
#   ./build_inject.sh inject_hello.c my_handler
#
# 产物：build/<name>.bin   直接喂给 fw_patch.py --inject
#
# 要点：
#   1. -Ttext 必须等于实际注入地址，代码里的绝对常量才对齐
#   2. 不能用 --gc-sections（没有入口引用，整个函数会被删成 0 字节）
#   3. 只导出 .text + .rodata，链接脚本把两者放在一起，字符串才不会丢

set -euo pipefail

TC="${TC:-/c/Program Files (x86)/Arm GNU Toolchain arm-none-eabi/14.2 rel1/bin}"
export PATH="$TC:$PATH"

SRC="${1:-inject_hello.c}"
ENTRY_FN="${2:-my_handler}"
NAME="$(basename "${SRC%.c}")"
OBJ="build/${NAME}.o"
ELF="build/${NAME}.elf"
BIN="build/${NAME}.bin"

mkdir -p build

CPU="-mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16"
CFLAGS="$CPU -Os -Wall -Wextra -std=gnu11 -ffreestanding -nostdlib -fno-common -fno-pic -fno-stack-protector"

echo "  CC  $SRC"
arm-none-eabi-gcc $CFLAGS -c "$SRC" -o "$OBJ"

echo "  LD  $ELF"
arm-none-eabi-gcc $CPU -nostartfiles -T inject.ld \
    -Wl,-e,"$ENTRY_FN" -Wl,--undefined="$ENTRY_FN" \
    "$OBJ" -o "$ELF"

echo "  BIN $BIN"
arm-none-eabi-objcopy -O binary "$ELF" "$BIN"

arm-none-eabi-size "$ELF"
echo "--- 反汇编"
arm-none-eabi-objdump -d "$ELF" | sed -n '/<'"$ENTRY_FN"'>:/,$p' | head -60

python - "$BIN" "$ENTRY_FN" <<'PY'
import sys, struct
p, fn = sys.argv[1], sys.argv[2]
d = open(p, 'rb').read()
print("\n  %s = %d 字节" % (p, len(d)))
print("  首 16 字节: %s" % d[:16].hex(' '))
# 检查代码里出现的 flash 地址常量（应是 0x121xxxxx/0x122199D5 等，且为奇数）
consts = []
for i in range(0, len(d) - 3, 2):
    v = struct.unpack_from('<I', d, i)[0]
    if 0x12070000 <= v < 0x12370000:
        consts.append((i, v))
print("  代码内 flash 地址常量 %d 处:" % len(consts))
for off, v in consts[:12]:
    print("    +0x%03X = 0x%08X  %s" % (off, v, "thumb位OK" if v & 1 else "!! 缺 thumb 位"))
print("  洞穴: 0x12070200..0x120707C0 共 %d 字节，本次占用 %d，余 %d"
      % (0x7C0 - 0x200, len(d), 0x7C0 - 0x200 - len(d)))
PY
