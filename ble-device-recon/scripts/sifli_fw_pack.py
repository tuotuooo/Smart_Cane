#!/usr/bin/env python3
"""SiFli SF32LB551 (悦心S1) DFU V2 固件包打包器

格式全部来自真机抓包实测 + 官方 imgtool 交叉验证：

  ctrl_packet (605 字节)
    [0:2]   hash_len  = 32
    [2:4]   packet_len= 601
    [4:36]  SHA256(control)
    [36:349] AES-256-CTR(control)      key=s01.bin  IV=sig_hash[:8]+b"\\0"*4  init=0
    [349:605] RSA-2048(PKCS#1 v1.5) 签名，签的是 [4:36]

  control (313 字节)
    dfu_id(1) hw_ver(4) sdk_ver(4) fw_ver(4) session_key(32)
    hdr_len(2) bksize(2) img_count(1)
    img_count × [ img_sig(256) img_len(4) flag(2) id(1) ]   ← 263 字节/项

  img_sig 签的是 SHA256(镜像补 0 到 img_len)

  data block (558 字节 payload)
    0A | flashid | 554(u32) | seq(u16) | 548(u16) | sha256(32) | offset(u32) | data(512)

用法：
  python fw_pack.py --check                       # 用官方参数重生成，和抓包比对
  python fw_pack.py --image my.bin --fw-ver 1001002 -o my_pkg
"""
import struct, hashlib, argparse, os, sys

# 密钥目录：官方 SDK 的 tools/secureboot/sifli02（含 s01.bin / sig_hash.bin / sig_pri.pem / sig_pub.pem）
# 可用 --keys 或环境变量 SIFLI_KEYS 覆盖
KS = os.environ.get("SIFLI_KEYS") or os.path.join(
    os.path.expanduser("~"), "sifli_sdk", "sb", "sifli02")
BLK = 512


def load_keys():
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    key = open(os.path.join(KS, "s01.bin"), "rb").read()
    sig_hash = open(os.path.join(KS, "sig_hash.bin"), "rb").read()
    pri = load_pem_private_key(open(os.path.join(KS, "sig_pri.pem"), "rb").read(), password=None)
    pub = load_pem_public_key(open(os.path.join(KS, "sig_pub.pem"), "rb").read())
    return key, sig_hash, pri, pub


def sign_digest(pri, digest32):
    """对 32 字节摘要做 PKCS#1 v1.5 签名（等价 imgtool 的 sign(hash)，摘要不再二次哈希）。"""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    return pri.sign(digest32, padding.PKCS1v15(), Prehashed(hashes.SHA256()))


def verify_digest(pub, digest32, sig):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    pub.verify(sig, digest32, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    return True


def aes_ctr(key, sig_hash, data, decrypt=False):
    """AES-256-CTR，IV = sig_hash[:8] + 12 字节大端计数器(从 0 起)。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = sig_hash[:8] + b"\x00" * 8
    c = Cipher(algorithms.AES(key), modes.CTR(iv))
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()


def build_control(dfu_id, hw_ver, sdk_ver, fw_ver, session_key, bksize, imgs):
    """imgs = [(sig256, img_len, flag, id), ...]"""
    c = struct.pack("<B", dfu_id)
    c += struct.pack("<I", hw_ver)
    c += struct.pack("<I", sdk_ver)
    c += struct.pack("<I", fw_ver)
    c += session_key
    c += struct.pack("<H", 266)          # hdr_len，实测固定 266
    c += struct.pack("<H", bksize)
    c += struct.pack("<B", len(imgs))
    for sig, ln, flag, iid in imgs:
        c += sig + struct.pack("<I", ln) + struct.pack("<H", flag) + struct.pack("<B", iid)
    return c


def build_ctrl_packet(control, key, sig_hash, pri):
    h = hashlib.sha256(control).digest()
    enc = aes_ctr(key, sig_hash, control)
    sig = sign_digest(pri, h)
    body = h + enc + sig
    return struct.pack("<HH", 32, len(body)) + body


def image_to_blocks(img, flashid=0, seq0=1):
    """切块。尾块按真实长度，不补齐（实测尾块 480B，blklen=516）。"""
    out = []
    n = (len(img) + BLK - 1) // BLK
    for i in range(n):
        chunk = img[i * BLK:(i + 1) * BLK]
        body = struct.pack("<BB", 0x0A, flashid)
        body += struct.pack("<I", 6 + 32 + 4 + len(chunk))
        body += struct.pack("<H", seq0 + i)
        body += struct.pack("<H", 32 + 4 + len(chunk))
        body += hashlib.sha256(chunk).digest()
        body += struct.pack("<I", i * BLK)
        body += chunk
        out.append(body)
    return out


def fragment(body):
    parts = [bytes([1, 1]) + struct.pack("<H", len(body)) + body[:240]]
    pos = 240
    while pos < len(body):
        seg = body[pos:pos + 242]
        pos += len(seg)
        parts.append(bytes([1, 3 if pos >= len(body) else 2]) + seg)
    return parts


def check():
    """用官方参数重生成 ctrl_packet，与抓包逐字节比对（session_key 用抓包值）。"""
    key, sig_hash, pri, pub = load_keys()
    p = open(os.path.join("ota_capture", "ctrl_0_605.bin"), "rb").read()
    control = aes_ctr(key, sig_hash, p[36:349], decrypt=True)
    assert hashlib.sha256(control).digest() == p[4:36], "control 解密后 SHA256 不匹配"

    sess = control[13:45]
    img = open(os.path.join("ota_capture", "fw_image_full.bin"), "rb").read()
    img_len = struct.unpack("<I", control[306:310])[0]
    print(f"  control 解密 OK: {len(control)}B  dfu_id={control[0]} "
          f"hw={struct.unpack('<I',control[1:5])[0]} sdk={struct.unpack('<I',control[5:9])[0]} "
          f"fw={struct.unpack('<I',control[9:13])[0]} img_len={img_len:,} 实际={len(img):,}")
    assert img_len == len(img), f"img_len {img_len} != 镜像长度 {len(img)}"
    isig = sign_digest(pri, hashlib.sha256(img).digest())
    print("  镜像签名匹配抓包内嵌签名:", isig == control[50:306])
    ctrl2 = build_control(control[0], *[struct.unpack("<I", control[i:i+4])[0] for i in (1, 5, 9)],
                          sess, 512, [(isig, img_len, control[310] | (control[311] << 8), control[312])])
    print("  control 重建一致:", ctrl2 == control, f"({len(ctrl2)} vs {len(control)})")
    pkt = build_ctrl_packet(ctrl2, key, sig_hash, pri)
    print("  ctrl_packet 重建:", len(pkt), "字节   与抓包完全一致:", pkt == p)
    if pkt != p:
        for i in range(min(len(pkt), len(p))):
            if pkt[i] != p[i]:
                print(f"    首处差异 @ {i}: 期望 {p[i]:02x} 得到 {pkt[i]:02x}")
                break
    return pkt == p


def get_session_key(opt):
    """random | orig(复用抓包里的) | 64 位 hex"""
    if opt == "random":
        return os.urandom(32)
    if opt == "orig":
        key, sig_hash, _, _ = load_keys()
        p = open(os.path.join("ota_capture", "ctrl_0_605.bin"), "rb").read()
        return aes_ctr(key, sig_hash, p[36:349], decrypt=True)[13:45]
    return bytes.fromhex(opt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", default=None,
                    help="密钥目录（缺省读环境变量 SIFLI_KEYS 或 ~/sifli_sdk/sb/sifli02）")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--image")
    ap.add_argument("--fw-ver", type=int, default=1001002)
    ap.add_argument("--hw-ver", type=int, default=51)
    ap.add_argument("--sdk-ver", type=int, default=7001)
    ap.add_argument("--dfu-id", type=int, default=1)
    ap.add_argument("--session-key", default="random",
                    help="random（默认）| orig（复用抓包会话密钥）| 64 位 hex")
    ap.add_argument("--flag", type=int, default=0, help="镜像项 flag（原件为 0）")
    ap.add_argument("--img-id", type=int, default=0, help="镜像项 id（原件为 0）")
    ap.add_argument("-o", "--out", default="pkg")
    a = ap.parse_args()

    global KS
    if a.keys:
        KS = a.keys
    if not os.path.isfile(os.path.join(KS, "s01.bin")):
        sys.exit(f"[!] 密钥目录无效：{KS}\n"
                 f"    需要 s01.bin / sig_hash.bin / sig_pri.pem / sig_pub.pem\n"
                 f"    来源：OpenSiFli/SiFli-SDK → tools/secureboot/sifli02/")

    if a.check:
        ok = check()
        sys.exit(0 if ok else 1)

    if not a.image:
        ap.error("需要 --image 或 --check")

    key, sig_hash, pri, pub = load_keys()
    img = open(a.image, "rb").read()
    img_len = len(img)
    nblk = (img_len + BLK - 1) // BLK
    print(f"[+] 镜像 {a.image}  {img_len:,} 字节  -> {nblk} 块（尾块 {img_len - (nblk-1)*BLK}B）")

    digest = hashlib.sha256(img).digest()
    isig = sign_digest(pri, digest)
    assert verify_digest(pub, digest, isig)
    print(f"[+] 镜像签名 {len(isig)}B 已生成并用公钥自验通过  sha256={digest.hex()[:16]}…")

    sess = get_session_key(a.session_key)
    print(f"[+] session_key ({a.session_key}) = {sess.hex()[:16]}…")
    control = build_control(a.dfu_id, a.hw_ver, a.sdk_ver, a.fw_ver, sess, 512,
                            [(isig, img_len, a.flag, a.img_id)])
    print(f"[+] control {len(control)} 字节  dfu_id={a.dfu_id} hw={a.hw_ver} sdk={a.sdk_ver} "
          f"fw={a.fw_ver} flag={a.flag} id={a.img_id}")
    pkt = build_ctrl_packet(control, key, sig_hash, pri)
    assert len(pkt) == 605, len(pkt)
    print(f"[+] ctrl_packet {len(pkt)} 字节（AES-256-CTR + RSA-2048 签名）")

    blocks = image_to_blocks(img)
    assert len(blocks) == nblk
    print(f"[+] 数据块 {len(blocks)} 个")

    with open(a.out + ".ctrl", "wb") as f:
        f.write(pkt)
    with open(a.out + ".blocks", "wb") as f:
        for b in blocks:
            f.write(struct.pack("<H", len(b)) + b)
    with open(a.out + ".json", "w", encoding="utf-8") as f:
        import json
        json.dump({"image": os.path.basename(a.image), "img_len": img_len, "fw_ver": a.fw_ver,
                   "hw_ver": a.hw_ver, "sdk_ver": a.sdk_ver, "dfu_id": a.dfu_id,
                   "blocks": len(blocks), "sha256": digest.hex(), "ctrl_len": len(pkt)}, f, indent=2)
    print(f"[+] 已写出 {a.out}.ctrl / {a.out}.blocks / {a.out}.json")


if __name__ == "__main__":
    main()
