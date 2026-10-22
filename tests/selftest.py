#!/usr/bin/env python3
"""不需要真实 .ncm 样本的自检：现场构造一个 NCM 容器再解回来。

运行: python tests/selftest.py
"""

from __future__ import annotations

import base64
import json
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from Crypto.Cipher import AES  # noqa: E402

import ncm2mp3 as n  # noqa: E402


def pad(data: bytes, block: int = 16) -> bytes:
    p = block - len(data) % block
    return data + bytes([p]) * p


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data))


def build_ncm(audio: bytes, meta: dict, cover: bytes, rc4_key: bytes,
              double_len_field: bool) -> bytes:
    key_blob = bytes(b ^ 0x64 for b in aes_ecb_encrypt(n.CORE_KEY, n.KEY_PREFIX + rc4_key))

    meta_json = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    meta_plain = b"music:" + meta_json
    meta_b64 = base64.b64encode(aes_ecb_encrypt(n.META_KEY, meta_plain))
    meta_blob = bytes(b ^ 0x63 for b in n.META_PREFIX.encode() + meta_b64)

    box = n.build_key_box(rc4_key)
    audio_ct = n.rc4_decrypt(box, audio)  # 异或对称，同一函数即加密

    out = bytearray(n.MAGIC)
    out += b"\x01\x70"
    out += struct.pack("<I", len(key_blob)) + key_blob
    out += struct.pack("<I", len(meta_blob)) + meta_blob
    out += b"\x24\xf7\x83\x6a"  # crc32 占位
    out += b"\x01"              # gap
    if double_len_field:
        out += struct.pack("<I", len(cover)) + struct.pack("<I", len(cover))
    else:
        out += struct.pack("<I", len(cover))
    out += cover
    out += audio_ct
    return bytes(out)


def main() -> int:
    audio = b"ID3\x03\x00\x00\x00\x00\x00\x00" + bytes(range(256)) * 400
    meta = {
        "musicId": "31478812",
        "musicName": "Super LOVE=Super LIVE!",
        "artist": [["μ's", "747064"]],
        "album": "ミはμ'sicのミ",
        "albumId": "3121201",
        "format": "mp3",
        "bitrate": 320000,
        "duration": 342453,
    }
    cover = b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes([0x11]) * 500
    rc4_key = bytes(range(1, 129))

    ok = True
    for double in (True, False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.ncm"
            path.write_bytes(build_ncm(audio, meta, cover, rc4_key, double))
            got_audio, got_cover, fmt, got_meta = n.decrypt(path)
            label = "双长度前缀布局" if double else "单长度前缀布局"
            checks = {
                "音频还原": got_audio == audio,
                "封面还原": got_cover == cover,
                "格式识别": fmt == "mp3",
                "歌名": got_meta.get("musicName") == meta["musicName"],
                "专辑": got_meta.get("album") == meta["album"],
            }
            for name, passed in checks.items():
                ok &= bool(passed)
                print(f"[{'PASS' if passed else 'FAIL'}] {label} / {name}")
    print("[=] 自检通过" if ok else "[=] 自检失败")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
