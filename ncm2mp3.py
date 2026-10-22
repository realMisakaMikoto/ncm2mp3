#!/usr/bin/env python3
"""ncm2mp3 — 网易云音乐 NCM 加密容器解密器 / NetEase Cloud Music NCM decryptor.

把 .ncm 还原成标准 MP3（FLAC 等其它容器则转码为 320k MP3），
并把歌名、艺人、专辑、封面写回 ID3v2.3 标签。

容器结构（逆向结论）:
    magic(8) "CTENFDAM"
    gap(2)
    key_len(4 LE) | key_data(异或 0x64 → AES-128-ECB → 去 PKCS7 → 去前缀)
    meta_len(4 LE) | meta(异或 0x63 → 去前缀 → Base64 → AES-128-ECB → JSON)
    crc32(4) | gap(1)
    image_len(4 LE) | image            （部分版本多一个 4 字节帧长度前缀）
    audio                                标准 RC4 变体 keystream

用法:
    python ncm2mp3.py                  # 处理当前目录
    python ncm2mp3.py song.ncm         # 处理单个文件
    python ncm2mp3.py D:\\Music -o out  # 指定目录 + 输出目录
"""

from __future__ import annotations

import argparse
import base64
import json
import struct
import subprocess
import sys
from pathlib import Path

from Crypto.Cipher import AES

__version__ = "1.0.0"

CORE_KEY = bytes.fromhex("687A4852416D736F356B496E62617857")  # b"hzHRAmso5kInbaxW"
META_KEY = bytes.fromhex("2331346C6A6B5F215C5D2630553C2728")  # b"#14ljk_!\\]&0U<'("
MAGIC = b"CTENFDAM"
KEY_PREFIX = b"neteasecloudmusic"
META_PREFIX = "163 key(Don't modify):"

JPEG_MAGIC = b"\xff\xd8\xff"
PNG_MAGIC = b"\x89PNG"


def unpad(data: bytes) -> bytes:
    """去掉 PKCS#7 填充；填充非法时原样返回。"""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data))


def build_key_box(key: bytes) -> bytearray:
    """由 RC4 密钥派生 keystream 查找表。"""
    box = bytearray(range(256))
    last = 0
    off = 0
    klen = len(key)
    for i in range(256):
        swap = box[i]
        c = (swap + last + key[off]) & 0xFF
        off = (off + 1) % klen
        box[i] = box[c]
        box[c] = swap
        last = c
    return box


def rc4_decrypt(box: bytearray, data: bytes) -> bytes:
    """NCM 使用的 RC4 变体：没有 KSA 重置，按索引流式异或。"""
    out = bytearray(data)
    for i in range(len(out)):
        j = (i + 1) & 0xFF
        idx = (box[j] + box[(box[j] + j) & 0xFF]) & 0xFF
        out[i] ^= box[idx]
    return bytes(out)


def parse_meta(raw: bytes) -> dict:
    """解析 meta 块，失败时返回空 dict（不影响音频解密）。"""
    try:
        text = raw[len(META_PREFIX):].decode("utf-8", "ignore")
        dec = aes_ecb_decrypt(META_KEY, base64.b64decode(text))
        return json.loads(dec[6:].decode("utf-8", "ignore"))  # 去 "music:"
    except Exception:
        return {}


def _has_image_magic(buf: bytes, at: int) -> bool:
    head = buf[at:at + 4]
    return head[:3] == JPEG_MAGIC or head == PNG_MAGIC


def decrypt(path: Path) -> tuple[bytes, bytes, str, dict]:
    """解密一个 NCM 文件，返回 (音频字节, 封面字节, 音频格式, 元信息)。"""
    blob = path.read_bytes()
    if blob[:8] != MAGIC:
        raise ValueError(f"不是 NCM 文件 (magic={blob[:8]!r})")

    pos = 10  # magic + gap
    (key_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    key_data = bytes(b ^ 0x64 for b in blob[pos:pos + key_len])
    pos += key_len
    rc4_key = aes_ecb_decrypt(CORE_KEY, key_data)[len(KEY_PREFIX):]

    (meta_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    meta = parse_meta(bytes(b ^ 0x63 for b in blob[pos:pos + meta_len])) if meta_len else {}
    pos += meta_len

    pos += 5  # crc32(4) + gap(1)

    # 封面区有两种布局: [图长][图] 与 [帧长][图长][图]，用图片魔数判定。
    (cover_len,) = struct.unpack_from("<I", blob, pos)
    audio_start = pos + 4 + cover_len
    if not _has_image_magic(blob, pos + 4):
        (next_len,) = struct.unpack_from("<I", blob, pos + 4)
        if next_len == cover_len and _has_image_magic(blob, pos + 8):
            audio_start = pos + 8 + cover_len
        else:
            audio_start, cover_len = pos + 4, 0  # 无封面
    cover = blob[audio_start - cover_len:audio_start] if cover_len else b""

    audio = rc4_decrypt(build_key_box(rc4_key), blob[audio_start:])
    fmt = (meta.get("format") or "").lower()
    if not fmt:
        fmt = "flac" if audio[:4] == b"fLaC" else (
            "mp3" if audio[:3] == b"ID3" or audio[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2") else "bin"
        )
    return audio, cover, fmt, meta


def artists_of(meta: dict) -> str:
    artists = meta.get("artist") or []
    return " / ".join(a[0] if isinstance(a, (list, tuple)) else str(a) for a in artists)


def to_mp3(audio_path: Path, out_path: Path, cover_path: Path | None, meta: dict,
           copy_audio: bool, bitrate: str) -> None:
    """用 ffmpeg 封装 MP3：可流拷贝（无损）或转码（FLAC 等）。"""
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(audio_path)]
    if cover_path and cover_path.exists():
        cmd += ["-i", str(cover_path), "-map", "0:a", "-map", "1:v",
                "-c:v", "copy", "-disposition:v", "attached_pic"]
    else:
        cmd += ["-map", "0:a"]
    cmd += ["-map_metadata", "-1", "-id3v2_version", "3"]
    cmd += ["-c:a", "copy"] if copy_audio else ["-c:a", "libmp3lame", "-b:a", bitrate]
    if meta.get("musicName"):
        cmd += ["-metadata", f"title={meta['musicName']}"]
    if artists_of(meta):
        cmd += ["-metadata", f"artist={artists_of(meta)}"]
    if meta.get("album"):
        cmd += ["-metadata", f"album={meta['album']}"]
    if meta.get("albumId"):
        cmd += ["-metadata", f"album_id={meta['albumId']}"]
    cmd.append(str(out_path))
    subprocess.run(cmd, check=True)


def process(path: Path, out_dir: Path | None, bitrate: str, keep: bool) -> Path:
    audio, cover, fmt, meta = decrypt(path)
    stem = path.with_suffix("")
    tmp_audio = path.with_suffix(f".dec.{fmt}")
    tmp_audio.write_bytes(audio)

    cover_path = None
    if cover:
        ext = ".png" if cover[:4] == PNG_MAGIC else ".jpg"
        cover_path = path.with_suffix(f".cover{ext}")
        cover_path.write_bytes(cover)

    print(f"[i] {path.name}: format={fmt} title={meta.get('musicName') or stem.name} "
          f"artist={artists_of(meta) or '-'} audio={len(audio)}B cover={len(cover)}B")
    if meta.get("duration"):
        print(f"    时长 {int(meta['duration']) / 1000:.2f}s / 码率 {meta.get('bitrate')} bps")

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    out = (out_dir / stem.name if out_dir else stem).with_suffix(".mp3")
    # 原生 MP3 直接流拷贝（bit-exact），其它容器才转码
    to_mp3(tmp_audio, out, cover_path, meta, copy_audio=(fmt == "mp3"), bitrate=bitrate)

    if not keep:
        tmp_audio.unlink(missing_ok=True)
        if cover_path:
            cover_path.unlink(missing_ok=True)
    print(f"[+] 输出: {out} ({out.stat().st_size} bytes)")
    return out


def collect(args: list[str]) -> list[Path]:
    targets: list[Path] = []
    seen: set[Path] = set()
    for arg in args or ["."]:
        p = Path(arg)
        found = sorted(p.glob("*.ncm")) if p.is_dir() else [p]
        for f in found:
            rp = f.resolve()
            if rp not in seen:
                seen.add(rp)
                targets.append(f)
    return targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ncm2mp3",
        description="把网易云音乐 .ncm 文件还原为 MP3（含标签与封面）。",
        epilog="示例: python ncm2mp3.py D:\\Music -o D:\\Music\\mp3",
    )
    parser.add_argument("paths", nargs="*", help=".ncm 文件或目录，默认当前目录")
    parser.add_argument("-o", "--out", metavar="DIR", help="输出目录，默认与源文件同级")
    parser.add_argument("-b", "--bitrate", default="320k", help="转码码率（仅非 MP3 源生效），默认 320k")
    parser.add_argument("--keep", action="store_true", help="保留中间文件（解密后音频、封面）")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str]) -> int:
    ns = build_parser().parse_args(argv)
    targets = collect(ns.paths)
    if not targets:
        print("没有找到 .ncm 文件", file=sys.stderr)
        return 1
    out_dir = Path(ns.out) if ns.out else None
    fails = 0
    for t in targets:
        try:
            process(t, out_dir, ns.bitrate, ns.keep)
        except Exception as exc:  # noqa: BLE001 - 单个文件失败不影响批量
            fails += 1
            print(f"[!] {t.name}: {exc}", file=sys.stderr)
    print(f"[=] 完成: 成功 {len(targets) - fails} / 失败 {fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
