# ncm2mp3

> 把网易云音乐的 `.ncm` 加密容器还原成标准 MP3 —— 顺带把歌名、艺人、专辑、封面写回 ID3v2.3。
>
> A small, dependency-light decryptor for NetEase Cloud Music `.ncm` files. Native MP3 streams are **remuxed bit-exactly** (no re-encode); FLAC and other containers are transcoded to 320 kbps MP3.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Deps](https://img.shields.io/badge/deps-pycryptodome%20%2B%20ffmpeg-informational)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 特性

- **零损失**：源文件本身是 MP3 时用 ffmpeg 流拷贝（`-c:a copy`），音频比特完全不变，只重写标签与封面。
- **标签完整**：从 NCM 的 meta 块解出 `title` / `artist` / `album` / `album_id`，写成 ID3v2.3。
- **封面复原**：解出原始 JPEG/PNG 并以 `attached_pic` 内嵌，播放器直接显示专辑图。
- **布局兼容**：封面区自动识别 `[图长][图]` 与 `[帧长][图长][图]` 两种历史布局，避免音频错位。
- **批量处理**：传目录即可递归处理其下所有 `.ncm`，单文件失败不影响其余文件。
- **可自检**：`tests/selftest.py` 现场合成 NCM 再解回来，不依赖真实样本。

## 环境要求

| 依赖 | 说明 |
| --- | --- |
| Python 3.10+ | 使用了 `X \| None`、`tuple[...]` 等新语法 |
| [pycryptodome](https://pypi.org/project/pycryptodome/) | AES-128-ECB 解密 |
| [ffmpeg](https://ffmpeg.org/) | 封装 MP3、内嵌封面、非 MP3 源转码（需在 `PATH` 中） |

```bash
# Windows
winget install Gyan.FFmpeg
# macOS
brew install ffmpeg
# Debian / Ubuntu
sudo apt install ffmpeg
```

```bash
pip install pycryptodome
```

## 用法

```bash
# 1) 处理当前目录下所有 .ncm，输出到同级目录
python ncm2mp3.py

# 2) 处理单个文件
python ncm2mp3.py "μ's - Super LOVE=Super LIVE!.ncm"

# 3) 指定目录 + 统一输出目录
python ncm2mp3.py D:\Music\NCM -o D:\Music\MP3

# 4) 保留中间产物（解密后的音频流、封面图）便于排查
python ncm2mp3.py D:\Music\NCM -o out --keep

# 5) 非 MP3 源（如 FLAC）改用 256k 转码
python ncm2mp3.py D:\Music\NCM -b 256k
```

### 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `paths...` | `.` | `.ncm` 文件或目录，可传多个 |
| `-o, --out DIR` | 与源文件同级 | 输出目录（自动创建） |
| `-b, --bitrate` | `320k` | 转码码率，**仅**对非 MP3 源生效 |
| `--keep` | 关闭 | 保留 `.dec.*` 音频流与 `.cover.*` 封面 |
| `-V, --version` | — | 打印版本 |

### 输出示例

```text
[i] μ's - Super LOVE=Super LIVE!.ncm: format=mp3 title=Super LOVE=Super LIVE! artist=μ's audio=13702039B cover=593410B
    时长 342.45s / 码率 320000 bps
[+] 输出: μ's - Super LOVE=Super LIVE!.mp3 (14294296 bytes)
[=] 完成: 成功 1 / 失败 0
```

## 它是怎么被解开的

`.ncm` 的容器结构（小端）：

| 区段 | 长度 | 处理方式 |
| --- | --- | --- |
| magic | 8 | 固定 `CTENFDAM`，用于识别文件 |
| gap | 2 | 跳过 |
| key 长度 | 4 | — |
| key 数据 | `key_len` | 每字节异或 `0x64` → AES-128-ECB 解密（密钥 `hzHRAmso5kInbaxW`）→ 去 PKCS#7 → 去掉 17 字节前缀 `neteasecloudmusic`，得到 RC4 密钥 |
| meta 长度 | 4 | — |
| meta 数据 | `meta_len` | 每字节异或 `0x63` → 去掉 `163 key(Don't modify):` → Base64 解码 → AES-128-ECB 解密（密钥 `#14ljk_!\]&0U<('`）→ 去掉 `music:` → JSON |
| crc32 + gap | 5 | 跳过 |
| 封面长度 | 4（有时 8） | 部分版本为 `帧长 + 图长` 两个字段，代码用 `FFD8FF` / `89504E47` 魔数判定 |
| 封面数据 | 变长 | 内嵌到输出 MP3 |
| 音频数据 | 剩余全部 | 用 key 块派生的查找表做 RC4 变体流式异或 |

RC4 变体与原版 RC4 的差别只在 keystream 索引：碰撞表按 `key` 循环填充一次（不用 PRGA 的 `i/j` 交换），解密时

```text
j   = (i + 1) & 0xff
idx = box[j] + box[(box[j] + j) & 0xff]   (mod 256)
plain[i] = cipher[i] ^ box[idx]
```

**踩坑记录**：如果封面区按「单长度字段」硬解，遇到「帧长 + 图长」布局会多算 4/8 字节，RC4 keystream 从这里整体错位，输出就是全噪声 —— 表现为 ffmpeg 满屏 `Header missing`、`duration=N/A`。用图片魔数定位起点即可彻底避开。

## 无损保证怎么验的

对同一个文件，分别把「解密出的原始音频流」和「最终成品」解成 PCM 比对指纹：

```bash
ffmpeg -hide_banner -loglevel error -i raw.mp3 -map 0:a -f md5 -
ffmpeg -hide_banner -loglevel error -i out.mp3 -map 0:a -f md5 -
```

两边都是 `49b16c73dd8c370374864d92e1d16226`，说明中间没有经过任何重编码。

## 自检

不需要真实样本，脚本会现场造一个 NCM 再解回来，覆盖两种封面布局：

```bash
python tests/selftest.py
```

```text
[PASS] 双长度前缀布局 / 音频还原
[PASS] 双长度前缀布局 / 封面还原
...
[=] 自检通过
```

## 项目结构

```text
ncm2mp3/
├── ncm2mp3.py        # 解密器 + CLI
├── tests/
│   └── selftest.py   # 合成样本自检
├── requirements.txt
├── .gitignore
└── README.md
```

## 常见问题

| 现象 | 原因 / 处理 |
| --- | --- |
| `不是 NCM 文件 (magic=...)` | 文件损坏，或其实是 `.uc!` / `.qmc` 等其它容器格式 |
| `FileNotFoundError: ffmpeg` | ffmpeg 不在 `PATH`，装好后重开终端 |
| 输出 MP3 是噪声 / `duration=N/A` | 打到了不兼容的封面布局，提 issue 并附文件头前 900 字节 hex |
| 封面缺失 | 该 NCM 本身未内嵌封面（`cover_len = 0`） |
| 输出比源文件小几 KB | 正常：丢弃了 NCM 的容器头、校验字段与加密开销 |
| 中文/日文文件名乱码 | 终端编码问题，输出文件本身按 UTF-8 命名，资源管理器里正常 |

## License

[MIT](LICENSE) © realMisakaMikoto

仅用于本地自有文件的格式转换。
