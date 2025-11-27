# encrypto

## 项目简介

本项目使用 Rust 实现两个 CLI 工具：`enc`、`dec`，基于 RSA-OAEP 与 AES-GCM 的混合加密方案。所有可执行文件都会在构建时内嵌密钥数据。混合方案通过固定 18 字节的 `ENHY` 头部，将 AES-GCM 载荷封装在 RSA OAEP 信封内（仍向后兼容早期 17 字节版本）。

## 先决条件

- 安装 [Rust](https://rustup.rs/)（推荐使用 rustup）
- 可选：安装 Python 与 [PyCryptodome](https://pycryptodome.readthedocs.io/) 用于运行测试脚本

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 可选：安装测试依赖
pip install pycryptodome
```

## 构建

```bash
cargo build --release
```

构建过程会自动生成 4096 位 RSA 密钥对并嵌入二进制文件。

## CLI 使用

所有 CLI 均以 `main(argc == 3, input, output)` 形式接收参数，参数不符时会输出 `Usage:` 提示。

- `enc <input> <output>`：输入既可以是常规文件，也可以是目录。目录会先按固定顺序打包为 `tar`，再按所选算法压缩后进入 AES-GCM/RSA 混合加密流程。输出路径可为文件或 `-`（标准输出），以便串联到其他工具。
- `dec <input|-> <output_dir>`：校验并解密混合容器，依据头部记录的算法还原压缩流并自动展开 `tar` 内容。`output_dir` 必须为尚不存在的目录名，命令会在其中恢复原始的文件/目录结构。
- 通过环境变量 `ENCRYPTO_COMPRESSION` 选择打包阶段的压缩算法：支持 `lz4`（默认）、`gzip`、`zstd` 以及 `none`（仅打包为裸 `tar`）。`dec` 会从容器头部识别算法并自动匹配，因此无需额外参数；头部缺省值兼容旧版仅含 `gzip` 的容器。

```bash
# 加密文件
./target/release/enc input.txt output.bin

# 加密目录
./target/release/enc ./my_folder output.bin

# 解密
./target/release/dec output.bin ./output_dir

# 使用指定压缩算法
ENCRYPTO_COMPRESSION=zstd ./target/release/enc input.txt output.bin
```

## 测试

```bash
# 运行单元测试
cargo test

# 运行端到端测试（需要 pycryptodome）
pip install pycryptodome
python scripts/test_rsa_cli.py
python scripts/test_rsa_cli.py --directory src  # 验证目录 round-trip
```

## 确定性随机数模式

设置环境变量 `ENCRYPTO_TEST_RANDOM_PATH` 后，所有 CLI 会从指定文件读取确定性随机数，满足 OAEP 与盲化场景需求。

## 混合容器格式

混合容器结构如下：

1. 第一个 RSA OAEP 密文封装 18 字节头部（v2：含魔数、协议版本、压缩算法、RSA 密文长度、IV/Tag 长度及压缩后载荷长度）。解密端仍兼容早期 17 字节版本（固定 `gzip`）。
2. 第二个 RSA OAEP 密文封装 32 字节 AES 会话密钥。
3. 随后依次为 12 字节 IV、AES-GCM 密文块，以及 16 字节 Tag。

| 字段 | 偏移/大小 | 编码 | 含义 |
| --- | --- | --- | --- |
| Magic | 0-3 字节 | ASCII `ENHY` | 固定魔数，标识混合容器 |
| Version | 第 4 字节 | `uint8` | 当前版本为 2；值为 1 时表示旧格式（默认 `gzip`） |
| Compression | 第 5 字节 | `uint8` | 压缩算法：0=`none`，1=`gzip`，2=`zstd`，3=`lz4` |
| RSA 密文长度 | 第 6-7 字节 | `uint16` 大端 | RSA OAEP 密文长度 |
| IV 长度 | 第 8 字节 | `uint8` | AES-GCM IV 长度，当前固定为 12 |
| Tag 长度 | 第 9 字节 | `uint8` | AES-GCM Tag 长度，当前固定为 16 |
| 密文长度 | 第 10-17 字节 | `uint64` 大端 | AES-GCM 密文长度（即压缩后 `tar` 尺寸） |

AES-GCM 固定使用 32 字节会话密钥、12 字节 IV、16 字节 Tag，并以 64 KiB 分块处理数据。

## 目录速览

- `src/`：Rust 源代码
  - `lib.rs`：库入口
  - `bin/`：CLI 可执行文件（`enc.rs`、`dec.rs`）
  - `crypto/`：加密模块（RSA、AES-GCM、RNG）
  - `compression.rs`：压缩算法支持
  - `format.rs`：容器格式定义
  - `key_data.rs`：密钥数据加载
  - `error.rs`：错误类型定义
- `scripts/`：测试脚本
- `build.rs`：构建脚本（密钥生成）

## License

MIT
