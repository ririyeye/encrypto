# Encrypto Copilot 指南

## 项目概览
- 项目生成两个 Rust CLI 可执行文件（`enc`、`dec`），实现基于 RSA-OAEP 与 AES-GCM 的混合加密工作流。
- 构建时会内嵌密钥数据；`build.rs` 负责生成 4096 位 RSA 密钥对，`src/key_data.rs` 加载嵌入的 DER 格式密钥。
- 混合模式通过固定 18 字节（v2）的 `ENHY` 头，将对称 AES-GCM 载荷封装在 RSA OAEP 信封中；解密端仍兼容早期 17 字节版本。
- 压缩算法可通过环境变量 `ENCRYPTO_COMPRESSION` 选择（默认 `lz4`，可选 `gzip`、`zstd`、`none`）。

## 生成资产
- `build.rs` 在编译时生成 RSA 密钥对，输出到 `$OUT_DIR/rsa_private_key.der` 和 `$OUT_DIR/rsa_public_key.der`。
- 密钥通过 `include_bytes!` 宏嵌入二进制文件，避免运行时文件依赖。

## 构建与工具链
- 使用 `cargo build --release` 编译；构建脚本会自动生成密钥。
- 二进制文件位于 `target/release/enc` 和 `target/release/dec`。

## 测试流程
- 运行 `cargo test` 执行单元测试。
- 运行 `python scripts/test_rsa_cli.py`（需安装 `pycryptodome`）执行端到端验证，可追加 `--directory <path>` 校验目录/树形结构 round-trip。
- 测试脚本通过设置 `ENCRYPTO_TEST_RANDOM_PATH` 注入确定性随机数。
- Python 参考容器生成支持 `gzip`/`none`，脚本会自动将 `ENCRYPTO_COMPRESSION` 固定为 `gzip`。

## 确定性 RNG 模式
- 所有 CLI 都检查 `ENCRYPTO_TEST_RANDOM_PATH`；存在时从指定文件读取确定性随机数。
- 扩展 RNG 调用时需复用 `src/crypto/rng.rs` 中的辅助方法。

## 混合容器格式
- 混合容器以两个 RSA-OAEP 密文开头：
	1. 第一个密文封装格式头。v2 为 18 字节（含压缩算法 ID），v1 为 17 字节（默认 `gzip`）；
	2. 第二个密文封装 32 字节 AES 会话密钥。
- 头部明文字段如下（解密后才能获取）：

| 字段 | 偏移/大小 | 编码 | 含义 |
| --- | --- | --- | --- |
| Magic | 0-3 字节 | ASCII `ENHY` | 固定魔数，标识混合容器 |
| Version | 第 4 字节 | `uint8` | v2=2，v1=1（旧格式，仅支持 `gzip`） |
| Compression | 第 5 字节 | `uint8` | v2：0=`none`，1=`gzip`，2=`zstd`，3=`lz4`；v1 缺省视为 `gzip` |
| RSA 密文长度 | 第 6-7 字节 | `uint16` 大端 | RSA OAEP 密文长度 |
| IV 长度 | 第 8 字节 | `uint8` | AES-GCM IV 长度，当前固定为 12 |
| Tag 长度 | 第 9 字节 | `uint8` | AES-GCM Tag 长度，当前固定为 16 |
| 密文长度 | 第 10-17 字节 | `uint64` 大端 | AES-GCM 密文长度（压缩后 `tar` 尺寸） |

- 头部后续布局：IV（`iv_len` 字节）、AES-GCM 密文（`明文长度` 字节）、Tag（`tag_len` 字节）。
- AES-GCM 固定使用 32 字节会话密钥、12 字节 IV、16 字节 Tag，并以 64 KiB 分块。
- 敏感数据使用 `zeroize` crate 进行安全擦除。

## 约定与扩展
- 所有 CLI 入口均为 `main(argc==3, input, output)`；接口保持简单，当参数不符时打印 `Usage:` 提示。
- 若修改密钥处理或容器格式，记得同步更新 `scripts/test_rsa_cli.py` 中的校验逻辑。

## 代码结构
- `src/lib.rs`：库入口，导出公共 API
- `src/bin/enc.rs`：加密 CLI
- `src/bin/dec.rs`：解密 CLI
- `src/crypto/`：加密模块
  - `mod.rs`：模块入口
  - `rsa_oaep.rs`：RSA-OAEP 加解密
  - `aes_gcm.rs`：AES-GCM 加解密
  - `rng.rs`：随机数生成（支持确定性模式）
- `src/compression.rs`：压缩算法支持
- `src/format.rs`：容器格式定义与解析
- `src/key_data.rs`：密钥数据加载
- `src/error.rs`：错误类型定义

## 其他
- 使用中文回答问题
