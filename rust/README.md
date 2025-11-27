# Encrypto Rust

Rust 版本的 Encrypto 混合加密工具，实现与 C 版本相同的 RSA-OAEP + AES-256-GCM 加密方案。

## 功能特性

- **混合加密**: RSA-4096 OAEP 用于密钥交换，AES-256-GCM 用于数据加密
- **多压缩算法支持**: 
  - `none` - 无压缩
  - `gzip` - Gzip 压缩
  - `zstd` - Zstandard 压缩
  - `lz4` - LZ4 压缩（默认）
- **文件/目录支持**: 可加密单个文件或整个目录
- **安全设计**: 
  - 使用 zeroize 擦除敏感数据
  - 支持确定性 RNG 用于测试
  - 容器格式兼容 C 版本

## 容器格式 (v2)

```
+---------------------------+
| RSA-OAEP 加密头部         | (rsa_len 字节)
+---------------------------+
| RSA-OAEP 加密会话密钥     | (rsa_len 字节)
+---------------------------+
| AES-GCM IV               | (12 字节)
+---------------------------+
| AES-GCM 密文             | (ct_len 字节)
+---------------------------+
| AES-GCM Tag              | (16 字节)
+---------------------------+
```

解密后的头部 (18 字节):
- 字节 0-3: 魔数 "ENHY"
- 字节 4: 版本号 (2)
- 字节 5: 压缩算法 ID
- 字节 6-7: RSA 密文长度 (大端 u16)
- 字节 8: IV 长度
- 字节 9: Tag 长度
- 字节 10-17: 密文长度 (大端 u64)

## 构建

```bash
cd rust
cargo build --release
```

构建时会自动生成 RSA-4096 密钥对并嵌入二进制文件。

## 使用

### 加密

```bash
# 加密文件
./target/release/enc input.txt output.bin

# 加密目录
./target/release/enc mydir/ mydir.bin

# 自动生成输出文件名
./target/release/enc input.txt  # 输出到 input.txt.bin

# 使用不同压缩算法
ENCRYPTO_COMPRESSION=zstd ./target/release/enc input.txt output.bin
ENCRYPTO_COMPRESSION=gzip ./target/release/enc input.txt output.bin
ENCRYPTO_COMPRESSION=none ./target/release/enc input.txt output.bin
```

### 解密

```bash
# 解密到指定目录
./target/release/dec encrypted.bin output_dir/

# 自动生成输出目录名
./target/release/dec encrypted.bin  # 输出到 encrypted/
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ENCRYPTO_COMPRESSION` | 压缩算法 (none/gzip/zstd/lz4) | `lz4` |
| `ENCRYPTO_TEST_RANDOM_PATH` | 确定性随机数文件路径（测试用） | - |

## 依赖

- `rsa` - RSA 加密
- `aes-gcm` - AES-GCM 加密
- `sha2` - SHA-256 哈希
- `tar` - Tar 归档
- `flate2` - Gzip 压缩
- `zstd` - Zstandard 压缩
- `lz4_flex` - LZ4 压缩
- `zeroize` - 安全内存擦除

## 与 C 版本的区别

1. **密钥生成**: Rust 版本在构建时生成新密钥，与 C 版本的密钥不互通
2. **压缩实现**: 使用纯 Rust 实现，不依赖系统库

## 许可证

MIT
