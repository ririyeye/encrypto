# encrypto

## 项目简介

本项目使用 mbedtls 实现两个 C99 CLI 工具：`enc`、`dec`。所有可执行文件都会在构建时内嵌密钥数据，`src/key_data.c` 输出的数组被统一复用。混合方案通过固定 18 字节的 `ENHY` 头部，将 AES-GCM 载荷封装在 RSA OAEP 信封内（仍向后兼容早期 17 字节版本）。

## 先决条件

- 安装 [xmake](https://xmake.io/)。
- 准备可运行仓库脚本的 Python 环境，并安装 [PyCryptodome](https://pycryptodome.readthedocs.io/)；如使用虚拟环境，请先激活。
- 密钥生成完全由 PyCryptodome 负责，无需安装额外的 `openssl` 可执行文件。
- 依赖 [libarchive](https://www.libarchive.org/) 及其 filter 支持；项目默认拉取的静态依赖已包含 `zstd`/`lz4`/`lzop` 等算法，若改用系统库，请确保开发包齐全。

```bash
python -m pip install pycryptodome
```
## 构建

执行下列任意命令都会触发自定义 `generate_keys` 规则，从而调用 `scripts/generate_keys.py` 利用 PyCryptodome 生成 PEM 与 `build/generated/` 下的 `rsa_private_key.h`、`rsa_public_key.h`（头文件内嵌 DER 字节流，便于避免二进制中出现 PEM 文本标记）：

```bash
xmake            # 构建所有目标
xmake build enc
```

目标二进制可通过 `xmake show -t <target>` 查询路径，最终安装物位于 `install/bin/`。

## CLI 使用

所有 CLI 均以 `main(argc == 3, input, output)` 形式接收参数，参数不符时会输出 `Usage:` 提示。

- `enc <input> <output>`：输入既可以是常规文件，也可以是目录。目录会先按固定顺序打包为 `tar`，再按所选算法压缩后进入 AES-GCM/RSA 混合加密流程。输出路径可为文件或 `-`（标准输出），以便串联到其他工具。
- `dec <input|-> <output_dir>`：校验并解密混合容器，依据头部记录的算法还原压缩流并自动展开 `tar` 内容。`output_dir` 必须为尚不存在的目录名，命令会在其中恢复原始的文件/目录结构。
- 通过环境变量 `ENCRYPTO_COMPRESSION` 选择打包阶段的压缩算法：支持 `lz4`（默认）、`gzip`、`zstd`、`lzop` 以及 `none`（仅打包为裸 `tar`）。`dec` 会从容器头部识别算法并自动匹配，因此无需额外参数；头部缺省值兼容旧版仅含 `gzip` 的容器。

## 测试

测试脚本覆盖文件与目录两类输入：默认跑一组随机文件载荷；如需再验证目录或完整树形结构，可通过参数手动指定目录，脚本会对其执行“打包 → 压缩 → 加密”流程，确保 CLI 输出与 Python 参考实现比对一致并验证解密结果。

```bash
pip install pycryptodome
python scripts/test_rsa_cli.py               # 仅文件载荷
python scripts/test_rsa_cli.py --directory src  # 额外验证目录 round-trip
```

脚本依赖 `xmake show -t <target>` 获取二进制路径，并在 `build/` 中写入临时数据。

> 默认情况下测试脚本会将 `ENCRYPTO_COMPRESSION` 固定为 `gzip` 以复用 Python 参考实现的产出。如需覆盖其他算法，可在运行前设置 `ENCRYPTO_TEST_COMPRESSION=<none|gzip|...>`，脚本会透传到 CLI 并比对相应容器（目前参考实现仅覆盖 `gzip`/`none`，目录模式同样遵循这一约束）。

## 确定性随机数模式

设置环境变量 `ENCRYPTO_TEST_RANDOM_PATH` 后，所有 CLI 会通过 `random_stream_load` 从指定文件读取确定性随机数，满足 OAEP 与盲化场景需求。当字节耗尽时实现会返回 `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED`。新增代码应复用现有 RNG 助手，并确保使用完的敏感缓冲区调用 `mbedtls_platform_zeroize` 擦除。

混合容器结构如下：

1. 第一个 RSA OAEP 密文封装 18 字节头部（v2：含魔数、协议版本、压缩算法、RSA 密文长度、IV/Tag 长度及压缩后载荷长度）。解密端仍兼容早期 17 字节版本（固定 `gzip`）。
2. 第二个 RSA OAEP 密文封装 32 字节 AES 会话密钥。
3. 随后依次为 12 字节 IV、AES-GCM 密文块，以及 16 字节 Tag。

| 字段 | 偏移/大小 | 编码 | 含义 |
| --- | --- | --- | --- |
| Magic | 0-3 字节 | ASCII `ENHY` | 固定魔数，标识混合容器 |
| Version | 第 4 字节 | `uint8` | 当前版本为 2；值为 1 时表示旧格式（默认 `gzip`） |
| Compression | 第 5 字节 | `uint8` | 压缩算法：0=`none`，1=`gzip`，2=`zstd`，3=`lz4`，4=`lzop` |
| RSA 密文长度 | 第 6-7 字节 | `uint16` 大端 | RSA OAEP 密文长度，应等于 `mbedtls_rsa_get_len` |
| IV 长度 | 第 8 字节 | `uint8` | AES-GCM IV 长度，当前固定为 12 |
| Tag 长度 | 第 9 字节 | `uint8` | AES-GCM Tag 长度，当前固定为 16 |
| 密文长度 | 第 10-17 字节 | `uint64` 大端 | AES-GCM 密文长度（即压缩后 `tar` 尺寸） |

AES-GCM 固定使用 32 字节会话密钥、12 字节 IV、16 字节 Tag，并以 64 KiB 分块处理数据。

## 目录速览

- `src/`：CLI 的实现及密钥数据绑定。
- `scripts/`：密钥生成与端到端测试脚本。
- `build/generated/`：构建时生成的密钥头文件（自动维护）。
- `install/bin/`：`xmake install` 产出的可执行文件。
