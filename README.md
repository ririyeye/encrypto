# encrypto

## 项目简介

本项目使用 mbedtls 实现两个 C99 CLI 工具：`enc`、`dec`。所有可执行文件都会在构建时内嵌密钥数据，`src/key_data.c` 输出的数组被统一复用。混合方案通过固定 17 字节的 `ENHY` 头部，将 AES-GCM 载荷封装在 RSA OAEP 信封内。

## 先决条件

- 安装 [xmake](https://xmake.io/)。
- Python 环境需可运行仓库根目录下的脚本，并已安装 [PyCryptodome](https://pycryptodome.readthedocs.io/)；如使用虚拟环境，请在调用脚本前激活。
- 不需要额外的 `openssl` 可执行文件，密钥生成完全由 PyCryptodome 负责。

```bash
python -m pip install pycryptodome
```

## 构建

执行下列任意命令都会触发自定义 `generate_keys` 规则，从而调用 `scripts/generate_keys.py` 利用 PyCryptodome 生成 PEM 与 `build/generated/` 下的 `rsa_private_key.h`、`rsa_public_key.h`：

```bash
xmake            # 构建所有目标
xmake build enc
```

> ⚠️ 请勿直接修改 `build/generated/` 内的文件，若需调整密钥或格式，请更新脚本或源 PEM。

目标二进制可通过 `xmake show -t <target>` 查询路径，最终安装物位于 `install/bin/`。

## CLI 使用

所有 CLI 均以 `main(argc == 3, input, output)` 形式接收参数，参数不符时会输出 `Usage:` 提示。

- `enc <input> <output>`：利用 RSA+AES-GCM 混合方案加密文件，输出包含 `ENHY` 头的容器。
- `dec <input> <output>`：校验并解密混合容器，恢复原始明文。

## 测试

测试脚本覆盖混合流程，并验证容器结构元数据的正确性。

```bash
pip install pycryptodome
python scripts/test_rsa_cli.py
```

脚本依赖 `xmake show -t <target>` 获取二进制路径，并在 `build/` 中写入临时数据。

## 确定性随机数模式

设置环境变量 `ENCRYPTO_TEST_RANDOM_PATH` 后，所有 CLI 会通过 `random_stream_load` 从指定文件读取确定性随机数，满足 OAEP 与盲化场景需求。当字节耗尽时实现会返回 `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED`。新增代码应复用现有 RNG 助手，并确保使用完的敏感缓冲区调用 `mbedtls_platform_zeroize` 擦除。

混合容器结构如下：

1. 第一个 RSA OAEP 密文封装固定 17 字节头部（含魔数、协议版本、RSA 密文长度、IV/Tag 长度及明文长度）。
2. 第二个 RSA OAEP 密文封装 32 字节 AES 会话密钥。
3. 随后依次为 12 字节 IV、AES-GCM 密文块，以及 16 字节 Tag。

| 字段 | 偏移/大小 | 编码 | 含义 |
| --- | --- | --- | --- |
| Magic | 0-3 字节 | ASCII `ENHY` | 固定魔数，标识混合容器 |
| Version | 第 4 字节 | `uint8` | 当前版本固定为 1 |
| RSA 密文长度 | 第 5-6 字节 | `uint16` 大端 | RSA OAEP 密文长度，应等于 `mbedtls_rsa_get_len` |
| IV 长度 | 第 7 字节 | `uint8` | AES-GCM IV 长度，当前固定为 12 |
| Tag 长度 | 第 8 字节 | `uint8` | AES-GCM Tag 长度，当前固定为 16 |
| 明文长度 | 第 9-16 字节 | `uint64` 大端 | 原始明文总长度（字节） |

AES-GCM 固定使用 32 字节会话密钥、12 字节 IV、16 字节 Tag，并以 64 KiB 分块处理数据。

## 目录速览

- `src/`：CLI 的实现及密钥数据绑定。
- `scripts/`：密钥生成与端到端测试脚本。
- `build/generated/`：构建时生成的密钥头文件（自动维护）。
- `install/bin/`：`xmake install` 产出的可执行文件。
