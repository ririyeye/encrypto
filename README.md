# encrypto

## Building

```bash
xmake
```

## Testing

Ensure `pycryptodome` is available in your Python 环境, then run:

```bash
python scripts/test_rsa_cli.py
```

测试脚本默认仅验证混合加密 CLI；若需额外跑纯 RSA CLI，可追加 `--rsa` 参数。

## 混合加密 CLI

- `hybrid_encrypt <input> <output>`：使用 RSA+AES-GCM 的混合方案加密任意文件。
- `hybrid_decrypt <input> <output>`：解密上述文件并验证完整性。
