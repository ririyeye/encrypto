#!/usr/bin/env python3
"""Generate RSA key pair PEM and header files for the build.

The script expects four arguments: the private key PEM path, the public key
PEM path, and the corresponding header destinations. Keys are regenerated on
every invocation using PyCryptodome (no external executables required).
"""

import os
import sys

KEY_BITS = 4096
PUBLIC_EXPONENT = 65537

try:
    from Crypto.PublicKey import RSA  # Debian/Ubuntu pip 命名
except ModuleNotFoundError:
    try:
        from Cryptodome.PublicKey import RSA  # 部分发行版仅暴露此命名空间
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
        print("error: missing dependency 'pycryptodome'", file=sys.stderr)
        print(f"import failure: {exc}", file=sys.stderr)
        print("hint: pip install pycryptodome", file=sys.stderr)
        sys.exit(1)


def _ensure_parent(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)


def _write_header_bytes(data: bytes, header_path: str, symbol: str) -> None:
    guard = symbol.upper().replace("/", "_").replace(".", "_") + "_H"
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        f"static const unsigned char {symbol}[] = {{",
    ]

    line = "    "
    for idx, byte in enumerate(data, start=1):
        line += f"0x{byte:02X},"
        if idx % 8 == 0:
            lines.append(line.rstrip())
            line = "    "
        else:
            line += " "
    if line.strip():
        lines.append(line.rstrip())

    lines.extend([
        "};",
        "",
        f"#endif /* {guard} */",
        "",
    ])

    with open(header_path, "w", encoding="ascii") as fp:
        fp.write("\n".join(lines))


def _generate_rsa_keypair() -> "RSA.RsaKey":
    return RSA.generate(KEY_BITS, e=PUBLIC_EXPONENT)


def main() -> int:
    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} <private.pem> <public.pem> <private.h> <public.h>",
            file=sys.stderr,
        )
        return 1

    priv_path = sys.argv[1]
    pub_path = sys.argv[2]
    priv_header = sys.argv[3]
    pub_header = sys.argv[4]

    for path in (priv_path, pub_path):
        _ensure_parent(path)
    for path in (priv_header, pub_header):
        _ensure_parent(path)

    private_key = _generate_rsa_keypair()
    public_key = private_key.public_key()

    private_pem = private_key.export_key(format="PEM")
    public_pem = public_key.export_key(format="PEM")

    private_der = private_key.export_key(format="DER")
    public_der = public_key.export_key(format="DER")

    with open(priv_path, "wb") as fp:
        fp.write(private_pem)
    with open(pub_path, "wb") as fp:
        fp.write(public_pem)

    _write_header_bytes(private_der, priv_header, "g_rsa_private_key")
    _write_header_bytes(public_der, pub_header, "g_rsa_public_key")

    return 0


if __name__ == "__main__":
    sys.exit(main())
