#!/usr/bin/env python3
"""Generate RSA key pair PEM files for the build.

The script expects two arguments: the private key path and the public key path.
OpenSSL must be available on PATH. Keys are regenerated on every invocation.
"""

import os
import shutil
import subprocess
import sys
from typing import List

KEY_BITS = 2048
PUBLIC_EXPONENT = 65537


def _ensure_parent(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)


def _run(cmd: List[str], desc: str) -> None:
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print(f"error: {cmd[0]} not found while attempting to {desc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"error: {desc} failed with exit code {exc.returncode}", file=sys.stderr)
        sys.exit(exc.returncode)


def _write_header(pem_path: str, header_path: str, symbol: str) -> None:
    with open(pem_path, "rb") as fp:
        data = fp.read()

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
        if idx % 12 == 0:
            lines.append(line)
            line = "    "
        else:
            line += " "
    if line.strip():
        lines.append(line)

    lines.extend([
        "};",
        "",
        f"#endif /* {guard} */",
        "",
    ])

    with open(header_path, "w", encoding="ascii") as fp:
        fp.write("\n".join(lines))


def main() -> int:
    if len(sys.argv) != 5:
        print(f"usage: {sys.argv[0]} <private.pem> <public.pem> <private.h> <public.h>", file=sys.stderr)
        return 1

    priv_path = sys.argv[1]
    pub_path = sys.argv[2]
    priv_header = sys.argv[3]
    pub_header = sys.argv[4]

    for path in (priv_path, pub_path):
        _ensure_parent(path)
    for path in (priv_header, pub_header):
        _ensure_parent(path)

    openssl = shutil.which("openssl")
    if not openssl:
        print("error: openssl executable not found in PATH", file=sys.stderr)
        return 1

    _run(
        [
            openssl,
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            f"rsa_keygen_bits:{KEY_BITS}",
            "-pkeyopt",
            f"rsa_keygen_pubexp:{PUBLIC_EXPONENT}",
            "-out",
            priv_path,
        ],
        "generate RSA private key",
    )

    _run(
        [
            openssl,
            "rsa",
            "-pubout",
            "-in",
            priv_path,
            "-out",
            pub_path,
        ],
        "derive RSA public key",
    )

    _write_header(priv_path, priv_header, "g_rsa_private_key")
    _write_header(pub_path, pub_header, "g_rsa_public_key")

    return 0


if __name__ == "__main__":
    sys.exit(main())
