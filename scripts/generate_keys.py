#!/usr/bin/env python3
"""Generate RSA key pair PEM and header files for the build.

The script expects four arguments: the private key PEM path, the public key
PEM path, and the corresponding header destinations. Keys are regenerated on
every invocation using PyCryptodome (no external executables required).
"""

import errno
import os
import sys
import time

KEY_BITS = 4096
PUBLIC_EXPONENT = 65537

LOCK_FILENAME = ".keygen.lock"
LOCK_SLEEP_SECONDS = 0.1

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
        if idx % 12 == 0:
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


def _generate_rsa_keypair() -> tuple[bytes, bytes]:
    key = RSA.generate(KEY_BITS, e=PUBLIC_EXPONENT)
    private_pem = key.export_key(format="PEM")
    public_pem = key.public_key().export_key(format="PEM")
    return private_pem, public_pem


def _artifacts_ready(*paths: str) -> bool:
    return all(os.path.isfile(path) and os.path.getsize(path) > 0 for path in paths)


def _acquire_lock(lock_path: str) -> int:
    _ensure_parent(lock_path)
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            time.sleep(LOCK_SLEEP_SECONDS)
            continue
        except OSError as exc:  # pragma: no cover - defensive path
            if exc.errno == errno.EEXIST:
                time.sleep(LOCK_SLEEP_SECONDS)
                continue
            raise
        else:
            os.write(fd, f"pid={os.getpid()}".encode("ascii"))
            return fd


def _release_lock(fd: int, lock_path: str) -> None:
    try:
        os.close(fd)
    finally:
        try:
            os.remove(lock_path)
        except FileNotFoundError:
            pass


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

    lock_path = os.path.join(os.path.dirname(os.path.abspath(priv_path)), LOCK_FILENAME)
    lock_fd = _acquire_lock(lock_path)
    try:
        if _artifacts_ready(priv_path, pub_path, priv_header, pub_header):
            return 0

        private_pem, public_pem = _generate_rsa_keypair()

        with open(priv_path, "wb") as fp:
            fp.write(private_pem)
        with open(pub_path, "wb") as fp:
            fp.write(public_pem)

        _write_header_bytes(private_pem, priv_header, "g_rsa_private_key")
        _write_header_bytes(public_pem, pub_header, "g_rsa_public_key")
    finally:
        _release_lock(lock_fd, lock_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
