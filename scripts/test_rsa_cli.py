#!/usr/bin/env python3
"""End-to-end tests for the hybrid CLI utilities.

The script builds the hybrid_encrypt/hybrid_decrypt binaries, prepares payloads of
various sizes, and verifies container integrity with PyCryptodome. It also
exercises deterministic randomness via ENCRYPTO_TEST_RANDOM_PATH to keep output
stable across runs.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Sequence

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except ModuleNotFoundError as exc:  # pragma: no cover - guard for missing dependency
    print(
        "error: missing dependency 'pycryptodome' (import failed: %s)" % exc,
        file=sys.stderr,
    )
    print("hint: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


def run(command: Sequence[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    """Run a subprocess, bubbling up failures with context."""

    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode != 0:
        raise SystemExit(
            "command failed (exit code %d): %s" % (result.returncode, " ".join(command))
        )


def ensure_built(repo_root: Path, targets: Sequence[str]) -> None:
    if not targets:
        return
    for target in targets:
        run(["xmake", "build", target], cwd=repo_root)


def resolve_target(repo_root: Path, name: str) -> Path:
    output = subprocess.check_output(["xmake", "show", "-t", name], cwd=repo_root)
    for line in output.decode().splitlines():
        stripped = line.strip()
        if stripped.startswith("targetfile"):
            path = ""
            for sep in (":", "："):
                if sep in stripped:
                    path = stripped.split(sep, 1)[1].strip()
                    break
            if not path:
                continue
            target_path = Path(path)
            if not target_path.is_absolute():
                target_path = repo_root / target_path
            return target_path.resolve()
    # Fallback: search under build directory for the expected binary name.
    build_root = repo_root / "build"
    if build_root.exists():
        for candidate in build_root.rglob(name):
            if candidate.is_file() or candidate.is_symlink():
                return candidate.resolve()
    raise SystemExit(f"Unable to determine target path for {name}")



def chunk_iter(data: bytes, block_size: int) -> Iterable[bytes]:
    for start in range(0, len(data), block_size):
        yield data[start : start + block_size]


def decrypt_python(private_key: RSA.RsaKey, key_len: int, ciphertext: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    blocks: List[bytes] = []
    for block in chunk_iter(ciphertext, key_len):
        blocks.append(cipher.decrypt(block))
    return b"".join(blocks)


def read_hybrid_container(path: Path, private_key: RSA.RsaKey) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    header_len = 17
    key_len = private_key.size_in_bytes()
    with path.open("rb") as fp:
        header_ct = fp.read(key_len)
        if len(header_ct) != key_len:
            raise AssertionError("Hybrid container missing encrypted header")
        header = decrypt_python(private_key, key_len, header_ct)
        if len(header) != header_len:
            raise AssertionError("Decrypted header length mismatch")
        if header[:4] != b"ENHY":
            raise AssertionError("Invalid hybrid magic")
        if header[4] != 1:
            raise AssertionError(f"Unsupported hybrid version {header[4]}")
        rsa_len = int.from_bytes(header[5:7], "big")
        iv_len = header[7]
        tag_len = header[8]
        cipher_len = int.from_bytes(header[9:17], "big")
        if rsa_len != key_len:
            raise AssertionError("RSA ciphertext length mismatch in header")
        rsa_ct = fp.read(rsa_len)
        if len(rsa_ct) != rsa_len:
            raise AssertionError("Incomplete RSA ciphertext in hybrid container")
        iv = fp.read(iv_len)
        if len(iv) != iv_len:
            raise AssertionError("Incomplete IV in hybrid container")
        ciphertext = fp.read(cipher_len)
        if len(ciphertext) != cipher_len:
            raise AssertionError("Incomplete ciphertext in hybrid container")
        tag = fp.read(tag_len)
        if len(tag) != tag_len:
            raise AssertionError("Incomplete tag in hybrid container")
        trailing = fp.read()
        if trailing:
            raise AssertionError("Unexpected trailing data in hybrid container")
    return header, rsa_ct, iv, ciphertext, tag


def run_cli(program: Path, src: Path, dst: Path, random_path: Path) -> None:
    env = os.environ.copy()
    env["ENCRYPTO_TEST_RANDOM_PATH"] = str(random_path)
    run([str(program), str(src), str(dst)], env=env)


def load_bytes(path: Path) -> bytes:
    with path.open("rb") as fp:
        return fp.read()


def write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as fp:
        fp.write(data)


def execute_tests(repo_root: Path, sizes: Sequence[int]) -> None:
    targets: List[str] = ["hybrid_encrypt", "hybrid_decrypt"]

    ensure_built(repo_root, targets)

    hybrid_encrypt_path: Path = resolve_target(repo_root, "hybrid_encrypt")
    hybrid_decrypt_path: Path = resolve_target(repo_root, "hybrid_decrypt")
    generated_dir = repo_root / "build" / "generated"
    priv_pem = generated_dir / "rsa_private.pem"
    pub_pem = generated_dir / "rsa_public.pem"

    if not priv_pem.exists() or not pub_pem.exists():
        raise SystemExit("RSA key material was not generated; run xmake build first")

    public_key = RSA.import_key(load_bytes(pub_pem))
    private_key = RSA.import_key(load_bytes(priv_pem))

    key_len = public_key.size_in_bytes()

    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)
        for size in sizes:
            plaintext = os.urandom(size)
            plain_path = tmpdir / f"hy_plain_{size}.bin"
            write_bytes(plain_path, plaintext)

            random_len = max(4 * key_len * 4, 1 << 16)
            random_bytes = os.urandom(random_len)
            random_path = tmpdir / f"hy_rand_{size}.bin"
            write_bytes(random_path, random_bytes)

            container_path = tmpdir / f"hy_enc_{size}.bin"
            run_cli(hybrid_encrypt_path, plain_path, container_path, random_path)

            header, rsa_ct, iv, ciphertext, tag = read_hybrid_container(container_path, private_key)
            cipher_len_header = int.from_bytes(header[9:17], "big")
            if cipher_len_header != len(ciphertext):
                raise AssertionError("Ciphertext length mismatch with header metadata")
            session_key = decrypt_python(private_key, key_len, rsa_ct)
            if len(session_key) != 32:
                raise AssertionError("Unexpected session key length from hybrid container")

            aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
            py_plain = aes.decrypt_and_verify(ciphertext, tag)
            if py_plain != plaintext:
                raise AssertionError(f"Hybrid container mismatch for payload size {size}")

            roundtrip_path = tmpdir / f"hy_roundtrip_{size}.bin"
            run_cli(hybrid_decrypt_path, container_path, roundtrip_path, random_path)
            if load_bytes(roundtrip_path) != plaintext:
                raise AssertionError(f"Hybrid decrypt mismatch for payload size {size}")

            print(f"[OK] hybrid processed payload of {size} bytes")

    print(f"All {len(sizes)} hybrid cases passed")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Test hybrid encrypt/decrypt CLI utilities")
    parser.add_argument(
        "--sizes",
        metavar="N",
        type=int,
        nargs="*",
        help="List of payload sizes to test (default: 10B..10MB assortment)",
    )
    args = parser.parse_args(argv)

    if args.sizes:
        sizes = [size for size in args.sizes if size > 0]
        if not sizes:
            parser.error("at least one positive payload size is required")
    else:
        sizes = [
            10,
            64,
            512,
            4096,
            65536,
            1048576,
            10 * 1024 * 1024,
        ]

    repo_root = Path(__file__).resolve().parents[1]
    execute_tests(repo_root, sizes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
