#!/usr/bin/env python3
"""End-to-end tests for the RSA CLI utilities.

The script builds the rsa_encrypt/rsa_decrypt binaries, generates test files of
varying sizes, and verifies interoperability with Python's RSA OAEP
implementation from PyCryptodome. It also exercises deterministic randomness via
ENCRYPTO_TEST_RANDOM_PATH so that ciphertexts match byte-for-byte.
"""

import argparse
import math
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Sequence

try:
    from Crypto.Cipher import PKCS1_OAEP
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
        run(["xmake", "build"], cwd=repo_root)
    else:
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


class RandomStream:
    """Callable stream that hands out deterministic bytes."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def __call__(self, size: int) -> bytes:
        end = self._offset + size
        if end > len(self._data):
            raise RuntimeError("deterministic random stream exhausted")
        chunk = self._data[self._offset:end]
        self._offset = end
        return chunk

    @property
    def consumed(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset


def chunk_iter(data: bytes, block_size: int) -> Iterable[bytes]:
    for start in range(0, len(data), block_size):
        yield data[start : start + block_size]


def encrypt_python(public_key: RSA.RsaKey, chunk_size: int, random_bytes: bytes, payload: bytes) -> bytes:
    stream = RandomStream(random_bytes)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256, randfunc=stream)
    blocks: List[bytes] = []
    for block in chunk_iter(payload, chunk_size):
        blocks.append(cipher.encrypt(block))
    return b"".join(blocks)


def decrypt_python(private_key: RSA.RsaKey, key_len: int, ciphertext: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    blocks: List[bytes] = []
    for block in chunk_iter(ciphertext, key_len):
        blocks.append(cipher.decrypt(block))
    return b"".join(blocks)


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
    ensure_built(repo_root, ["rsa_encrypt", "rsa_decrypt"])

    rsa_encrypt_path = resolve_target(repo_root, "rsa_encrypt")
    rsa_decrypt_path = resolve_target(repo_root, "rsa_decrypt")

    generated_dir = repo_root / "build" / "generated"
    priv_pem = generated_dir / "rsa_private.pem"
    pub_pem = generated_dir / "rsa_public.pem"

    if not priv_pem.exists() or not pub_pem.exists():
        raise SystemExit("RSA key material was not generated; run xmake build first")

    public_key = RSA.import_key(load_bytes(pub_pem))
    private_key = RSA.import_key(load_bytes(priv_pem))

    key_len = public_key.size_in_bytes()
    hash_len = SHA256.digest_size
    chunk_size = key_len - 2 * hash_len - 2
    if chunk_size <= 0:
        raise SystemExit("Invalid chunk size computed for current key parameters")

    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)
        for size in sizes:
            plaintext = os.urandom(size)
            plain_path = tmpdir / f"plain_{size}.bin"
            write_bytes(plain_path, plaintext)

            block_count = max(1, math.ceil(size / chunk_size))
            # Provide ample deterministic bytes for OAEP seeds and RSA blinding entropy.
            random_len = block_count * (hash_len + 4 * key_len)
            random_bytes = os.urandom(random_len)
            random_path = tmpdir / f"rand_{size}.bin"
            write_bytes(random_path, random_bytes)

            cli_cipher_path = tmpdir / f"cli_{size}.bin"
            run_cli(rsa_encrypt_path, plain_path, cli_cipher_path, random_path)
            cli_ciphertext = load_bytes(cli_cipher_path)

            py_ciphertext = encrypt_python(public_key, chunk_size, random_bytes, plaintext)
            if cli_ciphertext != py_ciphertext:
                raise AssertionError(f"Ciphertext mismatch for payload size {size}")

            cli_roundtrip_path = tmpdir / f"cli_roundtrip_{size}.bin"
            run_cli(rsa_decrypt_path, cli_cipher_path, cli_roundtrip_path, random_path)
            cli_plain_roundtrip = load_bytes(cli_roundtrip_path)
            if cli_plain_roundtrip != plaintext:
                raise AssertionError(f"CLI round-trip mismatch for payload size {size}")

            py_plain = decrypt_python(private_key, key_len, cli_ciphertext)
            if py_plain != plaintext:
                raise AssertionError(f"Python decrypt mismatch for payload size {size}")

            py_cipher_path = tmpdir / f"py_{size}.bin"
            write_bytes(py_cipher_path, py_ciphertext)
            cli_from_py_path = tmpdir / f"cli_from_py_{size}.bin"
            run_cli(rsa_decrypt_path, py_cipher_path, cli_from_py_path, random_path)
            if load_bytes(cli_from_py_path) != plaintext:
                raise AssertionError(f"CLI decrypt of Python ciphertext failed for payload size {size}")

            print(f"[OK] processed payload of {size} bytes")

    print(f"All {len(sizes)} cases passed")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Test RSA CLI utilities")
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
