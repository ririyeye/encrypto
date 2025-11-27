#!/usr/bin/env python3
"""End-to-end tests for the hybrid CLI utilities.

The script builds the enc/dec binaries, prepares payloads of
various sizes, and verifies container integrity with PyCryptodome. It also
exercises deterministic randomness via ENCRYPTO_TEST_RANDOM_PATH to keep output
stable across runs.
"""

import argparse
import gzip
import io
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
import hashlib
from pathlib import Path
from typing import List, Sequence

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except ModuleNotFoundError:
    try:
        from Cryptodome.Cipher import AES, PKCS1_OAEP
        from Cryptodome.Hash import SHA256
        from Cryptodome.PublicKey import RSA
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


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def resolve_target(repo_root: Path, name: str) -> Path:
    output = subprocess.check_output(["xmake", "show", "-t", name], cwd=repo_root)
    decoded = output.decode(errors="ignore")
    for raw_line in decoded.splitlines():
        stripped = _strip_ansi(raw_line).strip()
        lowered = stripped.lower()
        if lowered.startswith("targetfile") or "targetfile" in lowered:
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
        # Handle potential localized key (e.g., Chinese "目标文件").
        clean_line = stripped.replace("\x00", "")
        if "目标文件" in clean_line:
            path = clean_line.split("目标文件", 1)[1].strip(" ：:")
            if path:
                target_path = Path(path)
                if not target_path.is_absolute():
                    target_path = repo_root / target_path
                return target_path.resolve()

    build_root = repo_root / "build"
    if build_root.exists():
        expected_names = {name, f"{name}.exe", f"{name}.dll"}
        for candidate in build_root.rglob("*"):
            if not (candidate.is_file() or candidate.is_symlink()):
                continue
            if candidate.name in expected_names:
                return candidate.resolve()
    raise SystemExit(f"Unable to determine target path for {name}")

def run_cli(program: Path, src: Path, dst: Path, random_path: Path, compression: str) -> None:
    env = os.environ.copy()
    env["ENCRYPTO_TEST_RANDOM_PATH"] = str(random_path)
    if compression:
        env["ENCRYPTO_COMPRESSION"] = compression
    program_path = Path(program)
    if not program_path.exists():
        raise SystemExit(f"Executable not found: {program_path}")
    run([str(program_path), str(src), str(dst)], env=env)


def load_bytes(path: Path) -> bytes:
    with path.open("rb") as fp:
        return fp.read()


def write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as fp:
        fp.write(data)


def normalize_compression(value: str | None) -> str:
    if value is None:
        return "gzip"
    key = value.strip().lower()
    if not key:
        return "gzip"
    if key in {"gz", "gzip"}:
        return "gzip"
    if key in {"zstd", "zst"}:
        return "zstd"
    if key in {"none", "raw", "tar"}:
        return "none"
    if key == "lz4":
        return "lz4"
    raise ValueError(f"unsupported compression '{value}'")


def compression_to_id(name: str) -> int:
    lookup = {
        "none": 0,
        "gzip": 1,
        "zstd": 2,
        "lz4": 3,
    }
    if name not in lookup:
        raise ValueError(f"unknown compression '{name}'")
    return lookup[name]


class RandomByteStream:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def take(self, length: int) -> bytes:
        end = self._offset + length
        chunk = self._data[self._offset:end]
        if len(chunk) != length:
            raise AssertionError("deterministic RNG stream exhausted")
        self._offset = end
        return chunk

    def randfunc(self, length: int) -> bytes:
        return self.take(length)


def build_tar_bytes(root: Path) -> bytes:
    root = root.resolve()

    block_size = tarfile.BLOCKSIZE
    tar_buffer = io.BytesIO()

    def sanitize_tarinfo(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
        tarinfo.mtime = int(tarinfo.mtime)
        tarinfo.pax_headers = {}
        tarinfo.uname = ""
        tarinfo.gname = ""
        if tarinfo.devmajor is not None:
            tarinfo.devmajor = 0
        if tarinfo.devminor is not None:
            tarinfo.devminor = 0
        return tarinfo

    def add_path(archive: tarfile.TarFile, source: Path, arcname: str) -> None:
        archive.add(str(source), arcname=arcname, recursive=False, filter=sanitize_tarinfo)
        if source.is_dir():
            children = sorted(source.iterdir(), key=lambda p: p.name)
            for child in children:
                child_arc = f"{arcname}/{child.name}"
                add_path(archive, child, child_arc)

    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        if root.is_dir():
            add_path(archive, root, root.name)
        elif root.is_file():
            add_path(archive, root, root.name)
        else:
            raise AssertionError(f"tar source '{root}' must be a file or directory")

    tar_bytes = bytearray(tar_buffer.getvalue())

    def encode_octal(value: int, digits: int, trailer: bytes) -> bytes:
        text = f"{value:o}".rjust(digits, "0")
        if len(text) > digits:
            raise AssertionError("tar metadata value overflow")
        return text.encode("ascii") + trailer

    total_len = len(tar_bytes)
    start = 0
    while start + block_size <= total_len:
        block = bytes(tar_bytes[start : start + block_size])
        if not block or all(b == 0 for b in block):
            break

        info = tarfile.TarInfo.frombuf(block, encoding="utf-8", errors="surrogateescape")

        tar_bytes[start + 100 : start + 108] = encode_octal(info.mode, 6, b" \0")
        tar_bytes[start + 108 : start + 116] = encode_octal(info.uid, 6, b" \0")
        tar_bytes[start + 116 : start + 124] = encode_octal(info.gid, 6, b" \0")
        tar_bytes[start + 124 : start + 136] = encode_octal(info.size, 11, b" ")
        tar_bytes[start + 136 : start + 148] = encode_octal(int(info.mtime), 11, b" ")

        tar_bytes[start + 148 : start + 156] = b"        "
        tar_bytes[start + 156] = info.type if isinstance(info.type, int) else ord(info.type)

        tar_bytes[start + 265 : start + 297] = b"\0" * 32
        tar_bytes[start + 297 : start + 329] = b"\0" * 32

        dev_major = info.devmajor if info.devmajor is not None else 0
        dev_minor = info.devminor if info.devminor is not None else 0
        tar_bytes[start + 329 : start + 337] = encode_octal(dev_major, 6, b" \0")
        tar_bytes[start + 337 : start + 345] = encode_octal(dev_minor, 6, b" \0")

        header = bytearray(tar_bytes[start : start + block_size])
        header[148:156] = b"        "
        checksum = sum(header)
        header[148:156] = encode_octal(checksum, 6, b"\0 ")
        tar_bytes[start : start + block_size] = header

        data_size = info.size
        data_padding = (-data_size) % block_size
        start += block_size + data_size + data_padding

    zero_block = b"\0" * block_size
    idx = len(tar_bytes)
    while idx > 0 and tar_bytes[idx - block_size : idx] == zero_block:
        idx -= block_size
    trimmed_len = idx + 2 * block_size
    if trimmed_len > len(tar_bytes):
        trimmed_len = len(tar_bytes)
    return bytes(tar_bytes[:trimmed_len])


def gzip_from_tar(tar_bytes: bytes) -> bytes:
    compressor = zlib.compressobj(
        level=6,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=8,
        strategy=zlib.Z_DEFAULT_STRATEGY,
    )
    compressed = compressor.compress(tar_bytes)
    compressed += compressor.flush()

    crc = zlib.crc32(tar_bytes) & 0xFFFFFFFF
    isize = len(tar_bytes) & 0xFFFFFFFF

    header = b"\x1f\x8b\x08\x00" + struct.pack("<I", 0) + b"\x00\x03"
    trailer = struct.pack("<II", crc, isize)
    return header + compressed + trailer


def build_tar_payload(root: Path, compression: str) -> bytes:
    tar_bytes = build_tar_bytes(root)
    if compression == "none":
        return tar_bytes
    if compression == "gzip":
        return gzip_from_tar(tar_bytes)
    raise SystemExit(
        "python reference harness only supports 'gzip' or 'none'; "
        "set ENCRYPTO_TEST_COMPRESSION=gzip for other modes"
    )


def build_python_container(
    public_key: RSA.RsaKey, rng: RandomByteStream, payload: bytes, compression: str
) -> bytes:
    session_key = rng.take(32)
    iv = rng.take(12)

    oaep_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256, randfunc=rng.randfunc)
    rsa_session = oaep_cipher.encrypt(session_key)

    aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = aes.encrypt_and_digest(payload)

    compression_id = compression_to_id(compression)

    header = bytearray(18)
    header[0:4] = b"ENHY"
    header[4] = 2
    header[5] = compression_id
    header[6:8] = len(rsa_session).to_bytes(2, "big")
    header[8] = len(iv)
    header[9] = len(tag)
    header[10:18] = len(ciphertext).to_bytes(8, "big")

    rsa_header = oaep_cipher.encrypt(bytes(header))

    return rsa_header + rsa_session + iv + ciphertext + tag


def snapshot_directory(root: Path) -> dict[str, tuple]:
    snapshot: dict[str, tuple] = {}
    if not root.exists():
        return snapshot

    entries = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    for path in entries:
        rel = path.relative_to(root).as_posix()
        st = path.lstat()
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            snapshot[rel] = ("symlink", os.readlink(path))
        elif stat.S_ISDIR(st.st_mode):
            snapshot[rel] = ("dir", mode)
        elif stat.S_ISREG(st.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as fp:
                while True:
                    chunk = fp.read(64 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            snapshot[rel] = ("file", mode, digest.digest())
        else:
            raise AssertionError(f"Unsupported file type '{rel}' in snapshot")
    return snapshot


def compare_directories(lhs: Path, rhs: Path) -> None:
    left_snapshot = snapshot_directory(lhs)
    right_snapshot = snapshot_directory(rhs)

    if left_snapshot.keys() != right_snapshot.keys():
        missing_left = sorted(right_snapshot.keys() - left_snapshot.keys())
        missing_right = sorted(left_snapshot.keys() - right_snapshot.keys())
        raise AssertionError(
            f"Directory mismatch; only in left: {missing_right}, only in right: {missing_left}"
        )

    for rel in left_snapshot:
        left_entry = left_snapshot[rel]
        right_entry = right_snapshot[rel]
        if left_entry[0] != right_entry[0]:
            raise AssertionError(f"Type mismatch for '{rel}' ({left_entry[0]} vs {right_entry[0]})")
        if left_entry[0] == "dir":
            if left_entry[1] != right_entry[1]:
                raise AssertionError(f"Directory mode mismatch for '{rel}'")
        elif left_entry[0] == "file":
            if left_entry[1] != right_entry[1] or left_entry[2] != right_entry[2]:
                raise AssertionError(f"File mismatch for '{rel}'")
        elif left_entry[0] == "symlink":
            if left_entry[1] != right_entry[1]:
                raise AssertionError(f"Symlink target mismatch for '{rel}'")


def execute_tests(
    repo_root: Path, sizes: Sequence[int], compression: str | None, directory_payload: Path | None,
    rust_mode: bool = False
) -> None:
    try:
        compression = normalize_compression(compression)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if rust_mode:
        # Rust 版本测试：只做 round-trip 验证，不做确定性比对
        # 因为 Rust 版本使用不同的密钥
        rust_dir = repo_root / "rust"
        enc_path = rust_dir / "target" / "release" / "enc"
        dec_path = rust_dir / "target" / "release" / "dec"
        
        if not enc_path.exists() or not dec_path.exists():
            print("Building Rust binaries...")
            run(["cargo", "build", "--release"], cwd=rust_dir)
        
        if not enc_path.exists():
            raise SystemExit(f"Rust enc binary not found: {enc_path}")
        if not dec_path.exists():
            raise SystemExit(f"Rust dec binary not found: {dec_path}")
        
        print(f"Testing Rust version (compression: {compression})")
    else:
        if compression not in {"gzip", "none"}:
            raise SystemExit(
                "python reference harness only supports ENCRYPTO_COMPRESSION in {gzip, none}; "
                "set ENCRYPTO_TEST_COMPRESSION=gzip to match the reference output"
            )
        targets: List[str] = ["enc", "dec"]

        ensure_built(repo_root, targets)

        enc_path: Path = resolve_target(repo_root, "enc")
        dec_path: Path = resolve_target(repo_root, "dec")
        generated_dir = repo_root / "build" / "generated"
        priv_pem = generated_dir / "rsa_private.pem"
        pub_pem = generated_dir / "rsa_public.pem"

        if not priv_pem.exists() or not pub_pem.exists():
            raise SystemExit("RSA key material was not generated; run xmake build first")

        public_key = RSA.import_key(load_bytes(pub_pem))

    if not rust_mode:
        key_len = public_key.size_in_bytes()
        random_len = max(4 * key_len * 4, 1 << 16)

    if directory_payload is not None:
        directory_payload = directory_payload.resolve()
        if not directory_payload.exists():
            raise SystemExit(f"Directory payload '{directory_payload}' does not exist")

    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)

        for size in sizes:
            plaintext = os.urandom(size)
            plain_path = tmpdir / f"hy_plain_{size}.bin"
            write_bytes(plain_path, plaintext)

            if rust_mode:
                # Rust 版本：只做 round-trip 测试
                container_path = tmpdir / f"hy_enc_file_{size}.bin"
                env = os.environ.copy()
                if compression:
                    env["ENCRYPTO_COMPRESSION"] = compression
                run([str(enc_path), str(plain_path), str(container_path)], env=env)

                roundtrip_dir = tmpdir / f"hy_roundtrip_file_{size}"
                run([str(dec_path), str(container_path), str(roundtrip_dir)], env=env)
                extracted_file = roundtrip_dir / plain_path.name
                if not extracted_file.is_file():
                    raise AssertionError(f"Decrypted file missing for payload size {size}")
                if load_bytes(extracted_file) != plaintext:
                    raise AssertionError(f"Decrypted file mismatch for payload size {size}")
                extra_entries = [p for p in roundtrip_dir.iterdir() if p.name != plain_path.name]
                if extra_entries:
                    raise AssertionError(f"Unexpected entries after decrypt: {extra_entries}")
            else:
                random_bytes = os.urandom(random_len)
                random_path = tmpdir / f"hy_rand_file_{size}.bin"
                write_bytes(random_path, random_bytes)

                tar_payload = build_tar_payload(plain_path, compression)
                python_container = build_python_container(
                    public_key, RandomByteStream(random_bytes), tar_payload, compression
                )

                container_path = tmpdir / f"hy_enc_file_{size}.bin"
                run_cli(enc_path, plain_path, container_path, random_path, compression)

                cli_container = load_bytes(container_path)
                if cli_container != python_container:
                    raise AssertionError(f"Compressed+encrypted mismatch for file payload size {size}")

                roundtrip_dir = tmpdir / f"hy_roundtrip_file_{size}"
                run_cli(dec_path, container_path, roundtrip_dir, random_path, compression)
                extracted_file = roundtrip_dir / plain_path.name
                if not extracted_file.is_file():
                    raise AssertionError(f"Decrypted file missing for payload size {size}")
                if load_bytes(extracted_file) != plaintext:
                    raise AssertionError(f"Decrypted file mismatch for payload size {size}")
                extra_entries = [p for p in roundtrip_dir.iterdir() if p.name != plain_path.name]
                if extra_entries:
                    raise AssertionError(f"Unexpected entries after decrypt: {extra_entries}")

            print(f"[OK] file payload of {size} bytes round-tripped")

        if directory_payload is not None:
            if rust_mode:
                # Rust 版本：只做 round-trip 测试
                container_path = tmpdir / "hy_enc_dir.bin"
                env = os.environ.copy()
                if compression:
                    env["ENCRYPTO_COMPRESSION"] = compression
                run([str(enc_path), str(directory_payload), str(container_path)], env=env)

                roundtrip_root = tmpdir / "hy_roundtrip_dir"
                run([str(dec_path), str(container_path), str(roundtrip_root)], env=env)

                if directory_payload.is_dir():
                    expected_root = roundtrip_root
                    if not expected_root.exists():
                        raise AssertionError("Decrypted directory root not found")
                    compare_directories(directory_payload, expected_root)
                else:
                    expected_root = roundtrip_root / directory_payload.name
                    if not expected_root.is_file():
                        raise AssertionError("Decrypted file not found for directory payload")
                    if load_bytes(expected_root) != load_bytes(directory_payload):
                        raise AssertionError("Decrypted file mismatch for directory payload")
            else:
                tar_payload = build_tar_payload(directory_payload, compression)
                random_bytes = os.urandom(random_len)
                random_path = tmpdir / "hy_rand_dir.bin"
                write_bytes(random_path, random_bytes)

                python_container = build_python_container(
                    public_key, RandomByteStream(random_bytes), tar_payload, compression
                )

                container_path = tmpdir / "hy_enc_dir.bin"
                run_cli(enc_path, directory_payload, container_path, random_path, compression)

                cli_container = load_bytes(container_path)
                if cli_container != python_container:
                    raise AssertionError("Compressed+encrypted directory payload mismatch")

                roundtrip_root = tmpdir / "hy_roundtrip_dir"
                run_cli(dec_path, container_path, roundtrip_root, random_path, compression)

                if directory_payload.is_dir():
                    expected_root = roundtrip_root
                    if not expected_root.exists():
                        raise AssertionError("Decrypted directory root not found")
                    compare_directories(directory_payload, expected_root)
                else:
                    expected_root = roundtrip_root / directory_payload.name
                    if not expected_root.is_file():
                        raise AssertionError("Decrypted file not found for directory payload")
                    if load_bytes(expected_root) != load_bytes(directory_payload):
                        raise AssertionError("Decrypted file mismatch for directory payload")

            print(
                f"[OK] directory payload '{directory_payload.name}' round-trip verified"
            )

    summary = f"All {len(sizes)} file payload cases passed"
    if directory_payload is not None:
        summary += f"; directory '{directory_payload}' verified"
    print(summary)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Test hybrid encrypt/decrypt CLI utilities")
    parser.add_argument(
        "--sizes",
        metavar="N",
        type=int,
        nargs="*",
        help="List of payload sizes to test (default: 10B..10MB assortment)",
    )
    parser.add_argument(
        "--directory",
        type=Path,
        help="Optional directory payload to validate (default: skip directory test)",
    )
    parser.add_argument(
        "--rust",
        action="store_true",
        help="Test Rust version instead of C version (round-trip only, no deterministic comparison)",
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
    compression = os.environ.get("ENCRYPTO_TEST_COMPRESSION")
    execute_tests(repo_root, sizes, compression, args.directory, rust_mode=args.rust)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
