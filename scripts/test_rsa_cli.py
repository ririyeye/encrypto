#!/usr/bin/env python3
"""End-to-end tests for the hybrid CLI utilities.

The script builds the enc/dec binaries, prepares payloads of
various sizes, and verifies round-trip integrity.
"""

import argparse
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


def run(command: Sequence[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    """Run a subprocess, bubbling up failures with context."""

    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode != 0:
        raise SystemExit(
            "command failed (exit code %d): %s" % (result.returncode, " ".join(command))
        )


def load_bytes(path: Path) -> bytes:
    with path.open("rb") as fp:
        return fp.read()


def write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as fp:
        fp.write(data)


def normalize_compression(value: str | None) -> str:
    if value is None:
        return "lz4"
    key = value.strip().lower()
    if not key:
        return "lz4"
    if key in {"gz", "gzip"}:
        return "gzip"
    if key in {"zstd", "zst"}:
        return "zstd"
    if key in {"none", "raw", "tar"}:
        return "none"
    if key == "lz4":
        return "lz4"
    raise ValueError(f"unsupported compression '{value}'")


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
) -> None:
    try:
        compression = normalize_compression(compression)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    # Rust 是主体实现，只做 round-trip 验证
    enc_path = repo_root / "target" / "release" / "enc"
    dec_path = repo_root / "target" / "release" / "dec"
    
    if not enc_path.exists() or not dec_path.exists():
        print("Building Rust binaries...")
        run(["cargo", "build", "--release"], cwd=repo_root)
    
    if not enc_path.exists():
        raise SystemExit(f"enc binary not found: {enc_path}")
    if not dec_path.exists():
        raise SystemExit(f"dec binary not found: {dec_path}")
    
    print(f"Testing encrypto (compression: {compression})")

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

            # Round-trip 测试
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

            print(f"[OK] file payload of {size} bytes round-tripped")

        if directory_payload is not None:
            # 目录 round-trip 测试
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
    execute_tests(repo_root, sizes, compression, args.directory)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
