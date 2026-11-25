"""Secure ZIP inspection.

Uploaded archives are NEVER extracted to disk. Eligible entries are read into
memory with strict size limits and returned as text. Nothing in an archive is
ever executed, imported or passed to a shell.
"""
from __future__ import annotations

import io
import logging
import posixpath
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass, field

from app.config import Settings

logger = logging.getLogger("owasp_mentor.zip")

ALLOWED_EXTENSIONS = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".json", ".xml", ".yaml", ".yml"}
)

# Directory names that are skipped (dependencies, VCS data and build output).
EXCLUDED_DIRS = frozenset(
    {
        "node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv",
        "site-packages", "bower_components", "vendor", ".next", ".nuxt", ".cache",
        "coverage", ".tox", ".mypy_cache", ".pytest_cache", "target", ".gradle",
    }
)

# Generated files that are valid source extensions but not worth scanning.
GENERATED_FILENAMES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})

# Executables, libraries, bytecode and nested archives: the whole upload is rejected.
BLOCKED_BINARY_EXTENSIONS = frozenset(
    {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".war", ".pyc",
        ".pyo", ".o", ".a", ".lib", ".msi", ".apk", ".com", ".scr", ".sys", ".wasm",
        ".node", ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz",
    }
)

_MAX_PATH_LENGTH = 255
_MIN_SIZE_FOR_RATIO_CHECK = 64 * 1024


class ZipRejected(Exception):
    """Raised when an upload is refused. ``message`` is safe to show to users."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass(frozen=True)
class ZipLimits:
    max_upload_bytes: int
    max_entries: int
    max_total_uncompressed: int
    max_file_bytes: int
    max_compression_ratio: int
    max_text_chars: int

    @classmethod
    def from_settings(cls, settings: Settings) -> "ZipLimits":
        return cls(
            max_upload_bytes=settings.max_upload_bytes,
            max_entries=settings.max_entries,
            max_total_uncompressed=settings.max_total_uncompressed,
            max_file_bytes=settings.max_file_bytes,
            max_compression_ratio=settings.max_compression_ratio,
            max_text_chars=settings.max_text_chars,
        )


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str


@dataclass
class InspectionResult:
    files: list[SourceFile] = field(default_factory=list)
    total_entries: int = 0
    skipped_unsupported: int = 0
    skipped_excluded: int = 0
    truncated: bool = False

    @property
    def skipped(self) -> int:
        return self.skipped_unsupported + self.skipped_excluded


def _normalise_name(raw: str) -> tuple[str, bool]:
    """Validate an archive entry name. Returns (clean_path, is_directory)."""
    if "\x00" in raw or any(ord(ch) < 32 for ch in raw):
        raise ZipRejected(422, "The archive contains an entry with an unsafe name.")
    name = raw.replace("\\", "/")
    if len(name) > _MAX_PATH_LENGTH:
        raise ZipRejected(422, "The archive contains an entry with a path that is too long.")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ZipRejected(422, "The archive contains an absolute path, which is not allowed.")
    is_dir = name.endswith("/")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ZipRejected(422, "The archive contains a parent-directory (path traversal) entry, which is not allowed.")
    if not parts:
        raise ZipRejected(422, "The archive contains an entry with an empty name.")
    return "/".join(parts), is_dir


def _validate_entries(infos: list[zipfile.ZipInfo], data_len: int, limits: ZipLimits) -> list[tuple[str, zipfile.ZipInfo]]:
    """Check every entry's metadata before reading any content."""
    files: list[tuple[str, zipfile.ZipInfo]] = []
    seen: set[str] = set()
    declared_total = 0

    for info in infos:
        path, is_dir = _normalise_name(info.filename)

        if info.flag_bits & 0x1:
            raise ZipRejected(422, "Encrypted archive entries are not supported.")

        if info.create_system == 3:  # Unix: the high 16 bits of external_attr hold st_mode
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind == stat.S_IFLNK:
                raise ZipRejected(422, "The archive contains a symbolic link, which is not allowed.")
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ZipRejected(422, "The archive contains an unsafe special file.")

        if is_dir:
            continue

        key = path.casefold()
        if key in seen:
            raise ZipRejected(422, "The archive contains duplicate file names.")
        seen.add(key)

        if info.file_size > limits.max_file_bytes:
            raise ZipRejected(422, f"A file in the archive is larger than the {limits.max_file_bytes // (1024 * 1024)} MB per-file limit.")

        if (
            info.file_size >= _MIN_SIZE_FOR_RATIO_CHECK
            and info.compress_size > 0
            and info.file_size / info.compress_size > limits.max_compression_ratio
        ):
            raise ZipRejected(422, "The archive has a suspiciously high compression ratio.")

        declared_total += info.file_size
        files.append((path, info))

    if declared_total > limits.max_total_uncompressed:
        raise ZipRejected(422, f"The archive expands to more than the {limits.max_total_uncompressed // (1024 * 1024)} MB uncompressed limit.")
    if (
        declared_total >= _MIN_SIZE_FOR_RATIO_CHECK
        and data_len > 0
        and declared_total / data_len > limits.max_compression_ratio
    ):
        raise ZipRejected(422, "The archive has a suspiciously high compression ratio.")
    return files


def inspect_zip(data: bytes, limits: ZipLimits) -> InspectionResult:
    """Safely inspect a ZIP held in memory and return the eligible source files."""
    if len(data) > limits.max_upload_bytes:
        raise ZipRejected(413, f"The upload is larger than the {limits.max_upload_bytes // (1024 * 1024)} MB limit.")
    if not data:
        raise ZipRejected(400, "The uploaded file is empty.")
    if not (data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06")):
        raise ZipRejected(400, "The uploaded file is not a valid ZIP archive.")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, NotImplementedError):
        raise ZipRejected(400, "The ZIP archive is malformed or corrupted.") from None

    result = InspectionResult()
    with archive:
        try:
            infos = archive.infolist()
        except (zipfile.BadZipFile, EOFError, OSError, ValueError):
            raise ZipRejected(400, "The ZIP archive is malformed or corrupted.") from None

        result.total_entries = len(infos)
        if len(infos) > limits.max_entries:
            raise ZipRejected(
                422,
                f"The archive has more than {limits.max_entries} entries. "
                "Remove node_modules, build output and other generated folders before zipping.",
            )

        entries = _validate_entries(infos, len(data), limits)
        entries.sort(key=lambda item: item[0])

        actual_total = 0
        text_chars = 0

        for path, info in entries:
            parts = path.split("/")
            filename = parts[-1]

            if any(part.lower() in EXCLUDED_DIRS for part in parts[:-1]):
                result.skipped_excluded += 1
                continue

            ext = posixpath.splitext(filename)[1].lower()
            if ext in BLOCKED_BINARY_EXTENSIONS:
                raise ZipRejected(422, "The archive contains an unsupported binary or executable file.")
            if (
                ext not in ALLOWED_EXTENSIONS
                or filename.lower() in GENERATED_FILENAMES
                or filename.lower().endswith(".min.js")
            ):
                result.skipped_unsupported += 1
                continue

            if text_chars >= limits.max_text_chars:
                result.truncated = True
                result.skipped_unsupported += 1
                continue

            try:
                with archive.open(info, "r") as handle:
                    raw = handle.read(limits.max_file_bytes + 1)
            except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError, OSError, ValueError):
                raise ZipRejected(400, "The ZIP archive is malformed or corrupted.") from None

            if len(raw) > limits.max_file_bytes:
                raise ZipRejected(422, f"A file in the archive is larger than the {limits.max_file_bytes // (1024 * 1024)} MB per-file limit.")
            actual_total += len(raw)
            if actual_total > limits.max_total_uncompressed:
                raise ZipRejected(422, f"The archive expands to more than the {limits.max_total_uncompressed // (1024 * 1024)} MB uncompressed limit.")
            if b"\x00" in raw[:8192]:
                raise ZipRejected(422, "The archive contains a binary file disguised as source code.")

            text = raw.decode("utf-8-sig", errors="replace")
            remaining = limits.max_text_chars - text_chars
            if len(text) > remaining:
                text = text[:remaining]
                result.truncated = True
            text_chars += len(text)
            result.files.append(SourceFile(path=path, text=text))

    if not result.files:
        raise ZipRejected(422, "No supported source files were found in the archive.")

    logger.info(
        "ZIP inspected: entries=%d scanned=%d skipped=%d truncated=%s",
        result.total_entries, len(result.files), result.skipped, result.truncated,
    )
    return result
