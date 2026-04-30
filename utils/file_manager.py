"""
File Manager for Recon Bot - Subdomain Takeover Discovery Pipeline

Provides atomic file operations, thread-safe directory management,
and evidence silo creation for security research automation.
"""

import asyncio
import fcntl
import logging
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, BinaryIO, List, Optional, Union

logger = logging.getLogger(__name__)


class FileManagerError(Exception):
    """Base exception for FileManager operations."""
    pass


class PermissionDeniedError(FileManagerError):
    """Raised when file operations encounter permission errors."""
    pass


class AtomicWriteError(FileManagerError):
    """Raised when atomic write operations fail."""
    pass


class FileManager:
    """
    Manages file operations for the Recon Bot pipeline.

    Provides:
    - Atomic writes with temp file + rename pattern
    - Async-safe file locking for concurrent access
    - Automatic directory creation
    - Evidence silo management
    - Graceful permission error handling

    Thread-safe for asyncio environments.
    """

    def __init__(self, base_dir: Union[str, Path] = Path("targets")):
        """
        Initialize FileManager.

        Args:
            base_dir: Base directory for all target operations (default: 'targets')
        """
        self.base_dir = Path(base_dir)
        self._lock = asyncio.Lock()

    def _ensure_dir(self, path: Path) -> None:
        """
        Create directory path if it doesn't exist.

        Args:
            path: Directory path to create

        Raises:
            PermissionDeniedError: If directory cannot be created due to permissions
        """
        try:
            path.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise PermissionDeniedError(f"Cannot create directory {path}: {e}")

    def ensure_target_dir(self, domain: str) -> Path:
        """
        Create target directory structure for a domain.

        Creates: targets/{domain}/

        Args:
            domain: Target domain name

        Returns:
            Path to the target directory
        """
        target_dir = self.base_dir / domain
        self._ensure_dir(target_dir)
        return target_dir

    def ensure_evidence_silo(self, domain: str, subdomain: str) -> Path:
        """
        Create evidence silo for a specific subdomain finding.

        Creates: targets/{domain}/evidence/{subdomain}/

        Args:
            domain: Target domain name
            subdomain: Subdomain being investigated

        Returns:
            Path to the evidence silo directory
        """
        evidence_dir = self.base_dir / domain / "evidence" / subdomain
        self._ensure_dir(evidence_dir)
        return evidence_dir

    def _get_lock_path(self, file_path: Path) -> Path:
        """
        Get path for lock file associated with a target file.

        Args:
            file_path: Path to the file needing a lock

        Returns:
            Path to the lock file
        """
        return file_path.parent / f".{file_path.name}.lock"

    @asynccontextmanager
    async def _async_file_lock(self, file_path: Path) -> AsyncGenerator[None, None]:
        """
        Acquire an async lock for file operations.

        Uses a file-based lock with flock for cross-process safety.

        Args:
            file_path: Path to file to lock

        Yields:
            None when lock is acquired
        """
        lock_path = self._get_lock_path(file_path)
        self._ensure_dir(lock_path.parent)

        lock_file = None
        try:
            lock_file = open(lock_path, 'w')
            await asyncio.sleep(0)  # Yield to event loop

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

            yield

        finally:
            if lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                lock_file.close()

            # Clean up lock file if no longer needed
            try:
                if lock_path.exists():
                    lock_path.unlink()
            except OSError:
                pass

    async def atomic_write(
        self,
        file_path: Union[str, Path],
        content: Union[str, bytes],
        encoding: str = 'utf-8'
    ) -> None:
        """
        Write file atomically using temp file + rename pattern.

        Ensures file is only created/visible when write is complete.

        Args:
            file_path: Destination file path
            content: Content to write (str or bytes)
            encoding: Text encoding (default: utf-8)

        Raises:
            AtomicWriteError: If write operation fails
            PermissionDeniedError: If write permissions are denied
        """
        file_path = Path(file_path)
        temp_fd = None

        async with self._async_file_lock(file_path):
            try:
                # Create temp file in same directory for atomic rename
                temp_fd, temp_path = tempfile.mkstemp(
                    dir=file_path.parent,
                    prefix=f".{file_path.name}.",
                    suffix=".tmp"
                )

                if isinstance(content, str):
                    os.write(temp_fd, content.encode(encoding))
                else:
                    os.write(temp_fd, content)

                os.close(temp_fd)
                temp_fd = None

                # Atomic rename
                try:
                    os.replace(temp_path, file_path)
                except OSError as e:
                    raise AtomicWriteError(
                        f"Failed to rename temp file to {file_path}: {e}"
                    )

            except PermissionError as e:
                raise PermissionDeniedError(
                    f"Permission denied writing to {file_path}: {e}"
                )
            except AtomicWriteError:
                raise
            except Exception as e:
                raise AtomicWriteError(f"Atomic write failed for {file_path}: {e}")
            finally:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass

    def atomic_write_sync(
        self,
        file_path: Union[str, Path],
        content: Union[str, bytes],
        encoding: str = 'utf-8'
    ) -> None:
        """
        Synchronous version of atomic_write.

        Use in non-async contexts.

        Args:
            file_path: Destination file path
            content: Content to write (str or bytes)
            encoding: Text encoding (default: utf-8)
        """
        file_path = Path(file_path)
        self._ensure_dir(file_path.parent)

        try:
            with tempfile.NamedTemporaryFile(
                mode='w' if isinstance(content, str) else 'wb',
                dir=file_path.parent,
                prefix=f".{file_path.name}.",
                suffix=".tmp",
                encoding=encoding if isinstance(content, str) else None,
                delete=False
            ) as tmp:
                tmp.write(content)
                temp_path = tmp.name

            os.replace(temp_path, file_path)

        except PermissionError as e:
            raise PermissionDeniedError(
                f"Permission denied writing to {file_path}: {e}"
            )
        except Exception as e:
            raise AtomicWriteError(f"Atomic write failed for {file_path}: {e}")

    async def read_lines(
        self,
        file_path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> AsyncGenerator[str, None]:
        """
        Read file as lines (generator).

        Memory-efficient streaming of file lines.

        Args:
            file_path: Path to file to read
            encoding: Text encoding (default: utf-8)

        Yields:
            Individual lines from file (stripped of newlines)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return

        async with self._async_file_lock(file_path):
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    for line in f:
                        yield line.rstrip('\n\r')
            except PermissionError as e:
                logger.warning(f"Permission denied reading {file_path}: {e}")
            except UnicodeDecodeError as e:
                logger.warning(f"Encoding error reading {file_path}: {e}")

    def read_lines_sync(
        self,
        file_path: Union[str, Path],
        encoding: str = 'utf-8'
    ):
        """
        Synchronous generator for reading file lines.

        Args:
            file_path: Path to file to read
            encoding: Text encoding (default: utf-8)

        Yields:
            Individual lines from file (stripped of newlines)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return

        try:
            with open(file_path, 'r', encoding=encoding) as f:
                for line in f:
                    yield line.rstrip('\n\r')
        except PermissionError as e:
            logger.warning(f"Permission denied reading {file_path}: {e}")
        except UnicodeDecodeError as e:
            logger.warning(f"Encoding error reading {file_path}: {e}")

    async def append_to_file(
        self,
        file_path: Union[str, Path],
        lines: Union[List[str], str],
        encoding: str = 'utf-8'
    ) -> int:
        """
        Append lines to file (anew-style logic).

        Only appends lines that don't already exist in the file.
        Handles duplicates gracefully.

        Args:
            file_path: Path to file to append to
            lines: Line(s) to append (string or list of strings)
            encoding: Text encoding (default: utf-8)

        Returns:
            Number of lines actually appended
        """
        file_path = Path(file_path)

        if isinstance(lines, str):
            lines = [lines]

        if not lines:
            return 0

        self._ensure_dir(file_path.parent)

        async with self._async_file_lock(file_path):
            existing = set()

            # Read existing content to avoid duplicates
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        for line in f:
                            existing.add(line.rstrip('\n\r'))
                except PermissionError as e:
                    raise PermissionDeniedError(
                        f"Permission denied reading {file_path}: {e}"
                    )

            # Filter lines already present
            new_lines = [line for line in lines if line not in existing]

            if not new_lines:
                return 0

            # Append new lines
            try:
                with open(file_path, 'a', encoding=encoding) as f:
                    for line in new_lines:
                        f.write(line + '\n')
            except PermissionError as e:
                raise PermissionDeniedError(
                    f"Permission denied appending to {file_path}: {e}"
                )

            return len(new_lines)

    def append_to_file_sync(
        self,
        file_path: Union[str, Path],
        lines: Union[List[str], str],
        encoding: str = 'utf-8'
    ) -> int:
        """
        Synchronous version of append_to_file.

        Args:
            file_path: Path to file to append to
            lines: Line(s) to append (string or list of strings)
            encoding: Text encoding (default: utf-8)

        Returns:
            Number of lines actually appended
        """
        file_path = Path(file_path)

        if isinstance(lines, str):
            lines = [lines]

        if not lines:
            return 0

        self._ensure_dir(file_path.parent)

        try:
            existing = set()

            if file_path.exists():
                with open(file_path, 'r', encoding=encoding) as f:
                    for line in f:
                        existing.add(line.rstrip('\n\r'))

            new_lines = [line for line in lines if line not in existing]

            if not new_lines:
                return 0

            with open(file_path, 'a', encoding=encoding) as f:
                for line in new_lines:
                    f.write(line + '\n')

            return len(new_lines)

        except PermissionError as e:
            raise PermissionDeniedError(
                f"Permission denied appending to {file_path}: {e}"
            )

    def file_exists(self, file_path: Union[str, Path]) -> bool:
        """
        Check if file exists.

        Args:
            file_path: Path to check

        Returns:
            True if file exists, False otherwise
        """
        return Path(file_path).exists()

    def get_file_size(self, file_path: Union[str, Path]) -> int:
        """
        Get file size in bytes.

        Args:
            file_path: Path to file

        Returns:
            File size in bytes, or 0 if file doesn't exist

        Raises:
            PermissionDeniedError: If file cannot be accessed due to permissions
        """
        file_path = Path(file_path)

        try:
            return file_path.stat().st_size
        except FileNotFoundError:
            return 0
        except PermissionError as e:
            raise PermissionDeniedError(
                f"Permission denied accessing {file_path}: {e}"
            )

    def get_file_size_human(self, file_path: Union[str, Path]) -> str:
        """
        Get file size in human-readable format.

        Args:
            file_path: Path to file

        Returns:
            Human-readable file size (e.g., "1.5 MB")
        """
        size = self.get_file_size(file_path)

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0

        return f"{size:.1f} PB"

    async def safe_write_jsonl(
        self,
        file_path: Union[str, Path],
        records: List[dict]
    ) -> None:
        """
        Write records to a JSONL file atomically.

        Args:
            file_path: Path to JSONL file
            records: List of dictionaries to write
        """
        import json

        lines = [json.dumps(record) for record in records]
        await self.atomic_write(file_path, '\n'.join(lines) + '\n')

    def safe_write_jsonl_sync(
        self,
        file_path: Union[str, Path],
        records: List[dict]
    ) -> None:
        """
        Synchronous version of safe_write_jsonl.

        Args:
            file_path: Path to JSONL file
            records: List of dictionaries to write
        """
        import json

        lines = [json.dumps(record) for record in records]
        self.atomic_write_sync(file_path, '\n'.join(lines) + '\n')

    async def append_jsonl(
        self,
        file_path: Union[str, Path],
        record: dict
    ) -> None:
        """
        Append a single record to a JSONL file.

        Args:
            file_path: Path to JSONL file
            record: Dictionary to append
        """
        import json

        await self.append_to_file(file_path, json.dumps(record))

    def append_jsonl_sync(
        self,
        file_path: Union[str, Path],
        record: dict
    ) -> None:
        """
        Synchronous version of append_jsonl.

        Args:
            file_path: Path to JSONL file
            record: Dictionary to append
        """
        import json

        self.append_to_file_sync(file_path, json.dumps(record))

    def cleanup_lock_files(self) -> int:
        """
        Remove orphaned lock files from base directory.

        Returns:
            Number of lock files removed
        """
        removed = 0
        lock_pattern = ".lock"

        try:
            for path in self.base_dir.rglob(f"*{lock_pattern}"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        except OSError:
            pass

        return removed

    def __repr__(self) -> str:
        return f"FileManager(base_dir={self.base_dir})"