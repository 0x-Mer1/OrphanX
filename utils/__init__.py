"""
Recon Bot Utils - Subdomain Takeover Discovery Pipeline
========================================================

Utility modules for the Recon Bot pipeline providing file management,
Telegram notifications, and cloud watchlist operations.

Modules
-------
file_manager : FileManager
    Atomic file operations, async-safe locking, evidence silo management.
    Provides thread-safe file I/O for asyncio environments.

notifier : TelegramNotifier
    Async Telegram notifications with rate limiting for stage alerts,
    critical findings, and report delivery.

Usage
-----
    from utils import FileManager, TelegramNotifier

    # File operations
    fm = FileManager(base_dir="targets")
    await fm.atomic_write("/path/to/file", "content")

    # Telegram notifications
    notifier = await create_notifier(bot_token, chat_id)
    await notifier.send_stage1_complete(count=100)

Common Patterns
---------------
- All file operations support both async and sync variants
- Proper error handling with custom exceptions
- Atomic writes use temp file + rename pattern
- Rate limiting on Telegram API calls
- Lock files for cross-process safety

Notes
-----
    - FileManager uses fcntl.flock for async-safe file locking
    - TelegramNotifier uses token bucket rate limiting (20 msg/min)
    - Evidence silos created per subdomain for evidence collection
"""

import logging

# Import all utility modules
from utils import file_manager
from utils import notifier

# Import main classes and functions for convenient access
from utils.file_manager import (
    FileManager,
    FileManagerError,
    PermissionDeniedError,
    AtomicWriteError,
)

from utils.notifier import (
    TelegramNotifier,
    RateLimiter,
    create_notifier,
)

# Module-level logger
logger = logging.getLogger(__name__)

# Public API
__all__ = [
    # Modules
    "file_manager",
    "notifier",
    # FileManager
    "FileManager",
    "FileManagerError",
    "PermissionDeniedError",
    "AtomicWriteError",
    # TelegramNotifier
    "TelegramNotifier",
    "RateLimiter",
    "create_notifier",
]