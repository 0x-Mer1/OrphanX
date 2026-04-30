#!/usr/bin/env python3
"""
Watchlist Manager for Recon Bot - Subdomain Takeover Discovery Pipeline

Manages the cloud watchlist for periodic rescan operations.
Cloud watchlist is append-only — NEVER overwrite.

File format per line:
    {timestamp}|{cname_target}|{source_subdomain}|{status}

Status values: NEW, PROCESSING, DANGLED, SAFE, TAKEOVER_CONFIRMED

Trigger: /watchlist example.com
- Reads targets/example.com/cloud_watchlist.txt
- Re-runs Stage 4 (nslookup) on all entries
- New NXDOMAIN -> enters Stage 5 immediately
- Appends new findings to existing Silos
"""

import asyncio
import fcntl
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Set, Optional, List, Tuple


class WatchlistStatus(Enum):
    """Status values for watchlist entries."""
    NEW = "NEW"
    PROCESSING = "PROCESSING"
    DANGLED = "DANGLED"
    SAFE = "SAFE"
    TAKEOVER_CONFIRMED = "TAKEOVER_CONFIRMED"


class WatchlistManager:
    """
    Manages cloud watchlist entries for subdomain takeover discovery.

    Provides async-safe operations for reading, adding, and tracking
    watchlist entries across periodic rescans.

    File format per line:
        {timestamp}|{cname_target}|{source_subdomain}|{status}

    Attributes:
        base_dir: Base directory for target outputs (default: targets/)
    """

    LOCK_TIMEOUT = 10  # seconds

    def __init__(self, base_dir: str = "targets"):
        """
        Initialize WatchlistManager.

        Args:
            base_dir: Base directory for target outputs
        """
        self.base_dir = Path(base_dir)

    def _get_watchlist_path(self, domain: str) -> Path:
        """
        Get the full path to a domain's cloud watchlist file.

        Args:
            domain: Target domain

        Returns:
            Path to cloud_watchlist.txt
        """
        return self.base_dir / domain / "cloud_watchlist.txt"

    def _get_lock_path(self, domain: str) -> Path:
        """
        Get the lock file path for concurrent write safety.

        Args:
            domain: Target domain

        Returns:
            Path to watchlist lock file
        """
        return self.base_dir / domain / ".watchlist.lock"

    def _parse_line(self, line: str) -> Optional[Tuple[str, str, str, WatchlistStatus]]:
        """
        Parse a watchlist line into its components.

        Args:
            line: Line from watchlist file

        Returns:
            Tuple of (timestamp, cname_target, source_subdomain, status) or None if invalid
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split("|")
        if len(parts) != 4:
            return None

        timestamp, cname_target, source_subdomain, status_str = parts

        try:
            status = WatchlistStatus(status_str)
            return (timestamp, cname_target, source_subdomain, status)
        except ValueError:
            # Unknown status, treat as NEW
            return (timestamp, cname_target, source_subdomain, WatchlistStatus.NEW)

    def _format_entry(
        self,
        cname_target: str,
        source_subdomain: str,
        status: WatchlistStatus = WatchlistStatus.NEW
    ) -> str:
        """
        Format a watchlist entry line.

        Args:
            cname_target: The CNAME target (e.g., example.cloudfront.net)
            source_subdomain: The source subdomain (e.g., dev.example.com)
            status: Entry status

        Returns:
            Formatted line string
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"{timestamp}|{cname_target}|{source_subdomain}|{status.value}"

    async def _acquire_lock(self, lock_fd: int) -> bool:
        """
        Acquire an exclusive file lock with timeout.

        Args:
            lock_fd: File descriptor for lock file

        Returns:
            True if lock acquired, False on timeout
        """
        start_time = time.time()
        while time.time() - start_time < self.LOCK_TIMEOUT:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except (IOError, OSError):
                await asyncio.sleep(0.1)
        return False

    def _release_lock(self, lock_fd: int) -> None:
        """
        Release the file lock.

        Args:
            lock_fd: File descriptor for lock file
        """
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    async def read_watchlist(self, domain: str) -> Set[Tuple[str, str, str, WatchlistStatus]]:
        """
        Read all entries from cloud_watchlist.txt.

        Args:
            domain: Target domain

        Returns:
            Set of tuples: (cname_target, source_subdomain, timestamp, status)
        """
        watchlist_path = self._get_watchlist_path(domain)

        if not watchlist_path.exists():
            return set()

        try:
            content = await asyncio.to_thread(watchlist_path.read_text)
            entries = set()

            for line in content.splitlines():
                parsed = self._parse_line(line)
                if parsed:
                    timestamp, cname_target, source_subdomain, status = parsed
                    entries.add((cname_target, source_subdomain, timestamp, status))

            return entries
        except (IOError, OSError):
            return set()

    async def read_watchlist_raw(self, domain: str) -> List[str]:
        """
        Read all raw lines from cloud_watchlist.txt.

        Args:
            domain: Target domain

        Returns:
            List of raw line strings
        """
        watchlist_path = self._get_watchlist_path(domain)

        if not watchlist_path.exists():
            return []

        try:
            content = await asyncio.to_thread(watchlist_path.read_text)
            return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
        except (IOError, OSError):
            return []

    async def add_entries(
        self,
        domain: str,
        entries: List[Tuple[str, str]],
        status: WatchlistStatus = WatchlistStatus.NEW
    ) -> int:
        """
        Append new entries to cloud_watchlist.txt (append-only, never overwrite).

        Args:
            domain: Target domain
            entries: List of (cname_target, source_subdomain) tuples
            status: Initial status for new entries

        Returns:
            Number of entries actually appended (0 if all already exist)
        """
        if not entries:
            return 0

        watchlist_path = self._get_watchlist_path(domain)
        lock_path = self._get_lock_path(domain)

        # Ensure domain directory exists
        await asyncio.to_thread(watchlist_path.parent.mkdir, parents=True, exist_ok=True)

        # Read existing entries to avoid duplicates
        existing = await self.read_watchlist(domain)
        existing_keys = {(cname, sub) for cname, sub, _, _ in existing}

        # Filter out entries that already exist
        new_entries = [
            (cname, sub) for cname, sub in entries
            if (cname, sub) not in existing_keys
        ]

        if not new_entries:
            return 0

        # Acquire exclusive lock for writing
        lock_fd = await asyncio.to_thread(os.open, str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            if not await self._acquire_lock(lock_fd):
                raise RuntimeError(f"Failed to acquire lock for {domain} watchlist after {self.LOCK_TIMEOUT}s")

            # Re-check for duplicates under lock
            content = ""
            if watchlist_path.exists():
                content = await asyncio.to_thread(watchlist_path.read_text)

            existing_lines = set()
            for line in content.splitlines():
                parsed = self._parse_line(line)
                if parsed:
                    _, cname, sub, _ = parsed
                    existing_lines.add((cname, sub))

            # Format and filter new entries
            lines_to_append = []
            for cname_target, source_subdomain in new_entries:
                if (cname_target, source_subdomain) not in existing_lines:
                    lines_to_append.append(self._format_entry(cname_target, source_subdomain, status))

            if lines_to_append:
                # Append new entries
                append_content = "\n".join(lines_to_append) + "\n"
                await asyncio.to_thread(
                    watchlist_path.write_text,
                    append_content,
                    mode="a"
                )

            return len(lines_to_append)

        finally:
            self._release_lock(lock_fd)
            await asyncio.to_thread(os.close, lock_fd)

    async def get_unprocessed_entries(
        self,
        domain: str,
        statuses: Optional[Set[WatchlistStatus]] = None
    ) -> Set[Tuple[str, str, str, WatchlistStatus]]:
        """
        Get entries that need processing (typically NEW or DANGLED for rescan).

        Args:
            domain: Target domain
            statuses: Set of statuses to consider "unprocessed" (default: {NEW, DANGLED})

        Returns:
            Set of tuples: (cname_target, source_subdomain, timestamp, status)
        """
        if statuses is None:
            statuses = {WatchlistStatus.NEW, WatchlistStatus.DANGLED}

        entries = await self.read_watchlist(domain)
        return {
            (cname, sub, ts, status)
            for cname, sub, ts, status in entries
            if status in statuses
        }

    async def mark_processed(
        self,
        domain: str,
        entry: Tuple[str, str],
        new_status: WatchlistStatus
    ) -> bool:
        """
        Mark an entry as processed by updating its status.

        Args:
            domain: Target domain
            entry: Tuple of (cname_target, source_subdomain)
            new_status: New status to set

        Returns:
            True if entry was found and updated, False otherwise
        """
        watchlist_path = self._get_watchlist_path(domain)
        lock_path = self._get_lock_path(domain)

        if not watchlist_path.exists():
            return False

        # Acquire exclusive lock
        lock_fd = await asyncio.to_thread(os.open, str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            if not await self._acquire_lock(lock_fd):
                raise RuntimeError(f"Failed to acquire lock for {domain} watchlist")

            # Read current content
            content = await asyncio.to_thread(watchlist_path.read_text)
            lines = content.splitlines()

            # Find and update the entry
            found = False
            new_lines = []
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            for line in lines:
                parsed = self._parse_line(line)
                if parsed:
                    _, cname, sub, _ = parsed
                    if (cname, sub) == entry:
                        # Update status and timestamp
                        new_lines.append(f"{timestamp}|{entry[0]}|{entry[1]}|{new_status.value}")
                        found = True
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            if found:
                await asyncio.to_thread(watchlist_path.write_text, "\n".join(new_lines) + "\n")

            return found

        finally:
            self._release_lock(lock_fd)
            await asyncio.to_thread(os.close, lock_fd)

    async def get_entry_count(self, domain: str) -> int:
        """
        Get the total count of entries in the watchlist.

        Args:
            domain: Target domain

        Returns:
            Number of entries in watchlist
        """
        entries = await self.read_watchlist(domain)
        return len(entries)

    async def entries_exist(self, domain: str) -> bool:
        """
        Check if watchlist has any entries.

        Args:
            domain: Target domain

        Returns:
            True if watchlist exists and has entries
        """
        watchlist_path = self._get_watchlist_path(domain)
        if not watchlist_path.exists():
            return False

        try:
            content = await asyncio.to_thread(watchlist_path.read_text)
            return any(line.strip() and not line.startswith("#") for line in content.splitlines())
        except (IOError, OSError):
            return False

    async def get_entries_by_status(
        self,
        domain: str,
        status: WatchlistStatus
    ) -> Set[Tuple[str, str, str, WatchlistStatus]]:
        """
        Get all entries with a specific status.

        Args:
            domain: Target domain
            status: Status to filter by

        Returns:
            Set of tuples matching the status
        """
        entries = await self.read_watchlist(domain)
        return {
            (cname, sub, ts, st)
            for cname, sub, ts, st in entries
            if st == status
        }

    async def get_status_counts(self, domain: str) -> dict:
        """
        Get count of entries by status.

        Args:
            domain: Target domain

        Returns:
            Dictionary mapping status to count
        """
        entries = await self.read_watchlist(domain)
        counts = {s: 0 for s in WatchlistStatus}
        for _, _, _, status in entries:
            counts[status] += 1
        return {s.value: c for s, c in counts.items() if c > 0}

    async def append_finding(
        self,
        domain: str,
        cname_target: str,
        source_subdomain: str,
        status: WatchlistStatus,
        existing_silo: bool = True
    ) -> bool:
        """
        Append a new finding to the watchlist (for rescan findings).

        This is used during periodic rescan to record new NXDOMAIN findings.

        Args:
            domain: Target domain
            cname_target: The CNAME target
            source_subdomain: The source subdomain
            status: Final status (DANGLED, SAFE, TAKEOVER_CONFIRMED)
            existing_silo: If True, this finding has an existing evidence silo

        Returns:
            True if appended successfully
        """
        entries = [(cname_target, source_subdomain)]
        count = await self.add_entries(domain, entries, status)
        return count > 0


async def main():
    """Test/standalone execution for WatchlistManager."""
    import argparse

    parser = argparse.ArgumentParser(description="Watchlist Manager for Recon Bot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Read command
    read_parser = subparsers.add_parser("read", help="Read watchlist entries")
    read_parser.add_argument("domain", help="Target domain")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add watchlist entries")
    add_parser.add_argument("domain", help="Target domain")
    add_parser.add_argument("cname", help="CNAME target")
    add_parser.add_argument("subdomain", help="Source subdomain")
    add_parser.add_argument("--status", default="NEW", help="Entry status")

    # List command
    list_parser = subparsers.add_parser("list", help="List unprocessed entries")
    list_parser.add_argument("domain", help="Target domain")

    # Count command
    count_parser = subparsers.add_parser("count", help="Count entries")
    count_parser.add_argument("domain", help="Target domain")

    args = parser.parse_args()

    manager = WatchlistManager()

    if args.command == "read":
        entries = await manager.read_watchlist(args.domain)
        print(f"Watchlist entries for {args.domain}:")
        for cname, sub, ts, status in sorted(entries):
            print(f"  [{status.value}] {sub} -> {cname} ({ts})")
        print(f"Total: {len(entries)} entries")

    elif args.command == "add":
        try:
            status = WatchlistStatus(args.status)
        except ValueError:
            print(f"Invalid status: {args.status}")
            return 1

        count = await manager.add_entries(args.domain, [(args.cname, args.subdomain)], status)
        print(f"Added {count} entry(ies)")

    elif args.command == "list":
        entries = await manager.get_unprocessed_entries(args.domain)
        print(f"Unprocessed entries for {args.domain}:")
        for cname, sub, ts, status in sorted(entries):
            print(f"  [{status.value}] {sub} -> {cname} ({ts})")
        print(f"Total: {len(entries)} unprocessed")

    elif args.command == "count":
        count = await manager.get_entry_count(args.domain)
        print(f"Total entries: {count}")
        exists = await manager.entries_exist(args.domain)
        print(f"Has entries: {exists}")
        counts = await manager.get_status_counts(args.domain)
        print("By status:")
        for status, c in counts.items():
            print(f"  {status}: {c}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
