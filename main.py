#!/usr/bin/env python3
"""
Recon Bot - Telegram Bot Entry Point
Subdomain Takeover Discovery Pipeline

Professional security research tool for discovering and validating
subdomain takeovers via a multi-stage asyncio pipeline.

Commands:
    /scan <domain>    - Run full pipeline for target domain
    /status          - Show current scan stage/status
    /watchlist <domain> - Re-scan cloud watchlist
    /report <domain> - Send latest report
    /cancel          - Stop current scan

Usage:
    python main.py

Requires:
    TELEGRAM_BOT_TOKEN environment variable
    ALLOWED_CHAT_IDS environment variable (comma-separated)
"""

import asyncio
import logging
import os
import re
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# python-telegram-bot v20+
from telegram import Update, BotCommand
from telegram.constants import ParseMode
from telegram.error import Forbidden, TelegramError, InvalidToken
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

# Local modules
import config
from pipeline import (
    PipelineStage,
    PipelineResult,
    PipelineContext,
    run_pipeline,
    StageError,
    ToolNotFoundError,
)
from utils import FileManager, TelegramNotifier, create_notifier
from utils.watchlist import WatchlistManager, WatchlistStatus


# =============================================================================
# Configuration & Constants
# =============================================================================

# Domain validation regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Bot command definitions for Menulist
BOT_COMMANDS = [
    BotCommand("scan", "Run full pipeline for domain"),
    BotCommand("status", "Show current scan stage/status"),
    BotCommand("watchlist", "Re-scan cloud watchlist"),
    BotCommand("report", "Send latest report"),
    BotCommand("cancel", "Stop current scan"),
]


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure structured logging for the bot."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, log_level, logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)

    logger = logging.getLogger("recon-bot")
    logger.setLevel(numeric_level)

    return logger


logger = setup_logging()


# =============================================================================
# Scan State Management
# =============================================================================

class ScanState(Enum):
    """State of a scan operation."""
    IDLE = "idle"
    RUNNING = "running"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanTask:
    """Represents a running or completed scan task."""
    domain: str
    user_id: int
    chat_id: int
    state: ScanState = ScanState.IDLE
    current_stage: Optional[PipelineStage] = None
    stage_start_time: Optional[float] = None
    started_at: Optional[datetime] = None
    cancelled: bool = False
    error_message: Optional[str] = None
    result: Optional[PipelineResult] = None

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.state == ScanState.RUNNING and not self.cancelled

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds since scan started."""
        if self.stage_start_time:
            return time.time() - self.stage_start_time
        return 0.0


class ScanStateManager:
    """
    Manages scan state for all users/chats.

    Implements one-scan-per-user policy and provides
    thread-safe access to scan state.
    """

    def __init__(self):
        self._scans: Dict[int, ScanTask] = {}  # user_id -> ScanTask
        self._lock = asyncio.Lock()
        self._file_manager = FileManager(base_dir=config.TARGETS_DIR)
        self._watchlist_manager = WatchlistManager(base_dir=config.TARGETS_DIR)

    async def start_scan(
        self,
        user_id: int,
        chat_id: int,
        domain: str,
    ) -> tuple[bool, str]:
        """
        Attempt to start a new scan for a user.

        Returns:
            Tuple of (success, message)
        """
        async with self._lock:
            # Check for existing scan
            if user_id in self._scans:
                existing = self._scans[user_id]
                if existing.is_running:
                    return False, f"Scan already running for {existing.domain}. Use /cancel to stop it."

            # Create new scan task
            self._scans[user_id] = ScanTask(
                domain=domain,
                user_id=user_id,
                chat_id=chat_id,
                state=ScanState.RUNNING,
                stage_start_time=time.time(),
                started_at=datetime.now(),
            )

            return True, f"Scan started for {domain}"

    async def update_stage(
        self,
        user_id: int,
        stage: PipelineStage,
    ) -> None:
        """Update the current stage for a user's scan."""
        async with self._lock:
            if user_id in self._scans:
                self._scans[user_id].current_stage = stage
                self._scans[user_id].stage_start_time = time.time()

    async def complete_scan(
        self,
        user_id: int,
        result: PipelineResult,
        error_message: Optional[str] = None,
    ) -> None:
        """Mark a scan as completed or failed."""
        async with self._lock:
            if user_id in self._scans:
                self._scans[user_id].state = ScanState.COMPLETED
                self._scans[user_id].result = result
                self._scans[user_id].error_message = error_message

    async def cancel_scan(self, user_id: int) -> tuple[bool, str]:
        """
        Request cancellation of a user's scan.

        Returns:
            Tuple of (was_running, message)
        """
        async with self._lock:
            if user_id not in self._scans:
                return False, "No active scan to cancel."

            scan = self._scans[user_id]
            if not scan.is_running:
                return False, f"Scan is not running (state: {scan.state.value})."

            scan.cancelled = True
            scan.state = ScanState.CANCELLED
            return True, f"Scan cancelled for {scan.domain}"

    async def get_status(self, user_id: int) -> Optional[ScanTask]:
        """Get current scan state for a user."""
        async with self._lock:
            return self._scans.get(user_id)

    async def get_watchlist_status(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get watchlist status for a user's domain."""
        async with self._lock:
            if user_id not in self._scans:
                return None

            scan = self._scans[user_id]
            counts = await self._watchlist_manager.get_status_counts(scan.domain)
            return {
                "domain": scan.domain,
                "counts": counts,
            }

    def get_output_dir(self, domain: str) -> Path:
        """Get output directory for a domain."""
        return Path(config.TARGETS_DIR) / domain

    @property
    def file_manager(self) -> FileManager:
        """Access the file manager."""
        return self._file_manager

    @property
    def watchlist_manager(self) -> WatchlistManager:
        """Access the watchlist manager."""
        return self._watchlist_manager


# Global state manager instance
state_manager = ScanStateManager()


# =============================================================================
# Validation Functions
# =============================================================================

def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate domain format.

    Returns:
        Tuple of (is_valid, error_message)
    """
    domain = domain.strip().lower()

    if not domain:
        return False, "Domain cannot be empty."

    if not DOMAIN_REGEX.match(domain):
        return False, f"Invalid domain format: {domain}"

    # Check for obvious non-targets
    if domain.startswith((".", "*", "http://", "https://")):
        return False, f"Invalid domain: {domain}"

    if len(domain) > 253:
        return False, "Domain too long (max 253 characters)."

    return True, ""


def validate_bot_config() -> tuple[bool, str]:
    """
    Validate bot configuration (token, chat IDs).

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not config.TELEGRAM_BOT_TOKEN:
        return False, "TELEGRAM_BOT_TOKEN environment variable not set."

    if not config.ALLOWED_CHAT_IDS:
        logger.warning("No ALLOWED_CHAT_IDS configured - bot will not respond to any chats.")

    return True, ""


def is_chat_allowed(chat_id: int) -> bool:
    """Check if a chat ID is in the allowed list."""
    if not config.ALLOWED_CHAT_IDS:
        # If no allowed list, allow all (for testing)
        return True
    return str(chat_id) in config.ALLOWED_CHAT_IDS


# =============================================================================
# Telegram Helpers
# =============================================================================

async def send_safe(
    update: Update,
    text: str,
    parse_mode: str = ParseMode.MARKDOWN,
    disable_notification: bool = False,
    reply_markup: Optional[Any] = None,
) -> bool:
    """
    Send a message safely, handling Telegram errors gracefully.

    Returns:
        True if sent successfully, False otherwise.
    """
    try:
        await update.message.reply_text(
            text=text,
            parse_mode=parse_mode,
            disable_notification=disable_notification,
            reply_markup=reply_markup,
        )
        return True
    except Forbidden:
        logger.warning(f"Forbidden: chat_id={update.effective_chat.id}")
        return False
    except TelegramError as e:
        logger.error(f"Telegram error sending message: {e}")
        return False


async def send_safe_md(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    text: str,
    parse_mode: str = ParseMode.MARKDOWN,
    disable_notification: bool = False,
) -> bool:
    """Send markdown message to a specific chat ID."""
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=parse_mode,
            disable_notification=disable_notification,
        )
        return True
    except TelegramError as e:
        logger.error(f"Telegram error: {e}")
        return False


# =============================================================================
# Pipeline Execution
# =============================================================================

async def execute_pipeline(
    domain: str,
    user_id: int,
    chat_id: int,
    notifier: Optional[TelegramNotifier] = None,
) -> PipelineResult:
    """
    Execute the full pipeline for a domain.

    This runs as an async task and sends Telegram updates
    on stage completion.
    """
    output_dir = str(state_manager.get_output_dir(domain))
    logger.info(f"Starting pipeline for {domain}, output_dir={output_dir}")

    # Define stage completion callback for Telegram alerts
    async def stage_notify(message: str) -> None:
        """Send stage completion notification to Telegram."""
        if notifier:
            try:
                await notifier._send_message(message, disable_notification=True)
            except TelegramError as e:
                logger.warning(f"Failed to send stage notification: {e}")

        # Update state manager
        # Parse stage name from message if available
        for stage in PipelineStage:
            if stage.display_name in message and "Completed" in message:
                await state_manager.update_stage(user_id, stage)
                break

    try:
        result = await run_pipeline(
            domain=domain,
            output_dir=output_dir,
            notify_callback=stage_notify,
        )

        # Update final state
        if result.success:
            await state_manager.complete_scan(user_id, result)
            if notifier:
                await notifier._send_message(
                    f"✅ Pipeline completed for {domain}\n"
                    f"Found {len(result.findings)} potential takeovers\n"
                    f"Report: {result.report_path or 'N/A'}"
                )
        else:
            await state_manager.complete_scan(
                user_id,
                result,
                error_message="; ".join(result.errors) if result.errors else "Unknown error",
            )
            if notifier:
                await notifier.send_error(
                    "Pipeline",
                    result.errors[-1] if result.errors else "Unknown error",
                )

        return result

    except asyncio.CancelledError:
        logger.info(f"Pipeline cancelled for {domain}")
        await state_manager.complete_scan(user_id, PipelineResult(domain, f"{domain}-cancelled"))
        if notifier:
            await notifier._send_message(f"⚠️ Scan cancelled for {domain}")
        raise

    except Exception as e:
        logger.exception(f"Pipeline failed for {domain}: {e}")
        error_result = PipelineResult(domain, f"{domain}-error")
        error_result.success = False
        error_result.errors.append(str(e))
        await state_manager.complete_scan(user_id, error_result, error_message=str(e))

        if notifier:
            await notifier.send_error("Pipeline", str(e))

        return error_result


async def execute_watchlist_scan(
    domain: str,
    user_id: int,
    chat_id: int,
    notifier: Optional[TelegramNotifier] = None,
) -> Dict[str, Any]:
    """
    Execute watchlist rescan for a domain.

    Reads entries from cloud_watchlist.txt and re-runs
    Stage 4 (nslookup) on unprocessed entries.
    """
    from pipeline.stage4_nslookup import run_stage4

    output_dir = str(state_manager.get_output_dir(domain))
    wm = state_manager.watchlist_manager

    logger.info(f"Starting watchlist rescan for {domain}")

    # Get unprocessed entries
    entries = await wm.get_unprocessed_entries(domain)

    if not entries:
        return {
            "success": True,
            "domain": domain,
            "message": "No unprocessed entries in watchlist.",
            "new_findings": 0,
        }

    # Extract CNAME targets for Stage 4
    cname_targets = {cname for cname, _, _, _ in entries}

    try:
        # Run Stage 4 on these targets
        result = await run_stage4(domain, output_dir, cname_targets)

        dangling = result.get("dangling", set())
        still_active = result.get("still_active", set())

        # Update watchlist entries
        for cname in dangling:
            # Find matching entry to get source subdomain
            for entry_cname, source_sub, ts, status in entries:
                if entry_cname == cname:
                    await wm.mark_processed(domain, (cname, source_sub), WatchlistStatus.DANGLED)

        for cname in still_active:
            for entry_cname, source_sub, ts, status in entries:
                if entry_cname == cname:
                    await wm.mark_processed(domain, (cname, source_sub), WatchlistStatus.SAFE)

        # Send notification
        if notifier:
            await notifier._send_message(
                f"🔄 Watchlist rescan complete for {domain}\n"
                f"New dangling: {len(dangling)}\n"
                f"Still active: {len(still_active)}"
            )

        return {
            "success": True,
            "domain": domain,
            "dangling_count": len(dangling),
            "still_active_count": len(still_active),
            "new_findings": len(dangling),
        }

    except Exception as e:
        logger.exception(f"Watchlist scan failed for {domain}: {e}")
        if notifier:
            await notifier.send_error("Watchlist Scan", str(e))
        return {
            "success": False,
            "domain": domain,
            "error": str(e),
        }


# =============================================================================
# Command Handlers
# =============================================================================

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handle /scan <domain> command.

    Validates domain and starts the full pipeline asynchronously.
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Check chat permission
    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    # Parse domain from command args
    if not context.args or len(context.args) < 1:
        await send_safe(update, "Usage: /scan <domain>\nExample: /scan example.com")
        return ConversationHandler.END

    domain = context.args[0].strip().lower()

    # Validate domain
    is_valid, error_msg = validate_domain(domain)
    if not is_valid:
        await send_safe(update, f"❌ Invalid domain: {error_msg}")
        return ConversationHandler.END

    # Check for existing scan
    success, message = await state_manager.start_scan(user_id, chat_id, domain)
    if not success:
        await send_safe(update, f"❌ {message}")
        return ConversationHandler.END

    await send_safe(update, f"🔍 Starting scan for {domain}...\n"
                           f"This will run in background. Use /status to check progress.")

    # Create notifier for this user
    notifier = None
    try:
        notifier = await create_notifier(config.TELEGRAM_BOT_TOKEN, str(chat_id))
    except TelegramError as e:
        logger.warning(f"Could not create notifier: {e}")

    # Start pipeline as background task
    asyncio.create_task(
        execute_pipeline(domain, user_id, chat_id, notifier),
        name=f"pipeline-{user_id}-{domain}",
    )

    logger.info(f"Pipeline task created for {domain}, user={user_id}")
    return ConversationHandler.END


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handle /status command.

    Shows current scan stage/status for the user.
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Check chat permission
    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    scan = await state_manager.get_status(user_id)

    if not scan:
        await send_safe(update, "📋 No active or recent scan.\n"
                               "Use /scan <domain> to start a new scan.")
        return ConversationHandler.END

    # Format status message
    if scan.state == ScanState.IDLE:
        status_text = "🟡 Idle - No scan started."
    elif scan.state == ScanState.RUNNING:
        stage_info = scan.current_stage.display_name if scan.current_stage else "Initializing"
        elapsed = scan.elapsed_time
        status_text = (
            f"🟢 Running: {scan.domain}\n"
            f"Stage: {stage_info}\n"
            f"Elapsed: {elapsed:.1f}s"
        )
    elif scan.state == ScanState.CANCELLED:
        status_text = f"⚠️ Cancelled: {scan.domain}"
    elif scan.state == ScanState.COMPLETED:
        if scan.result:
            findings_count = len(scan.result.findings) if scan.result.findings else 0
            status_text = (
                f"✅ Completed: {scan.domain}\n"
                f"Findings: {findings_count}"
            )
        else:
            status_text = f"✅ Completed: {scan.domain}"
    elif scan.state == ScanState.FAILED:
        status_text = f"❌ Failed: {scan.domain}\nError: {scan.error_message or 'Unknown'}"
    else:
        status_text = f"❓ Unknown state: {scan.state.value}"

    await send_safe(update, status_text)
    return ConversationHandler.END


async def cmd_watchlist(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handle /watchlist <domain> command.

    Triggers watchlist rescan for the domain.
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Check chat permission
    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    # Parse domain from command args
    if not context.args or len(context.args) < 1:
        await send_safe(update, "Usage: /watchlist <domain>\nExample: /watchlist example.com")
        return ConversationHandler.END

    domain = context.args[0].strip().lower()

    # Validate domain
    is_valid, error_msg = validate_domain(domain)
    if not is_valid:
        await send_safe(update, f"❌ Invalid domain: {error_msg}")
        return ConversationHandler.END

    # Check if watchlist exists
    wm = state_manager.watchlist_manager
    has_entries = await wm.entries_exist(domain)

    if not has_entries:
        await send_safe(update, f"📋 No watchlist entries found for {domain}.\n"
                                 f"Run /scan {domain} first to populate the watchlist.")
        return ConversationHandler.END

    await send_safe(update, f"🔄 Starting watchlist rescan for {domain}...\n"
                           f"This runs Stage 4 (nslookup) on unprocessed entries.")

    # Create notifier
    notifier = None
    try:
        notifier = await create_notifier(config.TELEGRAM_BOT_TOKEN, str(chat_id))
    except TelegramError as e:
        logger.warning(f"Could not create notifier: {e}")

    # Start watchlist scan as background task
    asyncio.create_task(
        execute_watchlist_scan(domain, user_id, chat_id, notifier),
        name=f"watchlist-{user_id}-{domain}",
    )

    logger.info(f"Watchlist scan task created for {domain}, user={user_id}")
    return ConversationHandler.END


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handle /report <domain> command.

    Sends the latest report file for the domain.
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Check chat permission
    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    # Parse domain from command args
    if not context.args or len(context.args) < 1:
        await send_safe(update, "Usage: /report <domain>\nExample: /report example.com")
        return ConversationHandler.END

    domain = context.args[0].strip().lower()

    # Validate domain
    is_valid, error_msg = validate_domain(domain)
    if not is_valid:
        await send_safe(update, f"❌ Invalid domain: {error_msg}")
        return ConversationHandler.END

    # Look for report
    report_dir = state_manager.get_output_dir(domain)

    # Check for Stage 8 output - the report directory
    # Format: targets/{domain}/{domain}_Final_Report/dashboard.html
    final_report_dir = report_dir / f"{domain}_Final_Report"
    dashboard_path = final_report_dir / "dashboard.html"
    archive_path = final_report_dir / f"{domain}_report.zip"

    # Try to find any HTML report
    html_reports = list(report_dir.glob("*.html")) + list(report_dir.glob("*report*.html"))

    report_path = None
    if dashboard_path.exists():
        report_path = dashboard_path
    elif html_reports:
        report_path = html_reports[0]

    if not report_path or not report_path.exists():
        await send_safe(update, f"📋 No report found for {domain}.\n"
                                 f"Run /scan {domain} first to generate a report.")
        return ConversationHandler.END

    # Get file size for context
    file_size = state_manager.file_manager.get_file_size_human(report_path)

    await send_safe(update, f"📦 Sending report for {domain} ({file_size})...")

    try:
        # Send file directly
        with open(report_path, "rb") as f:
            await context.bot.send_document(
                chat_id=chat_id,
                document=f,
                filename=report_path.name,
                caption=f"📊 Report for {domain}",
                parse_mode=ParseMode.MARKDOWN,
            )

        logger.info(f"Report sent for {domain} to chat {chat_id}")

    except FileNotFoundError:
        await send_safe(update, f"❌ Report file not found: {report_path}")
    except TelegramError as e:
        logger.error(f"Failed to send report: {e}")
        await send_safe(update, f"❌ Failed to send report: {e}")

    return ConversationHandler.END


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    Handle /cancel command.

    Stops the current running scan for the user.
    """
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # Check chat permission
    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    success, message = await state_manager.cancel_scan(user_id)

    if success:
        # Try to cancel any running task
        current_task = asyncio.current_task()
        if current_task:
            current_task.cancel()

        await send_safe(update, f"✅ {message}")

        # Cancel any pending pipeline tasks for this user
        for task in asyncio.all_tasks():
            if task.get_name().startswith(f"pipeline-{user_id}-"):
                task.cancel()

        logger.info(f"Scan cancelled for user {user_id}")
    else:
        await send_safe(update, f"ℹ️ {message}")

    return ConversationHandler.END


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle /help command with bot usage information."""
    chat_id = update.effective_chat.id

    if not is_chat_allowed(chat_id):
        await send_safe(update, "⛔ Bot is not authorized for this chat.")
        return ConversationHandler.END

    help_text = """
🔍 *Recon Bot - Subdomain Takeover Scanner*

*Available Commands:*

/scan <domain>    - Run full takeover discovery pipeline
                   Example: `/scan example.com`

/status           - Show current scan stage and progress

/watchlist <domain> - Re-scan cloud watchlist entries
                      Example: `/watchlist example.com`

/report <domain>  - Send latest HTML report
                    Example: `/report example.com`

/cancel           - Stop the current running scan

/help             - Show this help message

*Pipeline Stages:*
1. Passive Discovery (subfinder, assetfinder, amass)
2. DNS Resolution
3. CNAME Filtering (cloud provider detection)
4. NXDOMAIN Gate (dangling DNS detection)
5. HTTP Probing (httpx)
6. Nuclei Confirmation (takeover templates)
7. Evidence Collection (dig, screenshots)
8. Report Generation (HTML dashboard)

*Notes:*
- Only one scan per user at a time
- Scans run asynchronously in background
- Use /status to check progress
"""

    await send_safe(update, help_text.strip())
    return ConversationHandler.END


# =============================================================================
# Error Handlers
# =============================================================================

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors caused by updates."""
    logger.error(f"Exception while handling an update: {context.error}")

    # Try to notify user
    if update and update.effective_chat:
        try:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ An error occurred: {context.error}",
                parse_mode=ParseMode.MARKDOWN,
            )
        except TelegramError:
            pass


# =============================================================================
# Bot Application Setup
# =============================================================================

def create_application() -> Application:
    """
    Create and configure the Telegram bot application.

    Returns:
        Configured Application instance ready to run.
    """
    # Validate configuration
    is_valid, error_msg = validate_bot_config()
    if not is_valid:
        logger.error(f"Bot configuration error: {error_msg}")
        raise ValueError(error_msg)

    # Create application with token
    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()

    # Add command handlers
    application.add_handler(CommandHandler("scan", cmd_scan))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("watchlist", cmd_watchlist))
    application.add_handler(CommandHandler("report", cmd_report))
    application.add_handler(CommandHandler("cancel", cmd_cancel))
    application.add_handler(CommandHandler("help", cmd_help))

    # Add error handler
    application.add_error_handler(error_handler)

    # Set bot commands menu
    application.bot.set_my_commands(BOT_COMMANDS)

    logger.info("Bot application created successfully")
    return application


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """Main entry point for the bot."""
    logger.info("=" * 60)
    logger.info("Recon Bot - Starting...")
    logger.info("=" * 60)

    # Validate tool paths on startup
    if os.environ.get("RECON_BOT_VALIDATE_TOOLS", "").lower() == "1":
        logger.info("Validating tool paths...")
        config.validate_tool_paths(verbose=True)

    try:
        application = create_application()

        # Setup graceful shutdown
        def shutdown_handler(signum, frame):
            logger.info("Received shutdown signal, stopping bot...")
            application.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        # Run the bot
        logger.info("Bot is now running. Press Ctrl+C to stop.")
        application.run_polling(
            allowed_updates=[],
            drop_pending_updates=True,
        )

    except InvalidToken:
        logger.error("Invalid Telegram bot token. Please check TELEGRAM_BOT_TOKEN.")
        sys.exit(1)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)

    finally:
        logger.info("Bot shutdown complete.")


if __name__ == "__main__":
    main()
