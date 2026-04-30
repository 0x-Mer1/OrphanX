"""
Telegram Notifier for Recon Bot
Subdomain takeover discovery pipeline alerts
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from telegram import Bot, ParseMode, InputFile
from telegram.error import TelegramError, RetryAfter, Forbidden, BadRequest

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter for Telegram API calls."""

    def __init__(self, max_messages: int = 20, window_seconds: int = 60):
        self.max_messages = max_messages
        self.window_seconds = window_seconds
        self.messages = []

    def can_send(self) -> bool:
        """Check if a message can be sent within rate limits."""
        now = time.time()
        # Remove messages outside the window
        self.messages = [t for t in self.messages if now - t < self.window_seconds]
        return len(self.messages) < self.max_messages

    def record_sent(self):
        """Record a sent message timestamp."""
        self.messages.append(time.time())

    async def wait_if_needed(self):
        """Wait if rate limit would be exceeded, then record the send."""
        while not self.can_send():
            oldest = self.messages[0]
            wait_time = self.window_seconds - (time.time() - oldest)
            if wait_time > 0:
                await asyncio.sleep(min(wait_time, 1.0))
            # Re-check after wait
            self.messages = [t for t in self.messages if time.time() - t < self.window_seconds]

        self.record_sent()


class TelegramNotifier:
    """
    Async Telegram notifier with rate limiting for Recon Bot pipeline alerts.

    Handles stage completion notifications, critical findings, and report delivery
    with proper error handling and markdown formatting.
    """

    def __init__(self, bot_token: str, chat_id: str):
        """
        Initialize the notifier.

        Args:
            bot_token: Telegram bot token from @BotFather
            chat_id: Target chat ID for notifications
        """
        if not bot_token:
            raise ValueError("bot_token is required")
        if not chat_id:
            raise ValueError("chat_id is required")

        self.bot = Bot(token=bot_token)
        self.chat_id = str(chat_id)
        self.rate_limiter = RateLimiter(max_messages=20, window_seconds=60)
        self._log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    async def _send_message(
        self,
        text: str,
        parse_mode: str = ParseMode.MARKDOWN,
        disable_notification: bool = False,
        reply_markup: Optional = None,
    ) -> bool:
        """
        Core message sending method with rate limiting and error handling.

        Args:
            text: Message text with markdown support
            parse_mode: Message parse mode (MARKDOWN or HTML)
            disable_notification: Send silently
            reply_markup: Optional reply markup

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            await self.rate_limiter.wait_if_needed()

            await self.bot.send_message(
                chat_id=self.chat_id,
                text=text,
                parse_mode=parse_mode,
                disable_notification=disable_notification,
                reply_markup=reply_markup,
            )
            self._log.debug(f"Message sent successfully to {self.chat_id}")
            return True

        except RetryAfter as e:
            self._log.warning(f"Rate limit hit, waiting {e.retry_after}s")
            await asyncio.sleep(e.retry_after)
            return await self._send_message(
                text, parse_mode, disable_notification, reply_markup
            )

        except Forbidden as e:
            self._log.error(f"Bot blocked or chat not found: {e}")
            return False

        except BadRequest as e:
            self._log.error(f"Invalid request: {e}")
            return False

        except TelegramError as e:
            self._log.error(f"Telegram API error: {e}")
            return False

    async def _send_file(
        self,
        file_path: str,
        caption: Optional[str] = None,
        parse_mode: str = ParseMode.MARKDOWN,
    ) -> bool:
        """
        Send a file (document) to the chat.

        Args:
            file_path: Path to the file to send
            caption: Optional caption with markdown support
            parse_mode: Message parse mode

        Returns:
            True if sent successfully, False otherwise
        """
        path = Path(file_path)

        if not path.exists():
            self._log.error(f"File not found: {file_path}")
            return False

        try:
            await self.rate_limiter.wait_if_needed()

            with open(path, "rb") as f:
                input_file = InputFile(f, filename=path.name)

            await self.bot.send_document(
                chat_id=self.chat_id,
                document=input_file,
                caption=caption,
                parse_mode=parse_mode,
            )
            self._log.info(f"File sent: {path.name}")
            return True

        except TelegramError as e:
            self._log.error(f"Failed to send file {file_path}: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────
    # Stage Alerts
    # ─────────────────────────────────────────────────────────────────

    async def send_stage1_complete(self, count: int) -> bool:
        """
        Stage 1 complete: Subdomains discovered.

        Args:
            count: Number of subdomains found

        Returns:
            True if sent successfully
        """
        message = (
            f"✅ *Stage 1 Complete*\n"
            f"Discovered `{count}` subdomains"
        )
        return await self._send_message(message)

    async def send_stage3_complete(self, count: int) -> bool:
        """
        Stage 3 complete: Cloud CNAMEs identified.

        Args:
            count: Number of cloud CNAMEs found

        Returns:
            True if sent successfully
        """
        message = (
            f"🔍 *Stage 3 Complete*\n"
            f"Found `{count}` cloud CNAMEs"
        )
        return await self._send_message(message)

    async def send_stage4_complete(self, count: int) -> bool:
        """
        Stage 4 complete: Dangling DNS records confirmed.

        Args:
            count: Number of dangling records found

        Returns:
            True if sent successfully
        """
        message = (
            f"⚠️ *Stage 4 Complete*\n"
            f"`{count}` dangling records confirmed"
        )
        return await self._send_message(message)

    # ─────────────────────────────────────────────────────────────────
    # Critical Findings
    # ─────────────────────────────────────────────────────────────────

    async def send_critical_finding(
        self,
        subdomain: str,
        target: str,
        severity: str = "HIGH",
    ) -> bool:
        """
        Critical subdomain takeover finding.

        Args:
            subdomain: Vulnerable subdomain
            target: Target cloud resource
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            True if sent successfully
        """
        severity_emoji = {
            "LOW": "🟡",
            "MEDIUM": "🟠",
            "HIGH": "🔴",
            "CRITICAL": "🚨",
        }.get(severity.upper(), "🚨")

        message = (
            f"{severity_emoji} *CRITICAL: Takeover Finding*\n\n"
            f"*Subdomain:* `{subdomain}`\n"
            f"*Target:* `{target}`\n"
            f"*Severity:* `{severity}`\n\n"
            f"⚡ Immediate action recommended"
        )
        return await self._send_message(message)

    # ─────────────────────────────────────────────────────────────────
    # Report Delivery
    # ─────────────────────────────────────────────────────────────────

    async def send_report_ready(self, file_path: str, domain: str) -> bool:
        """
        Stage 8 complete: Send the final report zip.

        Args:
            file_path: Path to the report zip file
            domain: Target domain being scanned

        Returns:
            True if sent successfully
        """
        caption = (
            f"📦 *Report Ready*\n"
            f"Domain: `{domain}`\n"
            f"Pipeline complete"
        )
        return await self._send_file(file_path, caption=caption)

    # ─────────────────────────────────────────────────────────────────
    # Error & Progress
    # ─────────────────────────────────────────────────────────────────

    async def send_error(self, stage: str, error_msg: str) -> bool:
        """
        Send an error notification.

        Args:
            stage: Stage where error occurred
            error_msg: Error description

        Returns:
            True if sent successfully
        """
        message = (
            f"❌ *Pipeline Error*\n"
            f"*Stage:* `{stage}`\n"
            f"*Error:* {error_msg}"
        )
        return await self._send_message(message)

    async def send_progress(self, stage: int, message: str) -> bool:
        """
        Send a progress update.

        Args:
            stage: Current stage number
            message: Progress message

        Returns:
            True if sent successfully
        """
        full_message = (
            f"📊 *Stage {stage} Progress*\n"
            f"{message}"
        )
        return await self._send_message(full_message, disable_notification=True)


# ─────────────────────────────────────────────────────────────────
# Convenience factory function
# ─────────────────────────────────────────────────────────────────

async def create_notifier(bot_token: str, chat_id: str) -> TelegramNotifier:
    """
    Factory function to create and validate a TelegramNotifier.

    Args:
        bot_token: Telegram bot token
        chat_id: Target chat ID

    Returns:
        Configured TelegramNotifier instance

    Raises:
        TelegramError: If bot token is invalid
    """
    notifier = TelegramNotifier(bot_token, chat_id)

    # Validate bot token by fetching bot info
    try:
        bot_info = await notifier.bot.get_me()
        logger.info(f"Bot authenticated: @{bot_info.username}")
    except TelegramError as e:
        raise TelegramError(f"Invalid bot token: {e}")

    return notifier