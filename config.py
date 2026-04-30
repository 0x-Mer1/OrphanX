"""
Recon Bot Configuration Module
Subdomain takeover discovery pipeline configuration and validation.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional


# =============================================================================
# Tool Paths (absolute paths)
# =============================================================================
SUBFINDER = "/home/azureuser/go/bin/subfinder"
ASSETFINDER = "/home/azureuser/go/bin/assetfinder"
AMASS = "/usr/local/bin/amass"
ANEW = "/home/azureuser/go/bin/anew"
DNSX = "/home/azureuser/go/bin/dnsx"
HTTPX = "/home/azureuser/go/bin/httpx"
NUCLEI = "/home/azureuser/go/bin/nuclei"
GOWITNESS = "/home/azureuser/go/bin/gowitness"
NOTIFY = "/home/azureuser/go/bin/notify"

TOOL_PATHS = {
    "subfinder": SUBFINDER,
    "assetfinder": ASSETFINDER,
    "amass": AMASS,
    "anew": ANEW,
    "dnsx": DNSX,
    "httpx": HTTPX,
    "nuclei": NUCLEI,
    "gowitness": GOWITNESS,
    "notify": NOTIFY,
}


# =============================================================================
# Config File Paths
# =============================================================================
SUBFINDER_CONFIG = "~/.config/subfinder/provider-config.yaml"
AMASS_CONFIG = "~/.config/amass/config.yaml"
NUCLEI_TEMPLATES = "~/.local/nuclei-templates/"


# =============================================================================
# API Keys (loaded from environment variables)
# =============================================================================
class APIKeys:
    """Container for API keys loaded from environment variables."""

    def __init__(self):
        self._github_tokens: List[str] = []
        self._load_keys()

    def _load_keys(self):
        """Load all API keys from environment variables."""
        # GitHub tokens (supports up to 3)
        github_tokens = []
        token_1 = os.environ.get("GITHUB_TOKEN", "").strip()
        token_2 = os.environ.get("GITHUB_TOKEN_2", "").strip()
        token_3 = os.environ.get("GITHUB_TOKEN_3", "").strip()

        if token_1:
            github_tokens.append(token_1)
        if token_2:
            github_tokens.append(token_2)
        if token_3:
            github_tokens.append(token_3)

        self._github_tokens = github_tokens
        self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        self.alienvault_otx_api_key = os.environ.get("ALIENVAULT_OTX_API_KEY", "").strip()
        self.chaos_api_key = os.environ.get("CHAOS_API_KEY", "").strip()

    @property
    def github_tokens(self) -> List[str]:
        """Return list of configured GitHub tokens."""
        return self._github_tokens

    @property
    def has_github_token(self) -> bool:
        """Check if at least one GitHub token is configured."""
        return len(self._github_tokens) > 0

    @property
    def github_token(self) -> Optional[str]:
        """Return primary GitHub token (first one configured)."""
        return self._github_tokens[0] if self._github_tokens else None

    def get_missing_keys(self) -> List[str]:
        """Return list of missing/incomplete API keys."""
        missing = []
        if not self.has_github_token:
            missing.append("GITHUB_TOKEN (or GITHUB_TOKEN_2, GITHUB_TOKEN_3)")
        if not self.virustotal_api_key:
            missing.append("VIRUSTOTAL_API_KEY")
        if not self.alienvault_otx_api_key:
            missing.append("ALIENVAULT_OTX_API_KEY")
        if not self.chaos_api_key:
            missing.append("CHAOS_API_KEY")
        return missing


# Global API keys instance (lazy loaded)
_api_keys: Optional[APIKeys] = None


def load_api_keys() -> APIKeys:
    """
    Load API keys from environment variables.

    Returns:
        APIKeys: Object containing all configured API keys.

    Example:
        >>> keys = load_api_keys()
        >>> print(keys.github_token)
        ghp_xxxxxxxxxxxxx
    """
    global _api_keys
    if _api_keys is None:
        _api_keys = APIKeys()
    return _api_keys


# =============================================================================
# Pipeline Settings
# =============================================================================
MAX_CONCURRENT_DNS = 50
MAX_CONCURRENT_HTTP = 20
NUCLEI_RATE_LIMIT = 150
DNS_RETRY_COUNT = 3
HTTP_TIMEOUT = 30


# =============================================================================
# Output Settings
# =============================================================================
TARGETS_DIR = "targets"
EVIDENCE_DIR = "evidence"


# =============================================================================
# Telegram Settings
# =============================================================================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()

ALLOWED_CHAT_IDS: List[str] = []
_allowed_ids_env = os.environ.get("ALLOWED_CHAT_IDS", "").strip()
if _allowed_ids_env:
    ALLOWED_CHAT_IDS = [cid.strip() for cid in _allowed_ids_env.split(",") if cid.strip()]

RATE_LIMIT_MSGS_PER_MIN = 20


# =============================================================================
# DNS Resolvers
# =============================================================================
DEFAULT_RESOLVERS: List[str] = [
    "1.1.1.1",        # Cloudflare
    "1.0.0.1",        # Cloudflare secondary
    "8.8.8.8",        # Google
    "8.8.4.4",        # Google secondary
    "9.9.9.9",        # Quad9
    "64.6.64.6",      # Verisign
]


def get_configured_resolvers() -> List[str]:
    """
    Return configured DNS resolvers for enumeration.

    Checks for custom resolver configuration in environment variable
    RESOLVERS, otherwise returns DEFAULT_RESOLVERS.

    Returns:
        List[str]: List of DNS resolver IP addresses.
    """
    resolvers_env = os.environ.get("RESOLVERS", "").strip()
    if resolvers_env:
        return [r.strip() for r in resolvers_env.split(",") if r.strip()]
    return DEFAULT_RESOLVERS.copy()


# =============================================================================
# Validation Functions
# =============================================================================
def validate_tool_paths(verbose: bool = True) -> bool:
    """
    Validate that all configured tool paths exist and are executable.

    Args:
        verbose: If True, print status for each tool. If False, only return status.

    Returns:
        bool: True if all tools exist and are executable, False otherwise.

    Raises:
        SystemExit: If critical tool is missing and sys.exit is allowed.
    """
    missing_tools = []
    invalid_tools = []

    for tool_name, tool_path in TOOL_PATHS.items():
        path = Path(tool_path).expanduser()
        if not path.exists():
            missing_tools.append((tool_name, str(path)))
            if verbose:
                print(f"[MISSING] {tool_name}: {path}", file=sys.stderr)
        elif not os.access(path, os.X_OK):
            invalid_tools.append((tool_name, str(path)))
            if verbose:
                print(f"[NOT EXECUTABLE] {tool_name}: {path}", file=sys.stderr)

    if missing_tools or invalid_tools:
        if verbose:
            print("\n[!] Tool validation failed. Please install missing tools.", file=sys.stderr)
        return False

    if verbose:
        print("[+] All tool paths validated successfully.")
    return True


def validate_config_paths(verbose: bool = True) -> bool:
    """
    Validate that config file paths exist (warning only, not required).

    Args:
        verbose: If True, print status for each path.

    Returns:
        bool: True if all paths exist, False otherwise.
    """
    config_paths = {
        "subfinder_config": Path(SUBFINDER_CONFIG).expanduser(),
        "amass_config": Path(AMASS_CONFIG).expanduser(),
        "nuclei_templates": Path(NUCLEI_TEMPLATES).expanduser(),
    }

    all_exist = True
    for name, path in config_paths.items():
        if path.exists():
            if verbose:
                print(f"[OK] {name}: {path}")
        else:
            if verbose:
                print(f"[WARN] {name}: {path} (not found)")
            all_exist = False

    return all_exist


def validate_api_keys(verbose: bool = True) -> bool:
    """
    Validate that required API keys are configured.

    Args:
        verbose: If True, print status for each key.

    Returns:
        bool: True if critical keys are present, False otherwise.
    """
    keys = load_api_keys()
    missing = keys.get_missing_keys()

    if not missing:
        if verbose:
            print("[+] All API keys configured.")
        return True

    if verbose:
        print("[WARN] Missing API keys:")
        for key in missing:
            print(f"  - {key}")
    return False


def full_validation(strict: bool = False) -> bool:
    """
    Run full configuration validation.

    Args:
        strict: If True, exit on validation failure. If False, only warn.

    Returns:
        bool: True if all validations pass, False otherwise.
    """
    print("=" * 60)
    print("Recon Bot Configuration Validation")
    print("=" * 60)

    print("\n[*] Validating tool paths...")
    tools_ok = validate_tool_paths(verbose=True)

    print("\n[*] Validating config paths...")
    validate_config_paths(verbose=True)

    print("\n[*] Validating API keys...")
    keys_ok = validate_api_keys(verbose=True)

    print("\n" + "=" * 60)
    if strict:
        if not tools_ok:
            print("[!] FAILED: Missing required tools.", file=sys.stderr)
            sys.exit(1)
        if not keys_ok:
            print("[!] FAILED: Missing required API keys.", file=sys.stderr)
            sys.exit(1)
    else:
        if not tools_ok:
            print("[!] WARNING: Some tools are missing.")

    print("[+] Configuration validation complete.")
    print("=" * 60)
    return tools_ok and keys_ok


# =============================================================================
# Module Initialization Check
# =============================================================================
def _check_environment():
    """Run environment check on module import (optional)."""
    if os.environ.get("RECON_BOT_STRICT_VALIDATION", "").lower() == "1":
        full_validation(strict=True)


if os.environ.get("RECON_BOT_AUTO_VALIDATE", "").lower() == "1":
    _check_environment()
