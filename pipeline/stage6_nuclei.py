#!/usr/bin/env python3
"""
Stage 6: Subdomain Takeover Confirmation via Nuclei
====================================================
Uses nuclei with takeover templates to confirm subdomain takeover vulnerabilities.
Templates are updated before each scan to ensure latest patterns.

Input: Probed domains from stage5
Output: {domain}_nuclei.jsonl - Confirmed takeover findings in JSONL format
"""

import asyncio
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, Dict, Any, List, Optional


# Nuclei configuration
NUCLEI_BIN = Path("/home/azureuser/go/bin/nuclei")
NUCLEI_TEMPLATES_DIR = Path.home() / ".local" / "nuclei-templates"
NUCLEI_UPDATE_INTERVAL = 3600  # Update templates at most once per hour

# Takeover template categories to focus on
TAKEOVER_TEMPLATES = [
    "takeover/",
    "exposed-tokens/",
    "miscellaneous/missing-dnssec.yaml",
]

# Nuclei operational flags
NUCLEI_RATE_LIMIT = 150  # Requests per second
NUCLEI_RETRIES = 2       # Retry failed requests
NUCLEI_TIMEOUT = 300     # 5 minute timeout per target


class NucleiTemplateUpdater:
    """Manages nuclei template updates with caching."""

    def __init__(self, nuclei_bin: Path, templates_dir: Path):
        self.nuclei_bin = nuclei_bin
        self.templates_dir = templates_dir
        self._last_update: Optional[datetime] = None

    async def update_if_needed(self) -> bool:
        """Update nuclei templates if stale or missing."""
        now = datetime.now()

        # Skip if updated recently (within update interval)
        if self._last_update:
            elapsed = (now - self._last_update).total_seconds()
            if elapsed < NUCLEI_UPDATE_INTERVAL:
                return True

        # Run nuclei update command
        try:
            proc = await asyncio.create_subprocess_exec(
                str(self.nuclei_bin),
                "-update-templates",
                "-ud", str(self.templates_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                self._last_update = now
                return True

            # Log error but don't fail - existing templates may work
            if stderr:
                print(f"[-] Nuclei template update warning: {stderr.decode().strip()}", file=sys.stderr)

            return True

        except Exception as e:
            print(f"[-] Nuclei template update failed: {e}", file=sys.stderr)
            # Continue with existing templates
            return True


class NucleiScanner:
    """Async nuclei scanner for subdomain takeover detection."""

    def __init__(
        self,
        nuclei_bin: Path,
        templates_dir: Path,
        rate_limit: int = NUCLEI_RATE_LIMIT,
        retries: int = NUCLEI_RETRIES,
    ):
        self.nuclei_bin = nuclei_bin
        self.templates_dir = templates_dir
        self.rate_limit = rate_limit
        self.retries = retries
        self.updater = NucleiTemplateUpdater(nuclei_bin, templates_dir)

    async def scan(self, targets: Set[str], output_file: Path) -> List[Dict[str, Any]]:
        """
        Run nuclei scan on targets using takeover templates.

        Args:
            targets: Set of domains/URLs to scan
            output_file: Path for JSONL output

        Returns:
            List of confirmed takeover findings
        """
        findings: List[Dict[str, Any]] = []

        if not targets:
            return findings

        # Ensure templates are up-to-date
        await self.updater.update_if_needed()

        # Verify nuclei binary exists
        if not self.nuclei_bin.exists():
            print(f"[-] Nuclei binary not found: {self.nuclei_bin}", file=sys.stderr)
            return findings

        # Build nuclei command with takeover templates
        cmd = [
            str(self.nuclei_bin),
            "-silent",
            "-json",
            "-rate-limit", str(self.rate_limit),
            "-retries", str(self.retries),
            "-timeout", str(NUCLEI_TIMEOUT),
            "-output", str(output_file),
        ]

        # Add takeover template path
        takeover_path = self.templates_dir / "takeover"
        if takeover_path.exists():
            cmd.extend(["-templates", str(takeover_path)])
        else:
            # Fallback to all templates if takeover dir not found
            cmd.extend(["-templates", str(self.templates_dir)])

        # Prepare domain list for stdin input
        target_list = sorted(targets)
        input_data = "\n".join(target_list).encode()

        try:
            # Run nuclei with stdin input
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate(input=input_data)

            # Parse JSON output from stdout
            if stdout:
                for line in stdout.decode().strip().split("\n"):
                    if line.strip():
                        try:
                            result = json.loads(line)
                            # Filter for actual takeover findings
                            if self._is_takeover_finding(result):
                                findings.append(result)
                        except json.JSONDecodeError:
                            continue

            # Log any errors
            if stderr and stderr.strip():
                stderr_text = stderr.decode().strip()
                # nuclei outputs summary to stderr on completion
                if "印" not in stderr_text and "error" not in stderr_text.lower():
                    print(f"[~] Nuclei stderr: {stderr_text}", file=sys.stderr)

        except Exception as e:
            print(f"[-] Nuclei scan error: {e}", file=sys.stderr)

        return findings

    def _is_takeover_finding(self, result: Dict[str, Any]) -> bool:
        """Filter nuclei results for actual takeover vulnerabilities."""
        # Check if it's a takeover-related finding
        info = result.get("info", {})
        classification = info.get("classification", {})

        # Look for takeover in matched template
        matched = result.get("matched-at", "")
        template = result.get("template", "")

        is_takeover = (
            "takeover" in matched.lower() or
            "takeover" in template.lower() or
            classification.get("security", "").lower() == "takeover" or
            info.get("name", "").lower().startswith("takeover")
        )

        return is_takeover


def parse_nuclei_finding(result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse and normalize nuclei finding into standard format."""
    info = result.get("info", {})

    return {
        "type": "takeover",
        "source": "nuclei",
        "target": result.get("matched-at", result.get("host", "")),
        "template": result.get("template", ""),
        "template_id": result.get("template-id", ""),
        "name": info.get("name", "Unknown takeover"),
        "severity": info.get("severity", "info"),
        "description": info.get("description", ""),
        "matched_at": result.get("matched-at", ""),
        "timestamp": result.get("timestamp", datetime.now().isoformat()),
        "ip": result.get("ip", ""),
        "host": result.get("host", ""),
        "port": result.get("port", 0),
    }


async def run_stage6(domain: str, output_dir: str, probed_domains: Set[str]) -> Dict[str, Any]:
    """
    Stage 6: Confirm subdomain takeovers using nuclei takeover templates.

    Args:
        domain: Target domain being analyzed
        output_dir: Directory for stage outputs
        probed_domains: Set of probed domains from stage5

    Returns:
        Dict containing:
            - findings: List of confirmed takeover vulnerabilities
            - scanned_count: Number of targets scanned
            - findings_count: Number of findings
            - output_file: Path to JSONL output
    """
    output_path = Path(output_dir)
    output_file = output_path / f"{domain}_nuclei.jsonl"

    print(f"[*] Stage 6: Nuclei takeover scan for {domain}")
    print(f"[*] Targets to scan: {len(probed_domains)}")

    # Initialize scanner
    scanner = NucleiScanner(
        nuclei_bin=NUCLEI_BIN,
        templates_dir=NUCLEI_TEMPLATES_DIR,
    )

    # Run nuclei scan
    start_time = datetime.now()
    results = await scanner.scan(probed_domains, output_file)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Parse and normalize findings
    findings = [parse_nuclei_finding(r) for r in results]

    # Output to anew for pipeline continuity
    if findings:
        # Append findings to output file using anew logic
        existing = set()
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    try:
                        existing.add(json.loads(line).get("target", ""))
                    except json.JSONDecodeError:
                        continue

        with open(output_file, "a") as f:
            for finding in findings:
                if finding["target"] not in existing:
                    f.write(json.dumps(finding) + "\n")

    print(f"[+] Nuclei scan complete: {len(findings)} takeover findings")
    print(f"[*] Scanned {len(probed_domains)} targets in {elapsed:.1f}s")
    print(f"[*] Output: {output_file}")

    return {
        "findings": findings,
        "scanned_count": len(probed_domains),
        "findings_count": len(findings),
        "output_file": str(output_file),
        "elapsed_seconds": elapsed,
    }


async def main():
    """Standalone execution for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Stage 6: Nuclei takeover scanner")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("--targets", help="File with targets (one per line)")
    args = parser.parse_args()

    # Load targets
    targets: Set[str] = set()
    if args.targets:
        with open(args.targets) as f:
            targets = {line.strip() for line in f if line.strip()}

    result = await run_stage6(args.domain, args.output_dir, targets)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
