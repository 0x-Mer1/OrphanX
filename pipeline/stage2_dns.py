#!/usr/bin/env python3
"""
Stage 2: DNS Resolution
Uses dnsx to resolve subdomains and capture A, AAAA, and CNAME records.
CNAME tracking is critical for subdomain takeover detection later in the pipeline.
NXDOMAIN responses are valuable signal — they indicate potentially abandoned subdomains.
"""

import asyncio
import logging
import os
from typing import Dict, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

TOOL_PATHS = {
    "dnsx": "/home/azureuser/go/bin/dnsx",
    "anew": "/home/azureuser/go/bin/anew",
}

DNS_TIMEOUT = 30  # seconds per subdomain batch


@dataclass
class ResolvedHost:
    """Represents a successfully resolved subdomain with its records."""
    subdomain: str
    a_records: Set[str] = field(default_factory=set)
    aaaa_records: Set[str] = field(default_factory=set)
    cname_records: Set[str] = field(default_factory=set)

    @property
    def has_cname(self) -> bool:
        return len(self.cname_records) > 0


@dataclass
class Stage2Result:
    """Results from Stage 2 DNS resolution."""
    resolved: Dict[str, ResolvedHost]  # subdomain -> ResolvedHost
    nxdomain: Set[str]  # subdomains that returned NXDOMAIN (takeover candidates)
    failed: Set[str]  # subdomains that failed for other reasons
    cname_map: Dict[str, str]  # maps CNAME target -> original subdomain

    @property
    def total_attempted(self) -> int:
        return len(self.resolved) + len(self.nxdomain) + len(self.failed)


def parse_dnsx_line(line: str) -> tuple[str, str, list]:
    """
    Parse a single line of dnsx output.

    Output format (from dnsx -silent):
    subdomain:A:1.2.3.4
    subdomain:AAAA:2001:db8::
    subdomain:CNAME:target.example.com

    Returns:
        tuple of (subdomain, record_type, value)
    """
    line = line.strip()
    if not line:
        return None, None, None

    parts = line.split(":", 2)
    if len(parts) < 3:
        return None, None, None

    subdomain, record_type, value = parts
    return subdomain, record_type, value


async def run_stage2(domain: str, output_dir: str, subdomains: Set[str]) -> dict:
    """
    Execute Stage 2 DNS resolution for discovered subdomains.

    Args:
        domain: Target domain (e.g., "example.com")
        output_dir: Base directory for output files
        subdomains: Set of subdomains from stage 1

    Returns:
        dict with keys:
            - resolved: Dict[str, ResolvedHost] of successfully resolved subdomains
            - nxdomain: Set[str] of subdomains that don't exist (NXDOMAIN)
            - failed: Set[str] of subdomains that failed for other reasons
            - cname_map: Dict[str, str] mapping CNAME targets to source subdomains
            - total_attempted: int
    """
    domain = domain.strip().lower()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    resolved_file = output_path / f"{domain}_resolved.txt"

    logger.info(f"[Stage 2] Starting DNS resolution for {domain}")
    logger.info(f"[Stage 2] Processing {len(subdomains)} subdomains")

    if not subdomains:
        logger.warning(f"[Stage 2] No subdomains provided for {domain}")
        return Stage2Result(
            resolved={},
            nxdomain=set(),
            failed=set(),
            cname_map={}
        ).__dict__

    dnsx_path = TOOL_PATHS.get("dnsx")
    if not dnsx_path or not os.path.isfile(dnsx_path):
        logger.error(f"dnsx not found at {dnsx_path}")
        return Stage2Result(
            resolved={},
            nxdomain=set(),
            failed=set(),
            cname_map={}
        ).__dict__

    # Resolve all subdomains via dnsx
    # dnsx flags:
    #   -retry 3: retry failed lookups 3 times
    #   -silent: clean output without stats
    #   -json: output as JSON (we'll parse carefully)
    #   -a -aaaa -cname: request A, AAAA, and CNAME records
    #
    # We use -silent with line-based output since it's more predictable than JSON
    # for parsing single records

    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            dnsx_path,
            "-silent",
            "-retry", "3",
            "-a",
            "-aaaa",
            "-cname",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Write all subdomains to dnsx stdin
        subdomain_input = "\n".join(sorted(subdomains)).encode()
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=subdomain_input),
            timeout=DNS_TIMEOUT
        )

        if process.returncode != 0:
            stderr_text = stderr.decode(errors="ignore").strip()
            logger.warning(f"dnsx exited with code {process.returncode}: {stderr_text}")

    except asyncio.TimeoutError:
        if process:
            process.kill()
        logger.error(f"[Stage 2] dnsx timed out after {DNS_TIMEOUT}s")
        return Stage2Result(
            resolved={},
            nxdomain=set(),
            failed=subdomains,
            cname_map={}
        ).__dict__
    except Exception as e:
        logger.error(f"[Stage 2] Error running dnsx: {e}")
        if process:
            try:
                process.kill()
            except Exception:
                pass
        return Stage2Result(
            resolved={},
            nxdomain=set(),
            failed=subdomains,
            cname_map={}
        ).__dict__

    # Parse dnsx output
    # Format: subdomain:record_type:value
    # e.g., dev.example.com:A:1.2.3.4
    #       dev.example.com:CNAME:target.example.com

    resolved_hosts: Dict[str, ResolvedHost] = {}
    nxdomain_subs: Set[str] = set()
    failed_subs: Set[str] = set()
    cname_map: Dict[str, str] = {}  # target_cname -> source_subdomain

    output_lines = stdout.decode(errors="ignore").strip().splitlines()

    for line in output_lines:
        if not line.strip():
            continue

        # Check for NXDOMAIN indicator (dnsx sometimes outputs this)
        if line.startswith("[NXDOMAIN]") or ":NXDOMAIN:" in line:
            parts = line.replace("[NXDOMAIN]", "").strip().split(":")
            if parts:
                nxdomain_subs.add(parts[0])
            continue

        subdomain, record_type, value = parse_dnsx_line(line)
        if not subdomain:
            continue

        # Initialize ResolvedHost if needed
        if subdomain not in resolved_hosts:
            resolved_hosts[subdomain] = ResolvedHost(subdomain=subdomain)

        host = resolved_hosts[subdomain]

        if record_type == "A":
            host.a_records.add(value)
        elif record_type == "AAAA":
            host.aaaa_records.add(value)
        elif record_type == "CNAME":
            host.cname_records.add(value)
            cname_map[value] = subdomain

    # Identify NXDOMAIN and failed subdomains
    # A subdomain is NXDOMAIN if it wasn't in the resolved output at all
    resolved_subdomains = set(resolved_hosts.keys())
    for sub in subdomains:
        if sub not in resolved_subdomains:
            # Could be NXDOMAIN or failure - dnsx doesn't always distinguish
            # If it's in output as "no answer", treat as failed
            # Otherwise, assume NXDOMAIN (valuable takeover signal)
            nxdomain_subs.add(sub)

    # Write resolved domains to file via anew
    anew_path = TOOL_PATHS.get("anew")
    if anew_path and os.path.isfile(anew_path) and resolved_hosts:
        try:
            resolved_content = []
            for host in resolved_hosts.values():
                # Format: subdomain,A=1.2.3.4,AAAA=::1,CNAME=target.com
                parts = [host.subdomain]
                if host.a_records:
                    parts.append(f"A={','.join(sorted(host.a_records))}")
                if host.aaaa_records:
                    parts.append(f"AAAA={','.join(sorted(host.aaaa_records))}")
                if host.cname_records:
                    parts.append(f"CNAME={','.join(sorted(host.cname_records))}")
                resolved_content.append(",".join(parts))

            async with asyncio.create_subprocess_exec(
                anew_path,
                str(resolved_file),
                stdin=asyncio.subprocess.PIPE,
            ) as anew_proc:
                await anew_proc.communicate(input="\n".join(resolved_content).encode())
        except Exception as e:
            logger.warning(f"[Stage 2] Failed to write to anew: {e}")

    result = Stage2Result(
        resolved=resolved_hosts,
        nxdomain=nxdomain_subs,
        failed=failed_subs,
        cname_map=cname_map,
    )

    logger.info(
        f"[Stage 2] DNS resolution complete for {domain}: "
        f"{len(resolved_hosts)} resolved, "
        f"{len(nxdomain_subs)} NXDOMAIN (takeover candidates), "
        f"{len(failed_subs)} failed "
        f"(total: {result.total_attempted})"
    )

    if cname_map:
        logger.info(f"[Stage 2] Found {len(cname_map)} CNAME records for takeover tracking")

    return result.__dict__


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Stage 2: DNS Resolution with dnsx")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-o", "--output-dir", default=".", help="Output directory")
    parser.add_argument(
        "-s", "--subdomains",
        help="File with subdomains (one per line), or use stdin with pipe",
    )
    args = parser.parse_args()

    # Load subdomains from file if provided
    subdomains: Set[str] = set()
    if args.subdomains:
        subdomain_file = Path(args.subdomains)
        if subdomain_file.is_file():
            content = subdomain_file.read_text()
            subdomains = {line.strip() for line in content.splitlines() if line.strip()}
        else:
            logger.error(f"Subdomain file not found: {args.subdomains}")
            exit(1)
    else:
        # Read from stdin
        import sys
        content = sys.stdin.read().strip()
        subdomains = {line.strip() for line in content.splitlines() if line.strip()}

    result = asyncio.run(run_stage2(args.domain, args.output_dir, subdomains))

    print(f"\nDNS Resolution Results for {args.domain}:")
    print(f"  Resolved: {len(result['resolved'])}")
    print(f"  NXDOMAIN: {len(result['nxdomain'])}")
    print(f"  Failed: {len(result['failed'])}")
    print(f"  CNAME records: {len(result['cname_map'])}")

    output_file = Path(args.output_dir) / f"{args.domain}_resolved.txt"
    print(f"\nResults saved to: {output_file}")