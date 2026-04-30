#!/usr/bin/env python3
"""
Stage 1: Passive Discovery
Runs subfinder, assetfinder, and amass in passive mode to enumerate subdomains.
Pipes all output through anew for deduplication on disk.
Tracks which tool discovered each subdomain for reporting.
"""

import asyncio
import logging
import os
import re
from typing import Dict, Set
from pathlib import Path

logger = logging.getLogger(__name__)

TOOL_PATHS = {
    "subfinder": "/home/azureuser/go/bin/subfinder",
    "assetfinder": "/home/azureuser/go/bin/assetfinder",
    "amass": "/usr/local/bin/amass",
}

SUBDOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_subdomain(line: str) -> bool:
    """Validate that a line looks like a subdomain."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    return bool(SUBDOMAIN_REGEX.match(line))


async def run_tool(
    tool: str,
    args: list,
    output_file: Path,
    domain: str,
) -> Set[str]:
    """
    Run a tool asynchronously and capture discovered subdomains.

    Returns a set of subdomains found by this tool.
    """
    tool_path = TOOL_PATHS.get(tool)
    if not tool_path:
        logger.error(f"Unknown tool: {tool}")
        return set()

    if not os.path.isfile(tool_path):
        logger.warning(f"Tool not found: {tool_path}")
        return set()

    logger.info(f"Running {tool} for {domain}")

    cmd = [tool_path] + args

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.warning(
                f"{tool} exited with code {process.returncode}: {stderr.decode(errors='ignore').strip()}"
            )

        output = stdout.decode(errors="ignore").strip()
        if output:
            discovered = {line.strip() for line in output.splitlines() if is_subdomain(line.strip())}
            if discovered:
                logger.info(f"{tool} found {len(discovered)} subdomains")

                # Append to output file via anew
                anew_path = TOOL_PATHS.get("anew", "/home/azureuser/go/bin/anew")
                if os.path.isfile(anew_path):
                    for sub in discovered:
                        async with asyncio.create_subprocess_exec(
                            anew_path,
                            str(output_file),
                            stdin=asyncio.subprocess.PIPE,
                        ) as anew_proc:
                            await anew_proc.communicate(input=sub.encode())

            return discovered

        return set()

    except Exception as e:
        logger.error(f"Error running {tool}: {e}")
        return set()


async def run_stage1(domain: str, output_dir: str) -> Dict:
    """
    Execute Stage 1 passive discovery for a given domain.

    Runs subfinder, assetfinder, and amass concurrently.

    Args:
        domain: Target domain (e.g., "example.com")
        output_dir: Base directory for output files

    Returns:
        dict with keys:
            - subdomains: Set[str] of all discovered subdomains
            - by_tool: dict mapping tool name -> Set[str] of subdomains
    """
    domain = domain.strip().lower()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    subdomain_file = output_path / f"{domain}_subdomains.txt"

    logger.info(f"[Stage 1] Starting passive discovery for {domain}")

    # Track results per tool
    by_tool: Dict[str, Set[str]] = {
        "subfinder": set(),
        "assetfinder": set(),
        "amass": set(),
    }

    # Prepare tasks to run concurrently
    tasks = []

    # subfinder: passive mode, silent output
    tasks.append(
        run_tool(
            "subfinder",
            ["-silent", "-passive", "-d", domain],
            subdomain_file,
            domain,
        )
    )

    # assetfinder: just domain argument
    tasks.append(
        run_tool(
            "assetfinder",
            [domain],
            subdomain_file,
            domain,
        )
    )

    # amass: passive enum, needs work directory, suppress stderr
    amass_workdir = output_path / "amass_work"
    amass_workdir.mkdir(parents=True, exist_ok=True)

    tasks.append(
        run_tool(
            "amass",
            ["enum", "-passive", "-dir", str(amass_workdir), "-d", domain],
            subdomain_file,
            domain,
        )
    )

    # Run all tools concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results by tool
    for tool_name, result in zip(by_tool.keys(), results):
        if isinstance(result, Exception):
            logger.error(f"{tool_name} raised exception: {result}")
            by_tool[tool_name] = set()
        else:
            by_tool[tool_name] = result

    # Merge all subdomains
    all_subdomains: Set[str] = set()
    for tool_subdomains in by_tool.values():
        all_subdomains.update(tool_subdomains)

    logger.info(
        f"[Stage 1] Discovery complete for {domain}: "
        f"{len(all_subdomains)} unique subdomains "
        f"(subfinder={len(by_tool['subfinder'])}, "
        f"assetfinder={len(by_tool['assetfinder'])}, "
        f"amass={len(by_tool['amass'])})"
    )

    return {
        "subdomains": all_subdomains,
        "by_tool": by_tool,
    }


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Stage 1: Passive Subdomain Discovery")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument(
        "-o", "--output-dir", default=".", help="Output directory (default: current directory)"
    )
    args = parser.parse_args()

    result = asyncio.run(run_stage1(args.domain, args.output_dir))

    print(f"\nDiscovered {len(result['subdomains'])} unique subdomains:")
    for tool, subs in result["by_tool"].items():
        print(f"  {tool}: {len(subs)} subdomains")

    output_file = Path(args.output_dir) / f"{args.domain}_subdomains.txt"
    print(f"\nResults saved to: {output_file}")