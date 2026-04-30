#!/usr/bin/env python3
"""
Stage 7: Evidence Collection

Subdomain takeover discovery pipeline - Stage 7.

Collects evidence for confirmed takeover findings:
- DNS records via dig (A, AAAA, CNAME, TXT, MX)
- Screenshots via gowitness

Evidence silos per finding in targets/{domain}/evidence/{subdomain}/
"""

import asyncio
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


async def run_dig(domain: str, subdomain: str, output_path: Path) -> Dict[str, Any]:
    """
    Run dig to collect DNS records for a subdomain.

    Args:
        domain: Target domain
        subdomain: Subdomain to query
        output_path: Path to save dig output

    Returns:
        Dict with dig results and any errors
    """
    result = {
        "subdomain": subdomain,
        "output_file": str(output_path),
        "success": False,
        "records": {},
        "error": None,
        "cname_chain": []
    }

    try:
        # Query multiple record types
        record_types = ["A", "AAAA", "CNAME", "TXT", "MX", "NS"]

        dig_outputs = []
        cname_chain = []

        for record_type in record_types:
            proc = await asyncio.create_subprocess_exec(
                "dig", f"@8.8.8.8", "+short", "+noall", "+answer",
                subdomain, record_type,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                output = stdout.decode("utf-8", errors="ignore").strip()
                if output:
                    dig_outputs.append(f"# {record_type} records:\n{output}")
                    result["records"][record_type] = output.split("\n") if output else []

                    # Track CNAME chain
                    if record_type == "CNAME":
                        for line in output.split("\n"):
                            if line:
                                cname_chain.append(line.strip())

        # Follow CNAME chain with additional queries
        if cname_chain:
            result["cname_chain"] = cname_chain
            # Query the final target after CNAME chain
            final_target = cname_chain[-1].split()[0].rstrip(".") if cname_chain else None
            if final_target and final_target != subdomain:
                dig_outputs.append(f"\n# CNAME chain target ({final_target}) resolution:")
                for record_type in ["A", "AAAA"]:
                    proc = await asyncio.create_subprocess_exec(
                        "dig", f"@8.8.8.8", "+short", "+noall", "+answer",
                        final_target, record_type,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()
                    if stdout:
                        output = stdout.decode("utf-8", errors="ignore").strip()
                        if output:
                            dig_outputs.append(f"# {record_type} for {final_target}:\n{output}")

        # Write combined output
        full_output = f"""# DNS records for: {subdomain}
# Domain: {domain}
# Query time: {asyncio.get_event_loop().time()}

"""
        full_output += "\n".join(dig_outputs)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_output)

        result["success"] = True
        logger.info(f"[{subdomain}] DNS records saved to {output_path}")

    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[{subdomain}] dig failed: {e}")

    return result


async def run_gowitness(url: str, output_path: Path, timeout: int = 30) -> Dict[str, Any]:
    """
    Run gowitness to capture a screenshot.

    Args:
        url: URL to screenshot
        output_path: Path to save screenshot
        timeout: Timeout in seconds

    Returns:
        Dict with gowitness results and any errors
    """
    result = {
        "url": url,
        "output_file": str(output_path),
        "success": False,
        "error": None
    }

    try:
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Run gowitness scan and export in one flow
        # First, do a quick single capture
        proc = await asyncio.create_subprocess_exec(
            "gowitness", "scan", "single",
            "-u", url,
            "-o", str(output_path.parent),
            "--full-page",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            result["error"] = "Screenshot timeout"
            logger.warning(f"[{url}] gowitness timeout")
            return result

        # gowitness outputs to a file based on the URL hash
        # Try to find the generated screenshot
        possible_paths = [
            output_path,
            output_path.parent / f"{hash(url)}.png",
            output_path.parent / f"{url.replace('://', '_').replace('/', '_').replace('.', '_')}.png"
        ]

        # Check if any known path exists
        found = False
        for p in possible_paths:
            if p.exists():
                # Move/copy to desired name if different
                if p != output_path:
                    import shutil
                    shutil.copy2(p, output_path)
                found = True
                break

        if not found:
            # gowitness may store in its db, try exporting
            export_proc = await asyncio.create_subprocess_exec(
                "gowitness", "export", "screenshot",
                "-u", url,
                "-o", str(output_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await export_proc.communicate()

            # If export approach didn't work, just mark as partial
            if not output_path.exists():
                result["error"] = "Screenshot file not found after capture"
                logger.warning(f"[{url}] Screenshot file not found")
                return result

        result["success"] = True
        logger.info(f"[{url}] Screenshot saved to {output_path}")

    except FileNotFoundError:
        result["error"] = "gowitness not installed"
        logger.error(f"[{url}] gowitness not found in PATH")
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"[{url}] gowitness failed: {e}")

    return result


async def collect_evidence_for_finding(
    domain: str,
    finding: dict,
    base_dir: Path,
    semaphore: asyncio.Semaphore
) -> Dict[str, Any]:
    """
    Collect evidence (DNS + screenshot) for a single finding.

    Args:
        domain: Target domain
        finding: Finding dict with subdomain and other metadata
        base_dir: Base directory for evidence
        semaphore: Semaphore for concurrency control

    Returns:
        Dict with evidence collection results
    """
    subdomain = finding.get("subdomain", finding.get("host", finding.get("url", "")))
    if not subdomain:
        return {"success": False, "error": "No subdomain in finding"}

    # Normalize subdomain (remove protocol if present)
    if "://" in subdomain:
        from urllib.parse import urlparse
        subdomain = urlparse(subdomain).netloc

    result = {
        "subdomain": subdomain,
        "finding_id": finding.get("id", finding.get("finding_id", "")),
        "dns": None,
        "screenshot": None,
        "success": False
    }

    # Create evidence silo directory
    silo_dir = base_dir / domain / "evidence" / subdomain
    dns_output = silo_dir / f"{subdomain}_dns.txt"
    screenshot_output = silo_dir / f"{subdomain}.png"

    async with semaphore:
        # Run dig and gowitness concurrently
        dns_task = run_dig(domain, subdomain, dns_output)
        screenshot_task = run_gowitness(
            f"https://{subdomain}" if not subdomain.startswith("http") else subdomain,
            screenshot_output
        )

        dns_result, screenshot_result = await asyncio.gather(
            dns_task,
            screenshot_task,
            return_exceptions=True
        )

        # Handle any exceptions from gather
        if isinstance(dns_result, Exception):
            result["dns"] = {"success": False, "error": str(dns_result)}
        else:
            result["dns"] = dns_result

        if isinstance(screenshot_result, Exception):
            result["screenshot"] = {"success": False, "error": str(screenshot_result)}
        else:
            result["screenshot"] = screenshot_result

        result["silo_path"] = str(silo_dir)
        result["success"] = result["dns"]["success"] or result["screenshot"]["success"]

    return result


async def run_stage7(domain: str, output_dir: str, findings: List[dict]) -> dict:
    """
    Stage 7: Evidence Collection

    Collects DNS records and screenshots for confirmed subdomain takeover findings.

    Args:
        domain: Target domain
        output_dir: Base output directory
        findings: List of confirmed takeover findings from stage 6

    Returns:
        Dict with:
            - domain: Target domain
            - total_findings: Number of findings processed
            - successful_evidence: Count of successfully collected evidence
            - evidence_paths: List of created evidence paths
            - results: Detailed results per finding
    """
    logger.info(f"[Stage 7] Starting evidence collection for {domain}")
    logger.info(f"[Stage 7] Processing {len(findings)} findings")

    base_dir = Path(output_dir)

    # Concurrency limit for evidence collection
    # Too many concurrent screenshots can overwhelm the system
    semaphore = asyncio.Semaphore(5)

    # Collect evidence for all findings concurrently
    tasks = [
        collect_evidence_for_finding(domain, finding, base_dir, semaphore)
        for finding in findings
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    evidence_paths = []
    successful_count = 0
    detailed_results = []

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Finding {i} raised exception: {result}")
            detailed_results.append({
                "index": i,
                "success": False,
                "error": str(result)
            })
        else:
            detailed_results.append(result)
            if result.get("success"):
                successful_count += 1
                evidence_paths.append(result.get("silo_path", ""))

    summary = {
        "domain": domain,
        "stage": 7,
        "stage_name": "evidence",
        "total_findings": len(findings),
        "successful_evidence": successful_count,
        "failed_evidence": len(findings) - successful_count,
        "evidence_paths": [p for p in evidence_paths if p],
        "results": detailed_results
    }

    logger.info(
        f"[Stage 7] Completed: {successful_count}/{len(findings)} "
        f"findings with successful evidence collection"
    )

    return summary


def sync_run_stage7(domain: str, output_dir: str, findings: List[dict]) -> dict:
    """
    Synchronous wrapper for run_stage7.

    Allows calling from non-async contexts while maintaining
    the async implementation.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(run_stage7(domain, output_dir, findings))


if __name__ == "__main__":
    # CLI for testing
    import json
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if len(sys.argv) < 3:
        print("Usage: stage7_evidence.py <domain> <output_dir> [findings_json]")
        sys.exit(1)

    domain = sys.argv[1]
    output_dir = sys.argv[2]

    if len(sys.argv) > 3:
        findings = json.loads(sys.argv[3])
    else:
        # Demo/test findings
        findings = [
            {"subdomain": f"test{i}.{domain}", "id": i}
            for i in range(1, 3)
        ]

    result = sync_run_stage7(domain, output_dir, findings)
    print(json.dumps(result, indent=2, default=str))
