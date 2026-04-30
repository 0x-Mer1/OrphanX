"""
Stage 5: HTTP Probing using httpx

Probes dangling domains with HTTP/HTTPS to detect what's responding.
This stage identifies potential subdomain takeover targets by analyzing:
- Status codes
- Content length
- Headers
- Redirects
- Page titles
- Technology detection
- Cloud provider default pages

Input: DANGING domains from stage4 (only after NXDOMAIN confirmation)
Output: {domain}/{domain}_probed.txt
"""

import asyncio
import logging
from pathlib import Path
from typing import Set, Dict, Any, List, Optional
import re

logger = logging.getLogger(__name__)

# Tool paths
HTTPX_PATH = "/home/azureuser/go/bin/httpx"

# httpx critical flags for subdomain takeover detection
HTTPX_FLAGS = [
    "-silent",
    "-status-code",
    "-content-length",
    "-follow-redirects",
    "-title",
    "-tech-detect",
    "-probe",
    "-json",  # Structured output for easier parsing
]


def parse_httpx_output(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line of httpx JSON output.

    Args:
        line: JSON line from httpx

    Returns:
        Parsed dict or None if parsing fails
    """
    import json
    try:
        return json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def detect_takeover_indicators(result: Dict[str, Any]) -> List[str]:
    """
    Detect potential subdomain takeover indicators from httpx results.

    Args:
        result: Parsed httpx result dict

    Returns:
        List of detected indicators
    """
    indicators = []

    # Extract relevant fields
    status_code = result.get("status_code", 0)
    url = result.get("url", "")
    title = result.get("title", "")
    technologies = result.get("technologies", [])
    redirect = result.get("redirect", "")
    content_length = result.get("length", 0)
    host = result.get("host", "")

    # Common cloud provider default page patterns
    cloud_provider_patterns = {
        "AWS S3": [
            "NoSuchBucket",
            "BucketNotFound",
            "specified bucket does not exist",
            "AccessDenied",
            "aws:s3",
        ],
        "Azure": [
            "The specified resource does not exist",
            "Web app not found",
            "AzureFunctions",
            "api://",
            "azurewebsites.net",
        ],
        "GCP": [
            "No such object",
            "storage.googleapis.com",
            "Google Cloud Storage",
        ],
        "GitHub Pages": [
            "There isn't a GitHub Pages site here",
            "Page not found",
            "404 File not found",
        ],
        "Netlify": [
            "Netlify",
            "Not Found",
            "page not found",
        ],
        "Vercel": [
            "Vercel",
            "The requested URL was not found",
        ],
        "Cloudflare": [
            "origin DNS",
            "cf-error",
            "Cloudflare",
        ],
        "DigitalOcean": [
            "Floating IP",
            " droplet ",
        ],
    }

    # Check for cloud provider takeover potential
    for provider, patterns in cloud_provider_patterns.items():
        for pattern in patterns:
            if pattern.lower() in (title + " " + str(result.get("body", ""))).lower():
                indicators.append(f"Potential {provider} takeover target")
                break

    # Check for redirect to registration/takeover pages
    registration_patterns = [
        r"buy\.",
        r"domain.*sale",
        r"register\.",
        r"auction\.",
        r"expired",
        r"renew",
    ]

    if redirect:
        for pattern in registration_patterns:
            if re.search(pattern, redirect, re.IGNORECASE):
                indicators.append("Redirect to registration/sale page")
                break

    # Check for NXDOMAIN-like response on a live host
    if status_code == 404 and content_length == 0:
        indicators.append("404 with zero content length")

    # Check for certificate mismatches
    if result.get("failed", False) and "certificate" in str(result.get("error", "")).lower():
        indicators.append("Certificate mismatch")

    # Generic takeover indicators
    if status_code in [404, 200] and content_length < 1000 and technologies:
        if any(tech in technologies for tech in ["AWS S3", "Azure", "Nginx", "Apache"]):
            indicators.append("Possible infrastructure takeover")

    if "redirect" in result and result["redirect"]:
        if "http" not in redirect and "/" not in redirect:
            indicators.append(f"Suspicious redirect: {redirect}")

    return list(set(indicators))  # Deduplicate


async def probe_domains(
    domain: str,
    dangling_domains: Set[str],
    output_file: Path
) -> Dict[str, Any]:
    """
    Probe dangling domains using httpx.

    Args:
        domain: Target domain
        dangling_domains: Set of dangling domains to probe
        output_file: Path to output file (via anew)

    Returns:
        Dict containing probe results and statistics
    """
    if not dangling_domains:
        return {
            "probed": 0,
            "responding": 0,
            "takeover_candidates": 0,
            "results": [],
            "errors": [],
        }

    logger.info(f"Probing {len(dangling_domains)} dangling domains with httpx...")

    results = []
    errors = []
    takeover_candidates = []

    # Prepare domains for stdin
    domain_list = sorted(dangling_domains)
    input_data = "\n".join(domain_list).encode()

    # Build httpx command
    cmd = [HTTPX_PATH] + HTTPX_FLAGS

    try:
        # Start httpx process
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Write domains to stdin and close
        stdout, stderr = await process.communicate(input=input_data)

        if process.returncode != 0:
            stderr_decoded = stderr.decode("utf-8", errors="replace")
            logger.warning(f"httpx exited with code {process.returncode}: {stderr_decoded}")
            errors.append(f"httpx process error: {stderr_decoded}")

        # Parse stdout
        stdout_decoded = stdout.decode("utf-8", errors="replace")
        lines = stdout_decoded.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue

            parsed = parse_httpx_output(line)
            if parsed:
                # Detect takeover indicators
                indicators = detect_takeover_indicators(parsed)

                result_entry = {
                    "url": parsed.get("url", ""),
                    "host": parsed.get("host", ""),
                    "status_code": parsed.get("status_code", 0),
                    "content_length": parsed.get("length", 0),
                    "title": parsed.get("title", ""),
                    "technologies": parsed.get("technologies", []),
                    "redirect": parsed.get("redirect", ""),
                    "failed": parsed.get("failed", False),
                    "error": parsed.get("error", ""),
                    "takeover_indicators": indicators,
                }

                results.append(result_entry)

                # Track responding hosts
                if parsed.get("status_code") or parsed.get("failed"):
                    if result_entry not in results:
                        pass  # Already added

                # Flag takeover candidates
                if indicators:
                    takeover_candidates.append(result_entry)

        logger.info(
            f"httpx probe complete: {len(results)} results, "
            f"{len(takeover_candidates)} takeover candidates"
        )

    except FileNotFoundError:
        error_msg = f"httpx not found at {HTTPX_PATH}"
        logger.error(error_msg)
        errors.append(error_msg)
    except PermissionError:
        error_msg = f"httpx not executable at {HTTPX_PATH}"
        logger.error(error_msg)
        errors.append(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during httpx probing: {str(e)}"
        logger.exception(error_msg)
        errors.append(error_msg)

    return {
        "probed": len(dangling_domains),
        "responding": len(results),
        "takeover_candidates": len(takeover_candidates),
        "results": results,
        "takeover_candidate_results": takeover_candidates,
        "errors": errors,
    }


async def write_results(
    domain: str,
    output_dir: Path,
    results: List[Dict[str, Any]]
) -> None:
    """
    Write probe results to output file using anew pattern.

    Args:
        domain: Target domain
        output_dir: Output directory path
        results: List of probe result dicts
    """
    output_file = output_dir / f"{domain}_probed.txt"

    try:
        with open(output_file, "a") as f:
            for result in results:
                # Format output line similar to httpx default but with takeover indicators
                url = result.get("url", "")
                status = result.get("status_code", "NA")
                content_length = result.get("content_length", 0)
                title = result.get("title", "")
                technologies = ",".join(result.get("technologies", []))
                redirect = result.get("redirect", "")
                indicators = "; ".join(result.get("takeover_indicators", []))

                # Build output line
                parts = [url, str(status), str(content_length)]
                if title:
                    parts.append(title)
                if technologies:
                    parts.append(f"[{technologies}]")
                if redirect:
                    parts.append(f"-> {redirect}")
                if indicators:
                    parts.append(f"## {indicators}")

                f.write(" | ".join(parts) + "\n")

        logger.info(f"Results written to {output_file}")

    except Exception as e:
        logger.exception(f"Failed to write results to {output_file}: {e}")
        raise


async def run_stage5(
    domain: str,
    output_dir: str,
    dangling_domains: Set[str]
) -> Dict[str, Any]:
    """
    Stage 5: HTTP Probing using httpx.

    Probes dangling domains discovered in stage4 with HTTP/HTTPS
    to detect what's responding and identify takeover candidates.

    Args:
        domain: Target domain being analyzed
        output_dir: Base output directory
        dangling_domains: Set of dangling domains (confirmed NXDOMAIN in stage4)

    Returns:
        Dict containing:
            - probed: Number of domains probed
            - responding: Number of responding hosts
            - takeover_candidates: Number of potential takeover targets
            - results: Full probe results
            - takeover_candidate_results: Filtered results with takeover indicators
            - errors: Any errors encountered

    Example takeover indicators:
        - AWS S3 bucket responses
        - Azure default pages
        - Redirects to registration pages
        - Certificate mismatches
        - Cloud provider specific error pages
    """
    logger.info(f"=== Stage 5: HTTP Probing for {domain} ===")
    logger.info(f"Input: {len(dangling_domains)} dangling domains from stage4")

    # Validate tool exists
    if not Path(HTTPX_PATH).exists():
        logger.error(f"httpx not found at {HTTPX_PATH}")
        return {
            "probed": 0,
            "responding": 0,
            "takeover_candidates": 0,
            "results": [],
            "takeover_candidate_results": [],
            "errors": [f"httpx not found at {HTTPX_PATH}"],
        }

    # Ensure output directory exists
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Probe domains with httpx
    probe_results = await probe_domains(domain, dangling_domains, output_path)

    # Write results via anew pattern (append)
    if probe_results["results"]:
        await write_results(domain, output_path, probe_results["results"])

    # Log summary
    logger.info(
        f"Stage 5 complete: {probe_results['probed']} domains probed, "
        f"{probe_results['responding']} responding, "
        f"{probe_results['takeover_candidates']} takeover candidates"
    )

    if probe_results.get("takeover_candidate_results"):
        logger.info("Takeover candidates detected:")
        for candidate in probe_results["takeover_candidate_results"]:
            logger.info(f"  - {candidate['url']}: {', '.join(candidate['takeover_indicators'])}")

    return probe_results


# CLI entry point for direct execution
if __name__ == "__main__":
    import sys
    import json

    async def main():
        if len(sys.argv) < 3:
            print("Usage: stage5_httpx.py <domain> <output_dir> [dangling_domains...]")
            sys.exit(1)

        domain = sys.argv[1]
        output_dir = sys.argv[2]
        dangling = set(sys.argv[3:]) if len(sys.argv) > 3 else set()

        # Support piped input
        if not dangling and not sys.stdin.isatty():
            dangling = set(line.strip() for line in sys.stdin if line.strip())

        results = await run_stage5(domain, output_dir, dangling)
        print(json.dumps(results, indent=2, default=str))
        return results

    asyncio.run(main())