"""
Stage 4: NXDOMAIN Gate - Dangling DNS Detection
================================================
This stage confirms which CNAMEs point to DANGLED/ORPHANED services.

CRITICAL RULE: Nslookup gate is mandatory - no Httpx without NXDOMAIN confirmation
- For each suspicious CNAME, resolve the CNAME TARGET (not the subdomain)
- If the CNAME target resolves to NXDOMAIN -> dangling/orphaned record!
- NXDOMAIN = potential subdomain takeover opportunity
- If resolution works = destination exists = probably safe

Input:  suspicious CNAMEs from stage3
Output: {domain}/{domain}_dangling.txt
"""

import asyncio
import logging
import re
import os
from typing import Set, Dict

logger = logging.getLogger(__name__)


def extract_cname_target(fqdn: str) -> str:
    """
    Extract the CNAME target from a fully qualified domain name.

    CNAMEs from stage3 are formatted as: subdomain.domain.tld -> target.domain.tld
    We need to extract just the target portion.

    Args:
        fqdn: Full domain string potentially containing '->' separator

    Returns:
        The CNAME target host (without any arrow notation)
    """
    if '->' in fqdn:
        # Format: "subdomain.domain.tld -> target.domain.tld"
        target = fqdn.split('->', 1)[1].strip()
        return target
    return fqdn.strip()


async def run_nslookup(hostname: str) -> Dict[str, any]:
    """
    Run nslookup for a given hostname and parse the result.

    Args:
        hostname: The hostname to look up

    Returns:
        Dict with keys:
            - success: bool (lookup completed without error)
            - nxdomain: bool (NXDOMAIN response detected)
            - answer: str or None (the answer from nslookup)
            - raw_output: str (raw nslookup output for debugging)
    """
    result = {
        'success': False,
        'nxdomain': False,
        'answer': None,
        'raw_output': ''
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            'nslookup',
            hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        raw_output = stdout.decode('utf-8', errors='replace')
        result['raw_output'] = raw_output

        # Check for NXDOMAIN in output
        # NXDOMAIN responses contain "NXDOMAIN" or "** server can't find"
        if 'NXDOMAIN' in raw_output.upper() or "server can't find" in raw_output.lower():
            result['nxdomain'] = True
            result['success'] = True
            logger.debug(f"NXDOMAIN detected for {hostname}")
            return result

        # Check if we got a successful answer
        # Look for Address: lines which indicate successful resolution
        address_pattern = re.compile(r'^Address:\s+\d+\.\d+\.\d+\.\d+$', re.MULTILINE)
        if address_pattern.search(raw_output):
            result['success'] = True
            # Extract the answer portion (typically after the "Name:" line)
            lines = raw_output.split('\n')
            for i, line in enumerate(lines):
                if 'Name:' in line and i + 1 < len(lines):
                    result['answer'] = lines[i + 1].strip()
                    break
            logger.debug(f"Resolved {hostname} -> {result['answer']}")
        else:
            # No clear NXDOMAIN but also no clear answer
            result['success'] = True  # Lookup completed, just no match
            logger.warning(f"nslookup completed but no clear answer for {hostname}: {raw_output[:200]}")

    except asyncio.TimeoutError:
        logger.error(f"nslookup timed out for {hostname}")
    except Exception as e:
        logger.error(f"nslookup error for {hostname}: {e}")

    return result


async def check_domain_dangling(domain: str, semaphore: asyncio.Semaphore) -> Dict[str, any]:
    """
    Check a single domain for dangling CNAME.

    Args:
        domain: The CNAME string (format: "subdomain -> target" or just "target")
        semaphore: Semaphore for concurrency control

    Returns:
        Dict with keys:
            - original: str (original domain string)
            - target: str (extracted CNAME target)
            - is_dangling: bool (True if NXDOMAIN)
            - nxdomain_result: dict from run_nslookup
    """
    async with semaphore:
        target = extract_cname_target(domain)

        logger.info(f"Checking CNAME target: {target} (from {domain})")

        nslookup_result = await run_nslookup(target)

        is_dangling = nslookup_result['nxdomain']

        if is_dangling:
            logger.info(f"DANGLING: {domain} -> {target} (NXDOMAIN)")
        else:
            logger.debug(f"ACTIVE: {domain} -> {target} (resolved OK)")

        return {
            'original': domain,
            'target': target,
            'is_dangling': is_dangling,
            'nxdomain_result': nslookup_result
        }


async def run_stage4(domain: str, output_dir: str, suspicious_domains: Set[str]) -> dict:
    """
    Stage 4: NXDOMAIN Gate - Identify dangling/orphaned DNS records.

    This is the MANDATORY GATE before HTTP probing. Only CNAMEs whose
    targets return NXDOMAIN are considered vulnerable to takeover.

    Args:
        domain: The target domain being analyzed
        output_dir: Directory for output files
        suspicious_domains: Set of suspicious CNAME strings from stage3

    Returns:
        Dict with keys:
            - dangling: Set[str] - CNAMEs with NXDOMAIN targets (VULNERABLE)
            - still_active: Set[str] - CNAMEs that still resolve (SAFE)
    """
    logger.info(f"[STAGE 4] Starting NXDOMAIN gate for {domain}")
    logger.info(f"[STAGE 4] Checking {len(suspicious_domains)} suspicious CNAMEs")

    dangling: Set[str] = set()
    still_active: Set[str] = set()

    if not suspicious_domains:
        logger.info(f"[STAGE 4] No suspicious domains to check")
        return {"dangling": dangling, "still_active": still_active}

    # Use semaphore to limit concurrent nslookups (avoid overwhelming DNS)
    semaphore = asyncio.Semaphore(10)

    # Create tasks for all domain checks
    tasks = [
        check_domain_dangling(d, semaphore)
        for d in suspicious_domains
    ]

    # Execute all checks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Exception during domain check: {result}")
            continue

        if result['is_dangling']:
            dangling.add(result['original'])
        else:
            still_active.add(result['original'])

    # Write dangling domains to output file
    output_file = os.path.join(output_dir, f"{domain}_dangling.txt")

    try:
        os.makedirs(output_dir, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(f"# Dangling DNS Records for {domain}\n")
            f.write(f"# Generated by Stage 4: NXDOMAIN Gate\n")
            f.write(f"# Total dangling: {len(dangling)}\n")
            f.write(f"# Total active: {len(still_active)}\n")
            f.write(f"\n")

            for d in sorted(dangling):
                f.write(f"{d}\n")

        logger.info(f"[STAGE 4] Wrote {len(dangling)} dangling domains to {output_file}")

    except Exception as e:
        logger.error(f"[STAGE 4] Failed to write output file {output_file}: {e}")

    # Summary
    logger.info(f"[STAGE 4] COMPLETE for {domain}")
    logger.info(f"[STAGE 4]   Dangling (VULNERABLE): {len(dangling)}")
    logger.info(f"[STAGE 4]   Still Active (SAFE):   {len(still_active)}")

    return {
        "dangling": dangling,
        "still_active": still_active
    }


if __name__ == "__main__":
    # Simple CLI test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    async def test():
        test_domain = "example.com"
        test_suspicious = {
            "api.example.com -> defunct-service.herokuapp.com",
            "docs.example.com -> github.io",
            "old.example.com -> abandoned-cloudfront.cloudfront.net",
        }
        result = await run_stage4(test_domain, "/tmp", test_suspicious)
        print(f"\nResults: {result}")

    asyncio.run(test())
