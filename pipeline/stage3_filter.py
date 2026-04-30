#!/usr/bin/env python3
"""
Stage 3: CNAME Filtering for Subdomain Takeover Discovery Pipeline

Filters resolved domains for CNAMEs pointing to cloud providers.
Suspicious (cloud-pointing) CNAMEs are written to {domain}_suspicious.txt.
Cloud watchlist entries are appended to cloud_watchlist.txt (append-only, never overwrite).

Input: resolved domains from stage2
Output:
  - {domain}/{domain}_suspicious.txt (CNAMEs to cloud providers)
  - {domain}/cloud_watchlist.txt (persistent archive)
"""

import asyncio
import re
from pathlib import Path
from typing import Set, Dict


# Default cloud provider CNAME patterns (compiled regex)
DEFAULT_CLOUD_PATTERNS = [
    # AWS
    r"\.amazonaws\.com$",
    r"\.aws\.amazon\.com$",
    r"\.awsglobal\.com$",
    r"\.awsaptrace\.com$",
    r"\.cloudfront\.net$",

    # Azure
    r"\.azurewebsites\.net$",
    r"\.cloudapp\.net$",
    r"\.azure\.com$",
    r"\.azureedge\.net$",
    r"\.windows\.net$",
    r"\.azurecontainer\.io$",
    r"\.azurecr\.io$",
    r"\.azureeventgrid\.com$",
    r"\.azurefd\.net$",
    r"\.azureiotcentral\.com$",
    r"\.azureiotedge\.com$",
    r"\.azurestorage\.cn$",
    r"\.azurewebsites\.windows\.net$",

    # GCP
    r"\.storage\.googleapis\.com$",
    r"\.appspot\.com$",
    r"\.cloudfunctions\.net$",
    r"\.googleusercontent\.com$",
    r"\.doubleclick\.net$",
    r"\.firebaseapp\.com$",
    r"\.firebase\.io$",
    r"\.googleapis\.com$",
    r"\.gweb\.io$",
    r"\.app\.googiestudio\.com$",
    r"\.web\.app$",

    # Cloudflare
    r"\.cloudflare\.net$",
    r"\.cloudflarED\.net$",
    r"\.cfcdn\.org$",
    r"\.cdn\.cloudflare\.net$",
    r"\.workers\.dev$",

    # GitHub Pages
    r"\.github\.io$",
    r"\.githubusercontent\.com$",

    # Heroku
    r"\.herokudns\.com$",
    r"\.herokuapp\.com$",
    r"\.herokussl\.com$",

    # Netlify
    r"\.netlify\.app$",
    r"\.netlify\.com$",
    r"\.netlify\.net$",

    # Vercel
    r"\.vercel\.app$",
    r"\.now\.sh$",
    r"\.vercel\.dns\.com$",

    # DigitalOcean
    r"\.digitalocean\.com$",
    r"\.digitalocean\.spaces$",
    r"\.cdn\.digitalocean\.com$",

    # Linode
    r"\.linode\.com$",
    r"\.linode\.users\.linode\.com$",
    r"\.linode\.net$",

    # Oracle Cloud
    r"\.oraclecloud\.net$",
    r"\.oci\.oraclecloud\.net$",
    r"\.oraclevcn\.com$",
    r"\.oraclecloudplatform\.net$",
    r"\.oraclecloudplatform\.com$",

    # IBM Cloud
    r"\.ibmcloud\.net$",
    r"\.bluemix\.net$",
    r"\.internetofthings\.ibmcloud\.com$",
    r"\.watson\.cloud\.ibm\.com$",

    # Fastly
    r"\.fastly\.net$",
    r"\.fastly\.lb\.core\.twttr\.net$",
    r"\.fastly Terrier$",
    r"\.fastlynet\.net$",

    # Akamai
    r"\.akamai\.net$",
    r"\.akamaized\.net$",
    r"\.akamaihd\.net$",
    r"\.edgesuite\.net$",
    r"\.akamaiedge\.net$",
    r"\.serving-sys\.com$",
    r"\.cloudfront\.net$",

    # CloudFront (AWS)
    r"\.cloudfront\.net$",

    # Sucuri
    r"\.sucuri\.net$",
    r"\.sucuri\.cloud$",

    # Imunify360
    r"\.imunify360\.net$",
    r"\.websecure\.cloud$",

    # WordPress.com
    r"\.wordpress\.com$",
    r"\.wp\.com$",

    # Shopify
    r"\.myshopify\.com$",
    r"\.shopify\.com$",
    r"\.shopifystatic\.com$",
    r"\.cdn\.shopify\.com$",

    # Squarespace
    r"\.squarespace\.com$",
    r"\.quarespace\.com$",
    r"\.ssl\.squarespace\.com$",

    # Wix
    r"\.wix\.com$",
    r"\.wixsite\.com$",
    r"\.wix-code\.com$",

    # Ghost
    r"\.ghost\.io$",

    # GitLab Pages
    r"\.gitlab\.io$",
    r"\.gitlabusercontent\.io$",

    # Bitbucket
    r"\.bitbucket\.io$",
    r"\.bitbucketusercontent\.io$",

    # GitLab
    r"\.gitlab\.com$",

    # Cloudflare Pages
    r"\.pages\.dev$",
    r"\.pages\.cloudflare\.net$",

    # Fly.io
    r"\.fly\.io$",
    r"\.fly.dev$",

    # Render
    r"\.onrender\.com$",
    r"\.render\.com$",

    # Surge
    r"\.surge\.sh$",

    # Surge (alternative)
    r"\.野心\.sh$",

    # Firebase Hosting
    r"\.firebase\.com$",
    r"\.web\.firebaseapp\.com$",

    # Supabase
    r"\.supabase\.co$",
    r"\.supabase\.net$",
    r"\.supabase\.io$",

    # Railway
    r"\.railway\.app$",

    # Platform.sh
    r"\.platform\.sh$",
    r"\.fr-git\.platform\.sh$",

    # Azure DevOps
    r"\.visualstudio\.com$",
    r"\.azure-dev\.com$",
    r"\.cloudapp\.azure\.com$",

    # AWS Elastic Beanstalk
    r"\.elasticbeanstalk\.com$",
    r"\.elasticbeanstalk\.aws$",

    # OpenShift
    r"\.openshift\.com$",
    r"\.rhev-us\.openshift\.com$",
    r"\.os\.rhcloud\.com$",

    # Pantheon
    r"\.pantheon\.io$",
    r"\.pantheonsite\.io$",
    r"\.gotpantheon\.com$",

    # Acquia
    r"\.acquia\.com$",
    r"\.acquia-mc\.com$",
    r"\.acquia-sites\.com$",
    r"\.cloud\.acquia\.com$",

    # Pressable
    r"\.pressable\.com$",
    r"\.pressablecdn\.com$",

    # WP Engine
    r"\.wpengine\.com$",
    r"\.wpengine\.net$",
    r"\.wpenginepowered\.com$",
    r"\.wpenginepowered\.net$",

    # Kinsta
    r"\.kinsta\.cloud$",
    r"\.kinsta\.com$",
    r"\.kinsta-cdn\.com$",

    # Cloudways
    r"\.cloudways\.com$",
    r"\.cloudwaysapps\.com$",

    # Hostinger
    r"\.hostinger\.com$",
    r"\.hstatic\.net$",

    # GoDaddy
    r"\.godaddy\.com$",
    r"\.secureserver\.net$",

    # Namecheap
    r"\.namecheap\.com$",
    r"\.namecheap\.net$",

    # Bluehost
    r"\.bluehost\.com$",
    r"\.bluehost\.in$",
    r"\.web\.bluehost\.com$",

    # Domain.com
    r"\.domain\.com$",
    r"\.domain\.com\.net$",

    # DreamHost
    r"\.dreamhost\.com$",
    r"\.dreamhosters\.com$",
    r"\.dh-media\.com$",

    # Hover
    r"\.hover\.com$",
    r"\.hover\.com\.net$",

    # Gandi
    r"\.gandi\.net$",
    r"\.gandislabs\.com$",
    r"\.gandi\.live$",

    # DigitalOcean App Platform
    r"\.ondigitalocean\.app$",

    # Zeit (now Vercel)
    r"\.zeit\.co$",
    r"\.now\.co$",

    # University-specific (common patterns)
    r"\.edu\.com$",
    r"\.edu\.cn$",
    r"\.edu\.au$",

    # Generic cloud patterns
    r"\.cloud\.com$",
    r"\.host\.com$",
    r"\.server\.com$",
    r"\.cdn\.com$",

    # Slack
    r"\.slack\.com$",
    r"\.slack-msgs\.com$",

    # Discord
    r"\.discord\.com$",
    r"\.discordapp\.net$",

    # Zoom
    r"\.zoom\.us$",
    r"\.zoomgov\.com$",

    # Trello
    r"\.trello\.com$",
    r"\.trellocdn\.com$",

    # Jira/Atlassian
    r"\.atlassian\.net$",
    r"\.jira\.com$",
    r"\.jira-dev\.com$",
    r"\.atlassian庭院\.net$",

    # Canva
    r"\.canva\.com$",
    r"\.canva-production\.com$",
    r"\.canva\.site$",

    # Figma
    r"\.figma\.com$",
    r"\.figma\.net$",

    # Notion
    r"\.notion\.com$",
    r"\.notion\.so$",
    r"\.notion-static\.com$",

    # Airtable
    r"\.airtable\.com$",
    r"\.airtable\.co$",
    r"\.airtableusercontent\.com$",

    # Stripe
    r"\.stripe\.com$",
    r"\.stripe\.net$",

    # PayPal
    r"\.paypal\.com$",
    r"\.paypal\.net$",

    # Shopify Lite
    r"\.shopify\.com$",
    r"\.myshopify\.com$",

    # BigCommerce
    r"\.bigcommerce\.com$",
    r"\.bigcommerce\.net$",
    r"\.commcloud\.com$",

    # Magento
    r"\.magento\.com$",
    r"\.magento\.cloud$",
    r"\.magento\.com\.cloud\.io$",

    # PrestaShop
    r"\.prestashop\.com$",
    r"\.prestashop-project\.com$",

    # WooCommerce
    r"\.woocommerce\.com$",
    r"\.woocommerce\.net$",
    r"\.woocommercedns\.com$",

    # Ecwid
    r"\.ecwid\.com$",
    r"\.ecwid\.net$",

    # Weebly
    r"\.weebly\.com$",
    r"\.weebly\.cloud$",
    r"\.weeblysite\.com$",

    # Webflow
    r"\.webflow\.com$",
    r"\.webflow\.io$",
    r"\.webflowusercontent\.com$",

    # Duda
    r"\.duda\.co$",
    r"\.duda\.site$",
    r"\.dudamobile\.com$",

    # Carrd
    r"\.carrd\.co$",

    # Webnode
    r"\.webnode\.com$",
    r"\.webnode\.cz$",
    r"\.webnode\.sk$",
]

# Compile patterns once for efficiency
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DEFAULT_CLOUD_PATTERNS]


def create_cname_whitelist_file(output_path: Path) -> None:
    """
    Helper function to create cname_whitelist.txt with default cloud provider patterns.

    Args:
        output_path: Path where the whitelist file should be written
    """
    content = """# CNAME Whitelist - Cloud Provider Domains
# Used by Stage 3 to identify cloud-hosted subdomains for subdomain takeover detection
#
# Format: One pattern per line (regex supported)
# Lines starting with # are comments
#
# AWS
*.amazonaws.com
*.aws.amazon.com
*.awsglobal.com
*.awsaptrace.com
*.cloudfront.net

# Azure
*.azurewebsites.net
*.cloudapp.net
*.azure.com
*.azureedge.net
*.windows.net
*.azurecontainer.io
*.azurecr.io
*.azureeventgrid.com
*.azurefd.net
*.azureiotcentral.com
*.azureiotedge.com
*.azurestorage.cn

# GCP
*.storage.googleapis.com
*.appspot.com
*.cloudfunctions.net
*.googleusercontent.com
*.doubleclick.net
*.firebaseapp.com
*.firebase.io
*.googleapis.com

# Cloudflare
*.cloudflare.net
*.cfcdn.org
*.cdn.cloudflare.net
*.workers.dev

# GitHub Pages
*.github.io
*.githubusercontent.com

# Heroku
*.herokudns.com
*.herokuapp.com

# Netlify
*.netlify.app
*.netlify.com

# Vercel
*.vercel.app
*.now.sh

# DigitalOcean
*.digitalocean.com
*.digitalocean.spaces

# Linode
*.linode.com

# Oracle Cloud
*.oraclecloud.net
*.oci.oraclecloud.net
*.oraclevcn.com

# IBM Cloud
*.ibmcloud.net
*.bluemix.net

# Fastly
*.fastly.net

# Akamai
*.akamai.net
*.akamaized.net
*.akamaihd.net
*.edgesuite.net

# WordPress.com
*.wordpress.com
*.wp.com

# Shopify
*.myshopify.com
*.shopify.com

# Squarespace
*.squarespace.com

# Wix
*.wix.com
*.wixsite.com

# Ghost
*.ghost.io

# GitLab
*.gitlab.io

# Bitbucket
*.bitbucket.io

# Cloudflare Pages
*.pages.dev

# Fly.io
*.fly.io

# Render
*.onrender.com
*.render.com

# Firebase Hosting
*.firebase.com

# Supabase
*.supabase.co

# Railway
*.railway.app

# Platform.sh
*.platform.sh

# Acquia
*.acquia.com
*.cloud.acquia.com

# WP Engine
*.wpengine.com

# Kinsta
*.kinsta.cloud

# Generic cloud patterns
*.cloud.com
"""
    output_path.write_text(content)


async def load_whitelist_patterns(whitelist_path: Path) -> Dict[str, re.Pattern]:
    """
    Load CNAME whitelist patterns from file.

    Args:
        whitelist_path: Path to cname_whitelist.txt

    Returns:
        Dictionary mapping pattern string to compiled regex pattern
    """
    patterns = {}

    if whitelist_path.exists():
        content = await asyncio.to_thread(whitelist_path.read_text)
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    patterns[line] = re.compile(line, re.IGNORECASE)
                except re.error:
                    # If it's not a valid regex, treat it as a literal string pattern
                    escaped = re.escape(line)
                    patterns[line] = re.compile(escaped, re.IGNORECASE)
    else:
        # Use default patterns if whitelist file doesn't exist
        for pattern in DEFAULT_CLOUD_PATTERNS:
            patterns[pattern] = re.compile(pattern, re.IGNORECASE)

    return patterns


def is_cloud_cname(cname: str, patterns: Dict[str, re.Pattern]) -> bool:
    """
    Check if a CNAME points to a cloud provider.

    Args:
        cname: The CNAME record value to check
        patterns: Dictionary of compiled regex patterns

    Returns:
        True if CNAME matches any cloud provider pattern
    """
    cname_lower = cname.lower().rstrip(".")

    for pattern in patterns.values():
        if pattern.search(cname_lower):
            return True

    return False


async def run_stage3(
    domain: str,
    output_dir: str,
    resolved_domains: Set[str]
) -> Dict[str, Set[str]]:
    """
    Stage 3: CNAME Filtering - Filter resolved domains for cloud provider CNAMEs.

    Args:
        domain: The target domain being analyzed
        output_dir: Directory for output files
        resolved_domains: Set of resolved domain strings from stage2

    Returns:
        Dictionary containing:
            - suspicious: Set of CNAMEs pointing to cloud providers
            - cloud_watchlist_entries: Set of entries appended to cloud_watchlist.txt
    """
    output_path = Path(output_dir)
    domain_path = output_path / domain

    # Ensure domain directory exists
    await asyncio.to_thread(domain_path.mkdir, parents=True, exist_ok=True)

    # Load whitelist patterns
    whitelist_path = output_path / "cname_whitelist.txt"
    if not whitelist_path.exists():
        await asyncio.to_thread(create_cname_whitelist_file, whitelist_path)

    patterns = await load_whitelist_patterns(whitelist_path)

    # Filter domains for cloud CNAMEs
    suspicious = set()
    cloud_watchlist_entries = set()

    for resolved in resolved_domains:
        # Extract CNAME from resolved domain (format: "subdomain.target.domain" or "CNAME: target")
        # Handle various formats from stage2 output
        cname_value = resolved

        # Check if it's a cloud provider CNAME
        if is_cloud_cname(cname_value, patterns):
            suspicious.add(cname_value)

            # Create watchlist entry with timestamp format
            # Format: domain|cname|timestamp (for archival)
            watchlist_entry = f"{domain}|{cname_value}"
            cloud_watchlist_entries.add(watchlist_entry)

    # Write suspicious CNAMEs to file
    suspicious_file = domain_path / f"{domain}_suspicious.txt"
    await asyncio.to_thread(
        suspicious_file.write_text,
        "\n".join(sorted(suspicious))
    )

    # Append cloud watchlist entries (append-only, never overwrite)
    cloud_watchlist_file = domain_path / "cloud_watchlist.txt"

    # Read existing entries to avoid duplicates
    existing_entries = set()
    if cloud_watchlist_file.exists():
        content = await asyncio.to_thread(cloud_watchlist_file.read_text)
        for line in content.splitlines():
            if line and not line.startswith("#"):
                # Parse existing entries (format: domain|cname)
                existing_entries.add(line.strip())

    # Only append new entries
    new_entries = cloud_watchlist_entries - existing_entries
    if new_entries:
        # Append new entries to the watchlist
        append_content = "\n".join(sorted(new_entries)) + "\n"
        await asyncio.to_thread(
            cloud_watchlist_file.write_text,
            append_content,
            mode="a"
        )

    return {
        "suspicious": suspicious,
        "cloud_watchlist_entries": cloud_watchlist_entries
    }


async def main():
    """Test/standalone execution for stage3."""
    import argparse

    parser = argparse.ArgumentParser(description="Stage 3: CNAME Filtering")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("--resolved-file", help="File containing resolved domains (one per line)")

    args = parser.parse_args()

    # Load resolved domains from file
    resolved_domains = set()
    if args.resolved_file:
        resolved_file = Path(args.resolved_file)
        if resolved_file.exists():
            content = await asyncio.to_thread(resolved_file.read_text)
            resolved_domains = {line.strip() for line in content.splitlines() if line.strip()}

    # Run stage3
    results = await run_stage3(args.domain, args.output_dir, resolved_domains)

    print(f"Stage 3 Complete: {args.domain}")
    print(f"  Suspicious CNAMEs: {len(results['suspicious'])}")
    print(f"  New watchlist entries: {len(results['cloud_watchlist_entries'])}")

    return results


if __name__ == "__main__":
    asyncio.run(main())
