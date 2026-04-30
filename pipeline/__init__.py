"""
Recon Bot - Subdomain Takeover Discovery Pipeline
==================================================

An asynchronous pipeline for discovering and validating subdomain takeovers.

Pipeline Flow
-------------
Stage 1  -> Passive Discovery
    Tools: subfinder, assetfinder, amass (passive mode)
    Output: Discovered subdomains with source tracking

Stage 2  -> Active Resolution (if implemented)
    Tools: DNS resolvers
    Output: Resolved domains

Stage 3  -> CNAME Filtering
    Purpose: Filter for cloud-provider CNAMEs (AWS, Azure, GCP, etc.)
    Output: Suspicious CNAMEs + persistent cloud_watchlist.txt

Stage 4  -> NXDOMAIN Gate
    Tool: nslookup
    Purpose: Confirm dangling/orphaned DNS (CNAME targets returning NXDOMAIN)
    Output: Dangling domains (vulnerable to takeover)

Stage 5  -> HTTP Probing
    Tool: httpx
    Purpose: Analyze HTTP responses for takeover indicators
    Output: Probed results with technology detection

Stage 6  -> Nuclei Confirmation
    Tool: nuclei (takeover templates)
    Purpose: Validate takeover vulnerabilities with security templates
    Output: Confirmed findings in JSONL format

Stage 7  -> Evidence Collection
    Tools: dig, gowitness
    Purpose: Collect DNS records and screenshots for findings
    Output: Evidence silos per subdomain

Stage 8  -> Report Generation
    Purpose: Generate HTML dashboard and ZIP archive
    Output: {domain}_Final_Report/dashboard.html + .zip

Usage
-----
    from pipeline import run_pipeline, PipelineStage

    results = await run_pipeline("example.com", "/output/dir")

Tool Paths
----------
    /home/azureuser/go/bin/     - subfinder, assetfinder, amass, httpx, nuclei, anew
    /usr/local/bin/            - dig, nslookup, gowitness

Notes
-----
    - All tool paths are absolute (shell PATH is ignored)
    - Output is piped through `anew` for deduplication
    - Amass stderr is suppressed (2>/dev/null)
    - Uses python-telegram-bot v20+ for notifications
"""

import asyncio
import logging
from enum import Enum, auto
from typing import Dict, Set, List, Any, Optional, Callable, Awaitable

# Import all stage modules
from pipeline import stage1_discovery
from pipeline import stage3_filter
from pipeline import stage4_nslookup
from pipeline import stage5_httpx
from pipeline import stage6_nuclei
from pipeline import stage7_evidence
from pipeline import stage8_report

# Stage module re-exports for convenience
__all__ = [
    # Modules
    "stage1_discovery",
    "stage3_filter",
    "stage4_nslookup",
    "stage5_httpx",
    "stage6_nuclei",
    "stage7_evidence",
    "stage8_report",
    # Enum
    "PipelineStage",
    "StageStatus",
    # Exceptions
    "PipelineError",
    "StageError",
    "ToolNotFoundError",
    "ConfigurationError",
    "TakeoverNotConfirmedError",
    # Types
    "PipelineContext",
    "Finding",
    "PipelineResult",
    # Core functions
    "run_pipeline",
    "run_stage",
    # Tool paths
    "TOOL_PATHS",
]


# =============================================================================
# Enums
# =============================================================================

class PipelineStage(Enum):
    """
    Pipeline stage enumeration.

    Use this enum to track pipeline progress and reference stages
    in pipeline results and logging.

    Example::
        current_stage = PipelineStage.STAGE3_FILTER
        next_stage = PipelineStage.STAGE4_NXDOMAIN
    """
    STAGE1_DISCOVERY = auto()   # Passive subdomain enumeration
    STAGE2_RESOLUTION = auto()  # DNS resolution (optional)
    STAGE3_FILTER = auto()      # CNAME filtering for cloud providers
    STAGE4_NXDOMAIN = auto()    # Dangling DNS detection via NXDOMAIN
    STAGE5_HTTPX = auto()       # HTTP probing
    STAGE6_NUCLEI = auto()      # Nuclei takeover confirmation
    STAGE7_EVIDENCE = auto()    # Evidence collection
    STAGE8_REPORT = auto()      # Report generation

    @property
    def display_name(self) -> str:
        """Human-readable stage name."""
        names = {
            PipelineStage.STAGE1_DISCOVERY: "Passive Discovery",
            PipelineStage.STAGE2_RESOLUTION: "Active Resolution",
            PipelineStage.STAGE3_FILTER: "CNAME Filtering",
            PipelineStage.STAGE4_NXDOMAIN: "NXDOMAIN Gate",
            PipelineStage.STAGE5_HTTPX: "HTTP Probing",
            PipelineStage.STAGE6_NUCLEI: "Nuclei Confirmation",
            PipelineStage.STAGE7_EVIDENCE: "Evidence Collection",
            PipelineStage.STAGE8_REPORT: "Report Generation",
        }
        return names.get(self, self.name)

    @property
    def stage_number(self) -> int:
        """Extract numeric stage identifier."""
        return int(self.name.split("_")[0].replace("STAGE", ""))


class StageStatus(Enum):
    """Status of a pipeline stage execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# =============================================================================
# Exceptions
# =============================================================================

class PipelineError(Exception):
    """Base exception for pipeline-related errors."""
    pass


class StageError(PipelineError):
    """Exception raised when a pipeline stage fails."""

    def __init__(self, stage: PipelineStage, message: str, original_error: Optional[Exception] = None):
        self.stage = stage
        self.original_error = original_error
        super().__init__(f"[{stage.display_name}] {message}")


class ToolNotFoundError(PipelineError):
    """Exception raised when a required tool binary is not found."""

    def __init__(self, tool: str, path: str):
        self.tool = tool
        self.path = path
        super().__init__(f"Tool '{tool}' not found at {path}")


class ConfigurationError(PipelineError):
    """Exception raised for invalid pipeline configuration."""
    pass


class TakeoverNotConfirmedError(PipelineError):
    """Exception raised when a subdomain takeover cannot be confirmed."""
    pass


# =============================================================================
# Types
# =============================================================================

class Finding:
    """
    Represents a subdomain takeover finding.

    Attributes:
        subdomain: The vulnerable subdomain
        cname: The CNAME record pointing to the vulnerable service
        provider: Detected cloud provider (AWS, Azure, GCP, etc.)
        template_id: Nuclei template ID that confirmed the finding
        severity: Finding severity (critical, high, medium, low, info)
        evidence: Dict containing paths to evidence files (screenshots, DNS records)
    """

    def __init__(
        self,
        subdomain: str,
        cname: str = "",
        provider: str = "",
        template_id: str = "",
        severity: str = "info",
        evidence: Optional[Dict[str, str]] = None,
    ):
        self.subdomain = subdomain
        self.cname = cname
        self.provider = provider
        self.template_id = template_id
        self.severity = severity
        self.evidence = evidence or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "provider": self.provider,
            "template_id": self.template_id,
            "severity": self.severity,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create a Finding from a dictionary."""
        return cls(
            subdomain=data.get("subdomain", ""),
            cname=data.get("cname", ""),
            provider=data.get("provider", ""),
            template_id=data.get("template_id", ""),
            severity=data.get("severity", "info"),
            evidence=data.get("evidence", {}),
        )


class PipelineContext:
    """
    Shared context passed through pipeline stages.

    Maintains state and accumulated results across all pipeline stages.

    Attributes:
        domain: Target domain being analyzed
        output_dir: Base output directory for all stage outputs
        subdomains: Discovered subdomains from stage 1
        suspicious_cnames: Cloud-pointing CNAMEs from stage 3
        dangling: Confirmed dangling domains from stage 4
        probed: HTTP probe results from stage 5
        findings: Confirmed takeover findings from stage 6
        evidence_paths: Paths to collected evidence from stage 7
        errors: Errors encountered during pipeline execution
    """

    def __init__(self, domain: str, output_dir: str):
        self.domain = domain
        self.output_dir = output_dir
        self.subdomains: Set[str] = set()
        self.by_tool: Dict[str, Set[str]] = {}
        self.suspicious_cnames: Set[str] = set()
        self.cloud_cnames: Set[str] = set()
        self.dangling: Set[str] = set()
        self.still_active: Set[str] = set()
        self.probed: List[Dict[str, Any]] = []
        self.takeover_candidates: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.evidence_silos: List[str] = []
        self.errors: List[str] = []
        self.started_at: Optional[str] = None
        self.stage_timings: Dict[str, Dict[str, Any]] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "domain": self.domain,
            "output_dir": self.output_dir,
            "subdomains": list(self.subdomains),
            "suspicious_cnames": list(self.suspicious_cnames),
            "cloud_cnames": list(self.cloud_cnames),
            "dangling": list(self.dangling),
            "still_active": list(self.still_active),
            "findings_count": len(self.findings),
            "evidence_silos": self.evidence_silos,
            "errors": self.errors,
        }


class PipelineResult:
    """
    Final result of a complete pipeline run.

    Attributes:
        domain: Target domain
        pipeline_id: Unique identifier for this pipeline run
        success: Whether the pipeline completed successfully
        findings: List of confirmed takeover findings
        summary: Statistics and summary data
        report_path: Path to generated HTML report
        archive_path: Path to generated ZIP archive
        errors: Any errors that occurred
        stages: Per-stage results for debugging/analysis
    """

    def __init__(self, domain: str, pipeline_id: str):
        self.domain = domain
        self.pipeline_id = pipeline_id
        self.success = True
        self.findings: List[Finding] = []
        self.summary: Dict[str, Any] = {}
        self.report_path: Optional[str] = None
        self.archive_path: Optional[str] = None
        self.errors: List[str] = []
        self.stages: Dict[PipelineStage, Dict[str, Any]] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "domain": self.domain,
            "pipeline_id": self.pipeline_id,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "report_path": self.report_path,
            "archive_path": self.archive_path,
            "errors": self.errors,
            "stages": {s.name: v for s, v in self.stages.items()},
        }


# =============================================================================
# Tool Paths (for reference and validation)
# =============================================================================

TOOL_PATHS = {
    # Go-based security tools
    "subfinder": "/home/azureuser/go/bin/subfinder",
    "assetfinder": "/home/azureuser/go/bin/assetfinder",
    "amass": "/usr/local/bin/amass",
    "httpx": "/home/azureuser/go/bin/httpx",
    "nuclei": "/home/azureuser/go/bin/nuclei",
    "anew": "/home/azureuser/go/bin/anew",
    # System tools
    "dig": "/usr/bin/dig",
    "nslookup": "/usr/bin/nslookup",
    "gowitness": "/usr/local/bin/gowitness",
}

# Stages that require this tool
STAGE_TOOL_REQUIREMENTS = {
    PipelineStage.STAGE1_DISCOVERY: {"subfinder", "assetfinder", "amass", "anew"},
    PipelineStage.STAGE3_FILTER: set(),
    PipelineStage.STAGE4_NXDOMAIN: {"nslookup"},
    PipelineStage.STAGE5_HTTPX: {"httpx"},
    PipelineStage.STAGE6_NUCLEI: {"nuclei"},
    PipelineStage.STAGE7_EVIDENCE: {"dig", "gowitness"},
    PipelineStage.STAGE8_REPORT: set(),
}


# =============================================================================
# Pipeline Runner
# =============================================================================

StageRunner = Callable[["PipelineContext"], Awaitable[Dict[str, Any]]]


def _get_stage_runner(stage: PipelineStage) -> StageRunner:
    """Map stage enum to actual stage module function."""
    runners = {
        PipelineStage.STAGE1_DISCOVERY: stage1_discovery.run_stage1,
        PipelineStage.STAGE3_FILTER: stage3_filter.run_stage3,
        PipelineStage.STAGE4_NXDOMAIN: stage4_nslookup.run_stage4,
        PipelineStage.STAGE5_HTTPX: stage5_httpx.run_stage5,
        PipelineStage.STAGE6_NUCLEI: stage6_nuclei.run_stage6,
        PipelineStage.STAGE7_EVIDENCE: stage7_evidence.run_stage7,
        PipelineStage.STAGE8_REPORT: stage8_report.run_stage8,
    }
    return runners.get(stage)


async def run_stage(ctx: PipelineContext, stage: PipelineStage) -> Dict[str, Any]:
    """
    Execute a single pipeline stage.

    Args:
        ctx: Pipeline context with accumulated state
        stage: Stage to execute

    Returns:
        Dict containing stage-specific results

    Raises:
        StageError: If the stage fails
    """
    logger = logging.getLogger(f"pipeline.{stage.name}")

    runner = _get_stage_runner(stage)
    if runner is None:
        raise StageError(stage, "No runner defined for this stage")

    logger.info(f"Starting {stage.display_name}")

    try:
        # Build stage-specific arguments from context
        if stage == PipelineStage.STAGE1_DISCOVERY:
            result = await runner(ctx.domain, ctx.output_dir)

        elif stage == PipelineStage.STAGE3_FILTER:
            # Stage 3 expects resolved domains set
            result = await runner(ctx.domain, ctx.output_dir, ctx.subdomains)

        elif stage == PipelineStage.STAGE4_NXDOMAIN:
            # Stage 4 expects suspicious domains set
            result = await runner(ctx.domain, ctx.output_dir, ctx.suspicious_cnames)

        elif stage == PipelineStage.STAGE5_HTTPX:
            # Stage 5 expects dangling domains set
            result = await runner(ctx.domain, ctx.output_dir, ctx.dangling)

        elif stage == PipelineStage.STAGE6_NUCLEI:
            # Stage 6 expects probed domains set
            probed_domains = {r.get("host", r.get("url", "")) for r in ctx.probed}
            result = await runner(ctx.domain, ctx.output_dir, probed_domains)

        elif stage == PipelineStage.STAGE7_EVIDENCE:
            # Stage 7 expects findings list
            result = await runner(ctx.domain, ctx.output_dir, ctx.findings)

        elif stage == PipelineStage.STAGE8_REPORT:
            # Stage 8 expects all pipeline data
            pipeline_data = {
                "pipeline_id": f"{ctx.domain}-{id(ctx)}",
                "stages": ctx.stage_timings,
                "stats": ctx.to_dict(),
            }
            result = await runner(ctx.domain, ctx.output_dir, pipeline_data)

        else:
            raise StageError(stage, f"Stage {stage.name} not implemented")

        # Update context based on stage results
        _update_context_from_result(ctx, stage, result)

        logger.info(f"Completed {stage.display_name}")
        return result

    except Exception as e:
        logger.error(f"Stage {stage.display_name} failed: {e}")
        raise StageError(stage, str(e), original_error=e) from e


def _update_context_from_result(ctx: PipelineContext, stage: PipelineStage, result: Dict[str, Any]) -> None:
    """Extract relevant data from stage results and update context."""
    if stage == PipelineStage.STAGE1_DISCOVERY:
        ctx.subdomains = set(result.get("subdomains", []))
        ctx.by_tool = result.get("by_tool", {})

    elif stage == PipelineStage.STAGE3_FILTER:
        ctx.suspicious_cnames = set(result.get("suspicious", []))
        ctx.cloud_cnames = set(result.get("cloud_watchlist_entries", []))

    elif stage == PipelineStage.STAGE4_NXDOMAIN:
        ctx.dangling = set(result.get("dangling", []))
        ctx.still_active = set(result.get("still_active", []))

    elif stage == PipelineStage.STAGE5_HTTPX:
        ctx.probed = result.get("results", [])
        ctx.takeover_candidates = result.get("takeover_candidate_results", [])

    elif stage == PipelineStage.STAGE6_NUCLEI:
        ctx.findings = result.get("findings", [])

    elif stage == PipelineStage.STAGE7_EVIDENCE:
        ctx.evidence_silos = result.get("evidence_paths", [])

    elif stage == PipelineStage.STAGE8_REPORT:
        ctx.summary = result.get("summary", {})


async def run_pipeline(
    domain: str,
    output_dir: str,
    stages: Optional[List[PipelineStage]] = None,
    notify_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
) -> PipelineResult:
    """
    Execute the complete subdomain takeover discovery pipeline.

    Args:
        domain: Target domain to analyze (e.g., "example.com")
        output_dir: Directory for all pipeline output
        stages: List of stages to run (defaults to all stages in order)
        notify_callback: Optional async function(bot_token, message) for Telegram notifications

    Returns:
        PipelineResult containing all findings and report paths

    Example::
        from pipeline import run_pipeline, PipelineStage

        result = await run_pipeline(
            "example.com",
            "/home/user/recon/example.com",
            stages=[PipelineStage.STAGE1_DISCOVERY, PipelineStage.STAGE3_FILTER],
        )

        if result.success:
            print(f"Found {len(result.findings)} vulnerabilities")
            print(f"Report: {result.report_path}")
    """
    import time
    from datetime import datetime

    # Initialize result
    pipeline_id = f"{domain}-{int(time.time())}"
    result = PipelineResult(domain, pipeline_id)
    ctx = PipelineContext(domain, output_dir)
    ctx.started_at = datetime.now().isoformat()

    logger = logging.getLogger("pipeline")
    logger.info(f"Starting pipeline for {domain} (ID: {pipeline_id})")

    # Default stages in order
    if stages is None:
        stages = [
            PipelineStage.STAGE1_DISCOVERY,
            PipelineStage.STAGE3_FILTER,
            PipelineStage.STAGE4_NXDOMAIN,
            PipelineStage.STAGE5_HTTPX,
            PipelineStage.STAGE6_NUCLEI,
            PipelineStage.STAGE7_EVIDENCE,
            PipelineStage.STAGE8_REPORT,
        ]

    # Execute each stage
    for stage in stages:
        start_time = time.time()
        ctx.stage_timings[stage.name] = {"start_time": datetime.now().isoformat()}

        try:
            stage_result = await run_stage(ctx, stage)
            elapsed = time.time() - start_time

            ctx.stage_timings[stage.name].update({
                "duration": elapsed,
                "status": "completed",
                "result": stage_result,
            })

            result.stages[stage] = stage_result

            # Send notification if callback provided
            if notify_callback:
                await notify_callback(
                    f"[{stage.display_name}] Completed in {elapsed:.1f}s - {domain}"
                )

        except StageError as e:
            elapsed = time.time() - start_time
            ctx.errors.append(str(e))
            result.errors.append(str(e))
            result.success = False

            ctx.stage_timings[stage.name].update({
                "duration": elapsed,
                "status": "failed",
                "error": str(e),
            })

            logger.error(f"Pipeline stage {stage.display_name} failed: {e}")

            # Continue to next stage or break depending on severity
            if stage in [PipelineStage.STAGE1_DISCOVERY, PipelineStage.STAGE8_REPORT]:
                # Critical stages - stop pipeline
                break

        except Exception as e:
            elapsed = time.time() - start_time
            error_msg = f"Unexpected error in {stage.display_name}: {e}"
            ctx.errors.append(error_msg)
            result.errors.append(error_msg)
            result.success = False

            ctx.stage_timings[stage.name].update({
                "duration": elapsed,
                "status": "failed",
                "error": str(e),
            })

            logger.exception(error_msg)
            break

    # Finalize results
    result.findings = [Finding.from_dict(f) for f in ctx.findings]
    result.summary = ctx.to_dict()

    # Get report paths from final stage if available
    if PipelineStage.STAGE8_REPORT in result.stages:
        stage8_result = result.stages[PipelineStage.STAGE8_REPORT]
        result.report_path = stage8_result.get("dashboard_path")
        result.archive_path = stage8_result.get("archive_path")

    logger.info(
        f"Pipeline {'completed successfully' if result.success else 'failed'} "
        f"for {domain}: {len(result.findings)} findings"
    )

    return result


# =============================================================================
# Module Information
# =============================================================================

__version__ = "1.0.0"
__author__ = "Recon Bot Team"
__description__ = "Subdomain Takeover Discovery Pipeline"