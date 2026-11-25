"""Pydantic models for rules, reports and API responses."""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CheckType = Literal["regex_finding", "regex_required", "manual"]
Status = Literal["PASSED", "FINDING", "NOT_VERIFIED"]
ExplanationSource = Literal["static", "ai", "fallback"]

MAX_PATTERN_LENGTH = 500


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
class RuleDefinition(BaseModel):
    """One requirement. Rules are data only and are never executed as code."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(max_length=1000)
    severity: Severity
    enabled: bool
    check_type: CheckType
    extensions: list[str] = Field(default_factory=list, max_length=30)
    pattern: str = Field(default="", max_length=MAX_PATTERN_LENGTH)
    recommendation: str = Field(max_length=1000)

    @field_validator("extensions")
    @classmethod
    def _normalise_extensions(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for ext in value:
            ext = ext.strip().lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,10}", ext):
                raise ValueError("extensions must look like '.js'")
            cleaned.append(ext)
        return cleaned

    @model_validator(mode="after")
    def _check_pattern(self) -> "RuleDefinition":
        if self.check_type in ("regex_finding", "regex_required") and self.enabled:
            if not self.pattern:
                raise ValueError("enabled regex rules need a pattern")
        if self.pattern:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from exc
        return self


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    official_list_verified: bool = False
    notice: str = ""
    rules: list[RuleDefinition]

    @model_validator(mode="after")
    def _unique_ids(self) -> "RuleSet":
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        if not ids:
            raise ValueError("at least one rule is required")
        return self


class RulesResponse(BaseModel):
    official_list_verified: bool
    notice: str
    count: int
    rules: list[RuleDefinition]


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
class Counts(BaseModel):
    passed: int
    failed: int
    not_verified: int


class Finding(BaseModel):
    rule_id: str
    title: str
    status: Status
    severity: Severity
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    explanation: str
    recommendation: str
    # Extra, optional fields (additive to the agreed contract).
    explanation_source: ExplanationSource = "static"
    why_it_matters: Optional[str] = None
    safer_practice: Optional[str] = None
    secure_example: Optional[str] = None


class AIUsage(BaseModel):
    provider: str
    model: str
    available: bool
    explanations_ai: int = 0
    explanations_fallback: int = 0


class ScanStats(BaseModel):
    files_scanned: int
    files_skipped: int
    source_truncated: bool


class ScanReport(BaseModel):
    scan_id: str
    filename: str
    overall_status: str
    counts: Counts
    findings: list[Finding]
    # Extra, optional fields (additive to the agreed contract).
    verification_complete: bool = False
    official_rules_verified: bool = False
    disclaimer: str = (
        "Automated, limited static check. This is not a complete security audit and "
        "does not prove the project is secure or compliant."
    )
    ai: Optional[AIUsage] = None
    stats: Optional[ScanStats] = None


class ScanSummary(BaseModel):
    scan_id: str
    filename: str
    overall_status: str
    counts: Optional[Counts] = None
    created_at: Optional[str] = None


# --------------------------------------------------------------------------
# Misc responses
# --------------------------------------------------------------------------
class AIStatus(BaseModel):
    provider: str
    model: str
    available: bool
    detail: Literal[
        "ready",
        "disabled",
        "unreachable",
        "model_not_found",
        "unsupported_provider",
        "non_local_url",
    ] = "ready"


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "owasp-mentor-ai"
