"""Static analyzer and OWASP rule engine.

Rules are plain data (see ``security/rules.json``). Only three check types are
supported and none of them executes anything from the rule file:

* ``regex_finding``  - a match is a FINDING. No match is NOT_VERIFIED, because
  a missing suspicious pattern does not prove the project is secure.
* ``regex_required`` - a match is evidence of an expected control (PASSED). No
  match in the in-scope files is a FINDING.
* ``manual``         - always NOT_VERIFIED.

Disabled rules are always NOT_VERIFIED.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional, Sequence

from pydantic import ValidationError

from app.config import RULES_PATH
from app.schemas import Counts, Finding, RuleDefinition, RuleSet
from app.services.zip_inspector import SourceFile

logger = logging.getLogger("owasp_mentor.scanner")

MAX_LINE_LENGTH = 2000
MAX_EVIDENCE_LENGTH = 200

_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    ((?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)["']?\s*[:=]\s*)
    (["'])(.{3,}?)\2
    """
)


class RuleConfigError(Exception):
    """The rules file is missing or invalid."""


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    counts: Counts = field(default_factory=lambda: Counts(passed=0, failed=0, not_verified=0))


def load_ruleset(path: Optional[Path] = None) -> RuleSet:
    rules_path = path or RULES_PATH
    try:
        raw = json.loads(rules_path.read_text(encoding="utf-8"))
        return RuleSet.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        logger.error("Rules file could not be loaded (%s).", type(exc).__name__)
        raise RuleConfigError("The rules file is missing or invalid.") from exc


@lru_cache(maxsize=1)
def get_ruleset() -> RuleSet:
    return load_ruleset()


def redact(line: str) -> str:
    """Trim a source line to short evidence and mask obvious secret values."""
    text = line.strip()[:MAX_EVIDENCE_LENGTH * 2]
    text = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}***REDACTED***{m.group(2)}", text)
    if len(text) > MAX_EVIDENCE_LENGTH:
        text = text[:MAX_EVIDENCE_LENGTH] + "..."
    return text


def _in_scope(path: str, extensions: Sequence[str]) -> bool:
    if not extensions:
        return True
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in extensions)


def _find_matches(rx: re.Pattern[str], files: Sequence[SourceFile], limit: int) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for source in files:
        for line_no, line in enumerate(source.text.splitlines(), start=1):
            if rx.search(line[:MAX_LINE_LENGTH]):
                hits.append((source.path, line_no, redact(line)))
                if len(hits) >= limit:
                    return hits
    return hits


def _result(rule: RuleDefinition, status: str, explanation: str, **extra: object) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        status=status,  # type: ignore[arg-type]
        severity=rule.severity,
        explanation=explanation,
        recommendation=rule.recommendation,
        explanation_source="static",
        **extra,  # type: ignore[arg-type]
    )


def _evaluate_rule(rule: RuleDefinition, files: Sequence[SourceFile], max_per_rule: int) -> list[Finding]:
    if not rule.enabled:
        return [_result(rule, "NOT_VERIFIED", "Not verified: this requirement is disabled, so no automatic check was run.")]
    if rule.check_type == "manual":
        return [_result(rule, "NOT_VERIFIED", "Not verified: no automatic check exists for this requirement. It needs a manual review.")]

    scope = [f for f in files if _in_scope(f.path, rule.extensions)]
    if not scope:
        return [_result(rule, "NOT_VERIFIED", "Not verified: no scanned files matched the file types for this check.")]

    rx = re.compile(rule.pattern)

    if rule.check_type == "regex_finding":
        hits = _find_matches(rx, scope, max_per_rule)
        if hits:
            return [
                _result(rule, "FINDING", rule.description, file=path, line=line, evidence=evidence)
                for path, line, evidence in hits
            ]
        return [
            _result(
                rule,
                "NOT_VERIFIED",
                f"No matching pattern was found in {len(scope)} scanned file(s). "
                "A missing pattern does not prove the requirement is met, so it stays unverified.",
            )
        ]

    # regex_required
    hits = _find_matches(rx, scope, 1)
    if hits:
        path, line, evidence = hits[0]
        return [
            _result(
                rule,
                "PASSED",
                "Evidence of the expected control was detected. This is supporting evidence from a pattern check, not proof of full compliance.",
                file=path,
                line=line,
                evidence=evidence,
            )
        ]
    return [
        _result(
            rule,
            "FINDING",
            f"No evidence of the expected control was found in {len(scope)} scanned file(s). {rule.description}",
        )
    ]


def analyze(files: Sequence[SourceFile], ruleset: RuleSet, max_findings_per_rule: int = 10) -> AnalysisResult:
    """Run every configured rule. Counts are per rule and always sum to len(rules)."""
    result = AnalysisResult()
    passed = failed = not_verified = 0

    for rule in ruleset.rules:
        entries = _evaluate_rule(rule, files, max_findings_per_rule)
        result.findings.extend(entries)
        statuses = {e.status for e in entries}
        if "FINDING" in statuses:
            failed += 1
        elif "PASSED" in statuses:
            passed += 1
        else:
            not_verified += 1

    result.counts = Counts(passed=passed, failed=failed, not_verified=not_verified)
    return result
