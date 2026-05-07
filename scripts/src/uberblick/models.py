from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    title: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None
    audit_packs: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PathHop:
    kind: str
    name: str
    detail: str | None = None


@dataclass
class GrantPath:
    source: str
    source_kind: str
    destination: str
    destination_kind: str
    privilege: str
    hops: list[PathHop]
    role_chain_depth: int

    def render(self) -> str:
        parts = [f"{self.source_kind}:{self.source}"]
        for hop in self.hops:
            label = hop.kind
            if hop.detail:
                label = f"{hop.kind}:{hop.detail}"
            parts.append(f"--({label})-->")
            parts.append(hop.name)
        return " ".join(parts)
