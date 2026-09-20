from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    rule: str
    file: str
    line: int
    message: str
    confidence: float
    remediation: str
    category: str = "general"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
