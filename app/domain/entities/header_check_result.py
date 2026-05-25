"""
Entidad HeaderCheckResult.
Representa el resultado individual del análisis de un header.
"""

from dataclasses import dataclass

from app.domain.value_objects.header_status import HeaderStatus


@dataclass(frozen=True)
class HeaderCheckResult:
    header_name: str
    present: bool
    value: str
    status: HeaderStatus
    severity: str
    recommendation: str
