"""
Entidad ScanReport.
Representa el reporte completo del análisis de un sitio web.
"""

from dataclasses import dataclass

from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.security_grade import SecurityGrade


@dataclass(frozen=True)
class ScanReport:
    url: str
    final_url: str
    status_code: int | None
    headers_found: dict[str, str]
    results: list[HeaderCheckResult]
    score: int
    classification: SecurityGrade
    error_message: str | None
    scan_date: str
