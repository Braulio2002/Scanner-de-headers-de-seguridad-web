"""
Entidad ScanTarget.
Representa un objetivo de escaneo (una URL).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTarget:
    raw_url: str
    normalized_url: str
    is_valid: bool
