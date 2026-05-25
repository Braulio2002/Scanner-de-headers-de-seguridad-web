"""
Implementación del lector de URLs desde archivos de texto plano (.txt).
Filtra comentarios, líneas en blanco, limpia duplicados y estructura la lista de objetivos.
"""

from pathlib import Path

from app.application.interfaces.url_reader_interface import UrlReaderInterface
from app.application.services.url_validator_service import UrlValidatorService
from app.domain.entities.scan_target import ScanTarget


class TxtUrlReader(UrlReaderInterface):
    """
    Lector de URLs para archivos .txt.
    """

    def __init__(self, url_validator: UrlValidatorService | None = None):
        self._validator = url_validator or UrlValidatorService()

    def read_urls(self, source_path: str, add_https_if_missing: bool = True) -> list[ScanTarget]:
        """
        Lee el archivo de URLs de texto, filtra comentarios y normaliza las URLs.
        """
        file_path = Path(source_path)
        if not file_path.exists():
            return []

        unique_lines = []
        seen = set()

        with open(file_path, encoding="utf-8") as f:
            for line in f:
                clean_line = line.strip()
                # Ignorar comentarios y líneas vacías
                if not clean_line or clean_line.startswith("#"):
                    continue

                if clean_line not in seen:
                    seen.add(clean_line)
                    unique_lines.append(clean_line)

        targets: list[ScanTarget] = []
        for line in unique_lines:
            # Normalizar URL (agregar https:// o http:// según aplique)
            normalized = self._validator.normalize(line, add_https=add_https_if_missing)
            # Validar formato global
            is_valid = self._validator.validate_format(
                normalized
            ) and self._validator.is_http_or_https(normalized)

            targets.append(ScanTarget(raw_url=line, normalized_url=normalized, is_valid=is_valid))

        return targets
