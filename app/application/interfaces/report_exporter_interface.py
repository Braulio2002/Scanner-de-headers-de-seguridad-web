"""
Definición de la interfaz de exportación de reportes.
Permite añadir nuevos formatos de exportación en el futuro sin modificar los casos de uso.
"""

from abc import ABC, abstractmethod

from app.domain.entities.scan_report import ScanReport


class ReportExporterInterface(ABC):
    """
    Interfaz abstracta para exportar los reportes generados a formatos como Excel, JSON, etc.
    """

    @abstractmethod
    def export(self, reports: list[ScanReport], output_dir: str, base_filename: str) -> str:
        """
        Exporta una lista de reportes al directorio especificado.
        Retorna la ruta completa del archivo generado.
        """
        pass
