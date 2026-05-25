"""
Definición de la interfaz del lector de URLs.
Asegura la inversión de dependencias para la lectura de orígenes de datos.
"""

from abc import ABC, abstractmethod

from app.domain.entities.scan_target import ScanTarget


class UrlReaderInterface(ABC):
    """
    Interfaz abstracta para leer URLs desde cualquier origen de persistencia (TXT, BD, API, etc.).
    """

    @abstractmethod
    def read_urls(self, source_path: str, add_https_if_missing: bool = True) -> list[ScanTarget]:
        """
        Lee y parsea las URLs de origen devolviendo una lista de entidades ScanTarget.
        """
        pass
