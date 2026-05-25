"""
Definición de excepciones del dominio.
Asegura que los errores de negocio estén tipados e independientes de librerías externas.
"""


class DomainException(Exception):
    """Excepción base del dominio."""

    pass


class InvalidUrlException(DomainException):
    """Se lanza cuando una URL tiene formato incorrecto o protocolo no soportado."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"URL inválida '{url}': {reason}")


class ScannerException(DomainException):
    """Excepción general en el proceso del escaneo."""

    pass
