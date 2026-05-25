"""
Servicio de validación y normalización de URLs.
Asegura que el scanner solo procese URLs con formatos y protocolos válidos de manera segura.
"""

import re
from urllib.parse import urlparse


class UrlValidatorService:
    """
    Servicio encargado de auditar y estructurar las URLs ingresadas por el usuario.
    """

    # Expresión regular robusta para validar URLs web estándar
    _URL_REGEX = re.compile(
        r"^https?://"  # http:// o https://
        # dominio...
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...o IP
        r"(?::\d+)?"  # puerto opcional
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    def validate_format(self, url: str) -> bool:
        """
        Valida si el string cumple con la estructura general de una URL.
        """
        if not url:
            return False
        return bool(self._URL_REGEX.match(url))

    def is_http_or_https(self, url: str) -> bool:
        """
        Verifica que el protocolo de la URL sea estrictamente http o https.
        """
        try:
            parsed = urlparse(url)
            return parsed.scheme.lower() in ("http", "https")
        except Exception:
            return False

    def normalize(self, url: str, add_https: bool = True) -> str:
        """
        Normaliza una URL limpiando espacios.
        Si no tiene esquema y add_https es True, añade 'https://' por defecto.
        """
        url = url.strip()
        if not url:
            return ""

        # Si no tiene esquema (por ejemplo: google.com o www.google.com)
        if not url.startswith(("http://", "https://")):
            if add_https:
                url = f"https://{url}"
            else:
                url = f"http://{url}"

        return url
