"""
Definición de la interfaz del cliente HTTP.
Asegura la inversión de dependencias para peticiones de red seguras.
"""

from abc import ABC, abstractmethod


class HttpClientInterface(ABC):
    """
    Interfaz abstracta para realizar peticiones HTTP de forma segura.
    """

    @abstractmethod
    def fetch_headers(
        self, url: str, timeout: int, follow_redirects: bool, verify_ssl: bool, user_agent: str
    ) -> tuple[int | None, str, dict[str, str], str | None]:
        """
        Realiza una petición HTTP segura para obtener los headers.
        Retorna una tupla: (status_code, final_url, headers_dict, error_message)
        """
        pass
