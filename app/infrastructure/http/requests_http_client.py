"""
Implementación del cliente HTTP usando la librería 'requests'.
Realiza peticiones seguras e identifica cabeceras de forma rápida y controlada.
"""

import requests
from requests.exceptions import RequestException, SSLError, Timeout

from app.application.interfaces.http_client_interface import HttpClientInterface


class RequestsHttpClient(HttpClientInterface):
    """
    Cliente HTTP seguro basado en requests.
    """

    def fetch_headers(
        self, url: str, timeout: int, follow_redirects: bool, verify_ssl: bool, user_agent: str
    ) -> tuple[int | None, str, dict[str, str], str | None]:
        """
        Ejecuta una petición GET con stream=True para capturar los headers eficientemente.
        """
        headers_config = {"User-Agent": user_agent}

        try:
            # Usar stream=True para descargar solo las cabeceras y evitar el cuerpo HTML pesado
            response = requests.get(
                url,
                headers=headers_config,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=verify_ssl,
                stream=True,
            )

            # Extraer headers y cerrar la conexión sin leer el cuerpo
            headers_dict = dict(response.headers)
            status_code = response.status_code
            final_url = response.url
            response.close()

            return status_code, final_url, headers_dict, None

        except SSLError as e:
            # Captura de error SSL explícita
            return None, url, {}, f"Error de SSL/TLS: {e}"
        except Timeout as e:
            # Captura de Timeout explícita
            return None, url, {}, f"Exceso de tiempo límite (Timeout después de {timeout}s): {e}"
        except RequestException as e:
            # Captura de otros errores de red/conexión
            return None, url, {}, f"Error de Conexión: {e}"
        except Exception as e:
            # Captura genérica de resguardo
            return None, url, {}, f"Fallo al contactar el servidor: {e}"
