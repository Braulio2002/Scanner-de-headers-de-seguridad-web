"""
Módulo de constantes del sistema.
Define los nombres de headers, pesos de scoring y severidades.
"""

from typing import Final

# Nombres de los Headers de Seguridad HTTP
HEADER_CSP: Final[str] = "Content-Security-Policy"
HEADER_HSTS: Final[str] = "Strict-Transport-Security"
HEADER_X_FRAME: Final[str] = "X-Frame-Options"
HEADER_X_CONTENT_TYPE: Final[str] = "X-Content-Type-Options"
HEADER_REFERRER_POLICY: Final[str] = "Referrer-Policy"
HEADER_PERMISSIONS_POLICY: Final[str] = "Permissions-Policy"
HEADER_COOP: Final[str] = "Cross-Origin-Opener-Policy"
HEADER_CORP: Final[str] = "Cross-Origin-Resource-Policy"
HEADER_COEP: Final[str] = "Cross-Origin-Embedder-Policy"
HEADER_CACHE_CONTROL: Final[str] = "Cache-Control"
HEADER_SET_COOKIE: Final[str] = "Set-Cookie"

# Pesos para el Scoring (Total: 100 puntos)
SCORING_WEIGHTS: Final[dict[str, int]] = {
    HEADER_CSP: 20,
    HEADER_HSTS: 15,
    HEADER_X_FRAME: 10,
    HEADER_X_CONTENT_TYPE: 10,
    HEADER_REFERRER_POLICY: 10,
    HEADER_PERMISSIONS_POLICY: 10,
    HEADER_COOP: 5,
    HEADER_CORP: 5,
    HEADER_COEP: 5,
    HEADER_SET_COOKIE: 10,
}

# Severidades de Recomendaciones
SEVERITY_HIGH: Final[str] = "ALTA"
SEVERITY_MEDIUM: Final[str] = "MEDIA"
SEVERITY_LOW: Final[str] = "BAJA"
SEVERITY_INFO: Final[str] = "INFO"
