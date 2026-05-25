"""
Módulo de configuración global de la aplicación.
Agrupa variables de entorno y constantes de comportamiento por defecto.
"""

import os
from pathlib import Path
from typing import Final

# Directorio raíz del proyecto
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent.parent

# Rutas de Carpetas e Insumos
INPUT_DIR: Final[str] = os.getenv("SCANNER_INPUT_DIR", str(BASE_DIR / "datos_entrada"))
OUTPUT_DIR: Final[str] = os.getenv("SCANNER_OUTPUT_DIR", str(BASE_DIR / "datos_salida"))
URLS_FILENAME: Final[str] = os.getenv("SCANNER_URLS_FILENAME", "urls.txt")

# Configuración HTTP/Auditoría
DEFAULT_TIMEOUT_SECS: Final[int] = int(os.getenv("SCANNER_TIMEOUT", "10"))
FOLLOW_REDIRECTS: Final[bool] = os.getenv("SCANNER_FOLLOW_REDIRECTS", "True").lower() == "true"
VERIFY_SSL: Final[bool] = os.getenv("SCANNER_VERIFY_SSL", "True").lower() == "true"
USER_AGENT: Final[str] = os.getenv(
    "SCANNER_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecurityHeadersScanner/1.0 (Defensive Audit)",
)
ADD_HTTPS_AUTOMATICALLY: Final[bool] = os.getenv("SCANNER_AUTO_HTTPS", "True").lower() == "true"

# Nombres Base para Reportes
BASE_REPORT_FILENAME: Final[str] = os.getenv("SCANNER_REPORT_NAME", "security_headers_report")
