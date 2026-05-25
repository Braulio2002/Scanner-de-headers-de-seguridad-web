"""
Módulo de configuración de logging.
Proporciona un logger configurado para el sistema.
"""

import logging
import sys

_logger: logging.Logger | None = None


def get_logger() -> logging.Logger:
    """
    Inicializa y retorna el logger centralizado del sistema.
    """
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("security_headers_scanner")
    logger.setLevel(logging.INFO)

    # Evitar duplicación de handlers si se llama múltiples veces
    if not logger.handlers:
        # Formato claro y legible para consola
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    _logger = logger
    return _logger
