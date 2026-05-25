"""
Módulo de utilidades para nombres de archivos.
Evita la sobreescritura de reportes existentes mediante sufijos incrementales.
"""

from pathlib import Path


def get_unique_filename(directory: Path, base_name: str, extension: str) -> Path:
    """
    Genera un Path único en el directorio especificado.
    Si 'base_name.extension' ya existe, añade un sufijo numérico (_1, _2, etc.).
    """
    # Limpiar extensión de puntos al inicio si existen
    ext = extension.lstrip(".")

    # Intentar el nombre base original
    target_path = directory / f"{base_name}.{ext}"
    if not target_path.exists():
        return target_path

    # Buscar sufijo incremental
    counter = 1
    while True:
        target_path = directory / f"{base_name}_{counter}.{ext}"
        if not target_path.exists():
            return target_path
        counter += 1
