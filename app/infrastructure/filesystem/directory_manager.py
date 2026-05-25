"""
Gestor de directorios y archivos de sistema.
Crea la estructura de carpetas inicial y genera plantillas por defecto si no existen.
"""

from pathlib import Path

from app.shared.logger import get_logger


class DirectoryManager:
    """
    Clase encargada de preparar el entorno local del sistema de archivos.
    """

    def __init__(self):
        self._logger = get_logger()

    def prepare_directories(
        self, input_dir_path: str, output_dir_path: str, default_filename: str
    ) -> None:
        """
        Crea los directorios de entrada/salida y crea urls.txt de plantilla si está ausente.
        """
        input_path = Path(input_dir_path)
        output_path = Path(output_dir_path)

        # Crear carpeta de entrada si no existe
        if not input_path.exists():
            self._logger.info(f"Creando carpeta {input_dir_path} si no existe...")
            input_path.mkdir(parents=True, exist_ok=True)

        # Crear carpeta de salida si no existe
        if not output_path.exists():
            self._logger.info(f"Creando carpeta {output_dir_path} si no existe...")
            output_path.mkdir(parents=True, exist_ok=True)

        # Crear urls.txt con ejemplos si no existe
        urls_file = input_path / default_filename
        if not urls_file.exists():
            self._logger.warning(
                f"Archivo '{default_filename}' no encontrado. Creando con ejemplos..."
            )
            sample_content = (
                "# Scanner de Headers de Seguridad Web - Lista de URLs\n"
                "# Agregue las URLs que desea auditar de manera defensiva.\n"
                "# Líneas que inician con '#' son comentarios e ignoradas.\n\n"
                "# Sitios de producción o ejemplo\n"
                "https://example.com\n"
                "https://httpbin.org\n\n"
                "# Sitios de ejemplo sin protocolo (se autocompletará https:// si está configurado)\n"
                "owasp.org\n"
            )
            with open(urls_file, "w", encoding="utf-8") as f:
                f.write(sample_content)
            self._logger.info(f"Archivo de ejemplo creado exitosamente en {urls_file.absolute()}")
