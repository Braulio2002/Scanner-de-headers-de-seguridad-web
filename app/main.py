"""
Punto de Entrada del Sistema (Main).
Inicializa la aplicación y cede el control a la capa de presentación CLI.
"""

from app.presentation.cli import SecurityHeadersScannerCLI


def main() -> None:
    """
    Función principal para inicializar la herramienta.
    """
    scanner_cli = SecurityHeadersScannerCLI()
    scanner_cli.run()


if __name__ == "__main__":
    main()
