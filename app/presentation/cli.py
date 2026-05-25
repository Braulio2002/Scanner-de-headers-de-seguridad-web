"""
Capa de Presentación: Consola/CLI.
Muestra de forma amigable e interactiva el progreso del análisis y el resumen ejecutivo final.
"""

import sys
from pathlib import Path

from app.application.services.recommendation_service import RecommendationService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.security_header_analyzer_service import SecurityHeaderAnalyzerService
from app.application.services.url_validator_service import UrlValidatorService
from app.application.use_cases.scan_security_headers_use_case import ScanSecurityHeadersUseCase
from app.config import settings
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter

# Importación de Componentes e Inversión de Dependencias
from app.infrastructure.filesystem.directory_manager import DirectoryManager
from app.infrastructure.http.requests_http_client import RequestsHttpClient
from app.infrastructure.readers.txt_url_reader import TxtUrlReader
from app.shared.logger import get_logger


class SecurityHeadersScannerCLI:
    """
    Controlador de la consola del Scanner de Headers de Seguridad.
    """

    def __init__(self):
        self._logger = get_logger()

    def run(self) -> None:
        """
        Punto de entrada de la CLI. Prepara directorios, ejecuta orquestador de negocio y resume hallazgos.
        """
        print("=" * 80)
        print("  WEB SECURITY HEADERS SCANNER - AUDITORÍA DE SEGURIDAD PASIVA (OWASP)")
        print("=" * 80)

        # 1. Preparar directorios de forma controlada
        dir_manager = DirectoryManager()
        dir_manager.prepare_directories(
            input_dir_path=settings.INPUT_DIR,
            output_dir_path=settings.OUTPUT_DIR,
            default_filename=settings.URLS_FILENAME,
        )

        input_file = Path(settings.INPUT_DIR) / settings.URLS_FILENAME

        # 2. Inicialización de dependencias (Clean Architecture Core)
        url_validator = UrlValidatorService()
        url_reader = TxtUrlReader(url_validator)
        http_client = RequestsHttpClient()

        recs_service = RecommendationService()
        excel_exporter = ExcelReportExporter(recs_service)
        json_exporter = JsonReportExporter()

        analyzer = SecurityHeaderAnalyzerService()
        score_calculator = ScoreCalculatorService()

        use_case = ScanSecurityHeadersUseCase(
            url_reader=url_reader,
            http_client=http_client,
            excel_exporter=excel_exporter,
            json_exporter=json_exporter,
            url_validator=url_validator,
            analyzer=analyzer,
            score_calculator=score_calculator,
            recommendation_service=recs_service,
        )

        # 3. Ejecutar caso de uso principal
        reports, recommendations, errors = use_case.execute(
            input_file=str(input_file.absolute()),
            output_dir=settings.OUTPUT_DIR,
            base_report_name=settings.BASE_REPORT_FILENAME,
            timeout=settings.DEFAULT_TIMEOUT_SECS,
            follow_redirects=settings.FOLLOW_REDIRECTS,
            verify_ssl=settings.VERIFY_SSL,
            user_agent=settings.USER_AGENT,
            add_https_automatically=settings.ADD_HTTPS_AUTOMATICALLY,
        )

        # 4. Mostrar Resumen de Métricas Ejecutivas en Consola
        if reports:
            print("\n" + "=" * 80)
            print("  RESUMEN DE AUDITORÍA EJECUTIVA")
            print("=" * 80)
            print(f"Total sitios analizados: {len(reports)}")
            print(f"Total recomendaciones generadas: {len(recommendations)}")
            print(f"Total fallos de conexión / caídas: {len(errors)}")
            print("-" * 80)

            # Clasificaciones encontradas
            grade_counts = {}
            total_scores = 0
            scanned_count = 0

            for r in reports:
                if r.error_message is None:
                    total_scores += r.score
                    scanned_count += 1
                grade = r.classification.value
                grade_counts[grade] = grade_counts.get(grade, 0) + 1

            promedio = int(total_scores / scanned_count) if scanned_count > 0 else 0
            print(f"Puntuación promedio de sitios exitosos: {promedio}/100")
            print("Distribución de clasificaciones:")
            for g, count in grade_counts.items():
                print(f"  - [{g}]: {count} sitios")

            print("-" * 80)
            print(f"Reportes de auditoría listos en la carpeta: {settings.OUTPUT_DIR}")
            print(f"  1. Excel (4 Hojas): {settings.BASE_REPORT_FILENAME}.xlsx")
            print(f"  2. JSON (Detalles completos): {settings.BASE_REPORT_FILENAME}.json")
            print("=" * 80)
        else:
            self._logger.warning(
                "El escaneo finalizó sin generar reportes válidos (valide urls.txt)."
            )
            sys.exit(1)
