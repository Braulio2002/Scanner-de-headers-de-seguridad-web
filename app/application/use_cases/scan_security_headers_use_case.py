"""
Caso de uso principal: Escanear Headers de Seguridad.
Orquesta todo el flujo de negocio aplicando Inversión de Dependencias y Responsabilidad Única.
"""

from datetime import datetime
from typing import Any

from app.application.interfaces.http_client_interface import HttpClientInterface
from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.application.interfaces.url_reader_interface import UrlReaderInterface
from app.application.services.recommendation_service import RecommendationService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.security_header_analyzer_service import SecurityHeaderAnalyzerService
from app.application.services.url_validator_service import UrlValidatorService
from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.entities.scan_report import ScanReport
from app.domain.entities.scan_target import ScanTarget
from app.domain.value_objects.security_grade import SecurityGrade
from app.shared.logger import get_logger


class ScanSecurityHeadersUseCase:
    """
    Caso de uso que orquesta el escaneo de seguridad HTTP.
    """

    def __init__(
        self,
        url_reader: UrlReaderInterface,
        http_client: HttpClientInterface,
        excel_exporter: ReportExporterInterface,
        json_exporter: ReportExporterInterface,
        url_validator: UrlValidatorService,
        analyzer: SecurityHeaderAnalyzerService,
        score_calculator: ScoreCalculatorService,
        recommendation_service: RecommendationService,
    ):
        self._url_reader = url_reader
        self._http_client = http_client
        self._excel_exporter = excel_exporter
        self._json_exporter = json_exporter
        self._url_validator = url_validator
        self._analyzer = analyzer
        self._score_calculator = score_calculator
        self._recommendation_service = recommendation_service
        self._logger = get_logger()

    def execute(
        self,
        input_file: str,
        output_dir: str,
        base_report_name: str,
        timeout: int,
        follow_redirects: bool,
        verify_ssl: bool,
        user_agent: str,
        add_https_automatically: bool = True,
    ) -> tuple[list[ScanReport], list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Ejecuta el escaneo de cabeceras de seguridad.
        Lee URLs, las valida, realiza peticiones HTTP, analiza headers, calcula el score y exporta reportes.
        Retorna (reports, recommendations, errors).
        """
        self._logger.info(f"Leyendo URLs desde {input_file}...")
        targets: list[ScanTarget] = self._url_reader.read_urls(
            input_file, add_https_if_missing=add_https_automatically
        )

        valid_targets = [t for t in targets if t.is_valid]
        self._logger.info(
            f"URLs encontradas: {len(targets)} (Válidas para escaneo: {len(valid_targets)})"
        )

        if not valid_targets:
            self._logger.warning("No se encontraron URLs válidas para auditar.")
            return [], [], []

        reports: list[ScanReport] = []
        all_recommendations: list[dict[str, Any]] = []
        errors_log: list[dict[str, Any]] = []

        self._logger.info("Validando URLs e iniciando peticiones HTTP...")

        for target in valid_targets:
            self._logger.info(f"Analizando headers de: {target.normalized_url}")
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                # 1. Petición HTTP
                status_code, final_url, headers, error_msg = self._http_client.fetch_headers(
                    url=target.normalized_url,
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                    verify_ssl=verify_ssl,
                    user_agent=user_agent,
                )

                if error_msg:
                    # Captura de error de red/SSL de forma controlada
                    self._logger.error(
                        f"Fallo en la petición para {target.normalized_url}: {error_msg}"
                    )
                    # Para URLs con fallos, creamos resultados vacíos o con error
                    results = self._analyzer.analyze({})
                    # Enmendar resultados como FALTANTE o con error
                    report = ScanReport(
                        url=target.normalized_url,
                        final_url=target.normalized_url,
                        status_code=None,
                        headers_found={},
                        results=results,
                        score=0,
                        classification=SecurityGrade.RIESGOSO,
                        error_message=error_msg,
                        scan_date=scan_date,
                    )
                    reports.append(report)
                    errors_log.append(
                        {
                            "url": target.normalized_url,
                            "tipo_error": "ConnectionError",
                            "mensaje_error": error_msg,
                            "fecha_analisis": scan_date,
                        }
                    )
                    continue

                # 2. Analizar headers encontrados
                results: list[HeaderCheckResult] = self._analyzer.analyze(headers)
                self._logger.info(f"Headers analizados correctamente para {target.normalized_url}")

                # 3. Calcular Score de seguridad
                self._logger.info(f"Calculando score de seguridad para {target.normalized_url}...")
                score = self._score_calculator.calculate_score(results)
                grade = self._score_calculator.get_grade(score)

                # 4. Crear entidad de Reporte
                report = ScanReport(
                    url=target.normalized_url,
                    final_url=final_url,
                    status_code=status_code,
                    headers_found=headers,
                    results=results,
                    score=score,
                    classification=grade,
                    error_message=None,
                    scan_date=scan_date,
                )
                reports.append(report)

                # 5. Generar Recomendaciones
                recs = self._recommendation_service.generate_recommendations(
                    target.normalized_url, results
                )
                all_recommendations.extend(recs)

            except Exception as e:
                # Salvaguardar contra fallos catastróficos en una sola URL
                err_msg = str(e)
                self._logger.critical(
                    f"Error inesperado al auditar {target.normalized_url}: {err_msg}"
                )
                errors_log.append(
                    {
                        "url": target.normalized_url,
                        "tipo_error": "UnexpectedError",
                        "mensaje_error": err_msg,
                        "fecha_analisis": scan_date,
                    }
                )

        # Exportar reportes utilizando los adaptadores de infraestructura
        if reports:
            self._logger.info("Generando reporte Excel...")
            excel_path = self._excel_exporter.export(reports, output_dir, base_report_name)
            self._logger.info(f"Reporte Excel exportado en: {excel_path}")

            self._logger.info("Generando reporte JSON...")
            json_path = self._json_exporter.export(reports, output_dir, base_report_name)
            self._logger.info(f"Reporte JSON exportado en: {json_path}")

        self._logger.info("Proceso finalizado")
        return reports, all_recommendations, errors_log
