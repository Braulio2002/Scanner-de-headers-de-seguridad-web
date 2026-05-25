"""
Tests de integración para el flujo completo del Scanner de Headers de Seguridad.
Simula la lectura, auditoría y exportación de archivos sin realizar peticiones de red reales.
"""

from app.application.interfaces.http_client_interface import HttpClientInterface
from app.application.interfaces.url_reader_interface import UrlReaderInterface
from app.application.services.recommendation_service import RecommendationService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.security_header_analyzer_service import SecurityHeaderAnalyzerService
from app.application.services.url_validator_service import UrlValidatorService
from app.application.use_cases.scan_security_headers_use_case import ScanSecurityHeadersUseCase
from app.domain.entities.scan_target import ScanTarget
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter
from app.shared.constants import HEADER_CSP, HEADER_HSTS


# Mock de Lectores e interfaces de red
class MockUrlReader(UrlReaderInterface):
    def read_urls(self, source_path: str, add_https_if_missing: bool = True) -> list[ScanTarget]:
        return [
            ScanTarget("example.com", "https://example.com", is_valid=True),
            ScanTarget("invalid-target", "https://invalid-target", is_valid=False),
        ]


class MockHttpClient(HttpClientInterface):
    def fetch_headers(
        self, url: str, timeout: int, follow_redirects: bool, verify_ssl: bool, user_agent: str
    ) -> tuple[int | None, str, dict[str, str], str | None]:
        if "example.com" in url:
            mock_headers = {
                "Server": "nginx",
                HEADER_CSP: "default-src 'self'",
                HEADER_HSTS: "max-age=31536000; includeSubDomains; preload",
            }
            return 200, "https://example.com", mock_headers, None
        return None, url, {}, "Fallo de conexión simulado"


def test_integration_flow(tmp_path):
    # Definición de directorios de pruebas
    input_file = tmp_path / "urls.txt"
    output_dir = tmp_path / "datos_salida"
    output_dir.mkdir()

    # Cableado de dependencias con Mocks y servicios reales
    url_validator = UrlValidatorService()
    url_reader = MockUrlReader()
    http_client = MockHttpClient()

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

    # Ejecución
    reports, _, _ = use_case.execute(
        input_file=str(input_file),
        output_dir=str(output_dir),
        base_report_name="test_report",
        timeout=5,
        follow_redirects=True,
        verify_ssl=True,
        user_agent="TestAgent",
    )

    # Verificaciones básicas
    assert len(reports) == 1
    assert reports[0].url == "https://example.com"
    assert reports[0].status_code == 200
    assert len(reports[0].results) > 0

    # Comprobación de que los reportes de salida se crearon exitosamente
    excel_files = list(output_dir.glob("*.xlsx"))
    json_files = list(output_dir.glob("*.json"))

    assert len(excel_files) == 1
    assert len(json_files) == 1

    assert excel_files[0].exists()
    assert json_files[0].exists()
