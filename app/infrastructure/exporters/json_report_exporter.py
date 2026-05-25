"""
Exportador de reportes en formato JSON (.json).
Estructura y serializa la auditoría técnica completa permitiendo su integración con sistemas externos (APIs, SIEM, etc.).
"""

import json
from pathlib import Path

from app.application.interfaces.report_exporter_interface import ReportExporterInterface
from app.domain.entities.scan_report import ScanReport
from app.shared.filename_utils import get_unique_filename


class JsonReportExporter(ReportExporterInterface):
    """
    Exportador JSON para serialización técnica completa.
    """

    def export(self, reports: list[ScanReport], output_dir: str, base_filename: str) -> str:
        """
        Exporta una lista de reportes en un formato JSON estructurado con sangría.
        """
        output_path = Path(output_dir)
        output_file = get_unique_filename(output_path, base_filename, "json")

        serializable_reports = []
        for r in reports:
            results_list = []
            for res in r.results:
                results_list.append(
                    {
                        "header_name": res.header_name,
                        "present": res.present,
                        "value": res.value,
                        "status": res.status.value,
                        "severity": res.severity,
                        "recommendation": res.recommendation,
                    }
                )

            serializable_reports.append(
                {
                    "url": r.url,
                    "final_url": r.final_url,
                    "status_code": r.status_code,
                    "score": r.score,
                    "classification": r.classification.value,
                    "error_message": r.error_message,
                    "scan_date": r.scan_date,
                    "results": results_list,
                }
            )

        # Serialización con identación limpia de 4 espacios
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(serializable_reports, f, indent=4, ensure_ascii=False)

        return str(output_file.absolute())
