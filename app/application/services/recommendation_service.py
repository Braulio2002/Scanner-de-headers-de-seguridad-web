"""
Servicio encargado de consolidar y priorizar las recomendaciones de seguridad.
Asegura que el reporte final guíe claramente al administrador en la remediación.
"""

from typing import Any

from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.header_status import HeaderStatus
from app.shared.constants import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM


class RecommendationService:
    """
    Servicio de aplicación para ordenar y priorizar recomendaciones de remediación.
    """

    def generate_recommendations(
        self, url: str, results: list[HeaderCheckResult]
    ) -> list[dict[str, Any]]:
        """
        Extrae y prioriza los hallazgos de un reporte de análisis de headers.
        Retorna una lista de diccionarios listos para los reportes de salida.
        """
        recommendations = []

        for res in results:
            # Solo generamos recomendaciones para headers ausentes, débiles o con errores
            if res.status in (HeaderStatus.FALTANTE, HeaderStatus.DEBIL, HeaderStatus.ERROR):
                # Determinar prioridad en base a la severidad
                priority_map = {SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3}
                priority_num = priority_map.get(res.severity, 4)

                # Definir una descripción legible del problema
                if res.status == HeaderStatus.FALTANTE:
                    problem = "Header de seguridad ausente"
                elif res.status == HeaderStatus.DEBIL:
                    problem = "Configuración débil o insegura detectada"
                else:
                    problem = "Error al intentar leer o procesar la cabecera"

                recommendations.append(
                    {
                        "url": url,
                        "prioridad": res.severity,
                        "priority_num": priority_num,
                        "header": res.header_name,
                        "problema": problem,
                        "recomendación": res.recommendation,
                    }
                )

        # Ordenar recomendaciones: alta prioridad primero
        recommendations.sort(key=lambda x: x["priority_num"])

        # Quitar la clave auxiliar antes de retornar
        for rec in recommendations:
            rec.pop("priority_num", None)

        return recommendations
