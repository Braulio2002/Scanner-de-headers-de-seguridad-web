"""
Servicio encargado del cálculo del score de seguridad web (0-100)
y asignación de la clasificación final (EXCELENTE, BUENO, REGULAR, RIESGOSO).
"""

from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.header_status import HeaderStatus
from app.domain.value_objects.security_grade import SecurityGrade
from app.shared.constants import HEADER_SET_COOKIE, SCORING_WEIGHTS


class ScoreCalculatorService:
    """
    Servicio de dominio para computar las puntuaciones de seguridad de forma justa e inteligente.
    """

    def calculate_score(self, results: list[HeaderCheckResult]) -> int:
        """
        Calcula un score de 0 a 100 basado en los resultados individuales de cada cabecera.
        """
        score = 0

        for result in results:
            header_name = result.header_name
            # Si el header no tiene un peso configurado, lo ignoramos para la puntuación (ej: Cache-Control)
            if header_name not in SCORING_WEIGHTS:
                continue

            weight = SCORING_WEIGHTS[header_name]

            # Si es Set-Cookie y no está presente pero el estado es CORRECTO (no se detectaron cookies),
            # le otorgamos el puntaje total ya que no hay cookies que securizar.
            if header_name == HEADER_SET_COOKIE and not result.present:
                if result.status == HeaderStatus.CORRECTO:
                    score += weight
                continue

            # Reglas de asignación de puntos según el estado
            if result.status == HeaderStatus.CORRECTO:
                score += weight
            elif result.status == HeaderStatus.PRESENTE:
                # Si está presente pero no es 100% restrictivo
                score += int(weight * 0.7)
            elif result.status == HeaderStatus.DEBIL:
                # Si está presente pero contiene fallos o debilidades críticas
                score += int(weight * 0.3)
            # FALTANTE o ERROR sumarán 0 puntos

        # Asegurar que el score no exceda 100 ni sea menor a 0
        return max(0, min(100, score))

    def get_grade(self, score: int) -> SecurityGrade:
        """
        Retorna la clasificación cualitativa basada en el score.
        """
        return SecurityGrade.from_score(score)
