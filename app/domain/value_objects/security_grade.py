"""
Value Object representativo de la clasificación de seguridad.
"""

from enum import Enum


class SecurityGrade(Enum):
    EXCELENTE = "Excelente"
    BUENO = "Bueno"
    REGULAR = "Regular"
    RIESGOSO = "Riesgoso"

    @classmethod
    def from_score(cls, score: int) -> "SecurityGrade":
        """
        Retorna la clasificación correspondiente según el score numérico (0-100).
        """
        if score >= 90:
            return cls.EXCELENTE
        elif score >= 75:
            return cls.BUENO
        elif score >= 50:
            return cls.REGULAR
        else:
            return cls.RIESGOSO
