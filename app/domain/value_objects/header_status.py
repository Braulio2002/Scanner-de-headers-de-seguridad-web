"""
Value Object representativo del estado de un header analizado.
"""

from enum import Enum


class HeaderStatus(Enum):
    PRESENTE = "PRESENTE"
    FALTANTE = "FALTANTE"
    DEBIL = "DEBIL"
    CORRECTO = "CORRECTO"
    ERROR = "ERROR"
