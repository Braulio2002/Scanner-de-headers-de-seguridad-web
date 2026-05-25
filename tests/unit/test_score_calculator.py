"""
Tests unitarios para el calculador de score y clasificación.
"""

import pytest

from app.application.services.score_calculator_service import ScoreCalculatorService
from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.header_status import HeaderStatus
from app.domain.value_objects.security_grade import SecurityGrade
from app.shared.constants import (
    HEADER_COEP,
    HEADER_COOP,
    HEADER_CORP,
    HEADER_CSP,
    HEADER_HSTS,
    HEADER_PERMISSIONS_POLICY,
    HEADER_REFERRER_POLICY,
    HEADER_SET_COOKIE,
    HEADER_X_CONTENT_TYPE,
    HEADER_X_FRAME,
    SEVERITY_HIGH,
    SEVERITY_INFO,
)


@pytest.fixture
def calculator():
    return ScoreCalculatorService()


def test_calculate_score_perfect(calculator):
    # Configuración completa y correcta
    results = [
        HeaderCheckResult(HEADER_CSP, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        HeaderCheckResult(HEADER_HSTS, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        HeaderCheckResult(HEADER_X_FRAME, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        HeaderCheckResult(
            HEADER_X_CONTENT_TYPE, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),
        HeaderCheckResult(
            HEADER_REFERRER_POLICY, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),
        HeaderCheckResult(
            HEADER_PERMISSIONS_POLICY, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),
        HeaderCheckResult(HEADER_COOP, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        HeaderCheckResult(HEADER_CORP, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        HeaderCheckResult(HEADER_COEP, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
        # No se detectaron cookies, le da 10 puntos (correcto)
        HeaderCheckResult(HEADER_SET_COOKIE, False, "", HeaderStatus.CORRECTO, SEVERITY_INFO, ""),
    ]

    score = calculator.calculate_score(results)
    assert score == 100
    assert calculator.get_grade(score) == SecurityGrade.EXCELENTE


def test_calculate_score_partial_and_weak(calculator):
    # Algunos faltan y otros son débiles
    results = [
        HeaderCheckResult(
            HEADER_CSP, True, "...", HeaderStatus.DEBIL, SEVERITY_HIGH, ""
        ),  # 20 * 0.3 = 6 pts
        HeaderCheckResult(
            HEADER_HSTS, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_X_FRAME, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),  # 10 pts
        HeaderCheckResult(
            HEADER_X_CONTENT_TYPE, True, "...", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),  # 10 pts
        HeaderCheckResult(
            HEADER_REFERRER_POLICY, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_PERMISSIONS_POLICY, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_COOP, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_CORP, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_COEP, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, ""
        ),  # 0 pts
        HeaderCheckResult(
            HEADER_SET_COOKIE, False, "", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),  # 10 pts
    ]

    score = calculator.calculate_score(results)
    # Total esperado: 6 + 0 + 10 + 10 + 0 + 0 + 0 + 0 + 0 + 10 = 36 pts
    assert score == 36
    assert calculator.get_grade(score) == SecurityGrade.RIESGOSO
