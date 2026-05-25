"""
Tests unitarios para el servicio de priorización de recomendaciones.
"""

import pytest

from app.application.services.recommendation_service import RecommendationService
from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.header_status import HeaderStatus
from app.shared.constants import (
    HEADER_CSP,
    HEADER_HSTS,
    HEADER_X_FRAME,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
)


@pytest.fixture
def service():
    return RecommendationService()


def test_generate_recommendations_sorting(service):
    # Generar resultados con diferentes severidades para verificar ordenamiento
    results = [
        # Correcto: no genera recomendación
        HeaderCheckResult(
            HEADER_X_FRAME, True, "SAMEORIGIN", HeaderStatus.CORRECTO, SEVERITY_INFO, ""
        ),
        # Débil (Baja severidad)
        HeaderCheckResult(
            HEADER_HSTS,
            True,
            "max-age=31536000",
            HeaderStatus.DEBIL,
            SEVERITY_LOW,
            "Añadir preload",
        ),
        # Faltante (Alta severidad)
        HeaderCheckResult(
            HEADER_CSP, False, "", HeaderStatus.FALTANTE, SEVERITY_HIGH, "Implementar CSP"
        ),
    ]

    recs = service.generate_recommendations("https://example.com", results)

    # Debe haber exactamente 2 recomendaciones (excluye el correcto)
    assert len(recs) == 2

    # Debe estar ordenado con Alta prioridad primero (CSP antes que HSTS)
    assert recs[0]["header"] == HEADER_CSP
    assert recs[0]["prioridad"] == SEVERITY_HIGH

    assert recs[1]["header"] == HEADER_HSTS
    assert recs[1]["prioridad"] == SEVERITY_LOW
