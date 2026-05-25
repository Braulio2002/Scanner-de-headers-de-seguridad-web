"""
Tests unitarios para el analizador profundo de headers de seguridad.
"""

import pytest

from app.application.services.security_header_analyzer_service import SecurityHeaderAnalyzerService
from app.domain.value_objects.header_status import HeaderStatus
from app.shared.constants import (
    HEADER_CSP,
    HEADER_HSTS,
    HEADER_SET_COOKIE,
    HEADER_X_FRAME,
)


@pytest.fixture
def analyzer():
    return SecurityHeaderAnalyzerService()


def test_analyze_csp_missing(analyzer):
    results = analyzer.analyze({})
    csp_res = next(r for r in results if r.header_name == HEADER_CSP)
    assert csp_res.present is False
    assert csp_res.status == HeaderStatus.FALTANTE


def test_analyze_csp_insecure(analyzer):
    headers = {HEADER_CSP: "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval';"}
    results = analyzer.analyze(headers)
    csp_res = next(r for r in results if r.header_name == HEADER_CSP)
    assert csp_res.present is True
    assert csp_res.status == HeaderStatus.DEBIL
    assert "unsafe-inline" in csp_res.recommendation


def test_analyze_hsts_weak_maxage(analyzer):
    headers = {HEADER_HSTS: "max-age=3600; includeSubDomains"}
    results = analyzer.analyze(headers)
    hsts_res = next(r for r in results if r.header_name == HEADER_HSTS)
    assert hsts_res.present is True
    assert hsts_res.status == HeaderStatus.DEBIL
    assert "max-age bajo" in hsts_res.recommendation


def test_analyze_hsts_correct(analyzer):
    headers = {HEADER_HSTS: "max-age=31536000; includeSubDomains; preload"}
    results = analyzer.analyze(headers)
    hsts_res = next(r for r in results if r.header_name == HEADER_HSTS)
    assert hsts_res.present is True
    assert hsts_res.status == HeaderStatus.CORRECTO


def test_analyze_x_frame_options(analyzer):
    # SAMEORIGIN es correcto
    res1 = analyzer.analyze({HEADER_X_FRAME: "SAMEORIGIN"})
    assert next(r for r in res1 if r.header_name == HEADER_X_FRAME).status == HeaderStatus.CORRECTO

    # Un valor desconocido es débil
    res2 = analyzer.analyze({HEADER_X_FRAME: "ALLOW-FROM https://bad.com"})
    assert next(r for r in res2 if r.header_name == HEADER_X_FRAME).status == HeaderStatus.DEBIL


def test_analyze_cookies_secure(analyzer):
    # Cookie con flags correctos
    headers_ok = {HEADER_SET_COOKIE: "sessionid=xyz123; Secure; HttpOnly; SameSite=Lax"}
    res_ok = analyzer.analyze(headers_ok)
    cookie_res = next(r for r in res_ok if r.header_name == HEADER_SET_COOKIE)
    assert cookie_res.status == HeaderStatus.CORRECTO

    # Cookie sin HttpOnly
    headers_weak = {HEADER_SET_COOKIE: "sessionid=xyz123; Secure; SameSite=Strict"}
    res_weak = analyzer.analyze(headers_weak)
    cookie_res_weak = next(r for r in res_weak if r.header_name == HEADER_SET_COOKIE)
    assert cookie_res_weak.status == HeaderStatus.DEBIL
    assert "sin HttpOnly" in cookie_res_weak.recommendation
