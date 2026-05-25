"""
Tests unitarios para el validador y normalizador de URLs.
"""

import pytest

from app.application.services.url_validator_service import UrlValidatorService


@pytest.fixture
def validator():
    return UrlValidatorService()


def test_validate_format_valid(validator):
    assert validator.validate_format("https://example.com") is True
    assert validator.validate_format("http://localhost:8080") is True
    assert validator.validate_format("https://sub.domain.corp/path?query=val") is True
    assert validator.validate_format("http://192.168.1.1") is True  # noqa: S104


def test_validate_format_invalid(validator):
    assert validator.validate_format("ftp://example.com") is False
    assert validator.validate_format("not-a-url") is False
    assert validator.validate_format("") is False


def test_is_http_or_https(validator):
    assert validator.is_http_or_https("https://google.com") is True
    assert validator.is_http_or_https("http://example.com") is True
    assert validator.is_http_or_https("ftp://server.com") is False
    assert validator.is_http_or_https("mailto:info@domain.com") is False


def test_normalize_add_https(validator):
    # Por defecto debe añadir https://
    assert validator.normalize("example.com") == "https://example.com"
    assert validator.normalize("http://example.com") == "http://example.com"
    assert validator.normalize("  https://google.com/  ") == "https://google.com/"


def test_normalize_no_https(validator):
    # Configurado para no autocompletar con https (usará http)
    assert validator.normalize("example.com", add_https=False) == "http://example.com"
