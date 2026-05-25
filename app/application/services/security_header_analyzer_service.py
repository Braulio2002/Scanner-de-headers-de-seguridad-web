"""
Servicio encargado del análisis profundo de los headers de seguridad HTTP.
Analiza tanto la presencia como la robustez de los valores configurados.
"""

from app.domain.entities.header_check_result import HeaderCheckResult
from app.domain.value_objects.header_status import HeaderStatus
from app.shared.constants import (
    HEADER_CACHE_CONTROL,
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
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)


class SecurityHeaderAnalyzerService:
    """
    Servicio de dominio para auditar el contenido de cada cabecera de seguridad.
    """

    def analyze(self, headers: dict[str, str]) -> list[HeaderCheckResult]:
        """
        Analiza un diccionario de cabeceras HTTP y retorna los resultados detallados.
        """
        # Normalizar las llaves de las cabeceras a minúsculas para una búsqueda insensible a mayúsculas
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        results: list[HeaderCheckResult] = []

        # 1. Content-Security-Policy
        results.append(self._analyze_csp(normalized_headers.get(HEADER_CSP.lower())))

        # 2. Strict-Transport-Security
        results.append(self._analyze_hsts(normalized_headers.get(HEADER_HSTS.lower())))

        # 3. X-Frame-Options
        results.append(self._analyze_x_frame(normalized_headers.get(HEADER_X_FRAME.lower())))

        # 4. X-Content-Type-Options
        results.append(
            self._analyze_x_content_type(normalized_headers.get(HEADER_X_CONTENT_TYPE.lower()))
        )

        # 5. Referrer-Policy
        results.append(
            self._analyze_referrer_policy(normalized_headers.get(HEADER_REFERRER_POLICY.lower()))
        )

        # 6. Permissions-Policy
        results.append(
            self._analyze_permissions_policy(
                normalized_headers.get(HEADER_PERMISSIONS_POLICY.lower())
            )
        )

        # 7. Cross-Origin-Opener-Policy
        results.append(self._analyze_coop(normalized_headers.get(HEADER_COOP.lower())))

        # 8. Cross-Origin-Resource-Policy
        results.append(self._analyze_corp(normalized_headers.get(HEADER_CORP.lower())))

        # 9. Cross-Origin-Embedder-Policy
        results.append(self._analyze_coep(normalized_headers.get(HEADER_COEP.lower())))

        # 10. Cache-Control
        results.append(
            self._analyze_cache_control(normalized_headers.get(HEADER_CACHE_CONTROL.lower()))
        )

        # 11. Set-Cookie
        # En requests, si hay varias cookies se unen por coma en headers o se extraen.
        # Analizamos el header Set-Cookie si existe
        results.append(self._analyze_set_cookie(normalized_headers.get(HEADER_SET_COOKIE.lower())))

        return results

    def _check_csp_wildcards(self, directives: list[str]) -> list[str]:
        """Busca comodines excesivos '*' en directivas clave de CSP."""
        wildcard_matches = []
        for directive in directives:
            parts = directive.split()
            if not parts:
                continue
            dir_name = parts[0].lower()
            if dir_name in ["default-src", "script-src", "style-src", "object-src", "connect-src"]:
                if "*" in parts[1:]:
                    wildcard_matches.append(dir_name)
        return wildcard_matches

    def _check_csp_insecure_values(self, val_lower: str) -> list[str]:
        """Identifica si el valor de CSP contiene valores inseguros."""
        insecure_values = []
        if "unsafe-inline" in val_lower:
            insecure_values.append("'unsafe-inline'")
        if "unsafe-eval" in val_lower:
            insecure_values.append("'unsafe-eval'")
        return insecure_values

    def _analyze_csp(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_CSP,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Implementar Content-Security-Policy (CSP) para mitigar "
                    "ataques de Cross-Site Scripting (XSS) e inyección de datos."
                ),
            )

        # CSP existe. Analicemos sus directivas
        directives = [d.strip() for d in value.split(";") if d.strip()]
        directive_names = {d.split()[0].lower() for d in directives if d.split()}

        required_directives = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "object-src",
            "frame-ancestors",
            "base-uri",
            "form-action",
        ]
        missing_directives = [rd for rd in required_directives if rd not in directive_names]

        # Validar valores inseguros y comodines excesivos
        insecure_values = self._check_csp_insecure_values(value.lower())
        wildcard_matches = self._check_csp_wildcards(directives)

        if insecure_values or wildcard_matches or missing_directives:
            recs = []
            if missing_directives:
                recs.append(f"Directivas faltantes: {', '.join(missing_directives)}.")
            if insecure_values:
                recs.append(f"Evitar el uso de valores inseguros: {', '.join(insecure_values)}.")
            if wildcard_matches:
                recs.append(
                    f"Restringir comodines '*' en directivas: {', '.join(wildcard_matches)}."
                )

            severity = SEVERITY_HIGH if (insecure_values or wildcard_matches) else SEVERITY_MEDIUM
            return HeaderCheckResult(
                header_name=HEADER_CSP,
                present=True,
                value=value,
                status=HeaderStatus.DEBIL,
                severity=severity,
                recommendation=f"CSP configurado con debilidades. {' '.join(recs)}",
            )

        return HeaderCheckResult(
            header_name=HEADER_CSP,
            present=True,
            value=value,
            status=HeaderStatus.CORRECTO,
            severity=SEVERITY_INFO,
            recommendation="Content-Security-Policy configurado correctamente con directivas fuertes.",
        )

    def _analyze_hsts(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_HSTS,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Implementar Strict-Transport-Security (HSTS) para forzar "
                    "conexiones seguras HTTPS. Recomendado: max-age=31536000; includeSubDomains; preload."
                ),
            )

        # Analizar directivas HSTS
        parts = [p.strip().lower() for p in value.split(";")]
        max_age = None
        include_subdomains = "includesubdomains" in parts
        preload = "preload" in parts

        for part in parts:
            if part.startswith("max-age"):
                try:
                    max_age = int(part.split("=")[1])
                except (IndexError, ValueError):
                    pass

        if max_age is None:
            return HeaderCheckResult(
                header_name=HEADER_HSTS,
                present=True,
                value=value,
                status=HeaderStatus.DEBIL,
                severity=SEVERITY_HIGH,
                recommendation="HSTS configurado sin un max-age válido. Configurar max-age=31536000 o superior.",
            )

        if max_age < 31536000:
            return HeaderCheckResult(
                header_name=HEADER_HSTS,
                present=True,
                value=value,
                status=HeaderStatus.DEBIL,
                severity=SEVERITY_MEDIUM,
                recommendation=f"HSTS configurado con max-age bajo ({max_age}s). Recomendado al menos 31536000s (1 año).",
            )

        recs = []
        if not include_subdomains:
            recs.append("Añadir la directiva 'includeSubDomains'.")
        if not preload:
            recs.append("Añadir la directiva 'preload'.")

        if recs:
            return HeaderCheckResult(
                header_name=HEADER_HSTS,
                present=True,
                value=value,
                status=HeaderStatus.DEBIL,
                severity=SEVERITY_LOW,
                recommendation=f"HSTS configurado parcialmente. {' '.join(recs)}",
            )

        return HeaderCheckResult(
            header_name=HEADER_HSTS,
            present=True,
            value=value,
            status=HeaderStatus.CORRECTO,
            severity=SEVERITY_INFO,
            recommendation="HSTS configurado de forma óptima con directivas seguras.",
        )

    def _analyze_x_frame(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_X_FRAME,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_HIGH,
                recommendation=(
                    "Implementar X-Frame-Options para mitigar vulnerabilidades "
                    "de Clickjacking. Usar valores seguros como DENY o SAMEORIGIN."
                ),
            )

        val_upper = value.upper().strip()
        if val_upper in ("DENY", "SAMEORIGIN"):
            return HeaderCheckResult(
                header_name=HEADER_X_FRAME,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation=f"X-Frame-Options configurado correctamente con el valor seguro {val_upper}.",
            )

        return HeaderCheckResult(
            header_name=HEADER_X_FRAME,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_MEDIUM,
            recommendation="X-Frame-Options configurado con valor obsoleto o débil. Cambiar a DENY o SAMEORIGIN.",
        )

    def _analyze_x_content_type(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_X_CONTENT_TYPE,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_HIGH,
                recommendation="Implementar X-Content-Type-Options: nosniff para prevenir ataques de MIME-sniffing.",
            )

        if value.strip().lower() == "nosniff":
            return HeaderCheckResult(
                header_name=HEADER_X_CONTENT_TYPE,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="X-Content-Type-Options configurado correctamente con el valor 'nosniff'.",
            )

        return HeaderCheckResult(
            header_name=HEADER_X_CONTENT_TYPE,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_HIGH,
            recommendation="X-Content-Type-Options debe tener configurado exactamente el valor 'nosniff'.",
        )

    def _analyze_referrer_policy(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_REFERRER_POLICY,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Implementar Referrer-Policy para mitigar la fuga de información sensible. "
                    "Se recomienda 'strict-origin-when-cross-origin' o 'no-referrer'."
                ),
            )

        val_lower = value.strip().lower()
        secure_values = [
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin",
        ]

        if val_lower in secure_values:
            return HeaderCheckResult(
                header_name=HEADER_REFERRER_POLICY,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation=f"Referrer-Policy configurado con el valor seguro '{val_lower}'.",
            )

        return HeaderCheckResult(
            header_name=HEADER_REFERRER_POLICY,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_MEDIUM,
            recommendation="Referrer-Policy expone potencialmente información sensible. Cambiar a strict-origin-when-cross-origin.",
        )

    def _analyze_permissions_policy(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_PERMISSIONS_POLICY,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_MEDIUM,
                recommendation=(
                    "Implementar Permissions-Policy para restringir APIs sensibles de navegador "
                    "(geolocation=(), microphone=(), camera=(), payment=(), usb=())."
                ),
            )

        # Buscar si restringe al menos camera, microphone o geolocation
        val_lower = value.lower()
        key_permissions = ["camera", "microphone", "geolocation", "payment", "usb"]
        restricted_count = sum(1 for p in key_permissions if p in val_lower)

        if restricted_count >= 3:
            return HeaderCheckResult(
                header_name=HEADER_PERMISSIONS_POLICY,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="Permissions-Policy configurado correctamente restringiendo múltiples APIs del navegador.",
            )

        return HeaderCheckResult(
            header_name=HEADER_PERMISSIONS_POLICY,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_LOW,
            recommendation="Permissions-Policy existe pero se recomienda restringir explícitamente cámara, micrófono y geolocalización.",
        )

    def _analyze_coop(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_COOP,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_MEDIUM,
                recommendation="Implementar Cross-Origin-Opener-Policy: same-origin para mitigar ataques de orígenes cruzados (XS-Leaks).",
            )

        if value.strip().lower() == "same-origin":
            return HeaderCheckResult(
                header_name=HEADER_COOP,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="COOP configurado correctamente como 'same-origin'.",
            )

        return HeaderCheckResult(
            header_name=HEADER_COOP,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_LOW,
            recommendation="COOP existe pero se recomienda elevar su restricción a 'same-origin'.",
        )

    def _analyze_corp(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_CORP,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_MEDIUM,
                recommendation="Implementar Cross-Origin-Resource-Policy con valores como 'same-origin' o 'same-site'.",
            )

        val_lower = value.strip().lower()
        if val_lower in ("same-origin", "same-site"):
            return HeaderCheckResult(
                header_name=HEADER_CORP,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation=f"CORP configurado de forma segura con el valor '{val_lower}'.",
            )

        return HeaderCheckResult(
            header_name=HEADER_CORP,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_LOW,
            recommendation="CORP existe pero expone potencialmente recursos. Cambiar a same-origin o same-site.",
        )

    def _analyze_coep(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_COEP,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_MEDIUM,
                recommendation="Implementar Cross-Origin-Embedder-Policy: require-corp para aislar el contexto de carga de scripts y recursos.",
            )

        if value.strip().lower() == "require-corp":
            return HeaderCheckResult(
                header_name=HEADER_COEP,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="COEP configurado correctamente como 'require-corp'.",
            )

        return HeaderCheckResult(
            header_name=HEADER_COEP,
            present=True,
            value=value,
            status=HeaderStatus.DEBIL,
            severity=SEVERITY_LOW,
            recommendation="COEP existe pero se recomienda configurarlo en 'require-corp'.",
        )

    def _analyze_cache_control(self, value: str | None) -> HeaderCheckResult:
        if not value:
            return HeaderCheckResult(
                header_name=HEADER_CACHE_CONTROL,
                present=False,
                value="",
                status=HeaderStatus.FALTANTE,
                severity=SEVERITY_LOW,
                recommendation=(
                    "Implementar Cache-Control en páginas sensibles o que manejan "
                    "datos privados, utilizando 'no-store, no-cache, must-revalidate'."
                ),
            )

        val_lower = value.lower()
        if "no-store" in val_lower or "no-cache" in val_lower or "private" in val_lower:
            return HeaderCheckResult(
                header_name=HEADER_CACHE_CONTROL,
                present=True,
                value=value,
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="Cache-Control configurado de forma segura para páginas sensibles o privadas.",
            )

        return HeaderCheckResult(
            header_name=HEADER_CACHE_CONTROL,
            present=True,
            value=value,
            status=HeaderStatus.PRESENTE,
            severity=SEVERITY_INFO,
            recommendation="Cache-Control está presente (se recomienda evaluar si la ruta maneja datos sensibles para aplicar no-store).",
        )

    def _analyze_set_cookie(self, value: str | None) -> HeaderCheckResult:
        if not value:
            # Si no hay cookies, no es un fallo de seguridad, por lo tanto es correcto e informativo.
            return HeaderCheckResult(
                header_name=HEADER_SET_COOKIE,
                present=False,
                value="",
                status=HeaderStatus.CORRECTO,
                severity=SEVERITY_INFO,
                recommendation="No se detectaron cookies (Set-Cookie) en la respuesta HTTP.",
            )

        # Analizar los flags de las cookies. En requests, si hay múltiples Set-Cookie, se separan por comas.
        # Vamos a dividir por comas para evaluar cada cookie individual
        cookies = [c.strip() for c in value.split(",") if c.strip()]
        weak_cookies = []

        for cookie in cookies:
            cookie_lower = cookie.lower()
            missing_flags = []

            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                # Extraer nombre aproximado de la cookie
                cookie_name = cookie.split("=")[0] if "=" in cookie else "Cookie"
                weak_cookies.append(f"{cookie_name} sin {', '.join(missing_flags)}")

        if weak_cookies:
            return HeaderCheckResult(
                header_name=HEADER_SET_COOKIE,
                present=True,
                value=value,
                status=HeaderStatus.DEBIL,
                severity=SEVERITY_HIGH,
                recommendation=f"Cookies configuradas sin flags de seguridad: {'; '.join(weak_cookies)}. Añadir HttpOnly, Secure y SameSite=Lax.",
            )

        return HeaderCheckResult(
            header_name=HEADER_SET_COOKIE,
            present=True,
            value=value,
            status=HeaderStatus.CORRECTO,
            severity=SEVERITY_INFO,
            recommendation="Todas las cookies Set-Cookie contienen los flags HttpOnly, Secure y SameSite configurados correctamente.",
        )
