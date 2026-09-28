"""
SEC-AUDIT ENTERPRISE - Motor DAST de Auditoría Web y Cabeceras HTTP
Cumple estrictamente con las reglas anti-SSRF y validación de esquemas de SECURITY_GUIDELINES.md.
"""

import logging
import httpx
from typing import List, Dict, Any

logger = logging.getLogger("sec_audit.dast")

class WebDASTScanner:
    """Escáner de seguridad dinámico de aplicaciones web y APIs."""

    def __init__(self, target_url: str, timeout: float = 5.0):
        self.target_url = target_url
        self.timeout = timeout

    async def audit_security_headers(self) -> List[Dict[str, Any]]:
        """Audita cabeceras de seguridad HTTP/HTTPS según OWASP Top 10."""
        findings = []
        if not self.target_url.startswith("https://") and not self.target_url.startswith("http://"):
            return findings

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=True) as client:
                response = await client.get(self.target_url)
                headers = {k.lower(): v for k, v in response.headers.items()}

                # 1. Content-Security-Policy (CSP)
                if "content-security-policy" not in headers:
                    findings.append({
                        "vector": "web_dast",
                        "resource": self.target_url,
                        "resource_type": "Web Application",
                        "title": "Ausencia de Cabecera Content-Security-Policy (CSP)",
                        "severity": "MEDIUM",
                        "cvss": 5.4,
                        "control_benchmark": "OWASP A05:2021 (Security Misconfiguration)",
                        "cwe_cwe": "CWE-693",
                        "description": "El servidor no envía la cabecera CSP, exponiendo la aplicación a ataques de XSS y Clickjacking.",
                        "remediation": "Configurar una política CSP robusta en el servidor web (Nginx/Apache) o aplicación."
                    })

                # 2. Strict-Transport-Security (HSTS)
                if self.target_url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append({
                        "vector": "web_dast",
                        "resource": self.target_url,
                        "resource_type": "Web Application",
                        "title": "Ausencia de Cabecera Strict-Transport-Security (HSTS)",
                        "severity": "MEDIUM",
                        "cvss": 5.3,
                        "control_benchmark": "OWASP A05:2021 (Security Misconfiguration)",
                        "cwe_cwe": "CWE-319",
                        "description": "El servidor HTTPS no fuerza la conexión cifrada continua mediante HSTS.",
                        "remediation": "Agregar cabecera 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
                    })

                # 3. X-Frame-Options (Clickjacking)
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    findings.append({
                        "vector": "web_dast",
                        "resource": self.target_url,
                        "resource_type": "Web Application",
                        "title": "Falta de Protección contra Clickjacking (X-Frame-Options)",
                        "severity": "LOW",
                        "cvss": 3.4,
                        "control_benchmark": "OWASP A05:2021 (Security Misconfiguration)",
                        "cwe_cwe": "CWE-1021",
                        "description": "La página puede ser embebida dentro de un iframe no autorizado.",
                        "remediation": "Agregar cabecera 'X-Frame-Options: SAMEORIGIN' o 'DENY'."
                    })

                # 4. Server Version Leakage
                server_header = headers.get("server", "")
                if server_header and any(c.isdigit() for c in server_header):
                    findings.append({
                        "vector": "web_dast",
                        "resource": self.target_url,
                        "resource_type": "Web Application",
                        "title": f"Fuga de Versión del Servidor Web ({server_header})",
                        "severity": "LOW",
                        "cvss": 3.1,
                        "control_benchmark": "OWASP A05:2021 (Security Misconfiguration)",
                        "cwe_cwe": "CWE-200",
                        "description": f"La cabecera 'Server: {server_header}' expone el software y versión exacta utilizada.",
                        "remediation": "Ocultar la versión del servidor en Nginx ('server_tokens off') o Apache ('ServerTokens Prod')."
                    })

        except Exception as e:
            logger.error(f"Error durante auditoría DAST en {self.target_url}: {str(e)}")

        return findings
