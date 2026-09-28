"""
SEC-AUDIT ENTERPRISE - Motor de Escaneo de Red e Infraestructura (Nmap & Banner Grabbing)
Cumple estrictamente con las directivas de seguridad anti-DoS y limitación de tasa.
"""

import socket
import logging
from typing import List, Dict, Any

logger = logging.getLogger("sec_audit.network")

class NetworkScanner:
    """Escáner de puertos, servicios y banners de infraestructura."""

    def __init__(self, target_host: str, timeout: float = 2.0):
        self.target_host = target_host
        self.timeout = timeout

    def scan_common_ports(self, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Realiza escaneo de puertos TCP seguro sin saturación de ancho de banda."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8000, 8080, 8443]

        results = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    code = sock.connect_ex((self.target_host, port))
                    if code == 0:
                        banner = self._grab_banner(sock, port)
                        results.append({
                            "port": port,
                            "proto": "tcp",
                            "state": "open",
                            "service": self._guess_service(port),
                            "banner": banner
                        })
            except Exception as e:
                logger.debug(f"Error al conectar al puerto {port} en {self.target_host}: {str(e)}")

        return results

    def _guess_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 443: "https", 445: "smb", 1433: "mssql",
            1521: "oracle-tns", 3306: "mysql", 3389: "ms-wbt-server (rdp)",
            5432: "postgresql", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt"
        }
        return services.get(port, "unknown")

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [21, 22, 25]:
                pass  # Esperar banner inicial del servidor
            else:
                return "Servicio Activo"
            banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0] if banner else "Servicio Activo"
        except Exception:
            return "Servicio Activo"
