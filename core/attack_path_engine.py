"""
SEC-AUDIT SERMIG - Motor de Grafo de Rutas de Ataque (Attack Path Engine)
Modelo jerárquico por niveles (Tiered Attack Topology) inspirado en Horizon3.ai NodeZero
con niveles ordenados (Left-to-Right), metadatos de activos y puntos de corte.
"""

from typing import List, Dict, Any

class AttackPathEngine:
    """Motor de análisis y modelado de rutas de ataque encadenadas."""

    def __init__(self):
        pass

    def get_attack_graph_data(self) -> Dict[str, Any]:
        """
        Retorna la topología organizada en niveles de profundidad (Levels 1 a 4)
        para garantizar un diseño limpio, no amontonado y de alta legibilidad.
        """
        nodes = [
            # NIVEL 1: VECTOR DE ENTRADA / ADVERSARIO
            {
                "id": "node-attacker",
                "label": "🔴 ATACANTE EXTERNO\n(Internet / Adversario)\nIP: 198.51.100.23",
                "level": 1,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#1e1b4b",
                    "border": "#e11d48",
                    "highlight": {"background": "#311042", "border": "#f43f5e"}
                },
                "font": {"color": "#fda4af", "size": 12, "face": "Segoe UI", "multi": True, "bold": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(225, 29, 72, 0.4)", "size": 12},
                "tier": "entry"
            },

            # NIVEL 2: PERÍMETRO, DMZ & CLOUD INGRESS
            {
                "id": "node-dmz-web",
                "label": "🌐 PORTAL WEB SERMIG\ntramites.serviciomigraciones.cl\n[Falta CSP / XSS Potencial]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#172554",
                    "border": "#3b82f6",
                    "highlight": {"background": "#1e3a8a", "border": "#60a5fa"}
                },
                "font": {"color": "#93c5fd", "size": 11, "face": "Segoe UI", "multi": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(59, 130, 246, 0.3)", "size": 8},
                "tier": "perimeter"
            },
            {
                "id": "node-azure-nsg",
                "label": "☁️ AZURE NSG INBOUND\nnsg-sermig-core-prod\n[RDP 3389 expuesto a Internet]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#450a0a",
                    "border": "#dc2626",
                    "highlight": {"background": "#7f1d1d", "border": "#ef4444"}
                },
                "font": {"color": "#fca5a5", "size": 11, "face": "Segoe UI", "multi": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(220, 38, 38, 0.35)", "size": 8},
                "tier": "cloud"
            },
            {
                "id": "node-oci-bucket",
                "label": "☁️ OCI OBJECT STORAGE\nBucket-Archivos-Temporales\n[Visibilidad Pública Activa]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#431407",
                    "border": "#ea580c",
                    "highlight": {"background": "#7c2d12", "border": "#fb923c"}
                },
                "font": {"color": "#fdba74", "size": 11, "face": "Segoe UI", "multi": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(234, 88, 12, 0.35)", "size": 8},
                "tier": "cloud"
            },

            # NIVEL 3: PIVOT INTERNO & MOVIMIENTO LATERAL
            {
                "id": "node-lan-endpoint",
                "label": "💻 PUESTO DE TRABAJO LAN\nHost: PC-OPERACIONES (10.123.8.79)\n[SMB 445 Activo / Sin NLA]",
                "level": 3,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#1e293b",
                    "border": "#f59e0b",
                    "highlight": {"background": "#334155", "border": "#fbbf24"}
                },
                "font": {"color": "#fde68a", "size": 11, "face": "Segoe UI", "multi": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(245, 158, 11, 0.3)", "size": 8},
                "tier": "lateral"
            },
            {
                "id": "node-sgsi-srv",
                "label": "🛡️ SERVIDOR SGSI-SOC\nsrv-sgsi-soc (10.100.1.34)\n[Nginx / Hardening Activo]",
                "level": 3,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#042f2e",
                    "border": "#14b8a6",
                    "highlight": {"background": "#115e59", "border": "#2dd4bf"}
                },
                "font": {"color": "#99f6e4", "size": 11, "face": "Segoe UI", "multi": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(20, 184, 166, 0.3)", "size": 8},
                "tier": "defended"
            },

            # NIVEL 4: OBJETIVOS DE MÁXIMO IMPACTO (JOYAS DE LA CORONA)
            {
                "id": "node-ad-dc",
                "label": "👑 CONTROLADOR DE DOMINIO\nDC01 (sermig.local)\n[Active Directory / Kerberos]",
                "level": 4,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#2e1065",
                    "border": "#a855f7",
                    "highlight": {"background": "#3b0764", "border": "#c084fc"}
                },
                "font": {"color": "#e9d5ff", "size": 12, "face": "Segoe UI", "multi": True, "bold": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(168, 85, 247, 0.5)", "size": 14},
                "tier": "crown_jewel"
            },
            {
                "id": "node-core-db",
                "label": "👑 BASE DE DATOS CENTRAL\nsrv-db-oracle (10.100.1.10)\n[Datos Migratorios & Visas]",
                "level": 4,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#2e1065",
                    "border": "#a855f7",
                    "highlight": {"background": "#3b0764", "border": "#c084fc"}
                },
                "font": {"color": "#e9d5ff", "size": 12, "face": "Segoe UI", "multi": True, "bold": True},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(168, 85, 247, 0.5)", "size": 14},
                "tier": "crown_jewel"
            }
        ]

        edges = [
            # CADENA 1: WEB DAST -> LATERAL SMB -> DOMAIN CONTROLLER
            {
                "from": "node-attacker",
                "to": "node-dmz-web",
                "label": "1. Robo de Sesión\n(CVSS 5.4)",
                "color": {"color": "#3b82f6", "highlight": "#60a5fa"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#93c5fd", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 2.5
            },
            {
                "from": "node-dmz-web",
                "to": "node-lan-endpoint",
                "label": "2. Movimiento Lateral SMB\n(Puerto 445)",
                "color": {"color": "#f59e0b", "highlight": "#fbbf24"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#fde68a", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 2.5
            },
            {
                "from": "node-lan-endpoint",
                "to": "node-ad-dc",
                "label": "3. Escalación de Privilegios\n(Kerberoasting)",
                "color": {"color": "#a855f7", "highlight": "#c084fc"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#e9d5ff", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },

            # CADENA 2: AZURE RDP -> CORE DB DIRECT
            {
                "from": "node-attacker",
                "to": "node-azure-nsg",
                "label": "1. Fuerza Bruta RDP\n(Puerto 3389 - CVSS 9.8)",
                "color": {"color": "#ef4444", "highlight": "#f87171"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#fca5a5", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },
            {
                "from": "node-azure-nsg",
                "to": "node-core-db",
                "label": "2. Acceso a Subred BD\n(Oracle 1521)",
                "color": {"color": "#a855f7", "highlight": "#c084fc"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#e9d5ff", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },

            # CADENA 3: OCI BUCKET -> FUGA DE DATOS
            {
                "from": "node-attacker",
                "to": "node-oci-bucket",
                "label": "Descarga No Autenticada\n(Bucket Público - CVSS 9.1)",
                "color": {"color": "#f97316", "highlight": "#fb923c"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#fdba74", "size": 10, "align": "middle", "background": "#0f172a"},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 2.5
            }
        ]

        return {"nodes": nodes, "edges": edges}

    def get_chokepoints(self) -> List[Dict[str, Any]]:
        """Calcula y prioriza los puntos de corte de mayor impacto."""
        return [
            {
                "id": "CHK-01",
                "priority": "CRÍTICA #1",
                "action": "Restringir Regla Inbound en NSG de Azure (Puerto 3389)",
                "impact": "Desarticula el 100% del vector de intrusión directa hacia la Base de Datos Central.",
                "effort": "Bajo (5 minutos - Cambiar prefijo a VPN institucional)",
                "paths_broken": 2,
                "status": "pending_retest"
            },
            {
                "id": "CHK-02",
                "priority": "ALTA #2",
                "action": "Bloquear Tráfico SMB (Puerto 445) entre Subredes de Puestos de Trabajo",
                "impact": "Impide el movimiento lateral hacia el Controlador de Dominio (Active Directory).",
                "effort": "Medio (Regla en Firewall Fortinet / Switch L3)",
                "paths_broken": 3,
                "status": "pending_retest"
            },
            {
                "id": "CHK-03",
                "priority": "ALTA #3",
                "action": "Deshabilitar Visibilidad Pública en Bucket OCI 'Bucket-Archivos-Temporales'",
                "impact": "Elimina la fuga de respaldos de datos de extranjeros sin requerir credenciales.",
                "effort": "Bajo (2 minutos - Cambiar a Private)",
                "paths_broken": 1,
                "status": "pending_retest"
            }
        ]

attack_path_engine = AttackPathEngine()
