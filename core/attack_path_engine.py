"""
SEC-AUDIT SERMIG - Motor de Grafo de Rutas de Ataque (Attack Path Engine)
Definición de colores oscuros estables en hover y highlight para evitar destellos blancos.
"""

from typing import List, Dict, Any

class AttackPathEngine:
    """Motor de análisis y modelado de rutas de ataque encadenadas."""

    def __init__(self):
        pass

    def get_attack_graph_data(self) -> Dict[str, Any]:
        """
        Retorna la topología con colores de fondo oscuros fijos y brillo suave
        en el borde para hover, garantizando legibilidad total del texto en todo momento.
        """
        nodes = [
            # NIVEL 1: ADVERSARIO / AMENAZA EXTERNA
            {
                "id": "node-attacker",
                "label": "🔴 Atacante Externo\n(Internet / Adversario)\nIP: 198.51.100.23",
                "level": 1,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#1e132b",
                    "border": "#f43f5e",
                    "hover": {"background": "#291a3a", "border": "#fb7185"},
                    "highlight": {"background": "#291a3a", "border": "#fb7185"}
                },
                "font": {"color": "#ffffff", "size": 12, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(244, 63, 94, 0.35)", "size": 8},
                "tier": "entry"
            },

            # NIVEL 2: PERÍMETRO WEB & CLOUD
            {
                "id": "node-dmz-web",
                "label": "🌐 Portal Web SERMIG\ntramites.serviciomigraciones.cl\n[Falta CSP / XSS]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#0b1528",
                    "border": "#38bdf8",
                    "hover": {"background": "#13233f", "border": "#7dd3fc"},
                    "highlight": {"background": "#13233f", "border": "#7dd3fc"}
                },
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(56, 189, 248, 0.25)", "size": 8},
                "tier": "perimeter"
            },
            {
                "id": "node-azure-nsg",
                "label": "☁️ Azure NSG Inbound\nnsg-sermig-core-prod\n[RDP 3389 expuesto 0.0.0.0/0]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#280a0a",
                    "border": "#ef4444",
                    "hover": {"background": "#3d1010", "border": "#f87171"},
                    "highlight": {"background": "#3d1010", "border": "#f87171"}
                },
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(239, 68, 68, 0.3)", "size": 8},
                "tier": "cloud"
            },
            {
                "id": "node-oci-bucket",
                "label": "☁️ OCI Object Storage\nBucket-Archivos-Temporales\n[Visibilidad Pública Activa]",
                "level": 2,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#2b1207",
                    "border": "#f97316",
                    "hover": {"background": "#3f1c0d", "border": "#fb923c"},
                    "highlight": {"background": "#3f1c0d", "border": "#fb923c"}
                },
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(249, 115, 22, 0.3)", "size": 8},
                "tier": "cloud"
            },

            # NIVEL 3: PIVOT INTERNO LAN
            {
                "id": "node-lan-endpoint",
                "label": "💻 Puesto de Trabajo LAN\nHost: PC-OPERACIONES (10.123.8.79)\n[SMB 445 Activo / Sin NLA]",
                "level": 3,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#1e293b",
                    "border": "#fbbf24",
                    "hover": {"background": "#2b394f", "border": "#fde047"},
                    "highlight": {"background": "#2b394f", "border": "#fde047"}
                },
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(251, 191, 36, 0.25)", "size": 8},
                "tier": "lateral"
            },
            {
                "id": "node-sgsi-srv",
                "label": "🛡️ Servidor SGSI-SOC\nsrv-sgsi-soc (10.100.1.34)\n[Nginx / Hardening Activo]",
                "level": 3,
                "shape": "box",
                "margin": 10,
                "color": {
                    "background": "#042f2e",
                    "border": "#2dd4bf",
                    "hover": {"background": "#094443", "border": "#5eead4"},
                    "highlight": {"background": "#094443", "border": "#5eead4"}
                },
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(45, 212, 191, 0.25)", "size": 8},
                "tier": "defended"
            },

            # NIVEL 4: JOYAS DE LA CORONA
            {
                "id": "node-ad-dc",
                "label": "👑 Controlador de Dominio\nDC01 (sermig.local)\n[Active Directory / Kerberos]",
                "level": 4,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#240e47",
                    "border": "#c084fc",
                    "hover": {"background": "#351566", "border": "#d8b4fe"},
                    "highlight": {"background": "#351566", "border": "#d8b4fe"}
                },
                "font": {"color": "#ffffff", "size": 12, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(192, 132, 252, 0.45)", "size": 10},
                "tier": "crown_jewel"
            },
            {
                "id": "node-core-db",
                "label": "👑 Base de Datos Central\nsrv-db-oracle (10.100.1.10)\n[Datos Migratorios & Visas]",
                "level": 4,
                "shape": "box",
                "margin": 12,
                "color": {
                    "background": "#240e47",
                    "border": "#c084fc",
                    "hover": {"background": "#351566", "border": "#d8b4fe"},
                    "highlight": {"background": "#351566", "border": "#d8b4fe"}
                },
                "font": {"color": "#ffffff", "size": 12, "face": "Segoe UI"},
                "borderWidth": 2,
                "shadow": {"enabled": True, "color": "rgba(192, 132, 252, 0.45)", "size": 10},
                "tier": "crown_jewel"
            }
        ]

        # ETIQUETAS DE ARISTAS: Ligeras, concisas y con fondo contrastado
        edges = [
            # CADENA 1: WEB -> SMB LAN -> ACTIVE DIRECTORY
            {
                "from": "node-attacker",
                "to": "node-dmz-web",
                "label": "Paso 1: Robo de Sesion Web (CVSS 5.4)",
                "color": {"color": "#38bdf8", "highlight": "#7dd3fc", "hover": "#7dd3fc"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 2.5
            },
            {
                "from": "node-dmz-web",
                "to": "node-lan-endpoint",
                "label": "Paso 2: Movimiento Lateral SMB 445",
                "color": {"color": "#fbbf24", "highlight": "#fde047", "hover": "#fde047"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 2.5
            },
            {
                "from": "node-lan-endpoint",
                "to": "node-ad-dc",
                "label": "Paso 3: Escalacion AD (Kerberoasting)",
                "color": {"color": "#c084fc", "highlight": "#d8b4fe", "hover": "#d8b4fe"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },

            # CADENA 2: AZURE RDP -> CORE DB DIRECT
            {
                "from": "node-attacker",
                "to": "node-azure-nsg",
                "label": "Paso 1: Fuerza Bruta RDP 3389 (CVSS 9.8)",
                "color": {"color": "#f87171", "highlight": "#fca5a5", "hover": "#fca5a5"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },
            {
                "from": "node-azure-nsg",
                "to": "node-core-db",
                "label": "Paso 2: Conexion a Subred BD (Oracle 1521)",
                "color": {"color": "#c084fc", "highlight": "#d8b4fe", "hover": "#d8b4fe"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
                "smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.3},
                "width": 3
            },

            # CADENA 3: OCI BUCKET -> FUGA DE DATOS
            {
                "from": "node-attacker",
                "to": "node-oci-bucket",
                "label": "Paso 1: Descarga Anonima Bucket (CVSS 9.1)",
                "color": {"color": "#fb923c", "highlight": "#fdba74", "hover": "#fdba74"},
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "font": {"color": "#ffffff", "size": 11, "face": "Segoe UI", "background": "#0f172a", "strokeWidth": 0},
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
