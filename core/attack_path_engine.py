"""
SEC-AUDIT SERMIG - Motor de Grafo de Rutas de Ataque (Attack Path Engine)
Inspirado en la metodología de Horizon3.ai NodeZero para modelar el encadenamiento
de vulnerabilidades, debilidades y puntos de corte (Chokepoints).
"""

from typing import List, Dict, Any

class AttackPathEngine:
    """Motor de análisis de rutas de ataque encadenadas y puntos de corte."""

    def __init__(self):
        pass

    def get_attack_graph_data(self) -> Dict[str, Any]:
        """
        Retorna los nodos (activos y vectores) y aristas (cadenas de explotación)
        para renderizado en Vis.js Network.
        """
        nodes = [
            # Entrada / Atacante
            {
                "id": "node-attacker",
                "label": "Atacante Externo\n(Internet / Adversario)",
                "shape": "box",
                "color": {"background": "#dc2626", "border": "#991b1b"},
                "font": {"color": "#ffffff", "size": 13, "bold": True},
                "group": "threat"
            },
            # DMZ / Web
            {
                "id": "node-dmz-web",
                "label": "Portal Web SERMIG\n(tramites.serviciomigraciones.cl)\n[Falta CSP / Cookies sin SameSite]",
                "shape": "box",
                "color": {"background": "#d97706", "border": "#b45309"},
                "font": {"color": "#ffffff", "size": 12},
                "group": "dmz"
            },
            # Nube Azure
            {
                "id": "node-azure-nsg",
                "label": "Azure NSG Inbound\n[RDP 3389 expuesto 0.0.0.0/0]",
                "shape": "box",
                "color": {"background": "#e11d48", "border": "#be123c"},
                "font": {"color": "#ffffff", "size": 12},
                "group": "cloud"
            },
            # Nube OCI
            {
                "id": "node-oci-bucket",
                "label": "OCI Object Storage\n[Bucket Público de Backups]",
                "shape": "box",
                "color": {"background": "#e11d48", "border": "#be123c"},
                "font": {"color": "#ffffff", "size": 12},
                "group": "cloud"
            },
            # Red Interna LAN / Endpoint
            {
                "id": "node-lan-workstation",
                "label": "Equipo Puesto de Trabajo\n(10.123.8.79)\n[Puerto 445 SMB / Sin NLA]",
                "shape": "box",
                "color": {"background": "#ea580c", "border": "#c2410c"},
                "font": {"color": "#ffffff", "size": 12},
                "group": "lan"
            },
            # Servidor SGSI-SOC / Linux
            {
                "id": "node-sgsi-srv",
                "label": "Servidor SGSI-SOC\n(10.100.1.34)\n[SSH / Nginx / API 55000]",
                "shape": "box",
                "color": {"background": "#0284c7", "border": "#0369a1"},
                "font": {"color": "#ffffff", "size": 12},
                "group": "server"
            },
            # Joyas de la Corona (Crown Jewels)
            {
                "id": "node-ad-dc",
                "label": "👑 Controlador de Dominio\n(Active Directory DC01)\n[Kerberos / Cuentas de Servicio]",
                "shape": "box",
                "color": {"background": "#7c3aed", "border": "#6d28d9"},
                "font": {"color": "#ffffff", "size": 13, "bold": True},
                "group": "crown_jewel"
            },
            {
                "id": "node-core-db",
                "label": "👑 Base de Datos RDBMS\n(10.100.1.10 Oracle 19c)\n[Datos Migratorios & Pasaportes]",
                "shape": "box",
                "color": {"background": "#7c3aed", "border": "#6d28d9"},
                "font": {"color": "#ffffff", "size": 13, "bold": True},
                "group": "crown_jewel"
            }
        ]

        edges = [
            # Cadena 1: Vía Web DAST -> LAN -> DC
            {
                "from": "node-attacker",
                "to": "node-dmz-web",
                "label": "1. XSS / Robo de Sesión\n(CVSS 5.4)",
                "color": {"color": "#d97706"},
                "arrows": "to",
                "font": {"color": "#fbbf24", "size": 10, "strokeWidth": 0}
            },
            {
                "from": "node-dmz-web",
                "to": "node-lan-workstation",
                "label": "2. Movimiento Lateral SMB 445\n(CVSS 7.5)",
                "color": {"color": "#ea580c"},
                "arrows": "to",
                "font": {"color": "#fb923c", "size": 10, "strokeWidth": 0}
            },
            {
                "from": "node-lan-workstation",
                "to": "node-ad-dc",
                "label": "3. Escalación de Privilegios AD\n(Kerberoasting)",
                "color": {"color": "#e11d48"},
                "arrows": "to",
                "font": {"color": "#f43f5e", "size": 10, "strokeWidth": 0}
            },

            # Cadena 2: Vía Azure RDP -> Core DB
            {
                "from": "node-attacker",
                "to": "node-azure-nsg",
                "label": "1. Fuerza Bruta RDP 3389\n(CVSS 9.8)",
                "color": {"color": "#e11d48"},
                "arrows": "to",
                "font": {"color": "#f43f5e", "size": 10, "strokeWidth": 0}
            },
            {
                "from": "node-azure-nsg",
                "to": "node-core-db",
                "label": "2. Acceso Directo a Subred DB\n(Puerto 1521 sin filtrar)",
                "color": {"color": "#e11d48"},
                "arrows": "to",
                "font": {"color": "#f43f5e", "size": 10, "strokeWidth": 0}
            },

            # Cadena 3: Vía OCI Bucket -> Fuga de Datos
            {
                "from": "node-attacker",
                "to": "node-oci-bucket",
                "label": "1. Descarga No Autenticada\n(CVSS 9.1)",
                "color": {"color": "#e11d48"},
                "arrows": "to",
                "font": {"color": "#f43f5e", "size": 10, "strokeWidth": 0}
            }
        ]

        return {"nodes": nodes, "edges": edges}

    def get_chokepoints(self) -> List[Dict[str, Any]]:
        """
        Calcula y prioriza los 'Chokepoints' (puntos de estrangulamiento):
        acciones de remediación que cortan el mayor número de rutas de ataque.
        """
        return [
            {
                "id": "CHK-01",
                "priority": "CRÍTICA #1",
                "action": "Restringir Regla Inbound en NSG de Azure (Puerto 3389)",
                "impact": "Corta el 100% de las rutas de compromiso directo hacia el Core Database desde la nube pública.",
                "effort": "Bajo (5 minutos - Modificar prefijo a VPN institucional)",
                "paths_broken": 2,
                "status": "pending_retest"
            },
            {
                "id": "CHK-02",
                "priority": "ALTA #2",
                "action": "Deshabilitar Visibilidad Pública en Bucket OCI 'Bucket-Archivos-Temporales'",
                "impact": "Elimina la exposición anónima de copias de seguridad de datos institucionales.",
                "effort": "Bajo (2 minutos - Cambiar a Private)",
                "paths_broken": 1,
                "status": "pending_retest"
            },
            {
                "id": "CHK-03",
                "priority": "ALTA #3",
                "action": "Bloquear Tráfico SMB (Puerto 445) entre Subredes de Puestos de Trabajo",
                "impact": "Impide el movimiento lateral hacia el Controlador de Dominio (Active Directory).",
                "effort": "Medio (Regla en Firewall Fortinet / Switch L3)",
                "paths_broken": 3,
                "status": "pending_retest"
            }
        ]

attack_path_engine = AttackPathEngine()
