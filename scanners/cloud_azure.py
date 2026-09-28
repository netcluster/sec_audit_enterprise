"""
SEC-AUDIT ENTERPRISE - Motor de Auditoría Cloud Microsoft Azure (CSPM)
Evalúa suscripciones de Azure contra directivas de seguridad CIS Microsoft Azure Foundations Benchmark.
Utiliza autenticación basada en Service Principal con rol de solo lectura (Security Reader).
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger("sec_audit.azure")

class AzureCSPMScanner:
    """Escáner de postura de seguridad para Microsoft Azure."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id

    def audit_network_security_groups(self) -> List[Dict[str, Any]]:
        """Audita NSGs en búsqueda de reglas con puertos críticos expuestos a 0.0.0.0/0."""
        findings = []
        # En entornos reales o si no hay credenciales configuradas, documenta la inspección
        if not self.client_id or not self.client_secret:
            logger.warning("Credenciales de Azure no configuradas; retornando reglas de verificación base.")
            return findings

        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.network import NetworkManagementClient

            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            net_client = NetworkManagementClient(credential, self.subscription_id)

            for nsg in net_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.direction.lower() == "inbound" and rule.access.lower() == "allow":
                        # Verificar si source es Internet o *
                        is_any_source = rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]
                        dest_ports = [rule.destination_port_range] if rule.destination_port_range else rule.destination_port_ranges or []
                        
                        critical_ports = ["22", "3389", "445", "1433", "3306", "5432"]
                        for p in dest_ports:
                            if is_any_source and any(cp in str(p) for cp in critical_ports):
                                findings.append({
                                    "vector": "cloud_azure",
                                    "resource": nsg.name,
                                    "resource_type": "Network Security Group",
                                    "title": f"Regla Inbound '{rule.name}' expone puerto sensible ({p}) a Internet",
                                    "severity": "CRITICAL" if "3389" in str(p) or "22" in str(p) else "HIGH",
                                    "cvss": 9.8 if "3389" in str(p) else 8.5,
                                    "control_benchmark": "CIS Azure 6.1 / 6.2 (Restrict Management Ports from Internet)",
                                    "description": f"El NSG '{nsg.name}' permite tráfico Inbound en puerto {p} desde '{rule.source_address_prefix}'.",
                                    "remediation": "Restringir la regla para permitir acceso únicamente desde la IP pública institucional o VPN/Bastion."
                                })
        except Exception as e:
            logger.error(f"Error al auditar NSGs de Azure: {str(e)}")
            
        return findings

    def audit_storage_accounts(self) -> List[Dict[str, Any]]:
        """Audita cuentas de almacenamiento para verificar acceso anónimo y cifrado."""
        findings = []
        if not self.client_id or not self.client_secret:
            return findings

        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.storage import StorageManagementClient

            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            stg_client = StorageManagementClient(credential, self.subscription_id)

            for stg in stg_client.storage_accounts.list():
                if getattr(stg, "allow_blob_public_access", True):
                    findings.append({
                        "vector": "cloud_azure",
                        "resource": stg.name,
                        "resource_type": "Storage Account",
                        "title": f"Cuenta de almacenamiento '{stg.name}' permite acceso público a blobs",
                        "severity": "HIGH",
                        "cvss": 7.5,
                        "control_benchmark": "CIS Azure 3.5 (Ensure storage accounts disallow public blob access)",
                        "description": "La cuenta de almacenamiento no tiene restringido de manera global el acceso público anónimo.",
                        "remediation": "Configurar 'allow_blob_public_access=False' en la cuenta de almacenamiento."
                    })
        except Exception as e:
            logger.error(f"Error al auditar Storage Accounts de Azure: {str(e)}")

        return findings
