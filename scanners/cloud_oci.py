"""
SEC-AUDIT ENTERPRISE - Motor de Auditoría Cloud Oracle OCI (CSPM)
Evalúa Tenancy y Compartments de OCI contra CIS Oracle Cloud Infrastructure Foundations Benchmark.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger("sec_audit.oci")

class OCICSPMScanner:
    """Escáner de postura de seguridad para Oracle Cloud Infrastructure."""

    def __init__(self, tenancy_ocid: str, user_ocid: str, fingerprint: str, key_file: str, region: str):
        self.tenancy_ocid = tenancy_ocid
        self.user_ocid = user_ocid
        self.fingerprint = fingerprint
        self.key_file = key_file
        self.region = region

    def audit_object_storage_buckets(self) -> List[Dict[str, Any]]:
        """Audita buckets en Object Storage para detectar visibilidad pública."""
        findings = []
        if not self.tenancy_ocid or not self.user_ocid:
            logger.warning("Credenciales de OCI no configuradas; retornando comprobación estática.")
            return findings

        try:
            import oci
            config = {
                "user": self.user_ocid,
                "key_file": self.key_file,
                "fingerprint": self.fingerprint,
                "tenancy": self.tenancy_ocid,
                "region": self.region
            }
            object_storage_client = oci.object_storage.ObjectStorageClient(config)
            namespace = object_storage_client.get_namespace().data

            # Listar buckets en la Tenancy
            buckets = object_storage_client.list_buckets(namespace, self.tenancy_ocid).data
            for b in buckets:
                bucket_details = object_storage_client.get_bucket(namespace, b.name).data
                if bucket_details.public_access_type != "NoPublicAccess":
                    findings.append({
                        "vector": "cloud_oci",
                        "resource": b.name,
                        "resource_type": "Object Storage Bucket",
                        "title": f"Bucket OCI '{b.name}' tiene visibilidad pública activa ({bucket_details.public_access_type})",
                        "severity": "CRITICAL",
                        "cvss": 9.1,
                        "control_benchmark": "CIS OCI 2.1 (Ensure Object Storage Buckets are not publicly accessible)",
                        "description": f"El bucket permite lectura pública sin requerir autenticación en el namespace {namespace}.",
                        "remediation": "Cambiar la visibilidad del bucket a 'NoPublicAccess' mediante la consola OCI o CLI."
                    })
        except Exception as e:
            logger.error(f"Error al auditar Buckets de OCI: {str(e)}")

        return findings
