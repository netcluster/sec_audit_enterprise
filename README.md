# 🛡️ SEC-AUDIT ENTERPRISE - SERMIG 2026
### Plataforma de Auditoría Técnica de Seguridad, Pentesting y Evaluación Continua de Superficie de Ataque (ASM / CSPM)
**Servicio Nacional de Migraciones (SERMIG)**

---

## 🏗️ Arquitectura del Sistema

* **Core Engine**: FastAPI + Pydantic v2 + SQLAlchemy (PostgreSQL).
* **Async Task Queue**: Celery + Redis para ejecución no bloqueante de escaneos.
* **Módulo Cloud (CSPM)**:
  * Azure: Evaluación de suscripciones, NSGs, IAM, Storage Accounts (CIS Benchmarks).
  * OCI: Evaluación de Tenancy, Compartments, Security Lists, Buckets, VCNs.
* **Módulo Infraestructura & Red**:
  * Orquestación de escaneo de puertos, banners y servicios (Nmap Engine).
  * Análisis de cifrado y certificados SSL/TLS (SSLyze Engine).
* **Módulo Web & APIs (DAST)**:
  * Análisis de vulnerabilidades web (OWASP Top 10) y cabeceras de seguridad.
* **Módulo de Reportes & Cumplimiento**:
  * Generación de informes Word / PDF con matrices de riesgo CVSS v3.1 y mapeo normativo (Ley N° 21.663 / ISO 27001).

---

## 🔒 Despliegue Seguro (Docker)

1. Configurar variables de entorno:
   ```bash
   cp .env.example .env
   # Editar credenciales y parámetros de seguridad
   ```

2. Desplegar servicios con Docker Compose:
   ```bash
   docker compose up -d --build
   ```

---

## 🛡️ Normativa de Seguridad

Este desarrollo implementa los controles estipulados en [SECURITY_GUIDELINES.md](SECURITY_GUIDELINES.md).
