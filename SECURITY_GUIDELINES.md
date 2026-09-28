# 🛡️ Guía de Desarrollo Seguro y Buenas Prácticas (DevSecOps)
## Sistema de Gestión de Seguridad de la Información (SGSI) & SOC SERMIG 2026

Dado que este sistema es la pieza central para **monitorear, auditar y resguardar la seguridad de la información del Servicio Nacional de Migraciones (SERMIG)**, todo código nuevo o modificado debe regirse bajo los siguientes principios inviolables de desarrollo seguro (OWASP Top 10, CIS Benchmarks e ISO/IEC 27001:2022).

---

### 📌 1. Reglas de Oro de Codificación Segura (Backend & Python)

#### A. Gestión Cero Secretos (Zero Hardcoded Secrets)
* ❌ **Prohibido:** Escribir contraseñas, tokens JWT, API keys, credenciales de base de datos o URLs con credenciales en archivos `.py`, `.yml`, `.json` o plantillas.
* ✅ **Obligatorio:** Utilizar variables de entorno (`os.getenv(...)` o archivos `.env` ignorados en `.gitignore`). Documentar variables en `.env.example`.

#### B. Prevención Estricta de SSRF (Server-Side Request Forgery)
* ❌ **Prohibido:** Usar `urllib.request.urlopen` con URLs proporcionadas por usuarios o webhooks sin sanitizar.
* ❌ **Prohibido:** Permitir peticiones salientes a esquemas no seguros (`http://`, `file://`, `gopher://`).
* ✅ **Obligatorio:** Toda petición HTTP externa debe:
  1. Forzar esquema **HTTPS** (`https://`).
  2. Validar una **Allowlist de dominios autorizados** (ej. `*.google.com`, `*.serviciomigraciones.cl`).
  3. Realizar **resolución DNS previa** y bloquear rangos privados (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`) y direcciones reservadas usando `ipaddress`.
  4. Configurar siempre un **timeout explícito** (`timeout=5.0` o similar) para evitar denegaciones de servicio (DoS).

#### C. Cifrado y Verificación TLS/SSL
* ❌ **Prohibido:** Dejar `verify=False` en peticiones `requests` o `httpx`.
* ✅ **Obligatorio:** Mantener `verify=True` por defecto. En conexiones internas con certificados institucionales o autofirmados (ej. Wazuh o GLPI), permitir especificar la ruta del bundle CA institucional (`verify=ssl_ca_path`) o bandera configurable.

#### D. Consultas a Base de Datos y Parámetros
* ❌ **Prohibido:** Concatenar strings o usar `f-strings` para construir queries SQL.
* ✅ **Obligatorio:** Usar SQLAlchemy ORM o consultas parametrizadas (`execute("SELECT ... WHERE id = :id", {"id": id})`).

---

### 🐳 2. Seguridad en Infraestructura y Contenedores (Docker & Nginx)

#### A. Principio de Menor Privilegio (Non-Root User)
* ❌ **Prohibido:** Ejecutar aplicaciones Docker como usuario `root`.
* ✅ **Obligatorio:** Definir un usuario de sistema sin privilegios en el `Dockerfile` (`USER sgsiapp`).

#### B. Aislamiento de Red de Base de Datos
* ❌ **Prohibido:** Publicar puertos de bases de datos al host (`ports: "5432:5432"` o `ports: "127.0.0.1:5432:5432"`).
* ✅ **Obligatorio:** La base de datos debe comunicarse exclusivamente a través de la red interna bridge de Docker (`networks: [sgsi_net]`).

#### C. Hardening del Runtime de Contenedores
* ✅ **Obligatorio:** Configurar en `docker-compose.yml`:
  - `security_opt: - no-new-privileges:true` (previene elevación de privilegios `setuid`).
  - `tmpfs: [/tmp]` (sistemas de archivos temporales en memoria sin persistencia de malware).

#### D. Servidor Web y Proxy Reverso (Nginx)
* ✅ **Obligatorio:**
  - Mitigación de H2C Request Smuggling vía `map $http_upgrade $connection_upgrade`.
  - Cabeceras de seguridad activas: `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` (HSTS), `Referrer-Policy` y `Permissions-Policy`.

---

### 🎨 3. Seguridad en Frontend (HTML & JavaScript)

#### A. Integridad de Recursos Externos (SRI & CDNs)
* ❌ **Prohibido:** Incluir scripts o estilos de CDNs externos sin hash de verificación.
* ✅ **Obligatorio:** Incluir siempre atributos criptográficos:
  ```html
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/.../all.min.css" integrity="sha512-..." crossorigin="anonymous" referrerpolicy="no-referrer">
  ```
* ✅ **Recomendado:** Alojar librerías estáticas críticas directamente en el servidor local (`/static/js/`, `/static/css/`).

#### B. Prevención de Cross-Site Scripting (XSS)
* ❌ **Prohibido:** Usar `innerHTML` o `document.write` con datos provenientes del usuario o APIs sin sanitizar.
* ✅ **Obligatorio:** Usar `textContent`, `innerText` o plantillas Jinja2 con autoescape activo.

---

### ⚙️ 4. Seguridad en CI/CD y Dependencias (GitHub Actions)

#### A. Inmutabilidad en Acciones (SHA Pinning)
* ❌ **Prohibido:** Usar tags mutables (`uses: actions/checkout@v4` o `@main`).
* ✅ **Obligatorio:** Fijar siempre el hash completo de commit SHA de 40 caracteres:
  ```yaml
  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  ```

#### B. Permisos Mínimos de Flujo
* ✅ **Obligatorio:** Declarar `permissions: contents: read` a nivel de workflow para evitar que tokens de GitHub Actions tengan privilegios de escritura no deseados.

#### C. Escaneo Automatizado Continuo en cada Push / PR
El pipeline `.github/workflows/audit.yml` ejecuta automáticamente:
1. **Semgrep**: Análisis estático de patrones de seguridad y lógica OWASP.
2. **Bandit**: Detección de vulnerabilidades de seguridad en Python.
3. **pip-audit**: Detección de vulnerabilidades CVE en librerías de `requirements.txt`.
4. **Ruff**: Verificación de calidad, formato y estilo de código.

---

### ✅ Checklist Rápido de Pre-Commit para Desarrolladores

Antes de realizar `git commit` y `git push`:
- [ ] ¿Hay contraseñas, tokens o secretos en el código? **(No)**
- [ ] ¿Toda petición HTTP externa usa HTTPS con timeout y validación anti-SSRF? **(Sí)**
- [ ] ¿Las consultas SQL están parametrizadas? **(Sí)**
- [ ] ¿Se añadieron CDNs sin atributos `integrity` / `crossorigin`? **(No)**
- [ ] ¿La sintaxis de Python compila sin errores (`python -m py_compile ...`)? **(Sí)**
- [ ] ¿El contenedor mantiene el usuario no-root `sgsiapp`? **(Sí)**
