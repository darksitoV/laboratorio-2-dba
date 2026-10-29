# EVIDENCIA 10: POLÍTICA INSTITUCIONAL DE PROTECCIÓN DE CLAVES CRIPTOGRÁFICAS

* **Materia:** Gestión de Seguridad y Desempeño de Bases de Datos  
* **Unidad:** II. Seguridad, privacidad y control de acceso  
* **Tema:** 2.4 Cifrado, credenciales y protección de las comunicaciones  
* **Motor:** PostgreSQL 16  
* **Estudiante:** Genaro Isaac Cárdenas Soto (@darksitoV)  
* **Organización / Escenario:** Comercializadora Norte S.A. de C.V.  
* **Documento Normativo:** POL-SEG-BD-002 — Gestión del Ciclo de Vida de Claves Criptográficas  

---

## 1. Objetivo
Establecer un marco normativo obligatorio y verificable compuesto por 8 reglas fundamentales que rijan la generación, almacenamiento, control de acceso, rotación periódica, respaldo seguro, revocación, contingencia ante divulgación accidental y destrucción definitiva de todas las claves criptográficas empleadas en la protección de bases de datos de Comercializadora Norte S.A. de C.V.

---

## 2. Marco de Aplicación y Alcance
Esta política es de observancia obligatoria para administradores de bases de datos (DBAs), arquitectos de software, desarrolladores de backend, operadores de infraestructura en la nube y personal de operaciones de TI que interactúen con bases de datos transaccionales, analíticas o respaldos de la organización.

---

## 3. Resultado Obtenido: Decálogo de Reglas Normativas

### Regla 1 — Generación Segura de Claves (Entropy & Strength)
* **Enunciado:** Todas las claves criptográficas simétricas y asimétricas deben generarse exclusivamente a través de generadores de números pseudoaleatorios criptográficamente seguros (CSPRNG) certificados bajo estándares FIPS 140-3 o NIST SP 800-90A.
* **Criterio técnico:** Queda terminantemente prohibido generar claves a partir de funciones predecibles (`random()`, timestamps) o frases elegidas manualmente por humanos. Las claves simétricas para cifrado en reposo deben ser AES con una longitud mínima de 256 bits (`AES-256-GCM`). Para claves asimétricas de transporte o firma, la longitud mínima será RSA de 3072 bits o curvas elípticas Ed25519 / NIST P-384.

### Regla 2 — Almacenamiento Aislado en Bóvedas Dedicadas (Storage Isolation)
* **Enunciado:** Las claves criptográficas jamás deben almacenarse en el mismo medio físico, volumen de disco, esquema de base de datos o repositorio de código que contiene los datos que protegen.
* **Criterio técnico:** Las claves maestras deben custodiarse exclusivamente en un Módulo de Seguridad de Hardware (HSM) o en un Servicio de Administración de Claves (KMS) institucional (ej. HashiCorp Vault, AWS KMS, Azure Key Vault). Ninguna clave criptográfica debe existir como texto claro en archivos de configuración locales, scripts `.sql` o imágenes de contenedores.

### Regla 3 — Prohibición Absoluta de Secretos en Control de Versiones (No Secrets in Git)
* **Enunciado:** Ninguna clave criptográfica, certificado privado, token de API o contraseña (real o temporal) podrá ser incorporada en repositorios de Git, independientemente de que el repositorio sea privado, restringido o local.
* **Criterio técnico:** Los pipelines de CI/CD de GitLab/GitHub deben ejecutar herramientas de análisis estático de secretos (*Secret Detection / GitGuardian / Gitleaks*) de manera obligatoria y bloqueante (*pre-receive hooks*). Cualquier commit que contenga cadenas coincidentes con patrones de claves provocará el rechazo automático del `git push`.

### Regla 4 — Control de Acceso Estricto y Principio de Mínimo Privilegio (Least Privilege Access)
* **Enunciado:** El acceso para solicitar operaciones de cifrado/descifrado a la bóveda de claves se concederá únicamente a identidades de servicio de aplicaciones acreditadas mediante autenticación mutua (mTLS) o roles IAM efímeros.
* **Criterio técnico:** Se establece el principio de **Separación de Funciones (Separation of Duties)**: el rol de DBA no tendrá acceso a exportar las claves de la bóveda de seguridad, y el Oficial de Seguridad de la Información (CISO) no tendrá privilegios para consultar directamente los registros de la base de datos. Ningún usuario humano tendrá acceso de lectura directo a claves maestras de producción.

### Regla 5 — Rotación Periódica Programada (Key Rotation Lifecycle)
* **Enunciado:** Todas las claves criptográficas activas utilizadas para proteger datos en reposo deberán rotarse automáticamente de acuerdo con un ciclo de vida definido por su criticidad.
* **Criterio técnico:**
  * Claves de cifrado de columnas de datos sensibles (RFC, datos financieros): rotación obligatoria cada **180 días**.
  * Certificados TLS de servidor: rotación anual (**365 días**) o automatizada mediante protocolo ACME cada 90 días.
  * Para datos ya almacenados, se debe utilizar el modelo de **Cifrado Envolvente (Envelope Encryption)** con Claves Maestras (KEK - Key Encryption Key) y Claves de Datos (DEK - Data Encryption Key), permitiendo rotar la KEK sin requerir re-cifrar físicamente terabytes de datos históricos.

### Regla 6 — Respaldo Seguro y Custodia Dividida (Escrow & Secret Sharing)
* **Enunciado:** El respaldo de las claves maestras de cifrado de la organización debe almacenarse en bóvedas fuera de línea (Cold Storage / Air-gapped), completamente separadas de la infraestructura de producción.
* **Criterio técnico:** La clave maestra de recuperación ante desastres (Disaster Recovery) debe protegerse mediante el esquema de **División de Secretos de Shamir ($m$-de-$n$)**, requiriendo la presencia simultánea de al menos 3 de 5 custodios autorizados (Director General, CISO, Líder de Infraestructura, Abogado General, Auditor Interno) para reconstituir la clave en caso de contingencia mayor.

### Regla 7 — Protocolo Inmediato de Revocación y Exposición Accidental (Breach Response)
* **Enunciado:** Ante cualquier sospecha, indicio o confirmación de divulgación no autorizada de una clave criptográfica (como un commit accidental en Git, una fuga de logs o un compromiso de servidor), la clave afectada se considerará **comprometida de inmediato**.
* **Criterio técnico:**
  1. Revocación inmediata de la clave en la bóveda KMS en un plazo menor a 15 minutos.
  2. Generación inmediata de una nueva clave activa.
  3. Ejecución de un proceso de re-cifrado de emergencia de los datos afectados.
  4. Invalidación de sesiones y tokens activos dependientes de la clave.
  5. Registro formal en la bitácora forense de incidentes y purga exhaustiva del historial de Git con `git-filter-repo`.

### Regla 8 — Destrucción Criptográfica Definitiva (Cryptographic Erasure / Sanitization)
* **Enunciado:** Cuando una clave criptográfica cumpla su ciclo de retención o los datos protegidos por ella deban eliminarse conforme al derecho de cancelación o políticas de retención, la clave debe destruirse de manera irreversible.
* **Criterio técnico:** Se aplicará el estándar de **Borrado Criptográfico (Crypto-Shredding)** conforme a la directriz NIST SP 800-88 Rev. 1. La destrucción física o lógica de la clave en el HSM/KMS vuelve el texto cifrado residual matemáticamente irrecuperable de forma instantánea, garantizando la eliminación efectiva de los datos sin requerir sobreescritura sector por sector de los medios de almacenamiento.

---

## 4. Matriz de Roles y Responsabilidades (RACI)

| Actividad / Regla | Oficial de Seguridad (CISO) | Administrador de BD (DBA) | Desarrollador Backend | Auditoría Interna |
| :--- | :---: | :---: | :---: | :---: |
| **Generación de Claves (R1)** | Responsable (R) | Consultado (C) | Consultado (C) | Informado (I) |
| **Administración del KMS (R2)** | Responsable (R) | Aprobador (A) | Informado (I) | Auditor (I) |
| **Prevención en Repositorios (R3)** | Aprobador (A) | Consultado (C) | Responsable (R) | Auditor (I) |
| **Control de Acceso IAM (R4)** | Responsable (R) | Aprobador (A) | Consultado (C) | Auditor (I) |
| **Ejecución de Rotación (R5)** | Aprobador (A) | Responsable (R) | Consultado (C) | Informado (I) |
| **Custodia de Respaldo DR (R6)** | Responsable (R) | Aprobador (A) | No Aplica | Consultado (C) |
| **Respuesta a Incidentes (R7)** | Responsable (R) | Responsable (R) | Consultado (C) | Aprobador (A) |
| **Crypto-Shredding (R8)** | Aprobador (A) | Responsable (R) | No Aplica | Auditor (I) |

---

## 5. Conclusión
El eslabón más débil de un esquema de cifrado es invariablemente la gestión humana y operativa de sus secretos. La presente política garantiza que Comercializadora Norte S.A. de C.V. no dependa de la memoria ni de la buena voluntad de los desarrolladores o administradores, sino de controles automáticos, bóvedas criptográficas especializadas y procedimientos inmutables que aseguren la confidencialidad a lo largo de todo el ciclo de vida del dato.
