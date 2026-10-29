# EVIDENCIA 07: COMPARATIVA — PROTECCIÓN EN REPOSO VS PROTECCIÓN EN TRÁNSITO

* **Materia:** Gestión de Seguridad y Desempeño de Bases de Datos  
* **Unidad:** II. Seguridad, privacidad y control de acceso  
* **Tema:** 2.4 Cifrado, credenciales y protección de las comunicaciones  
* **Motor:** PostgreSQL 16  
* **Estudiante:** Genaro Isaac Cárdenas Soto (@darksitoV)  
* **Organización / Escenario:** Comercializadora Norte S.A. de C.V.  

---

## 1. Objetivo
Analizar y contrastar de manera sistemática los diferentes mecanismos de protección criptográfica y arquitectónica disponibles en la administración de bases de datos, distinguiendo claramente entre la protección de la información mientras reside almacenada (en reposo) y mientras se transmite a través de la red (en tránsito), así como identificar el vector de ataque específico que cada técnica neutraliza.

---

## 2. Comando o Procedimiento Realizado
Se completó la matriz técnica comparativa estipulada en la Sección 14 del manual de laboratorio, contrastando los requerimientos de confidencialidad, integridad y disponibilidad para cada tipo de elemento sensible dentro del ecosistema de bases de datos.

---

## 3. Resultado Obtenido: Matriz Técnica Comparativa

| Situación / Elemento | Mecanismo Apropiado | Ámbito de Protección | ¿Qué protege? (Vector Mitigado) | ¿Por qué no debe usarse otro mecanismo? |
| :--- | :--- | :---: | :--- | :--- |
| **Contraseña de usuario** | **Derivación de claves con sal (Password Hashing)** con costo ajustable (`Argon2id`, `bcrypt`, `PBKDF2`). En PostgreSQL: `crypt()` + `gen_salt('bf')`. | Reposo / Autenticación | Protege la credencial contra filtraciones masivas de la base de datos (Data Breaches), volcados no autorizados y ataques con tablas precalculadas (Rainbow Tables). | **No debe cifrarse**: Si se cifrara con clave reversible, la obtención de la clave por un atacante expondría todas las contraseñas en claro. La autenticación no requiere leer la contraseña original. |
| **RFC almacenado en una tabla** | **Cifrado en reposo a nivel de columna (Column-level Encryption)** mediante algoritmos simétricos robustos (AES-256 / PGP) o cifrado transparente de base de datos (TDE). En PostgreSQL: `pgp_sym_encrypt()`. | Reposo | Protege la confidencialidad del identificador oficial ante consultas no autorizadas, accesos indebidos de usuarios de la base o sustracción de los archivos de datos (`base/`). | **No debe usarse hash**: El RFC es un dato operativo que **requiere ser recuperado en texto claro** para emitir facturación electrónica (CFDI) y realizar validaciones fiscales con el SAT. |
| **Consulta enviada desde un cliente al servidor** | **Cifrado en tránsito mediante TLS (Transport Layer Security)** versión 1.2 o 1.3 con `sslmode=verify-full`. | Tránsito | Protege las comunicaciones entre aplicaciones/DBAs y el motor contra intercepción pasiva (sniffing de paquetes en red), alteración maliciosa en ruta e intermediarios fraudulentos (Man-in-the-Middle). | **No se mitiga con cifrado de columna**: Si la conexión no usa TLS, el atacante de red puede capturar la clave enviada en la consulta, el usuario/password del handshake o los datos devueltos en claro tras el descifrado. |
| **Respaldo de una base de datos** | **Cifrado de respaldos en reposo** utilizando criptografía asimétrica o simétrica (`gpg`, `openssl enc -aes-256-cbc`, o utilidades nativas de backup cifrado como `pgBackRest` / `WAL-G`). | Reposo (Backup & Disaster Recovery) | Protege todo el dataset institucional contra robo físico de medios de almacenamiento, filtración de buckets en la nube (S3 mal configurados) o copias de seguridad transportadas fuera del datacenter. | **No basta con permisos de archivo**: Los respaldos frecuentemente se mueven a servidores secundarios, cintas o nubes públicas donde los controles de acceso del sistema operativo original dejan de aplicar. |
| **Clave criptográfica** | **Bóvedas de gestión de claves y secretos (KMS - Key Management Service / HSM)** como HashiCorp Vault, AWS KMS o Azure Key Vault, con control estricto de acceso IAM y auditoría. | Gestión y Gobierno | Protege el secreto raíz que permite descifrar toda la información cifrada de la empresa, evitando que termine expuesto en código fuente, repositorios Git, archivos de configuración o logs. | **No debe guardarse en la misma base de datos ni en el repositorio**: Guardar la clave junto con los datos cifrados o en el repositorio equivale a "dejar la llave pegada en la cerradura". |
| *Elemento adicional:* **Tokens de sesión / API Keys** | **Hash criptográfico rápido** (`SHA-256`) o firmado criptográfico asimétrico con expiración breve (JWT con Ed25519/RSA). | Reposo / En tránsito | Protege la autorización de sesiones contra robos de bases de datos que permitirían a un atacante suplantar sesiones activas de usuarios. | Si se almacenan en texto plano en la BD, un volcado permite secuestrar sesiones vigentes de usuarios sin conocer sus contraseñas. |

---

## 4. Análisis Técnico

### 4.1 Principio de Defensa en Profundidad
Ningún mecanismo de la matriz es redundante ni sustituye a los demás; cada uno cubre una fase distinta del ciclo de vida del dato:
```text
[ Cliente / App ]  ──( Cifrado en Tránsito: TLS 1.3 )──►  [ Motor PostgreSQL ]
       │                                                         │
       ▼                                                         ▼
(Gestión de Claves:                                     ( Cifrado en Reposo:
  KMS / Vault)                                             Columna: PGP / AES
                                                           Contraseñas: bcrypt )
                                                                 │
                                                                 ▼
                                                        ( Respaldo Cifrado:
                                                           GPG / pgBackRest )
```

* Si un administrador configura TLS pero almacena las contraseñas en texto claro, un atacante que obtenga un volcado de la base de datos comprometerá todas las cuentas.
* Si el administrador cifra las columnas sensibles con `pgcrypto` pero las consultas se transmiten por una red abierta sin TLS, un atacante capturará el dato descifrado en el tráfico de red mediante herramientas de análisis de paquetes.
* Si el servidor tiene TLS y las columnas están cifradas, pero la clave criptográfica se deja escrita en un archivo `.sql` subido a GitLab, el cifrado queda completamente anulado.

### 4.2 Criterio de Selección de Mecanismos
Para decidir qué técnica utilizar, el DBA debe responder a tres preguntas fundamentales:
1. **¿El dato necesita ser leído en su forma original nuevamente?**
   * *Sí:* Cifrado simétrico o asimétrico (ej. RFC, dirección, saldo).
   * *No:* Hash criptográfico unidireccional con salt (ej. contraseña).
2. **¿Dónde reside el riesgo en este momento?**
   * *En los medios de almacenamiento o volcados:* Cifrado en reposo.
   * *En el cable de red o antenas de transmisión:* TLS / Cifrado en tránsito.
3. **¿Quién tiene la custodia de la clave?**
   * Si la custodia la tiene la base de datos o el código, existe riesgo de divulgación. La custodia debe ser delegada a un componente especializado de gestión de claves.

---

## 5. Conclusión
La protección eficaz de una base de datos requiere una arquitectura multicapa balanceada. El error conceptual más común consiste en creer que "cifrar la base de datos" es una sola acción genérica. Como se demostró en este análisis, proteger contraseñas, proteger columnas fiscales, proteger el tráfico de red y proteger los respaldos son cuatro desafíos de ingeniería distintos que exigen herramientas, estándares y controles de acceso diferenciados.
