# LAB-02 — Cifrado, credenciales y comunicaciones seguras

* **Materia:** Gestión de Seguridad y Desempeño de Bases de Datos  
* **Unidad:** II. Seguridad, privacidad y control de acceso  
* **Tema:** 2.4 Cifrado, credenciales y protección de las comunicaciones  
* **Motor:** PostgreSQL 16 (Contenedor Podman)  
* **Estudiante:** Genaro Isaac Cárdenas Soto (@darksitoV)  
* **Organización Evaluada:** Comercializadora Norte S.A. de C.V.  

---

## 1. Descripción de la Práctica
Este repositorio contiene la implementación técnica integral del **Laboratorio 02: Cifrado, credenciales y comunicaciones seguras** para la empresa *Comercializadora Norte S.A. de C.V.*, desarrollado sobre **PostgreSQL 16**.

El objetivo central es diseñar, aplicar y auditar mecanismos criptográficos y defensivos indispensables en la administración de bases de datos para mitigar tres vulnerabilidades críticas:
1. **Credenciales expuestas:** Sustitución de contraseñas en texto claro por funciones de derivación criptográfica unidireccionales lentas con sal aleatoria (`bcrypt`/`crypt`).
2. **Datos sensibles sin cifrado:** Implementación de cifrado simétrico en reposo a nivel de columna (`pgp_sym_encrypt`) para proteger identificadores fiscales recuperables (RFC).
3. **Comunicaciones no protegidas:** Configuración, auditoría y verificación del cifrado de canal en tránsito mediante **TLS 1.3** y análisis estricto de parámetros de conexión (`sslmode=verify-full`).

---

## 2. Estructura del Repositorio

Conforme a lo especificado en la Sección 20 del manual oficial de la práctica:

```text
laboratorio-2-dba/
├── .gitignore                          # Protección estricta contra subida de secretos y certificados
├── README.md                           # Presentación ejecutiva del proyecto y secciones del informe
├── informe.md                          # Informe técnico exhaustivo y respuestas a preguntas de reflexión (Sección 23)
├── sql/                                # Scripts SQL listos para ejecución y auditoría
│   ├── 01-credenciales.sql             # Demostración antipatrón, hash con sal Blowfish y autenticación
│   ├── 02-cifrado-datos.sql            # Tabla protegida BYTEA, pgp_sym_encrypt y recuperación autorizada
│   └── 03-verificacion-tls.sql         # Parámetros SHOW ssl, endpoints y diagnóstico de pg_stat_ssl
└── evidencias/                         # Documentación técnica con comandos, resultados y análisis
    ├── img/                            # Capturas de ejecución en terminal (PNG de alta resolución)
    ├── 01-credenciales.md              # Evidencia de hash irreversible y autenticación booleana
    ├── 02-cifrado-datos.md             # Evidencia de cifrado simétrico y fallo ante clave errónea
    ├── 03-gestion-claves.md            # Auditoría contra hardcoded secrets y regla 9.2 (no secretos en Git)
    ├── 04-tls.md                       # Auditoría de TLS en tránsito y análisis comparativo de sslmode
    ├── 07-comparacion.md               # Matriz técnica: protección en reposo vs protección en tránsito
    ├── 08-analisis-escenario.md        # Caso Comercializadora Norte y análisis de defensa en profundidad
    └── 10-politica-claves.md           # Política institucional POL-SEG-BD-002 (decálogo de reglas KMS)
```

---

## 3. Resumen Ejecutivo del Informe Técnico (Sección 22)

### 3.1 Introducción
La seguridad de una base de datos no puede descansar únicamente en el control de acceso lógico (roles y permisos). Un sistema con privilegios bien definidos sigue expuesto a filtraciones catastróficas si los datos en reposo, las credenciales de acceso, los respaldos y los flujos de red viajan en texto claro o si las claves maestras se encuentran hardcodeadas en scripts de consulta.

### 3.2 Protección de Credenciales
* **Texto Claro:** Almacenar contraseñas legibles (`'Password123'`) es una negligencia crítica que compromete todas las cuentas ante cualquier volcado o inyección SQL.
* **Cifrado Reversible:** No debe utilizarse para contraseñas, pues la clave de descifrado se vuelve un punto único de falla catastrófica.
* **Hash con Sal (`bcrypt` / `crypt` + `gen_salt('bf')`):** Transforma la contraseña de forma unidireccional y computacionalmente costosa. La sal única impide ataques con tablas arcoíris (*Rainbow Tables*). La verificación se realiza recalculando el hash con la misma sal sin requerir recuperar la contraseña en claro.

### 3.3 Protección de Datos Sensibles
Se protegió el **RFC** en la tabla `clientes_protegidos` mediante la extensión `pgcrypto` y cifrado simétrico `pgp_sym_encrypt()` almacenado en columnas `BYTEA`. A diferencia de las contraseñas, el RFC **requiere recuperación legítima** en texto plano para la facturación electrónica ante el SAT, justificando el uso de cifrado bidireccional y denegando descifrados con claves incorrectas.

### 3.4 TLS y Comunicaciones Seguras
El protocolo **TLS (Transport Layer Security)** asegura el canal de comunicación entre clientes y PostgreSQL, garantizando confidencialidad (antiespionaje), integridad y autenticación del servidor. Se auditó la vista `pg_stat_ssl`, identificando la suite `TLS_AES_256_GCM_SHA384` y fundamentando la exigencia de `sslmode=verify-full` para impedir ataques de hombre en el medio (MitM) y suplantación de identidad.

### 3.5 Gestión de Claves Criptográficas
Colocar claves dentro de archivos SQL (`hardcoded secrets`) es un error gravísimo que las propaga al historial inmutable de Git, logs del motor y memorias de sesión. Las claves deben vivir en un Gestor de Secretos independiente (KMS / HashiCorp Vault) con rotación automática cada 180 días, segregación estricta de funciones y borrado criptográfico seguro (Crypto-Shredding).

### 3.6 Resultados Clave
* Erradicación de credenciales en claro mediante tablas con hashes protegidos.
* Blindaje de PII fiscal en reposo bajo estándar OpenPGP.
* Diagnóstico riguroso de parámetros TLS en PostgreSQL.
* Generación del decálogo normativo de gestión de claves y matriz integral de riesgos.

### 3.7 Problemas Encontrados y Soluciones
* **Estado inicial de TLS:** La imagen base de PostgreSQL en contenedores inicializa con `ssl=off`. Se documentó la generación de certificados X.509 (`server.crt` / `server.key`) para habilitar `ssl=on`.
* **Exposición en consultas:** Se determinó que el descifrado simétrico no debe ejecutarse con literales en consultas abiertas, sino en la capa de aplicación o mediante variables de sesión efímeras.
* **Eliminación de archivos demostrativos:** Se depuró el archivo temporal `sql/ejemplo-mala-practica.sql` antes de la entrega final conforme a la Regla 9.2.

### 3.8 Conclusiones
La criptografía moderna es matemáticamente sólida; las brechas reales ocurren casi invariablemente por debilidades en la custodia de claves o por la creencia errónea de que una sola técnica resuelve todos los vectores de amenaza. La postura de seguridad del DBA debe ser holística, aplicando **Defensa en Profundidad**.

---

## 4. Consulta del Informe Completo y Evidencias
Para consultar el desarrollo exhaustivo de cada actividad, justificaciones técnicas formales y las respuestas a las 10 preguntas de reflexión de la Sección 23, diríjase a:
* **[informe.md](file:///c:/Users/darks/OneDrive/Escritorio/dba/laboratorio-2-dba/informe.md)**
* **Carpeta de Evidencias:** [evidencias/](file:///c:/Users/darks/OneDrive/Escritorio/dba/laboratorio-2-dba/evidencias/)
