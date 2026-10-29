# EVIDENCIA 08: ANÁLISIS DE ESCENARIO DE SEGURIDAD

* **Materia:** Gestión de Seguridad y Desempeño de Bases de Datos  
* **Unidad:** II. Seguridad, privacidad y control de acceso  
* **Tema:** 2.4 Cifrado, credenciales y protección de las comunicaciones  
* **Motor:** PostgreSQL 16  
* **Estudiante:** Genaro Isaac Cárdenas Soto (@darksitoV)  
* **Organización / Escenario:** Comercializadora Norte S.A. de C.V.  

---

## 1. Objetivo
Evaluar integralmente la postura de seguridad de una organización corporativa (Comercializadora Norte S.A. de C.V.) en la que coexisten mecanismos correctos de control de acceso lógico (usuarios y roles) con vulnerabilidades críticas en el almacenamiento de credenciales, exposición de información sensible, comunicaciones de red no validadas, almacenamiento inseguro de secretos y respaldos desprotegidos.

---

## 2. Descripción del Escenario Evaluado
La empresa almacena dentro de su infraestructura de PostgreSQL los siguientes activos:
1. `nombre` (Identificador directo)
2. `correo electrónico` (Identificador directo y contacto)
3. `contraseña` (Credencial de acceso)
4. `rfc` (Identificador fiscal regulado)
5. `información financiera` (Cuentas bancarias y saldos)
6. `claves criptográficas` (Secretos del sistema)

A pesar de que el equipo de TI implementó roles y privilegios de usuario (`GRANT` / `REVOKE`) adecuadamente, una auditoría técnica identificó las siguientes cinco fallas graves:
* **Falla A:** Las contraseñas están almacenadas en texto claro en la tabla de usuarios.
* **Falla B:** El RFC y la información financiera se almacenan en texto claro sin controles criptográficos en reposo.
* **Falla C:** Las conexiones cliente-servidor se efectúan sin validación adecuada de la identidad del servidor (`sslmode=prefer` o `disable`).
* **Falla D:** Las claves criptográficas aparecen escritas directamente dentro de scripts SQL y archivos de código fuente.
* **Falla E:** Los respaldos periódicos de la base de datos se generan y almacenan sin cifrado adicional.

---

## 3. Resultado Obtenido: Respuestas y Evaluación Técnica

### 3.1 Pregunta 1: ¿Cuáles son los principales riesgos derivados de esta situación?
1. **Robo y suplantación masiva de identidades (Credenciales en claro):** Ante cualquier volcado accidental, acceso indebido o backup filtrado, un atacante obtiene las contraseñas de todos los clientes y administradores, permitiendo el secuestro inmediato de cuentas tanto dentro de la plataforma como en otros servicios externos donde los usuarios reutilicen contraseñas.
2. **Exfiltración masiva de datos fiscales y bancarios (RFC y finanzas en claro):** Cualquier usuario con privilegios de lectura básicos, un desarrollador o un atacante con SQLi puede exportar la base completa, provocando fraude financiero, robo de identidad y sanciones por incumplimiento de la LFPDPPP y del secreto bancario.
3. **Ataques Man-in-the-Middle y robo de sesiones en tránsito (Sin TLS estricto):** Al carecer de validación fuerte de certificados, un atacante ubicado en la red corporativa o un proveedor de telecomunicaciones puede interceptar el tráfico mediante *ARP Spoofing*, inyectar consultas fraudulentas y capturar datos confidenciales en tiempo real.
4. **Compromiso total de la criptografía por hardcoding (Claves en scripts SQL):** Si las claves residen en scripts, cualquier persona con acceso al control de versiones (GitLab), al historial de la terminal o a los respaldos puede anular todas las capas criptográficas que dependan de esas claves.
5. **Filtración silenciosa en la cadena de custodia (Respaldos sin cifrado):** Los archivos de backup (`pg_dump`) circulan entre servidores de almacenamiento, discos externos o almacenamiento en la nube; si caen en manos de un tercero no autorizado, el atacante tiene la base de datos entera sin necesidad de vulnerar el servidor de producción.

---

### 3.2 Pregunta 2: ¿Qué mecanismo utilizarías para cada uno de los elementos?

| Elemento | Mecanismo de Seguridad Recomendado | Justificación Técnica y Operativa |
| :--- | :--- | :--- |
| **Nombre** | **Control de Acceso basado en Roles (RBAC) + Enmascaramiento dinámico** para perfiles no administrativos. | Es un identificador directo necesario para la operación diaria; no suele cifrarse a nivel de columna para permitir búsquedas operativas e indexación eficiente. |
| **Correo Electrónico** | **RBAC + Enmascaramiento dinámico (vistas)** para soporte, y canal seguro TLS en tránsito. | Permite validar al titular ocultando el usuario (`an*****@dominio.com`) sin obstaculizar las notificaciones automáticas de la aplicación. |
| **Contraseña** | **Derivación de claves con salt (Password Hashing)** mediante algoritmos modernos como **Argon2id** o **bcrypt** (factor de costo 12+). | La contraseña jamás debe poder revertirse; solo se comprueba el hash en el proceso de inicio de sesión. |
| **RFC** | **Cifrado en reposo a nivel de columna (Column-level Encryption)** con `pgcrypto` (`pgp_sym_encrypt`) o Transparent Data Encryption (TDE). | Es un dato sensible que debe recuperarse para facturar electrónicamente, pero que debe permanecer ilegible en caso de lecturas no autorizadas directas. |
| **Información Financiera** | **Cifrado asimétrico / simétrico en reposo (AES-256-GCM / PGP)** + segregación estricta de esquemas y permisos SoD. | Requiere el más alto nivel de confidencialidad para cumplir con normativas de protección de datos financieros. |
| **Claves Criptográficas** | **Bóveda de gestión de claves externa (KMS / HSM / HashiCorp Vault)** con inyección en tiempo de ejecución. | Las claves deben vivir fuera del motor de base de datos y fuera del repositorio, con políticas de rotación programada y auditoría inmutable de accesos. |
| **Comunicaciones de Red** | **Cifrado en tránsito obligatorio con TLS 1.3** y directiva `sslmode=verify-full`. | Garantiza confidencialidad, autenticidad del servidor e integridad de los paquetes durante la transmisión entre clientes y PostgreSQL. |
| **Respaldos de Base de Datos** | **Cifrado de backups mediante llaves asimétricas públicas** (`pgBackRest`, `gpg -e -r dba-backup`). | Permite que el servidor cree respaldos cifrados con la clave pública, pero solo la dirección de TI con la clave privada puede descifrarlos en caso de desastre. |

---

### 3.3 Pregunta 3: ¿Cuál de los problemas consideras más crítico y por qué?
**El problema más crítico es la presencia de claves criptográficas dentro de archivos SQL y código fuente (Falla D), junto con el almacenamiento de contraseñas en texto claro (Falla A).**

* **Justificación técnica:**  
  La presencia de claves en scripts destruye el principio fundamental de Kerckhoffs: *"la seguridad de un sistema criptográfico debe depender exclusivamente de mantener en secreto la clave, no el algoritmo"*. Cuando la clave está hardcodeada, el cifrado se convierte en una **ilusión de seguridad**: no importa qué tan avanzado sea el algoritmo (AES-256, RSA), cualquier persona con acceso al archivo o al historial de Git tiene acceso total a los datos.  
  Asimismo, almacenar contraseñas en claro genera un riesgo de compromiso inmediato de cuentas que trasciende la propia empresa, afectando la vida digital de los usuarios.

---

### 3.4 Pregunta 4: ¿Tener correctamente configurados los usuarios y permisos elimina estos riesgos? Justifica tu respuesta.
**NO. Rotundamente NO.**  
El Control de Acceso Basado en Roles (RBAC / `GRANT` / `REVOKE`) es una condición necesaria pero **totalmente insuficiente** para garantizar la seguridad de la información. La justificación técnica radica en:

1. **Incapacidad ante vectores fuera del motor de base de datos:** Los permisos de PostgreSQL solo regulan las consultas enviadas al motor en tiempo de ejecución. No ofrecen ninguna protección si alguien sustrae el archivo de respaldo (`pg_dump`), accede físicamente a los bloques de disco (`base/`) o clona una máquina virtual.
2. **Incapacidad contra la intercepción en la red:** Si un usuario legítimo ejecuta una consulta autorizada sobre datos en claro a través de una red sin TLS, un espía de red captura los datos sin violar los permisos de la base de datos.
3. **El superusuario y la cuenta de servicio como punto de quiebre:** Cualquier atacante que logre escalar privilegios o comprometer las credenciales del usuario de la aplicación (`app_user`) o del superusuario (`postgres`) tiene acceso irrestricto a todas las tablas. Si los datos sensibles no están cifrados, la brecha es total.
4. **Vulnerabilidad ante inyección de código (SQLi):** En un ataque de Inyección SQL, la consulta maliciosa se ejecuta con los privilegios legítimos de la aplicación backend, evadiendo por completo las restricciones pensadas para usuarios humanos.

---

## 4. Análisis y Plan de Remediación Priorizado

```text
Prioridad 1 (Inmediata - 24 horas):
├── 1. Detener el hardcoding de claves: Extraer claves de archivos SQL y migrarlas a variables de entorno / Vault.
├── 2. Migrar contraseñas de texto plano a hashes con bcrypt/Argon2id con salt único.
│
Prioridad 2 (Corto Plazo - 72 horas):
├── 3. Habilitar TLS 1.3 en PostgreSQL con certificados válidos y configurar hostssl en pg_hba.conf.
├── 4. Cifrar los respaldos lógicos y físicos antes de depositarlos en repositorios de almacenamiento.
│
Prioridad 3 (Mediano Plazo - 2 semanas):
├── 5. Cifrar a nivel de columna el RFC y la información bancaria sensible con pgcrypto / TDE.
└── 6. Implementar análisis estático automatizado en GitLab CI/CD para detectar secretos antes de cada commit.
```

---

## 5. Conclusión
El caso de Comercializadora Norte S.A. de C.V. ilustra de forma paradigmática por qué la seguridad en bases de datos debe abordarse bajo el modelo de **Defensa en Profundidad (Defense-in-Depth)**. La correcta gestión de usuarios y roles protege el perímetro transaccional, pero sin cifrado en reposo, derivación de contraseñas, TLS estricto y una bóveda de claves externa, la base de datos continúa siendo extraordinariamente vulnerable a filtraciones catastróficas.
