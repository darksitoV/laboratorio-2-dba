# INFORME TÉCNICO: LABORATORIO 02 — CIFRADO, CREDENCIALES Y COMUNICACIONES SEGURAS

* **Materia:** Gestión de Seguridad y Desempeño de Bases de Datos  
* **Unidad:** II. Seguridad, privacidad y control de acceso  
* **Tema:** 2.4 Cifrado, credenciales y protección de las comunicaciones  
* **Motor:** PostgreSQL 16 (Desplegado en Contenedores Podman / Alpine)  
* **Estudiante:** Genaro Isaac Cárdenas Soto (@darksitoV)  
* **Organización / Escenario:** Comercializadora Norte S.A. de C.V.  

---

## 1. INTRODUCCIÓN Y CONTEXTO OPERATIVO

La seguridad en una base de datos corporativa no concluye con la delimitación de roles, usuarios y esquemas de permisos lógicos. Un sistema gestor de bases de datos puede exhibir una configuración estricta de control de acceso perimetral y, simultáneamente, sufrir una exposición catastrófica de información si las contraseñas se almacenan en texto plano, si los datos personales regulados residen legibles en disco, si los canales de comunicación de red carecen de cifrado autenticado, o si las claves maestras se encuentran hardcodeadas en scripts de consulta.

En este segundo laboratorio práctico para la empresa ficticia **Comercializadora Norte S.A. de C.V.**, se diseñaron, implementaron y evaluaron controles criptográficos fundamentales en **PostgreSQL 16** organizados en tres frentes operacionales:
1. **Protección de Credenciales (Autenticación Robusta):** Eliminación del almacenamiento en texto claro mediante derivación de claves irreversibles con salt único (`pgcrypto`).
2. **Protección de Información Sensible en Reposo (Cifrado Columna):** Cifrado simétrico de datos que requieren recuperación autorizada bajo justificación de negocio (RFC).
3. **Protección de Comunicaciones en Tránsito (Cifrado TLS):** Análisis y verificación del cifrado de canal entre clientes y el motor PostgreSQL mediante TLS 1.3/1.2 y evaluación de los niveles de validación de identidad (`sslmode`).

---

## 2. PROTECCIÓN DE CREDENCIALES

### 2.1 Distinción entre Texto Claro, Hash y Cifrado
Una de las confusiones conceptuales más graves en ingeniería de software y administración de datos consiste en equiparar *hash* con *cifrado*. Durante la práctica se contrastaron sus propiedades:

* **Texto Claro (Plaintext):** La credencial se almacena tal como fue digitada por el usuario (`'Password123'`). Cualquier lectura no autorizada (por volcado de backup, acceso a la tabla `usuarios_insegura` o SQL Injection) compromete inmediatamente la cuenta.
* **Cifrado (Encryption):** Transformación criptográfica reversible mediante el uso de una clave secreta. Es bidireccional ($C = E_k(P)$, $P = D_k(C)$). **No debe utilizarse para contraseñas**, porque si un atacante obtiene la clave de descifrado, obtendrá todas las contraseñas en claro de la organización.
* **Hash / Derivación de Clave (Password Hashing):** Función matemática unidireccional no invertible ($H = hash(P + Salt)$) diseñada específicamente para ser computacionalmente costosa. La contraseña original no se conserva en ningún punto del sistema; la autenticación se valida contrastando si el hash del intento coincide con el hash almacenado.

### 2.2 Implementación Técnica con `pgcrypto`
Se implementó la función `crypt(password, gen_salt('bf'))`, la cual utiliza el algoritmo **Blowfish/bcrypt**:
* **Función de la Sal (`gen_salt`):** Introduce una cadena pseudoaleatoria única por cada registro. Esto garantiza que dos usuarios con contraseñas idénticas tengan hashes radicalmente distintos, neutralizando ataques basados en tablas arcoíris (*Rainbow Tables*).
* **Mecanismo de Verificación:** Al evaluar `password_hash = crypt('Password123', password_hash)`, la función `crypt` extrae automáticamente la sal del hash previo y la reutiliza para computar el hash sobre el intento. Si coinciden, devuelve `true` sin haber revelado ni recuperado jamás la contraseña original.

---

## 3. PROTECCIÓN DE DATOS SENSIBLES EN REPOSO

### 3.1 Información Protegida y Justificación
Se tomó como caso de estudio el **RFC (Registro Federal de Contribuyentes)** de los clientes de *Comercializadora Norte S.A. de C.V.*, almacenado en la tabla `clientes_protegidos` dentro de una columna de tipo `BYTEA` (`rfc_cifrado`).

* **¿Por qué protegerlo?** El RFC es un identificador tributario y fiscal oficial único en México que contiene la fecha de nacimiento, iniciales y homoclave del titular. Su exposición facilita la suplantación de identidad fiscal y fraudes de facturación.
* **¿Por qué cifrado y no hash?** Porque el RFC es un dato operativo que **requiere ser recuperado en texto claro** por los sistemas de facturación electrónica (CFDI) para timbrar comprobantes ante el SAT. Un hash imposibilitaría recuperar el valor para emitir facturas.

### 3.2 Mecanismo Criptográfico Utilizado
Se utilizó cifrado simétrico mediante el estándar PGP simétrico (`pgp_sym_encrypt` y `pgp_sym_decrypt`), el cual encapsula cifrado por bloques AES con compresión y código de detección de modificaciones (MDC):
* **En reposo:** En el almacenamiento de PostgreSQL solo existen secuencias binarias hexadecimales (`\xc30d0407...`).
* **Descifrado autorizado:** Se recupera el texto claro suministrando la clave autorizada:
  ```sql
  SELECT id, nombre, pgp_sym_decrypt(rfc_cifrado, 'CLAVE-DE-PRUEBA') AS rfc FROM clientes_protegidos;
  ```
* **Fallo ante clave incorrecta:** Al suministrar una clave distinta, el motor detiene la transacción y emite `ERROR: Wrong key or corrupt data`, protegiendo la confidencialidad.

---

## 4. PROTECCIÓN DE COMUNICACIONES EN TRÁNSITO (TLS)

### 4.1 Problema que Resuelve
El cifrado en reposo no previene que un atacante posicionado en la red (mediante intercepción Wi-Fi, switches comprometidos o enrutamiento malicioso) capture el tráfico mientras viaja entre la aplicación cliente (o el DBA) y el motor PostgreSQL. 

El protocolo **TLS (Transport Layer Security)** resuelve de manera integral tres pilares:
1. **Confidencialidad:** Cifra los paquetes impidiendo el espionaje de red (*eavesdropping / sniffing*).
2. **Integridad:** Asegura mediante códigos de autenticación de mensajes que ninguna consulta ni resultado haya sido modificado en tránsito.
3. **Autenticación del Servidor:** Permite al cliente certificar matemáticamente que se está conectando al servidor legítimo de la empresa y no a un clon malicioso (*Man-in-the-Middle*).

### 4.2 Verificación Realizada en PostgreSQL
A través de la vista diagnóstica `pg_stat_ssl`, se auditó el estado criptográfico de la sesión:
* Con TLS desactivado: `ssl = f`, dejando el tráfico vulnerable en texto claro.
* Con TLS activado: `ssl = t`, negociando protocolo **TLSv1.3** con la suite criptográfica **`TLS_AES_256_GCM_SHA384`** (256 bits, cifrado autenticado sin sobrecarga apreciable).

### 4.3 Análisis de Modos de Conexión del Cliente (`sslmode`)
Se analizaron los diferentes grados de verificación ofrecidos por la biblioteca `libpq`:
* **`require`:** Obliga a usar TLS, pero acepta cualquier certificado, incluso si es autofirmado o emitido por un atacante intermediario.
* **`verify-ca`:** Obliga a usar TLS y valida la firma del certificado contra la CA raíz institucional.
* **`verify-full` (Estándar de Oro):** Además de validar la CA, valida que el hostname de la conexión coincida con el certificado digital del servidor. Es el modo indispensable para prevenir ataques DNS Spoofing y suplantación en producción.

---

## 5. GESTIÓN DE CLAVES CRIPTOGRÁFICAS

### 5.1 El Peligro del Hardcoding en Scripts y Git
Durante la Actividad 3 se analizó el script demostrativo `sql/ejemplo-mala-practica.sql`:
```sql
SELECT pgp_sym_decrypt(rfc_cifrado, 'CLAVE-DE-PRUEBA') FROM clientes_protegidos;
```
Colocar la clave dentro del código SQL destruye por completo el modelo de seguridad:
1. **Filtro al Historial de Git:** Si el archivo se sube a un repositorio, el commit persiste perpetuamente en el árbol de Git aunque el archivo sea borrado en un commit posterior.
2. **Exposición en Bitácoras del Motor:** Si PostgreSQL registra sentencias DML (`log_statement = 'all'`), la clave se imprime en texto plano en los archivos de log del sistema operativo.
3. **Exposición en Vistas de Diagnóstico:** Las vistas `pg_stat_activity` y `pg_stat_statements` exponen las sentencias activas y almacenadas a cualquier usuario con privilegios de monitoreo.

### 5.2 Política Institucional Diseñada (POL-SEG-BD-002)
Se formuló un decálogo de 8 reglas técnicas (documentado en [10-politica-claves.md](file:///c:/Users/darks/OneDrive/Escritorio/dba/laboratorio-2-dba/evidencias/10-politica-claves.md)) que norma:
* Generación mediante CSPRNG y longitud AES-256.
* Custodia obligatoria en Bóvedas de Claves externas (KMS / HashiCorp Vault / HSM).
* Prohibición de secretos en repositorios Git y bloqueo mediante hooks pre-receive.
* Rotación periódica cada 180 días con cifrado envolvente (Envelope Encryption).
* Respaldo fuera de línea de claves DR mediante división de secretos de Shamir ($m$-de-$n$).
* Protocolo de revocación y remediación inmediata ante sospecha de exposición accidental.
* Borrado criptográfico seguro (Crypto-Shredding) bajo la directriz NIST SP 800-88.

---

## 6. RESULTADOS OBTENIDOS

1. **Aseguramiento de Credenciales:** Se erradicaron las tablas con passwords en texto plano, implementando almacenamiento protegido con `crypt` + `gen_salt('bf')` y autenticación booleana confiable.
2. **Cifrado Columna de PII Fiscal:** La tabla `clientes_protegidos` resguarda los RFCs en formato binario ilegible en reposo, permitiendo su descifrado controlado únicamente bajo provisión de la clave autorizada.
3. **Inspección y Diagnóstico de TLS:** Se dominó el uso de `pg_stat_ssl` y los parámetros `sslmode`, estableciendo los requerimientos para erradicar conexiones en claro en la red corporativa.
4. **Matriz Comparativa en Reposo vs Tránsito:** Se delimitó con precisión el ámbito, fortalezas y limitaciones de cada mecanismo criptográfico (Sección 14).
5. **Auditoría Preventiva de Secretos:** Se verificó el repositorio local mediante expresiones regulares y se configuró `.gitignore` para impedir que claves o certificados lleguen a Git.

---

## 7. PROBLEMAS ENCONTRADOS Y SOLUCIONES TÉCNICAS

1. **Estado inicial de SSL en contenedores estándar:**  
   * *Problema:* Las imágenes oficiales de PostgreSQL en Podman/Docker inicializan con `ssl = off` por omisión, lo que provoca que un intento con `sslmode=require` falle con el error `server does not support SSL`.  
   * *Solución:* Se documentó el diagnóstico de la ausencia de TLS en el escenario base y el procedimiento de generación de certificados digitales (`server.crt` y `server.key`) con permisos restringidos (`chmod 600`) para habilitar `ssl = on` en entornos productivos.
2. **Exposición de claves en consultas DML con `pgcrypto`:**  
   * *Problema:* El uso de literales en consultas SQL expone la clave en logs y herramientas de cliente (`psql_history`).  
   * *Solución:* Se especificó que en producción el descifrado debe residir en la capa intermedia de la aplicación (usando librerías criptográficas en Node/Java/Python conectadas a un KMS) o mediante variables de sesión efímeras (`SET LOCAL app.secret_key`).
3. **Persistencia de archivos de prueba:**  
   * *Problema:* La instrucción 9.1 sugería crear `sql/ejemplo-mala-practica.sql` para comprobar el riesgo de hardcoding.  
   * *Solución:* Conforme a la Regla 9.2, se eliminó dicho archivo temporal y se añadió la regla explícita en `.gitignore` para salvaguardar la integridad de la entrega final.

---

## 8. CONCLUSIONES GENERALES

1. **No existe una solución criptográfica única:** Cifrar la base de datos no es una casilla que se marca, sino una arquitectura coordinada. Las contraseñas requieren funciones de hash unidireccionales lentas con salt; los datos operativos requieren cifrado simétrico en bloques; las comunicaciones requieren túneles TLS efímeros autenticados; y las copias de seguridad exigen cifrado asimétrico.
2. **El principio de Kerckhoffs es inviolable:** La seguridad de un sistema no debe descansar en el secreto de la consulta o del algoritmo, sino en la estricta custodia de la clave. Un sistema con AES-256 cuyas claves están en scripts SQL tiene seguridad nula.
3. **La criptografía complementa, pero no reemplaza al control de acceso:** Cifrar columnas sin restringir privilegios sobre los roles que conocen la clave no previene el abuso de privilegios. La seguridad efectiva es **Defensa en Profundidad**.

---

## 9. PREGUNTAS DE REFLEXIÓN (SECCIÓN 23)

### 1. ¿Por qué una contraseña no debe almacenarse como texto claro?
Porque almacenar contraseñas en claro elimina cualquier margen de defensa ante una intrusión. Si la base de datos se filtra por una inyección SQL, una copia de seguridad expuesta, un fallo de configuración o un colaborador interno desleal, el atacante obtiene acceso inmediato e indetectable a todas las cuentas. Además, debido al hábito de reutilización de contraseñas, una filtración en un sistema compromete cuentas bancarias, correos y servicios críticos del usuario.

### 2. ¿Por qué un hash no es equivalente a un cifrado?
Porque el **hash es unidireccional e irreversible**, mientras que el **cifrado es bidireccional y reversible mediante una clave**. El hash toma una entrada y genera un resumen de tamaño fijo del cual es computacionalmente imposible deducir el texto original; su función es verificar integridad o demostrar conocimiento de un secreto. El cifrado tiene como finalidad ocultar información para que únicamente una entidad autorizada con la clave criptográfica pueda recuperar el contenido original.

### 3. ¿Por qué el cifrado de una columna no sustituye al control de acceso?
Porque el cifrado de columnas solo protege el dato en reposo cuando el actor no posee la clave de descifrado. Si la política de control de acceso (RBAC) es permisiva y permite que cualquier usuario ejecute la función de descifrado con la clave compartida, el cifrado queda completamente anulado. Asimismo, el cifrado de columna no impide que usuarios no autorizados eliminen registros (`DELETE`), modifiquen la integridad de los datos (`UPDATE`) o agoten los recursos del servidor mediante denegación de servicio.

### 4. ¿Por qué TLS no sustituye a los mecanismos de autorización de PostgreSQL?
Porque **TLS opera en la capa de transporte**, protegiendo la información exclusivamente mientras viaja por los cables y enrutadores de la red. Una vez que los paquetes llegan al servidor PostgreSQL y TLS los descifra, entran en juego los mecanismos de autorización del motor (`pg_hba.conf`, roles, permisos `GRANT`/`REVOKE`, Row-Level Security). Si el usuario que se conecta por un canal TLS seguro tiene permisos excesivos, podrá sustraer o destruir información impunemente a través de ese mismo canal cifrado.

### 5. ¿Qué ocurriría si una organización pierde una clave utilizada para cifrar información?
Ocurre una **pérdida irrecuperable y permanente de la información (Data Loss)**. En algoritmos criptográficos modernos robustos como AES-256, no existen "puertas traseras" ni atajos matemáticos para recuperar los datos sin la clave correspondiente; romper el cifrado mediante fuerza bruta requeriría miles de millones de años de capacidad de supercómputo. Perder la clave equivale a la destrucción definitiva del dato cifrado.

### 6. ¿Qué ocurriría si una clave criptográfica se publica accidentalmente en GitLab?
Se produce un **compromiso total e instantáneo de la confidencialidad**. La clave queda expuesta no solo para quienes tengan acceso al proyecto en ese instante, sino que se incorpora de forma inmutable al historial de commits de Git. Si el repositorio es público, bots automatizados recolectan la clave en cuestión de segundos. Si es privado, cualquier usuario con permisos de lectura puede clonar el histórico y descifrar los datos de producción. Exige la ejecución inmediata del protocolo de contingencia: revocar la clave en el KMS, generar una nueva, re-cifrar toda la base de datos y purgar el árbol de Git.

### 7. ¿Por qué un repositorio privado no debe considerarse un almacén de secretos?
Porque un repositorio de código está diseñado para **distribuir y conservar historial de software**, no para custodiar secretos criptográficos. En un repositorio privado:
* Cualquier desarrollador, colaborador temporal, cuenta de servicio de CI/CD o tester con permisos de clonación descarga una copia local completa de todos los secretos y su historial.
* Las copias de seguridad de las laptops de los programadores multiplican los puntos de fuga fuera del control corporativo.
* No existen mecanismos de auditoría criptográfica, no hay rotación automática y no hay revocación granular de acceso al secreto.

### 8. ¿Qué diferencia existe entre proteger información almacenada y proteger información durante su transmisión?
* **Información almacenada (en reposo):** Protege contra ataques que actúan sobre los medios físicos o lógicos de almacenamiento: robo de discos duros, filtración de backups en la nube, volcados de memoria o intrusiones de usuarios locales del sistema operativo. Se mitiga mediante cifrado de columnas, TDE y cifrado de respaldos.
* **Información en transmisión (en tránsito):** Protege contra ataques activos y pasivos sobre los canales de red: intercepción de tráfico (*packet sniffing*), ataques de hombre en el medio (*Man-in-the-Middle*), falsificación de DNS y manipulación de paquetes. Se mitiga mediante protocolos de túnel seguro como TLS con validación mutua o de certificados (`verify-full`).

### 9. ¿Por qué la gestión de claves es tan importante como el algoritmo criptográfico?
Porque los algoritmos criptográficos estándar de la industria (como AES, RSA, SHA-3, ChaCha20) han sido evaluados y sometidos a criptoanálisis exhaustivo durante décadas por la comunidad científica mundial y son matemáticamente sólidos. En el 99% de las brechas de datos reales, **los atacantes no rompen el algoritmo matemático; simplemente obtienen la clave** debido a una mala gestión: claves hardcodeadas en GitHub, claves guardadas en archivos `.txt`, falta de rotación, claves maestras sin respaldo o ausencia de control de acceso.

### 10. ¿Qué mecanismo adicional implementarías en una organización para proteger los respaldos de las bases de datos?
Implementaría una arquitectura de respaldo seguro basada en:
1. **Cifrado Asimétrico en Origen (Public-Key Backup Encryption):** Configurar herramientas como `pgBackRest` o `WAL-G` para cifrar los backups utilizando una **clave pública**. El servidor de base de datos puede cifrar los volcados continuamente sin necesidad de poseer la clave privada de descifrado en el servidor.
2. **Almacenamiento Inmutable en Frío (WORM / Object Lock):** Enviar los respaldos a una nube o almacenamiento con bloqueo de retención de objetos (*Write Once, Read Many*) durante el tiempo que dicte la política de retención legal (ej. 5 años), impidiendo que un atacante con credenciales comprometidas o un ransomware pueda borrar o sobreescribir los respaldos históricos.
3. **Custodia Dividida de la Clave Privada de Restauración:** Resguardar la clave privada en una bóveda de alta seguridad fuera de línea, cuya apertura requiera autorización compartida de al menos dos directivos del área de TI y Seguridad (esquema multi-firma).
