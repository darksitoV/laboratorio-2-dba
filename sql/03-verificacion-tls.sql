-- ==============================================================================
-- LABORATORIO 02: Cifrado, credenciales y comunicaciones seguras
-- Unidad II: Seguridad, privacidad y control de acceso
-- Tema 2.4: Cifrado, credenciales y protección de las comunicaciones
-- Script: 03-verificacion-tls.sql
-- Motor: PostgreSQL 16
-- Estudiante: Genaro Isaac Cárdenas Soto (@darksitoV)
-- Organización: Comercializadora Norte S.A. de C.V.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. INSPECCIÓN DE LA CONFIGURACIÓN GLOBAL DE SSL/TLS EN POSTGRESQL
-- ------------------------------------------------------------------------------
-- Verifica si el motor tiene habilitado el soporte para conexiones TLS.
SHOW ssl;

-- Versión mínima del protocolo TLS configurada (recomendado TLSv1.2 o TLSv1.3)
SHOW ssl_min_protocol_version;

-- Puerto de escucha del servicio PostgreSQL (estándar 5432)
SHOW port;

-- Direcciones IP en las que el servidor escucha conexiones entrantes (* = todas)
SHOW listen_addresses;

-- Lista de suites de cifrado permitidas en el servidor
SHOW ssl_ciphers;


-- ------------------------------------------------------------------------------
-- 2. VERIFICACIÓN DE LOS ENDPOINTS DE LA CONEXIÓN ACTUAL
-- ------------------------------------------------------------------------------
-- Identifica la dirección IP y puerto del cliente conectado, así como del servidor.
SELECT 
    inet_client_addr() AS ip_cliente,
    inet_client_port() AS puerto_cliente,
    inet_server_addr() AS ip_servidor,
    inet_server_port() AS puerto_servidor;


-- ------------------------------------------------------------------------------
-- 3. INSPECCIÓN DEL ESTADO TLS DE LA SESIÓN ACTUAL (pg_stat_ssl)
-- ------------------------------------------------------------------------------
-- Consulta la vista de sistema pg_stat_ssl filtrando por el backend ID actual.
-- Si ssl = false, la sesión viaja en texto plano (vulnerable a intercepción de red).
-- Si ssl = true, muestra la versión de TLS negociada y la suite criptográfica activa.
SELECT 
    pid, 
    ssl, 
    version AS version_tls, 
    cipher AS algoritmo_cifrado, 
    bits, 
    client_dn
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();


-- ------------------------------------------------------------------------------
-- 4. MONITOREO GENERAL DE TODAS LAS CONEXIONES ACTIVAS Y SU ESTADO TLS
-- ------------------------------------------------------------------------------
-- Cruce entre pg_stat_ssl y pg_stat_activity para auditoría de conexiones seguras.
SELECT 
    s.pid,
    a.usename,
    a.client_addr,
    a.application_name,
    s.ssl AS tiene_tls,
    s.version AS version_tls,
    s.cipher AS suite_cifrado
FROM pg_stat_ssl s
JOIN pg_stat_activity a ON s.pid = a.pid
ORDER BY s.ssl DESC, s.pid ASC;


-- ------------------------------------------------------------------------------
-- 5. REFERENCIA TÉCNICA DE LOS MODOS DE CONEXIÓN DEL CLIENTE (sslmode)
-- ------------------------------------------------------------------------------
-- Los clientes PostgreSQL (psql, psycopg2, JDBC, pgAdmin) soportan los siguientes modos:
-- 
-- 1. disable:     No utiliza TLS; la comunicación es 100% en texto plano.
-- 2. prefer:      Intenta TLS; si el servidor no lo soporta, degrada a texto plano.
-- 3. require:     Exige TLS obligatoriamente; falla si el servidor no tiene TLS,
--                 pero NO valida el certificado contra una Autoridad Certificadora (CA).
-- 4. verify-ca:   Exige TLS y valida que el certificado del servidor haya sido firmado
--                 por una Autoridad Certificadora de confianza (root.crt).
-- 5. verify-full: Exige TLS, valida la cadena de confianza de la CA y comprueba que
--                 el Common Name (CN) o Subject Alternative Name (SAN) del certificado
--                 coincida con el hostname al que el cliente se conectó.
