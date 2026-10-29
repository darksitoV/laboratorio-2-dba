-- ==============================================================================
-- LABORATORIO 02: Cifrado, credenciales y comunicaciones seguras
-- Unidad II: Seguridad, privacidad y control de acceso
-- Tema 2.4: Cifrado, credenciales y protección de las comunicaciones
-- Script: 02-cifrado-datos.sql
-- Motor: PostgreSQL 16
-- Estudiante: Genaro Isaac Cárdenas Soto (@darksitoV)
-- Organización: Comercializadora Norte S.A. de C.V.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 0. PREPARACIÓN Y VERIFICACIÓN DE PGCRYPTO
-- ------------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------------------------
-- 1. CREACIÓN DE TABLA CON CAMPO CIFRADO A NIVEL DE COLUMNA
-- ------------------------------------------------------------------------------
-- Se utiliza el tipo de dato BYTEA para almacenar la secuencia binaria
-- del texto cifrado generado mediante el estándar PGP simétrico (AES/Blowfish).

DROP TABLE IF EXISTS clientes_protegidos;

CREATE TABLE clientes_protegidos (
    id BIGSERIAL PRIMARY KEY,
    nombre VARCHAR(120) NOT NULL,
    rfc_cifrado BYTEA NOT NULL
);

-- ------------------------------------------------------------------------------
-- 2. INSERCIÓN DE DATOS MEDIANTE CIFRADO SIMÉTRICO (pgp_sym_encrypt)
-- ------------------------------------------------------------------------------
-- Se utiliza una clave secreta para transformar el dato claro en ciphertext.
-- NOTA: La clave utilizada aquí es meramente ficticia para entorno de laboratorio.

INSERT INTO clientes_protegidos (nombre, rfc_cifrado)
VALUES 
    ('Ana López', pgp_sym_encrypt('LOPA900101ABC', 'CLAVE-DE-PRUEBA')),
    ('Carlos Pérez', pgp_sym_encrypt('PECA900720DEF', 'CLAVE-DE-PRUEBA')),
    ('María García', pgp_sym_encrypt('GAMA780912GHI', 'CLAVE-DE-PRUEBA'));

-- ------------------------------------------------------------------------------
-- 3. INSPECCIÓN DEL DATO EN REPOSO (TEXTO CIFRADO)
-- ------------------------------------------------------------------------------
-- Consulta directa: Demuestra que el RFC queda totalmente ilegible en el almacenamiento,
-- previniendo su lectura en volcados sin la clave o consultas no autorizadas.
SELECT id, nombre, rfc_cifrado 
FROM clientes_protegidos;


-- ------------------------------------------------------------------------------
-- 4. RECUPERACIÓN AUTORIZADA DE INFORMACIÓN (pgp_sym_decrypt)
-- ------------------------------------------------------------------------------
-- Cuando existe una necesidad legítima de negocio y el cliente/aplicación posee
-- la clave criptográfica correspondiente, el dato original se recupera en claro.
SELECT 
    id, 
    nombre, 
    pgp_sym_decrypt(rfc_cifrado, 'CLAVE-DE-PRUEBA') AS rfc_descifrado
FROM clientes_protegidos;


-- ------------------------------------------------------------------------------
-- 5. INTENTO DE RECUPERACIÓN CON CLAVE INCORRECTA
-- ------------------------------------------------------------------------------
-- Si se suministra una clave distinta o no autorizada, la función falla
-- y el motor arroja el error: "ERROR: Wrong key or corrupt data".
-- Descomentar la siguiente línea para comprobar el fallo criptográfico en psql:
-- SELECT pgp_sym_decrypt(rfc_cifrado, 'CLAVE-INCORRECTA') FROM clientes_protegidos WHERE id = 1;


-- ------------------------------------------------------------------------------
-- 6. MIGRACIÓN COMPLETA DESDE LA TABLA BASE `clientes` (LAB-01)
-- ------------------------------------------------------------------------------
-- Demostración de cómo poblar la tabla protegida cifrando masivamente los RFCs
-- provenientes de la tabla transaccional original.
INSERT INTO clientes_protegidos (nombre, rfc_cifrado)
SELECT 
    nombre, 
    pgp_sym_encrypt(rfc, 'CLAVE-DE-PRUEBA')
FROM public.clientes
ON CONFLICT DO NOTHING;

-- Verificación de los registros migrados y descifrados
SELECT 
    id, 
    nombre, 
    pgp_sym_decrypt(rfc_cifrado, 'CLAVE-DE-PRUEBA') AS rfc
FROM clientes_protegidos 
LIMIT 5;
