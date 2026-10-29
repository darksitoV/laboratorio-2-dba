-- ==============================================================================
-- LABORATORIO 02: Cifrado, credenciales y comunicaciones seguras
-- Unidad II: Seguridad, privacidad y control de acceso
-- Tema 2.4: Cifrado, credenciales y protección de las comunicaciones
-- Script: 01-credenciales.sql
-- Motor: PostgreSQL 16
-- Estudiante: Genaro Isaac Cárdenas Soto (@darksitoV)
-- Organización: Comercializadora Norte S.A. de C.V.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 0. PREPARACIÓN DEL ENTORNO CRIPTOGRÁFICO
-- ------------------------------------------------------------------------------
-- Habilitar la extensión pgcrypto para funciones criptográficas en PostgreSQL.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Verificar la instalación de la extensión
SELECT extname, extversion 
FROM pg_extension 
WHERE extname = 'pgcrypto';

-- ------------------------------------------------------------------------------
-- 1. IDENTIFICACIÓN DEL PROBLEMA: ALMACENAMIENTO INSEGURO EN TEXTO PLANO
-- ------------------------------------------------------------------------------
-- ANTIPATRÓN: Almacenar credenciales en texto claro permite que cualquier
-- usuario con acceso de lectura (o un atacante mediante volcado/SQLi)
-- comprometa inmediatamente todas las contraseñas del sistema.

DROP TABLE IF EXISTS usuarios_insegura;

CREATE TABLE usuarios_insegura (
    id BIGSERIAL PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL
);

-- Inserción de prueba con contraseña en texto plano
INSERT INTO usuarios_insegura (usuario, password)
VALUES ('juan', 'Password123');

-- Consulta de verificación: La contraseña es directamente legible
SELECT id, usuario, password 
FROM usuarios_insegura;


-- ------------------------------------------------------------------------------
-- 2. GENERACIÓN DE REPRESENTACIÓN NO REVERSIBLE (HASH CON SAL)
-- ------------------------------------------------------------------------------
-- Se utiliza gen_salt('bf') que genera un salt pseudoaleatorio con algoritmo
-- Blowfish/bcrypt, haciendo que la misma contraseña produzca salidas distintas
-- en cada ejecución (prevención de ataques con Rainbow Tables).

-- Primera ejecución:
SELECT crypt('Password123', gen_salt('bf')) AS hash_ejecucion_1;

-- Segunda ejecución (comprobar que el hash resultante difiere debido al salt aleatorio):
SELECT crypt('Password123', gen_salt('bf')) AS hash_ejecucion_2;


-- ------------------------------------------------------------------------------
-- 3. CREACIÓN DE TABLA DE CREDENCIALES PROTEGIDAS
-- ------------------------------------------------------------------------------
-- PATRÓN SEGURO: Almacenar únicamente el resultado de la función de derivación
-- criptográfica (hash con salt). La contraseña original NUNCA se almacena.

DROP TABLE IF EXISTS usuarios_segura;

CREATE TABLE usuarios_segura (
    id BIGSERIAL PRIMARY KEY,
    usuario VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Inserción segura calculando el hash con sal Blowfish (bcrypt)
INSERT INTO usuarios_segura (usuario, password_hash)
VALUES (
    'juan',
    crypt('Password123', gen_salt('bf'))
);

-- Consulta de verificación: La contraseña original no puede deducirse visualmente
SELECT id, usuario, password_hash 
FROM usuarios_segura;


-- ------------------------------------------------------------------------------
-- 4. VERIFICACIÓN Y AUTENTICACIÓN DE CREDENCIALES
-- ------------------------------------------------------------------------------
-- Para verificar la contraseña, se pasa el hash almacenado como segundo argumento
-- a crypt(). La función extrae automáticamente el salt del hash existente y recalcula
-- el hash sobre la contraseña ingresada. Si ambos hashes coinciden, la contraseña es válida.

-- Prueba 1: Contraseña correcta ('Password123') -> Debe retornar true (t)
SELECT 
    usuario, 
    (password_hash = crypt('Password123', password_hash)) AS contrasena_correcta
FROM usuarios_segura 
WHERE usuario = 'juan';

-- Prueba 2: Contraseña incorrecta ('OtraPassword') -> Debe retornar false (f)
SELECT 
    usuario, 
    (password_hash = crypt('OtraPassword', password_hash)) AS contrasena_correcta
FROM usuarios_segura 
WHERE usuario = 'juan';
