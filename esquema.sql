-- Esquema de referencia de TODAS las tablas de Acros.
--
-- Esto ya NO hace falta ejecutarlo a mano en ningún sitio: server.js
-- crea estas mismas tablas solo, la primera vez que arranca, si todavía
-- no existen (y no toca nada si ya existen con datos). Este archivo
-- queda solo para poder mirar de un vistazo cómo es cada tabla, sin
-- tener que leer todo server.js.

-- ============================================================
-- "Llamadme gratis"
-- ============================================================
CREATE TABLE IF NOT EXISTS solicitudes_llamada (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(120)      NOT NULL,
  telefono      VARCHAR(30)       NOT NULL,
  origen        VARCHAR(60)       NULL,
  atendida      TINYINT(1)        NOT NULL DEFAULT 0,
  creado_en     DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_solicitudes_atendida ON solicitudes_llamada (atendida, creado_en);

-- ============================================================
-- "Pide presupuesto" — la SOLICITUD del cliente (no confundir con las
-- propuestas de más abajo, que es lo que el asesor envía después)
-- ============================================================
CREATE TABLE IF NOT EXISTS solicitudes_presupuesto (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  servicios     TEXT              NOT NULL,
  detalle       TEXT              NULL,
  telefono      VARCHAR(30)       NOT NULL,
  correo        VARCHAR(190)      NULL,
  utm           VARCHAR(300)      NULL,
  origen        VARCHAR(60)       NULL,
  atendida      TINYINT(1)        NOT NULL DEFAULT 0,
  creado_en     DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_presupuesto_atendida ON solicitudes_presupuesto (atendida, creado_en);

-- ============================================================
-- CLIENTES
-- ============================================================
CREATE TABLE IF NOT EXISTS clientes (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  correo            VARCHAR(160)  NOT NULL UNIQUE,
  telefono          VARCHAR(30)   NULL,
  nombre            VARCHAR(120)  NULL,
  apellidos         VARCHAR(160)  NULL,
  tipo_documento    ENUM('dni','nie','pasaporte') NULL,
  numero_documento  VARCHAR(20)   NULL,
  estado            ENUM('activo','inerte') NOT NULL DEFAULT 'activo',
  creado_en         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- PROPUESTAS — nacen cuando el asesor las envía; el token es el enlace
-- mágico que el cliente usa para verla, aceptarla o rechazarla.
-- ============================================================
CREATE TABLE IF NOT EXISTS propuestas (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  cliente_id      INT NOT NULL,
  servicios       TEXT NOT NULL,
  importe_centimos INT NOT NULL,
  estado          ENUM('enviada','aceptada','rechazada','caducada') NOT NULL DEFAULT 'enviada',
  motivo_rechazo  VARCHAR(500) NULL,
  token           CHAR(32) NOT NULL UNIQUE,
  token_expira_en DATETIME NOT NULL,
  creado_en       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actualizado_en  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES clientes(id)
);
CREATE INDEX idx_propuestas_token ON propuestas (token);
CREATE INDEX idx_propuestas_estado ON propuestas (estado, token_expira_en);

-- ============================================================
-- PAGOS — automático (tarjeta) o autodeclarado (el resto, a la espera
-- de que el asesor lo confirme a mano).
-- ============================================================
CREATE TABLE IF NOT EXISTS pagos (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  propuesta_id      INT NOT NULL,
  metodo            ENUM('tarjeta','bizum','transferencia','cripto','otro') NOT NULL,
  hash_transaccion  VARCHAR(120) NULL,
  estado            ENUM('autodeclarado','confirmado') NOT NULL DEFAULT 'autodeclarado',
  confirmado_en     DATETIME NULL,
  creado_en         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (propuesta_id) REFERENCES propuestas(id)
);

-- ============================================================
-- DILIGENCIA REFORZADA (KYC/PBC) — retención 10 años (Ley 10/2010),
-- el borrado real es tarea de un proceso aparte, no de este esquema.
-- ============================================================
CREATE TABLE IF NOT EXISTS diligencias (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  cliente_id        INT NOT NULL,
  propuesta_id      INT NOT NULL,
  relacion          ENUM('puntual','continuado') NULL,
  opera_desde       ENUM('menos1','1a3','mas3') NULL,
  origen_fondos     VARCHAR(30) NULL,
  origen_fondos_otro VARCHAR(300) NULL,
  custodia          ENUM('exchange','wallet','ambas') NULL,
  patrimonio_rango  VARCHAR(20) NULL,
  terceros          TINYINT(1) NULL,
  terceros_detalle  VARCHAR(500) NULL,
  actividad         VARCHAR(200) NULL,
  prp               TINYINT(1) NULL,
  documento_ref     VARCHAR(300) NULL,
  firma_nombre      VARCHAR(160) NULL,
  firma_en          DATETIME NULL,
  estado            ENUM('pendiente','revision','examen','aprobado','rechazado') NOT NULL DEFAULT 'pendiente',
  coherencia        ENUM('si','no') NULL,
  nota_asesor       VARCHAR(1000) NULL,
  resuelto_en       DATETIME NULL,
  creado_en         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES clientes(id),
  FOREIGN KEY (propuesta_id) REFERENCES propuestas(id)
);
CREATE INDEX idx_diligencias_estado ON diligencias (estado);

-- ============================================================
-- TOKENS DE ACCESO — reentrada de clientes ya dados de alta. Caduca en
-- minutos (no días) y se invalida tras un uso.
-- ============================================================
CREATE TABLE IF NOT EXISTS tokens_acceso (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  cliente_id    INT NOT NULL,
  token         CHAR(32) NOT NULL UNIQUE,
  expira_en     DATETIME NOT NULL,
  usado         TINYINT(1) NOT NULL DEFAULT 0,
  creado_en     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES clientes(id)
);
CREATE INDEX idx_tokens_acceso_token ON tokens_acceso (token);

-- ============================================================
-- DOCUMENTOS FISCALES MÁS ALLÁ DEL DNI (10/09) — el asesor pide
-- documentos uno a uno por encargo; mismo patrón de cifrado que el DNI
-- (documento_ref/iv/clave_cifrada/tipo_mime cifrados en el navegador del
-- cliente, este servidor y R2 nunca ven el contenido en claro).
-- ============================================================
CREATE TABLE IF NOT EXISTS documentos_fiscales (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  cliente_id        INT NOT NULL,
  propuesta_id      INT NOT NULL,
  servicio          VARCHAR(50) NULL,
  nombre            VARCHAR(255) NOT NULL,
  urgente           TINYINT(1) NOT NULL DEFAULT 0,
  estado            ENUM('pendiente','enviado','valido','rechazado') NOT NULL DEFAULT 'pendiente',
  razon_rechazo     VARCHAR(300) NULL,
  documento_ref     VARCHAR(300) NULL,
  documento_iv      VARCHAR(50) NULL,
  documento_clave_cifrada VARCHAR(1000) NULL,
  documento_tipo_mime VARCHAR(100) NULL,
  subido_en         DATETIME NULL,
  creado_en         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES clientes(id),
  FOREIGN KEY (propuesta_id) REFERENCES propuestas(id)
);
CREATE INDEX idx_documentos_fiscales_propuesta ON documentos_fiscales (propuesta_id, estado);
CREATE INDEX idx_documentos_fiscales_estado ON documentos_fiscales (estado, creado_en);
