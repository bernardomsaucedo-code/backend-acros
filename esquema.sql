-- Esquema mínimo para que "Llamadme gratis" llegue de verdad a MySQL.
-- Esto ya NO hace falta ejecutarlo a mano: server.js crea esta misma
-- tabla solo, la primera vez que arranca, si todavía no existe. Este
-- archivo queda solo como referencia de cómo es la tabla.

CREATE TABLE IF NOT EXISTS solicitudes_llamada (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  nombre        VARCHAR(120)      NOT NULL,
  telefono      VARCHAR(30)       NOT NULL,
  origen        VARCHAR(60)       NULL,        -- de qué página vino (inicio, empieza_aqui...)
  atendida      TINYINT(1)        NOT NULL DEFAULT 0,
  creado_en     DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Índice para que el panel de admin pueda listar rápido "las que faltan por atender"
CREATE INDEX idx_solicitudes_atendida ON solicitudes_llamada (atendida, creado_en);
