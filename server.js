// Backend mínimo real para Acros — un único endpoint que recibe el
// formulario de "Llamadme gratis" y lo guarda en MySQL.
//
// Nada de esto es una maqueta: si lo despliegas y apuntas ENDPOINT_LLAMADA
// (en acros_inicio.html / acros_empieza_aqui.html) a su URL, los datos
// llegan de verdad a la base de datos.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(express.json());

// CORS: solo se aceptan peticiones desde los dominios de la propia web
// (ajusta ORIGENES_PERMITIDOS cuando tengáis el dominio definitivo).
const ORIGENES_PERMITIDOS = (process.env.ORIGENES_PERMITIDOS || '*')
  .split(',')
  .map(o => o.trim());
app.use(cors({ origin: ORIGENES_PERMITIDOS }));

// Pool de conexión a MySQL — reutiliza conexiones en vez de abrir una nueva
// por petición, que es lo que te encontrarías si esto creciera de verdad.
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

// Crea las tablas solas si no existen todavía, al arrancar el servidor —
// así no hace falta ejecutar SQL a mano en ningún sitio (Railway u otro
// proveedor). Reintenta unas cuantas veces por si la base de datos tarda
// unos segundos en aceptar conexiones justo tras un despliegue.
async function asegurarEsquema() {
  const INTENTOS = 5;
  for (let intento = 1; intento <= INTENTOS; intento++) {
    try {
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS solicitudes_llamada (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          nombre        VARCHAR(120)      NOT NULL,
          telefono      VARCHAR(30)       NOT NULL,
          origen        VARCHAR(60)       NULL,
          atendida      TINYINT(1)        NOT NULL DEFAULT 0,
          creado_en     DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `);
      try {
        await pool.execute(
          'CREATE INDEX idx_solicitudes_atendida ON solicitudes_llamada (atendida, creado_en)'
        );
      } catch (err) {
        if (err.code !== 'ER_DUP_KEYNAME') throw err;
      }

      await pool.execute(`
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
        )
      `);
      try {
        await pool.execute(
          'CREATE INDEX idx_presupuesto_atendida ON solicitudes_presupuesto (atendida, creado_en)'
        );
      } catch (err) {
        if (err.code !== 'ER_DUP_KEYNAME') throw err;
      }

      console.log('Tablas solicitudes_llamada y solicitudes_presupuesto listas.');
      return;
    } catch (err) {
      console.error(`Intento ${intento}/${INTENTOS} de preparar la base de datos falló:`, err.message);
      if (intento < INTENTOS) await new Promise(r => setTimeout(r, 2000));
    }
  }
  console.error('No se pudo preparar las tablas tras varios intentos. El servidor sigue arrancando; los endpoints fallarán hasta que la base de datos esté disponible.');
}

// Validación mínima: nombre no vacío, teléfono con al menos 9 dígitos.
// Esto es justo lo mismo que ya valida el propio formulario en el
// navegador (refrescarEnviarLlamada) — se repite aquí porque nunca hay
// que fiarse solo de lo que valida el cliente.
function datosValidos(cuerpo) {
  const nombre = (cuerpo.nombre || '').trim();
  const digitos = (cuerpo.telefono || '').replace(/\D/g, '');
  return nombre.length > 0 && digitos.length >= 9;
}

app.post('/api/llamada', async (req, res) => {
  if (!datosValidos(req.body)) {
    return res.status(400).json({ error: 'Nombre o teléfono no válidos' });
  }
  const { nombre, telefono, origen } = req.body;
  try {
    await pool.execute(
      'INSERT INTO solicitudes_llamada (nombre, telefono, origen) VALUES (?, ?, ?)',
      [nombre.trim(), telefono.trim(), origen || null]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Error al guardar la solicitud de llamada:', err);
    res.status(500).json({ error: 'No se pudo guardar la solicitud' });
  }
});

// Comprobación rápida de que el servicio está vivo (útil para Railway/Render
// y para que tú mismo compruebes la URL en el navegador antes de conectar
// el formulario de verdad).
app.get('/salud', (req, res) => res.json({ estado: 'ok' }));

// Validación mínima para "Pide presupuesto": hace falta indicar algún
// servicio (o el texto de "necesito algo más") y un teléfono válido.
// El correo es opcional, igual que en el propio formulario.
function datosPresupuestoValidos(cuerpo) {
  const servicios = cuerpo.servicios;
  const hayServicios = Array.isArray(servicios)
    ? servicios.length > 0
    : (servicios || '').toString().trim().length > 0;
  const digitos = (cuerpo.telefono || '').replace(/\D/g, '');
  return hayServicios && digitos.length >= 9;
}

app.post('/api/presupuesto', async (req, res) => {
  if (!datosPresupuestoValidos(req.body)) {
    return res.status(400).json({ error: 'Faltan servicios o el teléfono no es válido' });
  }
  const { servicios, detalle, telefono, correo, utm, origen } = req.body;
  try {
    await pool.execute(
      'INSERT INTO solicitudes_presupuesto (servicios, detalle, telefono, correo, utm, origen) VALUES (?, ?, ?, ?, ?, ?)',
      [
        Array.isArray(servicios) ? JSON.stringify(servicios) : servicios.toString().trim(),
        detalle ? detalle.toString().trim() : null,
        telefono.trim(),
        correo ? correo.toString().trim() : null,
        utm ? JSON.stringify(utm) : null,
        origen || null,
      ]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Error al guardar la solicitud de presupuesto:', err);
    res.status(500).json({ error: 'No se pudo guardar la solicitud' });
  }
});

const PUERTO = process.env.PORT || 3000;
asegurarEsquema().finally(() => {
  app.listen(PUERTO, () => console.log(`Backend de Acros escuchando en el puerto ${PUERTO}`));
});
