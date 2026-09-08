// Backend de Acros — todo en un único servidor (Node.js + Express).
//
// IMPORTANTE sobre cómo funciona esto: NINGUNA tabla se crea a mano. El
// propio servidor las crea todas solas, la primera vez que arranca (función
// asegurarEsquema, más abajo) — así nunca hace falta tocar SQL en Railway
// ni en ningún otro sitio. Para actualizar el backend desplegado, basta con
// sustituir este archivo en GitHub (arrastrando, como siempre); Railway
// despliega solo y, al arrancar, el propio programa se asegura de que las
// tablas nuevas existan sin tocar las que ya tenías con datos.
//
// Qué hay aquí, en el orden en que se construyó:
//   1. "Llamadme gratis"   → POST /api/llamada       (ya desplegado)
//   2. "Pide presupuesto"  → POST /api/presupuesto    (ya desplegado — esto
//      es la SOLICITUD del cliente, el formulario de contacto)
//   3. "Propuesta formal"  → todo lo de abajo, NUEVO — esto es cuando TÚ,
//      el asesor, ya has decidido el precio y se lo envías al cliente con
//      un enlace para aceptar y pagar. Antes lo llamé "presupuesto" a
//      secas, pero es fácil de confundir con el punto 2 — de ahí el
//      cambio de nombre a "propuesta" en tablas y endpoints.
//
// Alcance dejado fuera a propósito (para no llevarte una sorpresa):
// - No hay pantalla en el panel todavía para "enviar propuesta" ni para
//   "confirmar pago" — hoy estos endpoints solo se pueden probar con una
//   herramienta como Postman, no con un botón en pantalla. Es el
//   siguiente paso natural, no incluido en esta entrega.
// - Sin envío de correos real: el enlace de la propuesta y el de acceso
//   se devuelven en la respuesta en vez de mandarse por correo.
// - "Tarjeta" se trata igual que un pago autodeclarado más, hasta que
//   haya cuenta de Stripe real que conectar con su propio webhook.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const app = express();
app.use(express.json());

// Bug real encontrado y corregido (08/09): con ORIGENES_PERMITIDOS=* el
// .split(',') de antes convertía "*" en el ARRAY ['*'] — y el paquete
// "cors" trata un array como una lista de orígenes exactos a comparar,
// no como el comodín "cualquier origen". Eso hacía que NINGUNA petición
// con cabeceras extra (Content-Type: application/json en un POST, o
// x-admin-key) pasara el preflight, aunque la variable dijera "*". Con
// una sola URL no fallaba (algunos navegadores son más permisivos en
// GET simples), por eso no se había notado hasta probar el panel de
// admin de verdad contra el servidor real.
const ORIGENES_PERMITIDOS_RAW = process.env.ORIGENES_PERMITIDOS || '*';
const ORIGENES_PERMITIDOS = ORIGENES_PERMITIDOS_RAW.trim() === '*'
  ? '*'
  : ORIGENES_PERMITIDOS_RAW.split(',').map(o => o.trim());
app.use(cors({ origin: ORIGENES_PERMITIDOS }));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
});

const ADMIN_KEY = process.env.ADMIN_KEY || '';

// ================================================================
// ESQUEMA — todas las tablas se crean solas aquí. CREATE TABLE IF NOT
// EXISTS no toca nada si la tabla ya existe (y ya tiene datos de verdad
// de Vikn), así que subir este archivo no borra nada de lo ya guardado.
// ================================================================
async function asegurarEsquema() {
  const INTENTOS = 5;
  for (let intento = 1; intento <= INTENTOS; intento++) {
    try {
      // --- Llamadme gratis (ya desplegado, sin cambios) ---
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
      await creaIndiceSiFalta('idx_solicitudes_atendida ON solicitudes_llamada (atendida, creado_en)');

      // --- Pide presupuesto (ya desplegado, sin cambios) ---
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
      await creaIndiceSiFalta('idx_presupuesto_atendida ON solicitudes_presupuesto (atendida, creado_en)');

      // --- NUEVO: clientes, propuestas, pagos, diligencias, acceso ---
      await pool.execute(`
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
        )
      `);

      await pool.execute(`
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
        )
      `);
      await creaIndiceSiFalta('idx_propuestas_token ON propuestas (token)');
      await creaIndiceSiFalta('idx_propuestas_estado ON propuestas (estado, token_expira_en)');

      await pool.execute(`
        CREATE TABLE IF NOT EXISTS pagos (
          id                INT AUTO_INCREMENT PRIMARY KEY,
          propuesta_id      INT NOT NULL,
          metodo            ENUM('tarjeta','bizum','transferencia','cripto','otro') NOT NULL,
          hash_transaccion  VARCHAR(120) NULL,
          estado            ENUM('autodeclarado','confirmado') NOT NULL DEFAULT 'autodeclarado',
          confirmado_en     DATETIME NULL,
          creado_en         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (propuesta_id) REFERENCES propuestas(id)
        )
      `);

      await pool.execute(`
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
        )
      `);
      await creaIndiceSiFalta('idx_diligencias_estado ON diligencias (estado)');

      await pool.execute(`
        CREATE TABLE IF NOT EXISTS tokens_acceso (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          cliente_id    INT NOT NULL,
          token         CHAR(32) NOT NULL UNIQUE,
          expira_en     DATETIME NOT NULL,
          usado         TINYINT(1) NOT NULL DEFAULT 0,
          creado_en     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (cliente_id) REFERENCES clientes(id)
        )
      `);
      await creaIndiceSiFalta('idx_tokens_acceso_token ON tokens_acceso (token)');

      console.log('Todas las tablas están listas (llamada, presupuesto, propuestas, pagos, diligencias, acceso).');
      return;
    } catch (err) {
      console.error(`Intento ${intento}/${INTENTOS} de preparar la base de datos falló:`, err.message);
      if (intento < INTENTOS) await new Promise(r => setTimeout(r, 2000));
    }
  }
  console.error('No se pudo preparar el esquema tras varios intentos. El servidor sigue arrancando; los endpoints fallarán hasta que la base de datos esté disponible.');
}
// CREATE INDEX no admite "IF NOT EXISTS" en MySQL/MariaDB — se ignora el
// único error posible (que ya exista, de un arranque anterior).
async function creaIndiceSiFalta(definicion) {
  try {
    await pool.execute('CREATE INDEX ' + definicion);
  } catch (err) {
    if (err.code !== 'ER_DUP_KEYNAME') throw err;
  }
}

// ================================================================
// "Llamadme gratis" — sin cambios.
// ================================================================
function datosValidosLlamada(cuerpo) {
  const nombre = (cuerpo.nombre || '').trim();
  const digitos = (cuerpo.telefono || '').replace(/\D/g, '');
  return nombre.length > 0 && digitos.length >= 9;
}
app.post('/api/llamada', async (req, res) => {
  if (!datosValidosLlamada(req.body)) {
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

app.get('/salud', (req, res) => res.json({ estado: 'ok' }));

// ================================================================
// "Pide presupuesto" — sin cambios (la SOLICITUD del cliente).
// ================================================================
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

// ================================================================
// UTILIDADES COMUNES (para todo lo de abajo, nuevo)
// ================================================================
const generarToken = () => crypto.randomBytes(16).toString('hex');
const ahora = () => new Date();
const sumarDias = (fecha, dias) => new Date(fecha.getTime() + dias * 86400000);
const sumarMinutos = (fecha, min) => new Date(fecha.getTime() + min * 60000);
const aSQLDatetime = fecha => fecha.toISOString().slice(0, 19).replace('T', ' ');

function requiereAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).json({ error: 'ADMIN_KEY no configurada en el servidor' });
  if (req.get('x-admin-key') !== ADMIN_KEY) return res.status(401).json({ error: 'No autorizado' });
  next();
}

async function obtenerOCrearCliente(conn, { correo, telefono }) {
  const correoNorm = (correo || '').trim().toLowerCase();
  const [filas] = await conn.execute('SELECT * FROM clientes WHERE correo = ?', [correoNorm]);
  if (filas.length) return filas[0];
  const [r] = await conn.execute(
    'INSERT INTO clientes (correo, telefono) VALUES (?, ?)',
    [correoNorm, telefono || null]
  );
  const [nuevo] = await conn.execute('SELECT * FROM clientes WHERE id = ?', [r.insertId]);
  return nuevo[0];
}

// ================================================================
// PROPUESTAS (antes lo llamaba "presupuestos" — cambiado de nombre para
// no confundirlo con /api/presupuesto, que es la solicitud del cliente)
// ================================================================

// "servicios" acepta dos formas (08/09, desglose opcional a petición de
// Vikn: algunos clientes quieren ver "esto cuesta tanto, esto otro
// tanto", otros no):
//   - simple:    ["renta", "m721"]                       + importe_centimos aparte
//   - desglosado: [{id:"renta", precio_centimos:20000}, ...]  (el total se
//     calcula SIEMPRE en el servidor sumando las partes — nunca nos
//     fiamos del total que mande el navegador, aunque lo desglosado
//     venga de nuestro propio panel).
function normalizarServiciosPropuesta(servicios, importeCentimosBody) {
  if (!Array.isArray(servicios) || !servicios.length) return null;
  const esDesglose = typeof servicios[0] === 'object' && servicios[0] !== null;
  if (esDesglose) {
    for (const s of servicios) {
      if (!s || typeof s.id !== 'string' || !s.id.trim() || !Number.isInteger(s.precio_centimos) || s.precio_centimos <= 0) return null;
    }
    const total = servicios.reduce((acc, s) => acc + s.precio_centimos, 0);
    return { servicios, importe_centimos: total };
  }
  if (!servicios.every(s => typeof s === 'string' && s.trim())) return null;
  if (!Number.isInteger(importeCentimosBody) || importeCentimosBody <= 0) return null;
  return { servicios, importe_centimos: importeCentimosBody };
}

app.post('/api/propuestas', requiereAdmin, async (req, res) => {
  const { correo, telefono, servicios, importe_centimos } = req.body;
  const normalizado = correo ? normalizarServiciosPropuesta(servicios, importe_centimos) : null;
  if (!correo || !normalizado) {
    return res.status(400).json({ error: 'Faltan datos: correo, y servicios — o bien un array de ids + importe_centimos, o bien un array de {id, precio_centimos} con el desglose' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const cliente = await obtenerOCrearCliente(conn, { correo, telefono });
    const token = generarToken();
    const expira = sumarDias(ahora(), 14);
    const [r] = await conn.execute(
      'INSERT INTO propuestas (cliente_id, servicios, importe_centimos, token, token_expira_en) VALUES (?, ?, ?, ?, ?)',
      [cliente.id, JSON.stringify(normalizado.servicios), normalizado.importe_centimos, token, aSQLDatetime(expira)]
    );
    await conn.commit();
    res.status(201).json({ ok: true, propuesta_id: r.insertId, token, expira_en: expira.toISOString(), importe_centimos: normalizado.importe_centimos });
  } catch (err) {
    await conn.rollback();
    console.error('Error al crear la propuesta:', err);
    res.status(500).json({ error: 'No se pudo crear la propuesta' });
  } finally {
    conn.release();
  }
});

async function propuestaVigente(conn, token) {
  const [filas] = await conn.execute('SELECT * FROM propuestas WHERE token = ?', [token]);
  if (!filas.length) return null;
  let p = filas[0];
  if (p.estado === 'enviada' && new Date(p.token_expira_en) < ahora()) {
    await conn.execute('UPDATE propuestas SET estado = ? WHERE id = ?', ['caducada', p.id]);
    p.estado = 'caducada';
  }
  return p;
}

app.get('/api/propuestas/:token', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    res.json({
      estado: p.estado, servicios: JSON.parse(p.servicios), importe_centimos: p.importe_centimos,
      motivo_rechazo: p.motivo_rechazo, expira_en: p.token_expira_en,
    });
  } finally {
    conn.release();
  }
});

// Estado combinado (08/09) — para que el área de clientes sepa de una
// sola llamada qué pantalla tocar, sin tener que deducir el estado real
// combinando por su cuenta propuesta + pago + diligencia (esa lógica
// vive aquí, en el servidor, no repetida en el navegador).
app.get('/api/propuestas/:token/estado', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [clientes] = await conn.execute('SELECT correo, telefono, nombre, apellidos, tipo_documento, numero_documento FROM clientes WHERE id = ?', [p.cliente_id]);
    const [pagos] = await conn.execute('SELECT metodo, estado, hash_transaccion, creado_en, confirmado_en FROM pagos WHERE propuesta_id = ? ORDER BY id DESC LIMIT 1', [p.id]);
    const [diligencias] = await conn.execute('SELECT estado, coherencia, resuelto_en FROM diligencias WHERE propuesta_id = ? ORDER BY id DESC LIMIT 1', [p.id]);
    res.json({
      propuesta: { estado: p.estado, servicios: JSON.parse(p.servicios), importe_centimos: p.importe_centimos, motivo_rechazo: p.motivo_rechazo, expira_en: p.token_expira_en },
      cliente: clientes[0] || null,
      pago: pagos[0] || null,
      diligencia: diligencias[0] || null,
    });
  } finally {
    conn.release();
  }
});

// Datos de "Primer acceso" (nombre, apellidos, documento) — hoy solo se
// pedían en el navegador y no se guardaban en ningún sitio.
function datosIdentidadValidos(b) {
  return (b.nombre || '').trim().length > 1
    && (b.apellidos || '').trim().length > 1
    && ['dni', 'nie', 'pasaporte'].includes(b.tipo_documento)
    && (b.numero_documento || '').trim().length > 0;
}
app.post('/api/propuestas/:token/identidad', async (req, res) => {
  if (!datosIdentidadValidos(req.body)) {
    return res.status(400).json({ error: 'Faltan nombre, apellidos, tipo_documento o numero_documento' });
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    await conn.execute(
      'UPDATE clientes SET nombre = ?, apellidos = ?, tipo_documento = ?, numero_documento = ? WHERE id = ?',
      [req.body.nombre.trim(), req.body.apellidos.trim(), req.body.tipo_documento, req.body.numero_documento.trim(), p.cliente_id]
    );
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.post('/api/propuestas/:token/aceptar', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (p.estado !== 'enviada') return res.status(409).json({ error: `No se puede aceptar: estado actual "${p.estado}"` });
    await conn.execute('UPDATE propuestas SET estado = ? WHERE id = ?', ['aceptada', p.id]);
    res.json({ ok: true, estado: 'aceptada' });
  } finally {
    conn.release();
  }
});

app.post('/api/propuestas/:token/rechazar', async (req, res) => {
  const motivo = (req.body.motivo || '').trim().slice(0, 500) || null;
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (p.estado !== 'enviada') return res.status(409).json({ error: `No se puede rechazar: estado actual "${p.estado}"` });
    await conn.execute('UPDATE propuestas SET estado = ?, motivo_rechazo = ? WHERE id = ?', ['rechazada', motivo, p.id]);
    res.json({ ok: true, estado: 'rechazada' });
  } finally {
    conn.release();
  }
});

// ================================================================
// PAGO AUTODECLARADO + CONFIRMACIÓN MANUAL
// ================================================================
const METODOS_PAGO = ['tarjeta', 'bizum', 'transferencia', 'cripto', 'otro'];

app.post('/api/propuestas/:token/pago', async (req, res) => {
  const { metodo, hash_transaccion } = req.body;
  if (!METODOS_PAGO.includes(metodo)) {
    return res.status(400).json({ error: `Método no válido. Debe ser uno de: ${METODOS_PAGO.join(', ')}` });
  }
  if (metodo === 'cripto' && !(hash_transaccion || '').trim()) {
    return res.status(400).json({ error: 'Falta el hash de la transacción, obligatorio para cripto' });
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (p.estado !== 'aceptada') return res.status(409).json({ error: `No se puede declarar el pago: la propuesta está "${p.estado}", no "aceptada"` });
    const [r] = await conn.execute(
      'INSERT INTO pagos (propuesta_id, metodo, hash_transaccion) VALUES (?, ?, ?)',
      [p.id, metodo, (hash_transaccion || '').trim() || null]
    );
    res.status(201).json({ ok: true, pago_id: r.insertId, estado: 'autodeclarado' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/pagos', requiereAdmin, async (req, res) => {
  const estado = req.query.estado;
  const conn = await pool.getConnection();
  try {
    const [filas] = estado
      ? await conn.execute(
          `SELECT pg.*, p.token, c.correo FROM pagos pg
           JOIN propuestas p ON p.id = pg.propuesta_id
           JOIN clientes c ON c.id = p.cliente_id
           WHERE pg.estado = ? ORDER BY pg.creado_en`, [estado])
      : await conn.execute(
          `SELECT pg.*, p.token, c.correo FROM pagos pg
           JOIN propuestas p ON p.id = pg.propuesta_id
           JOIN clientes c ON c.id = p.cliente_id
           ORDER BY pg.creado_en`);
    res.json(filas);
  } finally {
    conn.release();
  }
});

app.post('/api/admin/pagos/:id/confirmar', requiereAdmin, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM pagos WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Pago no encontrado' });
    if (filas[0].estado === 'confirmado') return res.status(409).json({ error: 'Ese pago ya estaba confirmado' });
    await conn.execute('UPDATE pagos SET estado = ?, confirmado_en = ? WHERE id = ?', ['confirmado', aSQLDatetime(ahora()), req.params.id]);
    res.json({ ok: true, estado: 'confirmado' });
  } finally {
    conn.release();
  }
});

// ================================================================
// DILIGENCIA REFORZADA (KYC/PBC)
// ================================================================
const ORIGENES_FONDOS = ['trabajo', 'ahorro', 'venta', 'herencia', 'actividad', 'otro'];
const RANGOS_PATRIMONIO = ['menos10k', '10a50k', '50a250k', 'mas250k', 'prefiero_no'];

function validarDiligencia(b) {
  const errores = [];
  if (!['puntual', 'continuado'].includes(b.relacion)) errores.push('relacion');
  if (!['menos1', '1a3', 'mas3'].includes(b.opera_desde)) errores.push('opera_desde');
  if (!ORIGENES_FONDOS.includes(b.origen_fondos)) errores.push('origen_fondos');
  if (b.origen_fondos === 'otro' && !(b.origen_fondos_otro || '').trim()) errores.push('origen_fondos_otro');
  if (!['exchange', 'wallet', 'ambas'].includes(b.custodia)) errores.push('custodia');
  if (!RANGOS_PATRIMONIO.includes(b.patrimonio_rango)) errores.push('patrimonio_rango');
  if (typeof b.terceros !== 'boolean') errores.push('terceros');
  if (b.terceros === true && !(b.terceros_detalle || '').trim()) errores.push('terceros_detalle');
  if (!(b.actividad || '').trim()) errores.push('actividad');
  if (typeof b.prp !== 'boolean') errores.push('prp');
  if (!['dni', 'nie', 'pasaporte'].includes(b.tipo_documento)) errores.push('tipo_documento');
  if (!(b.documento_ref || '').trim()) errores.push('documento_ref');
  if (!(b.firma_nombre || '').trim() || b.firma_nombre.trim().length < 2) errores.push('firma_nombre');
  return errores;
}

app.post('/api/propuestas/:token/diligencia', async (req, res) => {
  const errores = validarDiligencia(req.body);
  if (errores.length) return res.status(400).json({ error: 'Faltan o son inválidos: ' + errores.join(', ') });
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [pagos] = await conn.execute('SELECT * FROM pagos WHERE propuesta_id = ?', [p.id]);
    if (!pagos.length) return res.status(409).json({ error: 'No hay ningún pago registrado para esta propuesta todavía' });

    const [existentes] = await conn.execute('SELECT id FROM diligencias WHERE propuesta_id = ?', [p.id]);
    if (existentes.length) return res.status(409).json({ error: 'Ya se envió un cuestionario de diligencia para esta propuesta' });

    const b = req.body;
    await conn.execute(
      `INSERT INTO diligencias
        (cliente_id, propuesta_id, relacion, opera_desde, origen_fondos, origen_fondos_otro,
         custodia, patrimonio_rango, terceros, terceros_detalle, actividad, prp,
         documento_ref, firma_nombre, firma_en, estado)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'revision')`,
      [p.cliente_id, p.id, b.relacion, b.opera_desde, b.origen_fondos, b.origen_fondos_otro || null,
       b.custodia, b.patrimonio_rango, b.terceros ? 1 : 0, b.terceros_detalle || null, b.actividad.trim(), b.prp ? 1 : 0,
       b.documento_ref.trim(), b.firma_nombre.trim(), aSQLDatetime(ahora())]
    );
    await conn.execute('UPDATE clientes SET tipo_documento = ?, numero_documento = ? WHERE id = ?',
      [b.tipo_documento, b.numero_documento || null, p.cliente_id]);
    res.status(201).json({ ok: true, estado: 'revision' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/diligencias', requiereAdmin, async (req, res) => {
  const estado = req.query.estado;
  const conn = await pool.getConnection();
  try {
    const [filas] = estado
      ? await conn.execute(
          `SELECT d.*, c.correo, c.nombre, c.apellidos FROM diligencias d
           JOIN clientes c ON c.id = d.cliente_id WHERE d.estado = ? ORDER BY d.creado_en`, [estado])
      : await conn.execute(
          `SELECT d.*, c.correo, c.nombre, c.apellidos FROM diligencias d
           JOIN clientes c ON c.id = d.cliente_id ORDER BY d.creado_en`);
    res.json(filas);
  } finally {
    conn.release();
  }
});

const ACCIONES_DILIGENCIA = {
  aprobar: [['revision', 'examen'], 'aprobado'],
  examen: [['revision'], 'examen'],
  rechazar: [['examen'], 'rechazado'],
};

app.post('/api/admin/diligencias/:id/resolver', requiereAdmin, async (req, res) => {
  const { accion, coherencia, nota } = req.body;
  const regla = ACCIONES_DILIGENCIA[accion];
  if (!regla) return res.status(400).json({ error: 'Acción no válida. Debe ser: aprobar, examen o rechazar' });
  if (coherencia !== undefined && coherencia !== null && !['si', 'no'].includes(coherencia)) {
    return res.status(400).json({ error: 'coherencia debe ser "si" o "no"' });
  }
  const [estadosPermitidos, estadoResultante] = regla;
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM diligencias WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Diligencia no encontrada' });
    const d = filas[0];
    if (!estadosPermitidos.includes(d.estado)) {
      return res.status(409).json({ error: `Acción "${accion}" no permitida desde el estado "${d.estado}"` });
    }
    await conn.execute(
      'UPDATE diligencias SET estado = ?, coherencia = COALESCE(?, coherencia), nota_asesor = COALESCE(?, nota_asesor), resuelto_en = ? WHERE id = ?',
      [estadoResultante, coherencia || null, nota || null, aSQLDatetime(ahora()), d.id]
    );
    if (accion === 'rechazar') {
      await conn.execute('UPDATE clientes SET estado = ? WHERE id = ?', ['inerte', d.cliente_id]);
    }
    res.json({ ok: true, estado: estadoResultante });
  } finally {
    conn.release();
  }
});

// ================================================================
// ACCESO DE CLIENTES YA DADOS DE ALTA (enlace mágico de reentrada)
// ================================================================
const MINUTOS_VIGENCIA_ACCESO = 15;

app.post('/api/acceso/solicitar', async (req, res) => {
  const correo = (req.body.correo || '').trim().toLowerCase();
  if (!correo) return res.status(400).json({ error: 'Falta el correo' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM clientes WHERE correo = ?', [correo]);
    if (filas.length && filas[0].estado === 'activo') {
      const token = generarToken();
      const expira = sumarMinutos(ahora(), MINUTOS_VIGENCIA_ACCESO);
      await conn.execute(
        'INSERT INTO tokens_acceso (cliente_id, token, expira_en) VALUES (?, ?, ?)',
        [filas[0].id, token, aSQLDatetime(expira)]
      );
      return res.json({ ok: true, token_demo: token, expira_en: expira.toISOString() });
    }
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.get('/api/acceso/:token', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM tokens_acceso WHERE token = ?', [req.params.token]);
    if (!filas.length) return res.status(404).json({ error: 'Enlace no válido' });
    const t = filas[0];
    if (t.usado) return res.status(410).json({ error: 'Este enlace ya se ha usado' });
    if (new Date(t.expira_en) < ahora()) return res.status(410).json({ error: 'Este enlace ha caducado' });
    await conn.execute('UPDATE tokens_acceso SET usado = 1 WHERE id = ?', [t.id]);
    const [cliente] = await conn.execute('SELECT id, correo, nombre, apellidos FROM clientes WHERE id = ?', [t.cliente_id]);
    res.json({ ok: true, cliente: cliente[0] });
  } finally {
    conn.release();
  }
});

const PUERTO = process.env.PORT || 3000;
asegurarEsquema().finally(() => {
  app.listen(PUERTO, () => console.log(`Backend de Acros escuchando en el puerto ${PUERTO}`));
});
