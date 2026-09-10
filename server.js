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
// Qué cubre esto hoy (10/09), de menos a más reciente:
//   - Formularios públicos: "Llamadme gratis" y "Pide presupuesto" (la
//     SOLICITUD del cliente, no confundir con "propuesta" más abajo).
//   - Propuestas: el asesor decide el precio y se lo envía al cliente con
//     enlace mágico para aceptar y pagar (Bizum/transferencia/cripto/
//     tarjeta — "tarjeta" sigue siendo autodeclarado hasta que haya Stripe
//     real con su propio webhook).
//   - Diligencia reforzada (KYC/PBC): cuestionario + documento de
//     identidad cifrado, revisión del asesor con sus transiciones.
//   - Documentación fiscal más allá del DNI: el asesor pide documentos,
//     el cliente los sube cifrados igual que el DNI.
//   - Documentos cifrados en Cloudflare R2 (RSA-4096 + AES-256, cifrado
//     en el navegador del cliente — este servidor y R2 nunca ven el
//     contenido en claro) + copia de seguridad.
//   - Correo real por Brevo (con fallback a modo maqueta si faltan las
//     claves) y enlaces mágicos de acceso/reentrada.
//   - Cuentas de asesor con login propio (ya no una ADMIN_KEY compartida
//     para el día a día) y rol de administrador.
//   - Verificación automática de pagos cripto por hash (BTC/ETH/SOL +
//     USDC/USDT) contra el explorador público de cada red.
//
// Alcance dejado fuera a propósito (para no llevarte una sorpresa):
// - Stripe real: "tarjeta" se trata igual que un pago autodeclarado más.
// - SITE_URL vacía todavía: los correos llevan el código en texto en vez
//   de un enlace clicable, hasta que haya dominio real.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const app = express();

// Red de seguridad (10/09, encontrado mientras se probaba lo de asesores):
// un error async que escape de una ruta sin pasar por su propio
// try/catch (p. ej. una consulta contra una tabla que de pronto no
// existe, o cualquier fallo de red con la base de datos a mitad de
// petición) podía tirar abajo TODO el proceso — no solo esa petición,
// sino el servidor entero para todos los clientes a la vez. Se registra
// el error y el servidor sigue vivo; la petición que falló recibe su
// error de todos modos (Express ya responde 500 antes de que esto se
// dispare), pero las demás no se ven arrastradas.
process.on('unhandledRejection', err => {
  console.error('Unhandled rejection (el servidor sigue vivo):', err);
});
// Límite de payload subido a 15mb (04/09... 10/09: encontrado el bug real):
// el límite por defecto de express.json() es 100kb. Los PDFs escaneados del
// DNI suelen colar por debajo de eso, pero una foto de móvil (el caso normal
// si el cliente sube una imagen en vez de un PDF) pesa varios MB y en
// base64 crece ~33% más — así que toda subida de imagen quedaba rechazada
// con 413 antes de llegar siquiera al route handler, mientras los PDF (más
// comprimidos) pasaban. No era un problema de tipo de archivo, era de
// tamaño. 15mb cubre con margen una foto de cámara de móvil típica ya en
// base64.
app.use(express.json({ limit: '15mb' }));

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
// ALMACENAMIENTO DE DOCUMENTOS (09/09) — Cloudflare R2, con API
// compatible con S3 (por eso se usa el SDK oficial de AWS). El archivo
// que se guarda aquí SIEMPRE llega ya cifrado desde el navegador del
// cliente (RSA + AES, ver /api/propuestas/:token/documento-identidad) —
// este servidor nunca ve el contenido en claro, y R2 tampoco.
// ================================================================
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const r2 = new S3Client({
  region: 'auto',
  endpoint: process.env.R2_ENDPOINT,
  forcePathStyle: true, // imprescindible para R2 (y para pruebas locales): sin esto, el SDK intenta usar bucket.tu-endpoint en vez de tu-endpoint/bucket
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});
const R2_BUCKET = process.env.R2_BUCKET;

async function subirAR2(clave, buffer, tipoMime) {
  await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: clave, Body: buffer, ContentType: tipoMime }));
}
async function bajarDeR2(clave) {
  const resp = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: clave }));
  const trozos = [];
  for await (const trozo of resp.Body) trozos.push(trozo);
  return { buffer: Buffer.concat(trozos), tipoMime: resp.ContentType };
}

// ================================================================
// CORREO (09/09) — Brevo. Sin ADMIN_KEY... digo, sin BREVO_API_KEY
// configurada, el sistema sigue funcionando exactamente como hasta
// ahora (el enlace se devuelve en la respuesta, en vez de mandarse por
// correo) — así no hace falta tener ya la cuenta de Brevo para seguir
// probando el resto en local.
const axios = require('axios');
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const BREVO_REMITENTE = process.env.BREVO_REMITENTE || '';
const SITE_URL = (process.env.SITE_URL || '').replace(/\/+$/, ''); // sin barra final
const brevoActivo = () => !!(BREVO_API_KEY && BREVO_REMITENTE);

async function enviarCorreo(destinatario, asunto, html) {
  const url = process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email';
  await axios.post(url, {
    sender: { email: BREVO_REMITENTE, name: 'Acros' },
    to: [{ email: destinatario }],
    subject: asunto,
    htmlContent: html,
  }, { headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' } });
}
function enlaceArea(ruta, token) {
  // Sin SITE_URL configurada todavía (no hay dominio público real), el
  // correo incluye el token en texto en vez de un enlace clicable — se
  // arregla solo en cuanto Vikn tenga dominio y se configure SITE_URL.
  return SITE_URL ? `${SITE_URL}/${ruta}?token=${token}` : null;
}

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
          cuestionario  TEXT              NULL,
          atendida      TINYINT(1)        NOT NULL DEFAULT 0,
          creado_en     DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `);
      // "cuestionario" es nueva (08/09): si la tabla ya existía de antes
      // (desplegada sin esta columna), se añade aquí sin tocar nada de lo
      // que ya hubiera — CREATE TABLE IF NOT EXISTS no la habría creado sola.
      await agregaColumnaSiFalta('solicitudes_presupuesto', 'cuestionario', 'TEXT NULL');
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
          documento_iv      VARCHAR(50) NULL,
          documento_clave_cifrada VARCHAR(1000) NULL,
          documento_tipo_mime VARCHAR(100) NULL,
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
      // Cifrado del documento de identidad (09/09): columnas nuevas — si la
      // tabla ya existía de antes sin ellas, se añaden solas sin tocar nada.
      await agregaColumnaSiFalta('diligencias', 'documento_iv', 'VARCHAR(50) NULL');
      await agregaColumnaSiFalta('diligencias', 'documento_clave_cifrada', 'VARCHAR(1000) NULL');
      await agregaColumnaSiFalta('diligencias', 'documento_tipo_mime', 'VARCHAR(100) NULL');
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

      // --- Documentación fiscal más allá del DNI (10/09) ---
      // Reutiliza el mismo patrón de cifrado ya construido para el DNI
      // (RSA-OAEP + AES-GCM en el navegador del cliente): este servidor y
      // R2 solo mueven bytes que no pueden leer. A diferencia del DNI (uno
      // por diligencia), aquí puede haber varios documentos por encargo,
      // pedidos por el asesor uno a uno — igual que ya hacía la maqueta de
      // "Documentación" en acros_area.html, ahora conectado de verdad.
      await pool.execute(`
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
        )
      `);
      await creaIndiceSiFalta('idx_documentos_fiscales_propuesta ON documentos_fiscales (propuesta_id, estado)');
      await creaIndiceSiFalta('idx_documentos_fiscales_estado ON documentos_fiscales (estado, creado_en)');

      // --- Cuentas individuales de asesor (10/09) ---
      // Sustituye la ADMIN_KEY compartida para el uso diario del panel.
      // La ADMIN_KEY no desaparece: sigue existiendo como "clave maestra"
      // solo para dar de alta cuentas nuevas (ver /api/admin/asesores),
      // nunca para las acciones del día a día — esas ahora requieren una
      // sesión de asesor real, y quedan atribuidas a quién las hizo.
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS asesores (
          id                INT AUTO_INCREMENT PRIMARY KEY,
          correo            VARCHAR(160)  NOT NULL UNIQUE,
          nombre            VARCHAR(120)  NOT NULL,
          contrasena_hash   VARCHAR(100)  NOT NULL,
          activo            TINYINT(1)    NOT NULL DEFAULT 1,
          es_admin          TINYINT(1)    NOT NULL DEFAULT 0,
          creado_en         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `);
      // "es_admin" es nueva (10/09, segunda vuelta): si la tabla ya
      // existía de antes sin ella, se añade sola sin tocar nada de lo
      // que ya hubiera.
      await agregaColumnaSiFalta('asesores', 'es_admin', 'TINYINT(1) NOT NULL DEFAULT 0');
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS sesiones_asesor (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          asesor_id     INT NOT NULL,
          token         CHAR(48) NOT NULL UNIQUE,
          expira_en     DATETIME NOT NULL,
          creado_en     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (asesor_id) REFERENCES asesores(id)
        )
      `);
      await creaIndiceSiFalta('idx_sesiones_asesor_token ON sesiones_asesor (token)');
      // Atribución: quién resolvió/confirmó qué. NULL para todo lo de
      // antes de esta fecha (no había manera de saberlo) y para lo que
      // se siga resolviendo con la clave maestra directamente.
      await agregaColumnaSiFalta('diligencias', 'resuelto_por_asesor_id', 'INT NULL');
      await agregaColumnaSiFalta('documentos_fiscales', 'resuelto_por_asesor_id', 'INT NULL');
      await agregaColumnaSiFalta('documentos_fiscales', 'pedido_por_asesor_id', 'INT NULL');
      await agregaColumnaSiFalta('pagos', 'confirmado_por_asesor_id', 'INT NULL');
      await agregaColumnaSiFalta('propuestas', 'creado_por_asesor_id', 'INT NULL');

      // Verificación automática de cripto por hash (10/09, cuarta vuelta).
      // "red"/"moneda_cripto"/"importe_cripto" no se guardaban hasta hoy
      // — el cliente los elegía en pantalla pero solo viajaba el hash, así
      // que no había con qué comparar la transacción real de la cadena.
      await agregaColumnaSiFalta('pagos', 'red', "VARCHAR(10) NULL");
      await agregaColumnaSiFalta('pagos', 'moneda_cripto', "VARCHAR(10) NULL");
      await agregaColumnaSiFalta('pagos', 'importe_cripto', "VARCHAR(40) NULL");
      await agregaColumnaSiFalta('pagos', 'verificado_auto', 'TINYINT(1) NOT NULL DEFAULT 0');

      console.log('Todas las tablas están listas (llamada, presupuesto, propuestas, pagos, diligencias, acceso, documentos fiscales, asesores).');
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
// Igual que creaIndiceSiFalta, pero para columnas nuevas en tablas que ya
// existían antes de que esa columna se añadiera al código.
async function agregaColumnaSiFalta(tabla, columna, definicionTipo) {
  try {
    await pool.execute(`ALTER TABLE ${tabla} ADD COLUMN ${columna} ${definicionTipo}`);
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') throw err;
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
// Los formularios reales (acros_inicio.html / acros_empieza_aqui.html) NO
// mandan un campo "origen" ni "utm" — mandan fuente/medio/campana sueltos
// (estilo utm_source/utm_medium/utm_campaign) y un campo trampa "hp"
// (honeypot: casilla invisible para humanos; si un bot la rellena, se
// acepta la petición con normalidad pero no se guarda nada, para no
// delatar el filtro). Sin esto, todo llegaba con origen/utm en blanco.
function esSpam(cuerpo) { return !!(cuerpo.hp || '').toString().trim(); }
function resolverAtribucion(cuerpo) {
  const { fuente, medio, campana } = cuerpo;
  const hayUtm = fuente || medio || campana;
  const utm = cuerpo.utm
    ? (typeof cuerpo.utm === 'string' ? cuerpo.utm : JSON.stringify(cuerpo.utm))
    : (hayUtm ? JSON.stringify({ fuente, medio, campana }) : null);
  const origen = (cuerpo.origen || fuente || null);
  return { utm, origen: origen ? origen.toString().slice(0, 60) : null };
}
app.post('/api/llamada', async (req, res) => {
  if (!datosValidosLlamada(req.body)) {
    return res.status(400).json({ error: 'Nombre o teléfono no válidos' });
  }
  if (esSpam(req.body)) return res.status(201).json({ ok: true }); // honeypot: no se guarda, pero no se delata
  const { nombre, telefono } = req.body;
  const { origen } = resolverAtribucion(req.body);
  try {
    await pool.execute(
      'INSERT INTO solicitudes_llamada (nombre, telefono, origen) VALUES (?, ?, ?)',
      [nombre.trim(), telefono.trim(), origen]
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
  if (esSpam(req.body)) return res.status(201).json({ ok: true }); // honeypot: no se guarda, pero no se delata
  const { servicios, detalle, telefono, correo, cuestionario } = req.body;
  const { utm, origen } = resolverAtribucion(req.body);
  try {
    await pool.execute(
      'INSERT INTO solicitudes_presupuesto (servicios, detalle, telefono, correo, utm, origen, cuestionario) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        Array.isArray(servicios) ? JSON.stringify(servicios) : servicios.toString().trim(),
        detalle ? detalle.toString().trim() : null,
        telefono.trim(),
        correo ? correo.toString().trim() : null,
        utm,
        origen,
        (cuestionario && Object.keys(cuestionario).length) ? JSON.stringify(cuestionario) : null,
      ]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Error al guardar la solicitud de presupuesto:', err);
    res.status(500).json({ error: 'No se pudo guardar la solicitud' });
  }
});

// ================================================================
// PANEL DEL ASESOR — ver y marcar como atendidas las solicitudes
// entrantes ("Llamadme gratis" y "Pide presupuesto"), 09/09. Hasta
// ahora solo se podían consultar entrando a la base de datos a mano.
// ================================================================
app.get('/api/admin/llamadas', requiereSesionAsesor, async (req, res) => {
  // 09/09: antes solo distinguía "pendientes" (atendida=0) de "todas" —
  // pedir expresamente las atendidas (atendida=1) devolvía TODAS sin
  // filtrar, mezclando pendientes y atendidas en el panel.
  const conn = await pool.getConnection();
  try {
    let filas;
    if (req.query.atendida === '0') [filas] = await conn.execute('SELECT * FROM solicitudes_llamada WHERE atendida = 0 ORDER BY creado_en');
    else if (req.query.atendida === '1') [filas] = await conn.execute('SELECT * FROM solicitudes_llamada WHERE atendida = 1 ORDER BY creado_en DESC');
    else [filas] = await conn.execute('SELECT * FROM solicitudes_llamada ORDER BY creado_en DESC LIMIT 100');
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.post('/api/admin/llamadas/:id/atender', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE solicitudes_llamada SET atendida = 1 WHERE id = ?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de llamada no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
// "Desatender" (09/09): por si se marcó por error o hace falta retomarla
// — nunca se borra nada, solo se mueve entre pendiente/atendida.
app.post('/api/admin/llamadas/:id/desatender', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE solicitudes_llamada SET atendida = 0 WHERE id = ?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de llamada no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/solicitudes-presupuesto', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    let filas;
    if (req.query.atendida === '0') [filas] = await conn.execute('SELECT * FROM solicitudes_presupuesto WHERE atendida = 0 ORDER BY creado_en');
    else if (req.query.atendida === '1') [filas] = await conn.execute('SELECT * FROM solicitudes_presupuesto WHERE atendida = 1 ORDER BY creado_en DESC');
    else [filas] = await conn.execute('SELECT * FROM solicitudes_presupuesto ORDER BY creado_en DESC LIMIT 100');
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.post('/api/admin/solicitudes-presupuesto/:id/atender', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE solicitudes_presupuesto SET atendida = 1 WHERE id = ?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de presupuesto no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
app.post('/api/admin/solicitudes-presupuesto/:id/desatender', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE solicitudes_presupuesto SET atendida = 0 WHERE id = ?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de presupuesto no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
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

// Antes ("requiereAdmin") protegía TODO el panel con esta única clave
// compartida. Ahora solo protege el alta de cuentas de asesor — el uso
// diario pasa a requiereSesionAsesor, más abajo. Se mantiene con la
// ADMIN_KEY de siempre a propósito: sirve de "llave maestra" para poder
// crear la primera cuenta sin depender de que ya exista ninguna.
function requiereClaveMaestra(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).json({ error: 'ADMIN_KEY no configurada en el servidor' });
  if (req.get('x-admin-key') !== ADMIN_KEY) return res.status(401).json({ error: 'Clave maestra incorrecta' });
  next();
}

// ================================================================
// CUENTAS INDIVIDUALES DE ASESOR (10/09) — sustituye la ADMIN_KEY
// compartida para el uso diario. Cada acción del panel queda atribuida
// a quién la hizo de verdad (req.asesor), no a "el panel" en general.
// Contraseñas con bcrypt; sesiones con un token propio (no JWT — no hace
// falta nada más elaborado para un equipo de un puñado de personas), con
// caducidad larga (30 días) porque es una herramienta interna, no el
// área de un cliente.
// ================================================================
const bcrypt = require('bcryptjs');
const DIAS_VIGENCIA_SESION_ASESOR = 30;

async function requiereSesionAsesor(req, res, next) {
  const token = (req.get('x-sesion-token') || '').trim();
  if (!token) return res.status(401).json({ error: 'Falta iniciar sesión' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT s.id AS sesion_id, s.expira_en, a.id, a.nombre, a.correo, a.activo, a.es_admin
       FROM sesiones_asesor s JOIN asesores a ON a.id = s.asesor_id WHERE s.token = ?`, [token]
    );
    if (!filas.length) return res.status(401).json({ error: 'Sesión no válida. Vuelve a iniciar sesión.' });
    const s = filas[0];
    if (new Date(s.expira_en) < ahora()) return res.status(401).json({ error: 'Tu sesión ha caducado. Vuelve a iniciar sesión.' });
    if (!s.activo) return res.status(403).json({ error: 'Esta cuenta está desactivada.' });
    req.asesor = { id: s.id, nombre: s.nombre, correo: s.correo, esAdmin: !!s.es_admin };
    next();
  } finally {
    conn.release();
  }
}

// Alta de un asesor nuevo — protegida por la clave maestra (ADMIN_KEY),
// no por una sesión: así se puede dar de alta al primer asesor sin que
// exista ninguna cuenta todavía. Pensada para usarse pocas veces (cada
// vez que se incorpora alguien al equipo), no como login del día a día.
app.post('/api/admin/asesores', requiereClaveMaestra, async (req, res) => {
  const correo = (req.body.correo || '').trim().toLowerCase();
  const nombre = (req.body.nombre || '').trim();
  const contrasena = req.body.contrasena || '';
  const esAdmin = req.body.es_admin ? 1 : 0;
  if (!correo || !nombre) return res.status(400).json({ error: 'Faltan correo o nombre' });
  if (contrasena.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  const conn = await pool.getConnection();
  try {
    const hash = await bcrypt.hash(contrasena, 10);
    const [r] = await conn.execute('INSERT INTO asesores (correo, nombre, contrasena_hash, es_admin) VALUES (?,?,?,?)', [correo, nombre, hash, esAdmin]);
    res.status(201).json({ ok: true, id: r.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Ya existe un asesor con ese correo' });
    throw err;
  } finally {
    conn.release();
  }
});

// Cambiar si un asesor YA existente es administrador o no — protegido
// también por la clave maestra (no por sesión, ni siquiera de un
// administrador): es un cambio de privilegios, mismo nivel de confianza
// que dar de alta una cuenta nueva. Sirve para el caso de "se me olvidó
// marcar la casilla al crear mi cuenta" sin tener que borrarla y
// rehacerla.
app.post('/api/admin/asesores/:id/rol', requiereClaveMaestra, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE asesores SET es_admin = ? WHERE id = ?', [req.body.es_admin ? 1 : 0, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Asesor no encontrado' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.post('/api/admin/login', async (req, res) => {
  const correo = (req.body.correo || '').trim().toLowerCase();
  const contrasena = req.body.contrasena || '';
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM asesores WHERE correo = ?', [correo]);
    // Mismo mensaje tanto si el correo no existe como si la contraseña es
    // incorrecta — no hay que confirmar a quien intenta entrar cuáles de
    // los dos falló.
    const error = () => res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    if (!filas.length) return error();
    const asesor = filas[0];
    if (!asesor.activo) return res.status(403).json({ error: 'Esta cuenta está desactivada' });
    const ok = await bcrypt.compare(contrasena, asesor.contrasena_hash);
    if (!ok) return error();
    const token = crypto.randomBytes(24).toString('hex');
    const expira = new Date(ahora().getTime() + DIAS_VIGENCIA_SESION_ASESOR * 24 * 60 * 60 * 1000);
    await conn.execute('INSERT INTO sesiones_asesor (asesor_id, token, expira_en) VALUES (?,?,?)', [asesor.id, token, aSQLDatetime(expira)]);
    res.json({ ok: true, token, nombre: asesor.nombre, correo: asesor.correo, es_admin: !!asesor.es_admin, expira_en: expira.toISOString() });
  } finally {
    conn.release();
  }
});

app.post('/api/admin/logout', requiereSesionAsesor, async (req, res) => {
  const token = req.get('x-sesion-token');
  const conn = await pool.getConnection();
  try {
    await conn.execute('DELETE FROM sesiones_asesor WHERE token = ?', [token]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// Cambiar la propia contraseña (10/09) — exige la actual, como cualquier
// "cambiar contraseña" normal. De momento no invalida las demás sesiones
// abiertas en otros navegadores (aparcado: no parece grave para un
// equipo de un puñado de personas, pero queda anotado como pendiente).
app.post('/api/admin/mi-contrasena', requiereSesionAsesor, async (req, res) => {
  const actual = req.body.contrasena_actual || '';
  const nueva = req.body.contrasena_nueva || '';
  if (nueva.length < 8) return res.status(400).json({ error: 'La contraseña nueva debe tener al menos 8 caracteres' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT contrasena_hash FROM asesores WHERE id = ?', [req.asesor.id]);
    const ok = await bcrypt.compare(actual, filas[0].contrasena_hash);
    if (!ok) return res.status(401).json({ error: 'Tu contraseña actual no es correcta' });
    const hash = await bcrypt.hash(nueva, 10);
    await conn.execute('UPDATE asesores SET contrasena_hash = ? WHERE id = ?', [hash, req.asesor.id]);
    // Cierra todas las DEMÁS sesiones abiertas de este asesor (otro
    // navegador, otro móvil...) — si el motivo para cambiarla era una
    // sospecha de que alguien más tenía acceso, cambiar la contraseña
    // sin esto no serviría de mucho, esa otra sesión seguiría viva hasta
    // que caducase sola (30 días). La sesión actual (con la que se pidió
    // el cambio) se mantiene, para no cerrar la sesión a quien lo acaba
    // de hacer él mismo.
    const tokenActual = req.get('x-sesion-token');
    await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ? AND token != ?', [req.asesor.id, tokenActual]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// Listado de asesores (10/09) — para poder ver quién tiene cuenta y
// desactivar a alguien que se va, sin tener que tocar la base de datos a
// mano. Cualquier asesor con sesión puede verlo y activar/desactivar a
// otros (equipo pequeño, no hace falta un rol de "superadmin" aparte) —
// pero nadie puede desactivarse a sí mismo, para no quedarse fuera sin
// querer y sin nadie más conectado en ese momento.
app.get('/api/admin/asesores', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT id, nombre, correo, activo, es_admin, creado_en FROM asesores ORDER BY nombre');
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.post('/api/admin/asesores/:id/activo', requiereSesionAsesor, async (req, res) => {
  // Solo un administrador puede activar/desactivar a otros asesores —
  // cualquier asesor puede VER el listado, pero no tocarlo. Quién es
  // administrador se decide al dar de alta la cuenta (o cambiando el rol
  // después), en los dos casos con la clave maestra, nunca desde aquí.
  if (!req.asesor.esAdmin) return res.status(403).json({ error: 'Solo un administrador puede activar o desactivar cuentas' });
  if (Number(req.params.id) === req.asesor.id) {
    return res.status(400).json({ error: 'No puedes activar o desactivar tu propia cuenta' });
  }
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE asesores SET activo = ? WHERE id = ?', [req.body.activo ? 1 : 0, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Asesor no encontrado' });
    // Si se desactiva, sus sesiones abiertas se cierran también — si no,
    // seguiría pudiendo actuar hasta que caducasen solas (30 días).
    if (!req.body.activo) await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ?', [req.params.id]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

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

app.post('/api/propuestas', requiereSesionAsesor, async (req, res) => {
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
      'INSERT INTO propuestas (cliente_id, servicios, importe_centimos, token, token_expira_en, creado_por_asesor_id) VALUES (?, ?, ?, ?, ?, ?)',
      [cliente.id, JSON.stringify(normalizado.servicios), normalizado.importe_centimos, token, aSQLDatetime(expira), req.asesor.id]
    );
    await conn.commit();
    if (brevoActivo()) {
      const enlace = enlaceArea('acros_area.html', token);
      const importeTexto = (normalizado.importe_centimos / 100).toFixed(2) + ' €';
      const cuerpo = enlace
        ? `<p>Hola,</p><p>Tu asesor te ha enviado una propuesta por ${importeTexto}. Puedes verla y aceptarla aquí:</p><p><a href="${enlace}">${enlace}</a></p><p>Válida durante 14 días.</p>`
        : `<p>Hola,</p><p>Tu asesor te ha enviado una propuesta por ${importeTexto}. Tu código de acceso es:</p><p><strong>${token}</strong></p><p>Válida durante 14 días.</p>`;
      try {
        await enviarCorreo(correo, 'Tu propuesta de Acros', cuerpo);
      } catch (err) {
        console.error('Error al enviar el correo de propuesta (Brevo):', err.response?.data || err.message);
      }
    }
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
    // Solo interesa mandar la lista de documentos una vez la diligencia está
    // aprobada — antes de eso la sección sigue bloqueada en el navegador, y
    // no hace falta el viaje de más. El propio documento cifrado no viaja
    // aquí (solo referencia/estado): el archivo se pide aparte, igual que
    // el del DNI.
    let documentos = [];
    if (diligencias[0] && diligencias[0].estado === 'aprobado') {
      const [filas] = await conn.execute(
        'SELECT id, servicio, nombre, urgente, estado, razon_rechazo, subido_en, creado_en FROM documentos_fiscales WHERE propuesta_id = ? ORDER BY creado_en',
        [p.id]
      );
      documentos = filas;
    }
    res.json({
      propuesta: { estado: p.estado, servicios: JSON.parse(p.servicios), importe_centimos: p.importe_centimos, motivo_rechazo: p.motivo_rechazo, expira_en: p.token_expira_en },
      cliente: clientes[0] || null,
      pago: pagos[0] || null,
      diligencia: diligencias[0] || null,
      documentos,
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

const REDES_CRIPTO = ['btc', 'eth', 'sol'];
const MONEDAS_CRIPTO = ['btc', 'eth', 'sol', 'usdc', 'usdt'];

app.post('/api/propuestas/:token/pago', async (req, res) => {
  const { metodo, hash_transaccion, red, moneda_cripto, importe_cripto } = req.body;
  if (!METODOS_PAGO.includes(metodo)) {
    return res.status(400).json({ error: `Método no válido. Debe ser uno de: ${METODOS_PAGO.join(', ')}` });
  }
  if (metodo === 'cripto') {
    if (!(hash_transaccion || '').trim()) return res.status(400).json({ error: 'Falta el hash de la transacción, obligatorio para cripto' });
    if (!REDES_CRIPTO.includes(red)) return res.status(400).json({ error: `Falta o no es válida la red. Debe ser una de: ${REDES_CRIPTO.join(', ')}` });
    if (!MONEDAS_CRIPTO.includes(moneda_cripto)) return res.status(400).json({ error: `Falta o no es válida la moneda. Debe ser una de: ${MONEDAS_CRIPTO.join(', ')}` });
    // El importe en cripto es solo orientativo (viene de CoinGecko en el
    // navegador del cliente) — si esa consulta falló, no hay por qué
    // bloquear el pago por eso; simplemente no se podrá intentar la
    // verificación automática después, y quedará para revisión manual
    // como hasta ahora.
    if (importe_cripto !== undefined && importe_cripto !== null && (isNaN(Number(importe_cripto)) || Number(importe_cripto) <= 0)) {
      return res.status(400).json({ error: 'El importe en cripto, si se manda, tiene que ser un número mayor que cero' });
    }
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (p.estado !== 'aceptada') return res.status(409).json({ error: `No se puede declarar el pago: la propuesta está "${p.estado}", no "aceptada"` });
    const [r] = await conn.execute(
      'INSERT INTO pagos (propuesta_id, metodo, hash_transaccion, red, moneda_cripto, importe_cripto) VALUES (?, ?, ?, ?, ?, ?)',
      [p.id, metodo, (hash_transaccion || '').trim() || null, metodo === 'cripto' ? red : null,
       metodo === 'cripto' ? moneda_cripto : null, metodo === 'cripto' ? String(importe_cripto) : null]
    );
    res.status(201).json({ ok: true, pago_id: r.insertId, estado: 'autodeclarado' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/pagos', requiereSesionAsesor, async (req, res) => {
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

app.post('/api/admin/pagos/:id/confirmar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM pagos WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Pago no encontrado' });
    if (filas[0].estado === 'confirmado') return res.status(409).json({ error: 'Ese pago ya estaba confirmado' });
    await conn.execute('UPDATE pagos SET estado = ?, confirmado_en = ?, confirmado_por_asesor_id = ? WHERE id = ?', ['confirmado', aSQLDatetime(ahora()), req.asesor.id, req.params.id]);
    res.json({ ok: true, estado: 'confirmado' });
  } finally {
    conn.release();
  }
});

// ================================================================
// VERIFICACIÓN AUTOMÁTICA DE CRIPTO POR HASH (10/09, "nivel 1" — ver
// ACROS_WEB_ESTADO.md). Consulta el explorador público de la red
// correspondiente y, si el hash es real, va a la dirección esperada,
// el importe cuadra (con tolerancia, porque el tipo de cambio se movió
// entre que el cliente vio el precio y envió la transacción) y tiene
// al menos una confirmación, marca el pago como confirmado SOLO —
// nunca rechaza nada por sí sola: si algo no cuadra o el explorador
// falla, se queda tal cual para que el asesor lo revise a mano, como
// hasta ahora. Direcciones esperadas: variables de entorno
// (CRIPTO_DIRECCION_BTC/ETH/SOL) — las mismas que ya usa Vikn en
// `acros_area.html` (constante DATOS_PAGO), todavía sin rellenar con
// las reales (ver Plan de ruta) — sin ellas configuradas, se avisa con
// claridad en vez de fallar en silencio.
// URLs de los tres exploradores/RPC configurables por variable de
// entorno — útil tanto para poder apuntar a otro proveedor si el
// público da problemas de límite de peticiones, como para las pruebas
// (apuntan a un simulador local, nunca a la red real).
// ================================================================
const EXPLORER_BTC_URL = process.env.EXPLORER_BTC_URL || 'https://mempool.space/api';
const EXPLORER_ETH_RPC_URL = process.env.EXPLORER_ETH_RPC_URL || 'https://eth.llamarpc.com';
const EXPLORER_SOL_RPC_URL = process.env.EXPLORER_SOL_RPC_URL || 'https://api.mainnet-beta.solana.com';
const TOLERANCIA_IMPORTE_CRIPTO = 0.03; // 3% — el precio se mueve entre que se calcula y se envía

// Contratos ERC-20 (Ethereum mainnet) y mints SPL (Solana mainnet) de
// las dos stablecoins aceptadas — hace falta conocerlos para leer el
// Transfer real en vez de solo mirar el "to"/"value" nativo de la tx.
const CONTRATOS_ERC20 = {
  usdc: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  usdt: '0xdac17f958d2ee523a2206206994597c13d831ec7',
};
const MINTS_SPL = {
  usdc: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  usdt: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
};
const TOPIC_TRANSFER_ERC20 = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function importeDentroDeTolerancia(real, esperado) {
  if (!esperado) return true; // sin importe orientativo guardado, no se puede comparar — no bloquea, solo no aporta esa comprobación
  const diferencia = Math.abs(real - esperado) / esperado;
  return diferencia <= TOLERANCIA_IMPORTE_CRIPTO;
}

async function verificarBTC(hash, direccionEsperada, importeEsperado) {
  const { data } = await axios.get(`${EXPLORER_BTC_URL}/tx/${hash}`);
  if (!data || !data.status) return { ok: false, motivo: 'Transacción no encontrada en mempool.space' };
  if (!data.status.confirmed) return { ok: false, motivo: 'Todavía sin confirmar en la red Bitcoin' };
  const salida = (data.vout || []).find(v => (v.scriptpubkey_address || '').toLowerCase() === direccionEsperada.toLowerCase());
  if (!salida) return { ok: false, motivo: 'Esa transacción no envía nada a la dirección esperada' };
  const btcReal = salida.value / 1e8; // sats -> BTC
  if (!importeDentroDeTolerancia(btcReal, importeEsperado)) {
    return { ok: false, motivo: `El importe (${btcReal} BTC) no coincide con el esperado (${importeEsperado} BTC)` };
  }
  return { ok: true, detalles: { importe_real: btcReal, confirmaciones: 1 } };
}

async function llamarRpc(url, metodo, params) {
  const { data } = await axios.post(url, { jsonrpc: '2.0', id: 1, method: metodo, params });
  if (data.error) throw new Error(data.error.message || 'Error del nodo RPC');
  return data.result;
}

async function verificarETH(hash, direccionEsperada, moneda, importeEsperado) {
  const recibo = await llamarRpc(EXPLORER_ETH_RPC_URL, 'eth_getTransactionReceipt', [hash]);
  if (!recibo) return { ok: false, motivo: 'Transacción no encontrada (o todavía pendiente) en la red Ethereum' };
  if (recibo.status !== '0x1') return { ok: false, motivo: 'La transacción existe pero falló en la cadena' };
  if (moneda === 'eth') {
    const tx = await llamarRpc(EXPLORER_ETH_RPC_URL, 'eth_getTransactionByHash', [hash]);
    if (!tx || (tx.to || '').toLowerCase() !== direccionEsperada.toLowerCase()) {
      return { ok: false, motivo: 'Esa transacción no envía nada a la dirección esperada' };
    }
    const ethReal = Number(BigInt(tx.value)) / 1e18;
    if (!importeDentroDeTolerancia(ethReal, importeEsperado)) {
      return { ok: false, motivo: `El importe (${ethReal} ETH) no coincide con el esperado (${importeEsperado} ETH)` };
    }
    return { ok: true, detalles: { importe_real: ethReal } };
  }
  // USDC/USDT: hay que leer el evento Transfer de los logs, no el "value"
  // nativo de la transacción (que para un envío de token es 0).
  const contrato = CONTRATOS_ERC20[moneda];
  if (!contrato) return { ok: false, motivo: `Moneda "${moneda}" no soportada en Ethereum` };
  const direccionPadded = '0x' + direccionEsperada.toLowerCase().replace(/^0x/, '').padStart(64, '0');
  const log = (recibo.logs || []).find(l =>
    (l.address || '').toLowerCase() === contrato && (l.topics || [])[0] === TOPIC_TRANSFER_ERC20 && (l.topics || [])[2] === direccionPadded
  );
  if (!log) return { ok: false, motivo: 'Esa transacción no incluye ningún envío de esta stablecoin a la dirección esperada' };
  const importeReal = Number(BigInt(log.data)) / 1e6; // USDC/USDT: 6 decimales en Ethereum
  if (!importeDentroDeTolerancia(importeReal, importeEsperado)) {
    return { ok: false, motivo: `El importe (${importeReal} ${moneda.toUpperCase()}) no coincide con el esperado (${importeEsperado})` };
  }
  return { ok: true, detalles: { importe_real: importeReal } };
}

async function verificarSOL(hash, direccionEsperada, moneda, importeEsperado) {
  const tx = await llamarRpc(EXPLORER_SOL_RPC_URL, 'getTransaction', [hash, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]);
  if (!tx) return { ok: false, motivo: 'Transacción no encontrada en la red Solana' };
  if (tx.meta && tx.meta.err) return { ok: false, motivo: 'La transacción existe pero falló en la cadena' };
  const claves = tx.transaction.message.accountKeys.map(k => (k.pubkey || k));
  if (moneda === 'sol') {
    const indice = claves.findIndex(k => k === direccionEsperada);
    if (indice === -1) return { ok: false, motivo: 'Esa dirección no participa en la transacción' };
    const antes = tx.meta.preBalances[indice], despues = tx.meta.postBalances[indice];
    const solReal = (despues - antes) / 1e9; // lamports -> SOL
    if (solReal <= 0) return { ok: false, motivo: 'Esa dirección no recibió SOL en esta transacción' };
    if (!importeDentroDeTolerancia(solReal, importeEsperado)) {
      return { ok: false, motivo: `El importe (${solReal} SOL) no coincide con el esperado (${importeEsperado} SOL)` };
    }
    return { ok: true, detalles: { importe_real: solReal } };
  }
  const mint = MINTS_SPL[moneda];
  if (!mint) return { ok: false, motivo: `Moneda "${moneda}" no soportada en Solana` };
  // El campo "owner" (con encoding jsonParsed) ya es la wallet del titular
  // del token, no la cuenta asociada (ATA) — comparar contra eso es lo
  // correcto; comparar contra accountKeys[accountIndex] compararía con la
  // dirección de la ATA, que es distinta de la wallet real del cliente.
  const antes = (tx.meta.preTokenBalances || []).find(b => b.mint === mint && b.owner === direccionEsperada);
  const despues = (tx.meta.postTokenBalances || []).find(b => b.mint === mint && b.owner === direccionEsperada);
  if (!despues) return { ok: false, motivo: 'Esa transacción no incluye ningún envío de esta stablecoin a la dirección esperada' };
  const importeReal = Number(despues.uiTokenAmount.uiAmount || 0) - Number(antes ? antes.uiTokenAmount.uiAmount || 0 : 0);
  if (!importeDentroDeTolerancia(importeReal, importeEsperado)) {
    return { ok: false, motivo: `El importe (${importeReal} ${moneda.toUpperCase()}) no coincide con el esperado (${importeEsperado})` };
  }
  return { ok: true, detalles: { importe_real: importeReal } };
}

const DIRECCIONES_ESPERADAS = {
  btc: process.env.CRIPTO_DIRECCION_BTC,
  eth: process.env.CRIPTO_DIRECCION_ETH,
  sol: process.env.CRIPTO_DIRECCION_SOL,
};

app.post('/api/admin/pagos/:id/verificar-cripto', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM pagos WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Pago no encontrado' });
    const pago = filas[0];
    if (pago.metodo !== 'cripto') return res.status(400).json({ error: 'Este pago no es en cripto' });
    if (pago.estado === 'confirmado') return res.status(409).json({ error: 'Ese pago ya estaba confirmado' });
    if (!pago.hash_transaccion || !pago.red || !pago.moneda_cripto) {
      return res.status(400).json({ error: 'A este pago le falta la red, la moneda o el hash — no se puede verificar automáticamente' });
    }
    const direccionEsperada = DIRECCIONES_ESPERADAS[pago.red];
    if (!direccionEsperada) {
      return res.status(500).json({ error: `Falta configurar CRIPTO_DIRECCION_${pago.red.toUpperCase()} en el servidor — sin eso no hay con qué comparar` });
    }
    const importeEsperado = pago.importe_cripto ? Number(pago.importe_cripto) : null;
    let resultado;
    try {
      if (pago.red === 'btc') resultado = await verificarBTC(pago.hash_transaccion, direccionEsperada, importeEsperado);
      else if (pago.red === 'eth') resultado = await verificarETH(pago.hash_transaccion, direccionEsperada, pago.moneda_cripto, importeEsperado);
      else if (pago.red === 'sol') resultado = await verificarSOL(pago.hash_transaccion, direccionEsperada, pago.moneda_cripto, importeEsperado);
      else return res.status(400).json({ error: `Red "${pago.red}" no soportada` });
    } catch (err) {
      console.error('Error consultando el explorador para verificar un pago cripto:', err.message);
      return res.status(502).json({ error: 'No se pudo consultar el explorador de la red ahora mismo. Puedes reintentarlo, o confirmarlo a mano si ya lo has comprobado tú.' });
    }
    if (!resultado.ok) return res.json({ ok: true, verificado: false, motivo: resultado.motivo });
    await conn.execute(
      'UPDATE pagos SET estado = ?, confirmado_en = ?, verificado_auto = 1 WHERE id = ?',
      ['confirmado', aSQLDatetime(ahora()), req.params.id]
    );
    res.json({ ok: true, verificado: true, estado: 'confirmado', detalles: resultado.detalles });
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
  if (!(b.documento_iv || '').trim()) errores.push('documento_iv');
  if (!(b.documento_clave_cifrada || '').trim()) errores.push('documento_clave_cifrada');
  if (!(b.firma_nombre || '').trim() || b.firma_nombre.trim().length < 2) errores.push('firma_nombre');
  return errores;
}

// Sube el documento de identidad YA CIFRADO por el navegador del cliente
// (ver acros_area.html: RSA-OAEP + AES-GCM, con la clave pública que solo
// puede cifrar — nunca descifrar). Este servidor guarda bytes que no
// puede leer, en un sitio (R2) que tampoco puede leerlos.
function limiteTamanoOk(base64, limiteBytes) {
  // Una cadena base64 pesa ~4/3 del tamaño real — cálculo aproximado, de sobra para un límite de seguridad.
  return (base64.length * 3) / 4 <= limiteBytes;
}
app.post('/api/propuestas/:token/documento-identidad', async (req, res) => {
  const { archivo_cifrado, iv, clave_cifrada, tipo_mime } = req.body;
  if (!archivo_cifrado || !iv || !clave_cifrada) {
    return res.status(400).json({ error: 'Faltan archivo_cifrado, iv o clave_cifrada' });
  }
  if (!limiteTamanoOk(archivo_cifrado, 15 * 1024 * 1024)) {
    return res.status(400).json({ error: 'El archivo no puede superar los 15 MB' });
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const clave = `dilig/${p.cliente_id}/${generarToken()}.enc`;
    await subirAR2(clave, Buffer.from(archivo_cifrado, 'base64'), 'application/octet-stream');
    // La clave de R2, el iv y la clave AES cifrada viajan de vuelta al
    // navegador — se reenvían tal cual en el POST final de /diligencia,
    // igual que el resto de respuestas del cuestionario. No se guardan
    // aquí todavía porque la fila de "diligencias" no existe hasta ese
    // envío final.
    res.status(201).json({ ok: true, documento_ref: clave, iv, clave_cifrada, tipo_mime: tipo_mime || 'image/jpeg' });
  } catch (err) {
    console.error('Error al subir el documento de identidad:', err);
    res.status(500).json({ error: 'No se pudo subir el documento' });
  } finally {
    conn.release();
  }
});

// El asesor recupera el documento (sigue cifrado) para descifrarlo en su
// propio navegador con su clave privada — este servidor solo hace de
// intermediario entre R2 y el panel, nunca ve el contenido en claro.
app.get('/api/admin/diligencias/:id/documento', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT documento_ref, documento_iv, documento_clave_cifrada, documento_tipo_mime FROM diligencias WHERE id = ?', [req.params.id]);
    if (!filas.length || !filas[0].documento_ref) return res.status(404).json({ error: 'Documento no encontrado' });
    const d = filas[0];
    const { buffer } = await bajarDeR2(d.documento_ref);
    res.json({
      archivo_cifrado: buffer.toString('base64'),
      iv: d.documento_iv, clave_cifrada: d.documento_clave_cifrada, tipo_mime: d.documento_tipo_mime,
    });
  } catch (err) {
    console.error('Error al recuperar el documento:', err);
    res.status(500).json({ error: 'No se pudo recuperar el documento' });
  } finally {
    conn.release();
  }
});

// Copia de seguridad completa (09/09; 10/09 amplía a los documentos
// fiscales además del DNI) — TODOS los documentos cifrados que hay en R2,
// en un único .zip, junto con un manifiesto con lo que hace falta para
// descifrar cada uno (iv + clave AES cifrada). Sigue viajando todo
// cifrado — la copia en el propio dispositivo de Vikn es tan ilegible
// para cualquier otro como el original en R2. Pensado para pulsarlo de
// vez en cuando y guardarlo aparte (protección contra perder Railway/R2
// Y contra perder el propio ordenador, no solo uno de los dos).
const archiver = require('archiver');
app.get('/api/admin/documentos/backup', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [dniFilas] = await conn.execute(
      `SELECT d.id, d.documento_ref, d.documento_iv, d.documento_clave_cifrada, d.documento_tipo_mime,
              d.creado_en, c.correo
       FROM diligencias d JOIN clientes c ON c.id = d.cliente_id
       WHERE d.documento_ref IS NOT NULL ORDER BY d.id`
    );
    const [fiscalFilas] = await conn.execute(
      `SELECT d.id, d.nombre, d.documento_ref, d.documento_iv, d.documento_clave_cifrada, d.documento_tipo_mime,
              d.subido_en, c.correo
       FROM documentos_fiscales d JOIN clientes c ON c.id = d.cliente_id
       WHERE d.documento_ref IS NOT NULL ORDER BY d.id`
    );
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="acros_documentos_${new Date().toISOString().slice(0, 10)}.zip"`);
    const zip = archiver('zip');
    zip.on('error', err => { console.error('Error al construir el zip de backup:', err); res.status(500).end(); });
    zip.pipe(res);

    const manifiesto = [];
    for (const d of dniFilas) {
      try {
        const { buffer } = await bajarDeR2(d.documento_ref);
        const nombreEnZip = `documentos/diligencia_${d.id}.enc`;
        zip.append(buffer, { name: nombreEnZip });
        manifiesto.push({
          archivo: nombreEnZip, tipo: 'dni', diligencia_id: d.id, cliente_correo: d.correo,
          iv: d.documento_iv, clave_cifrada: d.documento_clave_cifrada,
          tipo_mime: d.documento_tipo_mime, subido_en: d.creado_en,
        });
      } catch (err) {
        console.error(`No se pudo incluir el documento de la diligencia ${d.id} en el backup:`, err.message);
      }
    }
    for (const d of fiscalFilas) {
      try {
        const { buffer } = await bajarDeR2(d.documento_ref);
        const nombreEnZip = `documentos/fiscal_${d.id}.enc`;
        zip.append(buffer, { name: nombreEnZip });
        manifiesto.push({
          archivo: nombreEnZip, tipo: 'fiscal', documento_id: d.id, nombre: d.nombre, cliente_correo: d.correo,
          iv: d.documento_iv, clave_cifrada: d.documento_clave_cifrada,
          tipo_mime: d.documento_tipo_mime, subido_en: d.subido_en,
        });
      } catch (err) {
        console.error(`No se pudo incluir el documento fiscal ${d.id} en el backup:`, err.message);
      }
    }
    const leeme = 'Cada archivo .enc está cifrado — para abrirlo, pega tu clave privada en el panel de Acros ' +
      '(acros_admin.html) y usa "Ver documento" en la diligencia o documento correspondiente, o descifra tú mismo ' +
      'con metadatos.json (iv + clave_cifrada por archivo, cifrados con RSA-OAEP/SHA-256 tu clave pública; ' +
      'archivo cifrado con AES-256-GCM).';
    zip.append(JSON.stringify(manifiesto, null, 2), { name: 'metadatos.json' });
    zip.append(leeme, { name: 'LEEME.txt' });
    await zip.finalize();
  } catch (err) {
    console.error('Error al generar la copia de seguridad:', err);
    if (!res.headersSent) res.status(500).json({ error: 'No se pudo generar la copia de seguridad' });
  } finally {
    conn.release();
  }
});

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
         documento_ref, documento_iv, documento_clave_cifrada, documento_tipo_mime,
         firma_nombre, firma_en, estado)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'revision')`,
      [p.cliente_id, p.id, b.relacion, b.opera_desde, b.origen_fondos, b.origen_fondos_otro || null,
       b.custodia, b.patrimonio_rango, b.terceros ? 1 : 0, b.terceros_detalle || null, b.actividad.trim(), b.prp ? 1 : 0,
       b.documento_ref.trim(), b.documento_iv.trim(), b.documento_clave_cifrada.trim(), b.documento_tipo_mime || 'image/jpeg',
       b.firma_nombre.trim(), aSQLDatetime(ahora())]
    );
    await conn.execute('UPDATE clientes SET tipo_documento = ?, numero_documento = ? WHERE id = ?',
      [b.tipo_documento, b.numero_documento || null, p.cliente_id]);
    res.status(201).json({ ok: true, estado: 'revision' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/diligencias', requiereSesionAsesor, async (req, res) => {
  const estado = req.query.estado;
  const conn = await pool.getConnection();
  try {
    // c.tipo_documento/numero_documento (08/09): viven en clientes, no en
    // diligencias — sin este JOIN, el panel del asesor no podía mostrar
    // qué documento aportó el cliente. asesor_cartera (10/09): quién creó
    // la propuesta de este cliente — da contexto de "de quién es" aunque
    // la diligencia en sí todavía no la haya resuelto nadie.
    const columnas = `d.*, c.correo, c.nombre, c.apellidos, c.tipo_documento, c.numero_documento,
              ac.nombre AS asesor_cartera`;
    const [filas] = estado
      ? await conn.execute(
          `SELECT ${columnas} FROM diligencias d
           JOIN clientes c ON c.id = d.cliente_id
           LEFT JOIN propuestas p ON p.id = d.propuesta_id
           LEFT JOIN asesores ac ON ac.id = p.creado_por_asesor_id
           WHERE d.estado = ? ORDER BY d.creado_en`, [estado])
      : await conn.execute(
          `SELECT ${columnas} FROM diligencias d
           JOIN clientes c ON c.id = d.cliente_id
           LEFT JOIN propuestas p ON p.id = d.propuesta_id
           LEFT JOIN asesores ac ON ac.id = p.creado_por_asesor_id
           ORDER BY d.creado_en`);
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

app.post('/api/admin/diligencias/:id/resolver', requiereSesionAsesor, async (req, res) => {
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
      'UPDATE diligencias SET estado = ?, coherencia = COALESCE(?, coherencia), nota_asesor = COALESCE(?, nota_asesor), resuelto_en = ?, resuelto_por_asesor_id = ? WHERE id = ?',
      [estadoResultante, coherencia || null, nota || null, aSQLDatetime(ahora()), req.asesor.id, d.id]
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
// DOCUMENTACIÓN FISCAL MÁS ALLÁ DEL DNI (10/09)
// Mismo patrón de cifrado que el documento de identidad: el archivo se
// cifra en el navegador del cliente (RSA-OAEP + AES-GCM) antes de salir de
// él — este servidor y R2 solo mueven bytes que no pueden leer. A
// diferencia del DNI (uno por diligencia), aquí hay una fila por
// documento pedido, y el asesor puede pedir tantos como haga falta por
// encargo — igual que ya hacía la maqueta de "Documentación", ahora de
// verdad.
// ================================================================

// Lista de clientes con diligencia aprobada — el conjunto de clientes a
// los que de verdad tiene sentido pedirles un documento fiscal (antes de
// eso, la sección de Documentación en su área sigue bloqueada). Sirve
// para el desplegable de "pedir documento nuevo" del panel.
app.get('/api/admin/clientes-activos', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT c.id AS cliente_id, c.correo, c.nombre, c.apellidos, d.propuesta_id
       FROM diligencias d JOIN clientes c ON c.id = d.cliente_id
       WHERE d.estado = 'aprobado' ORDER BY d.resuelto_en DESC`
    );
    res.json(filas);
  } finally {
    conn.release();
  }
});

// El asesor pide un documento nuevo a un cliente concreto (equivalente al
// formulario "Vista asesor · pedir documento nuevo" de la maqueta).
app.post('/api/admin/documentos', requiereSesionAsesor, async (req, res) => {
  const { propuesta_id, servicio, nombre, urgente } = req.body;
  if (!propuesta_id || !(nombre || '').trim()) {
    return res.status(400).json({ error: 'Faltan propuesta_id o nombre' });
  }
  const conn = await pool.getConnection();
  try {
    const [propuestas] = await conn.execute('SELECT id, cliente_id FROM propuestas WHERE id = ?', [propuesta_id]);
    if (!propuestas.length) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [r] = await conn.execute(
      'INSERT INTO documentos_fiscales (cliente_id, propuesta_id, servicio, nombre, urgente, pedido_por_asesor_id) VALUES (?,?,?,?,?,?)',
      [propuestas[0].cliente_id, propuesta_id, servicio || null, nombre.trim(), urgente ? 1 : 0, req.asesor.id]
    );
    res.status(201).json({ ok: true, id: r.insertId });
  } finally {
    conn.release();
  }
});

// Cola del panel: todos los documentos pedidos/enviados, opcionalmente
// filtrados por estado (p. ej. ?estado=enviado para la cola de revisión).
app.get('/api/admin/documentos', requiereSesionAsesor, async (req, res) => {
  const estado = req.query.estado;
  const conn = await pool.getConnection();
  try {
    // OJO: documentos_fiscales y clientes tienen las dos una columna
    // "nombre" (el nombre del documento vs. el nombre de pila) — con
    // SELECT d.*, c.nombre chocarían y una pisaría a la otra en el
    // objeto resultado. Se renombran las dos explícitamente. asesor_pide
    // (10/09): quién lo pidió — tiene sentido mostrarlo ya en la cola de
    // revisión, a diferencia de "quién lo resolvió" (que por definición
    // todavía es nadie mientras siga en esta cola).
    const columnas = `d.id, d.cliente_id, d.propuesta_id, d.servicio, d.nombre AS nombre_doc, d.urgente,
              d.estado, d.razon_rechazo, d.subido_en, d.creado_en,
              c.correo, c.nombre AS nombre_cliente, c.apellidos,
              ap.nombre AS asesor_pide`;
    const [filas] = estado
      ? await conn.execute(
          `SELECT ${columnas} FROM documentos_fiscales d
           JOIN clientes c ON c.id = d.cliente_id
           LEFT JOIN asesores ap ON ap.id = d.pedido_por_asesor_id
           WHERE d.estado = ? ORDER BY d.urgente DESC, d.creado_en`, [estado])
      : await conn.execute(
          `SELECT ${columnas} FROM documentos_fiscales d
           JOIN clientes c ON c.id = d.cliente_id
           LEFT JOIN asesores ap ON ap.id = d.pedido_por_asesor_id
           ORDER BY d.urgente DESC, d.creado_en`);
    res.json(filas);
  } finally {
    conn.release();
  }
});

// El asesor retira una solicitud que ya no hace falta — solo si el
// cliente no ha subido nada todavía (si ya envió algo, hay que
// resolverlo con /revisar, no desaparecerlo sin más).
app.delete('/api/admin/documentos/:id', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT estado FROM documentos_fiscales WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Documento no encontrado' });
    if (filas[0].estado !== 'pendiente') {
      return res.status(409).json({ error: 'Solo se puede retirar una solicitud mientras sigue pendiente de subida' });
    }
    await conn.execute('DELETE FROM documentos_fiscales WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// El cliente sube el archivo (ya cifrado por su navegador) contra un
// documento pedido en concreto. Mismo límite de tamaño que el DNI.
app.post('/api/propuestas/:token/documentos/:id/subir', async (req, res) => {
  const { archivo_cifrado, iv, clave_cifrada, tipo_mime } = req.body;
  if (!archivo_cifrado || !iv || !clave_cifrada) {
    return res.status(400).json({ error: 'Faltan archivo_cifrado, iv o clave_cifrada' });
  }
  if (!limiteTamanoOk(archivo_cifrado, 15 * 1024 * 1024)) {
    return res.status(400).json({ error: 'El archivo no puede superar los 15 MB' });
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [filas] = await conn.execute('SELECT * FROM documentos_fiscales WHERE id = ? AND propuesta_id = ?', [req.params.id, p.id]);
    if (!filas.length) return res.status(404).json({ error: 'Documento no encontrado' });
    const clave = `docs/${p.cliente_id}/${generarToken()}.enc`;
    await subirAR2(clave, Buffer.from(archivo_cifrado, 'base64'), 'application/octet-stream');
    // Re-subir tras un rechazo también vale — vuelve a "enviado" y borra
    // la razón anterior, para que el asesor lo revise de nuevo desde cero.
    await conn.execute(
      `UPDATE documentos_fiscales SET estado = 'enviado', razon_rechazo = NULL,
       documento_ref = ?, documento_iv = ?, documento_clave_cifrada = ?, documento_tipo_mime = ?, subido_en = ?
       WHERE id = ?`,
      [clave, iv, clave_cifrada, tipo_mime || 'application/octet-stream', aSQLDatetime(ahora()), req.params.id]
    );
    res.json({ ok: true, estado: 'enviado' });
  } catch (err) {
    console.error('Error al subir un documento fiscal:', err);
    res.status(500).json({ error: 'No se pudo subir el documento' });
  } finally {
    conn.release();
  }
});

// El asesor recupera el archivo (sigue cifrado) para descifrarlo en su
// propio navegador con su clave privada — igual que con el DNI.
app.get('/api/admin/documentos/:id/descargar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT documento_ref, documento_iv, documento_clave_cifrada, documento_tipo_mime FROM documentos_fiscales WHERE id = ?', [req.params.id]);
    if (!filas.length || !filas[0].documento_ref) return res.status(404).json({ error: 'Documento no encontrado' });
    const d = filas[0];
    const { buffer } = await bajarDeR2(d.documento_ref);
    res.json({
      archivo_cifrado: buffer.toString('base64'),
      iv: d.documento_iv, clave_cifrada: d.documento_clave_cifrada, tipo_mime: d.documento_tipo_mime,
    });
  } catch (err) {
    console.error('Error al recuperar un documento fiscal:', err);
    res.status(500).json({ error: 'No se pudo recuperar el documento' });
  } finally {
    conn.release();
  }
});

const ACCIONES_DOCUMENTO = { valido: 'valido', rechazar: 'rechazado' };

// El asesor valida o rechaza (con motivo) un documento ya enviado.
app.post('/api/admin/documentos/:id/revisar', requiereSesionAsesor, async (req, res) => {
  const { accion, razon } = req.body;
  const estadoResultante = ACCIONES_DOCUMENTO[accion];
  if (!estadoResultante) return res.status(400).json({ error: 'Acción no válida. Debe ser: valido o rechazar' });
  if (accion === 'rechazar' && !(razon || '').trim()) {
    return res.status(400).json({ error: 'Falta la razón del rechazo' });
  }
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT estado FROM documentos_fiscales WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Documento no encontrado' });
    if (filas[0].estado !== 'enviado') {
      return res.status(409).json({ error: `Solo se puede revisar un documento en estado "enviado" (actual: "${filas[0].estado}")` });
    }
    await conn.execute(
      'UPDATE documentos_fiscales SET estado = ?, razon_rechazo = ?, resuelto_por_asesor_id = ? WHERE id = ?',
      [estadoResultante, accion === 'rechazar' ? razon.trim() : null, req.asesor.id, req.params.id]
    );
    res.json({ ok: true, estado: estadoResultante });
  } finally {
    conn.release();
  }
});
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
      if (brevoActivo()) {
        const enlace = enlaceArea('acros_area.html', token);
        const cuerpo = enlace
          ? `<p>Hola,</p><p>Aquí tienes tu acceso, válido durante 15 minutos:</p><p><a href="${enlace}">${enlace}</a></p>`
          : `<p>Hola,</p><p>Tu código de acceso (válido 15 minutos) es:</p><p><strong>${token}</strong></p>`;
        try {
          await enviarCorreo(correo, 'Tu acceso a Acros', cuerpo);
        } catch (err) {
          console.error('Error al enviar el correo de acceso (Brevo):', err.response?.data || err.message);
        }
        return res.json({ ok: true, expira_en: expira.toISOString() });
      }
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

// Middleware de error genérico (10/09): un payload que supera el límite de
// express.json() (15mb) llegaba antes como una página HTML cruda de
// Express, no como el JSON que espera el resto de la web. No es un fallo
// nuevo de la subida de documentos — afectaba a cualquier ruta — pero se
// nota más ahí porque es la única que mueve archivos grandes de verdad.
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'El archivo es demasiado grande (máximo 15 MB por subida).' });
  }
  next(err);
});

const PUERTO = process.env.PORT || 3000;
asegurarEsquema().finally(() => {
  app.listen(PUERTO, () => console.log(`Backend de Acros escuchando en el puerto ${PUERTO}`));
});
