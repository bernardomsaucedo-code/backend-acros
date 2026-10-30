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
//   - Web pública editable desde el panel (05/10): logo, equipo,
//     destacados y ofertas, con historial y vuelta atrás.
//
// Alcance dejado fuera a propósito (para no llevarte una sorpresa):
// - Stripe real: "tarjeta" se trata igual que un pago autodeclarado más.
// - SITE_URL vacía todavía: los correos llevan el código en texto en vez
//   de un enlace clicable, hasta que haya dominio real.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const zlib = require('zlib');
const mysql = require('mysql2/promise');

const app = express();
// 08/10: en Express 4, si una ruta async falla (error de base de datos,
// etc.) el error no llega a Express: la petición se queda colgada y el
// panel esperando. Se envuelven todas las rutas para que cualquier fallo
// acabe en el gestor de errores de abajo, que responde con un JSON 500.
for (const metodo of ['get', 'post', 'put', 'delete', 'patch']) {
  const original = app[metodo].bind(app);
  app[metodo] = (ruta, ...manejadores) => original(ruta, ...manejadores.map(h =>
    (typeof h === 'function' && h.length < 4)
      ? (req, res, next) => { try { const r = h(req, res, next); if (r && typeof r.catch === 'function') r.catch(next); } catch (e) { next(e); } }
      : h));
}

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

// ================================================================
// REGISTRO MAESTRO (30/10, Vikn)
// Todo queda anotado: lo que hace el equipo (con el antes y el después en lo que cambia datos), quién abre qué ficha o documento,
// entradas, salidas y PIN, lo que hacen los clientes y lo que hace el propio sistema (correos, avisos, copias). Nunca contraseñas, PIN,
// códigos, tokens ni el contenido de documentos o mensajes. Solo se añade: no hay forma de editarlo ni de borrarlo (salvo el tope de
// 15 años). Lo ven solo los administradores, y la IA cuando le pregunta un administrador.
// ================================================================
const CAMPOS_SECRETOS = /hash|secreto|recuperacion|token|clave|_ref$|_iv$|contrasena|^pin_|cifrad|totp/i;
const CAMPOS_CONTENIDO = /^(texto|cuerpo|contenido|mensaje)$/i;
const REG_SENSIBLES = [
  [/^(PUT|POST|DELETE|PATCH)$/, /^\/api\/admin\/asesores\/(\d+)(\/[a-z0-9\/-]*)?$/, 'asesores'],
  [/^(PUT|POST|PATCH)$/, /^\/api\/admin\/clientes\/(\d+)(\/(fusionar|2fa\/reiniciar|asesor|codigo|datos))?$/, 'clientes'],
  [/^(PUT|POST|DELETE)$/, /^\/api\/admin\/personas\/(\d+)(\/horario)?$/, 'personas'],
  [/^(PUT|POST|DELETE)$/, /^\/api\/admin\/equipos\/(\d+)(\/[a-z-]+)?$/, 'equipos'],
  [/^(PUT|POST)$/, /^\/api\/admin\/documentos\/(\d+)\/revisar$/, 'documentos_fiscales'],
  [/^(PUT|POST)$/, /^\/api\/admin\/pagos\/(\d+)(\/[a-z]+)?$/, 'pagos'],
  [/^(PUT|POST)$/, /^\/api\/admin\/diligencias\/(\d+)(\/[a-z-]+)?$/, 'diligencias'],
  [/^(PUT|POST)$/, /^\/api\/admin\/cambios-asesor\/(\d+)\/resolver$/, 'cambios_asesor'],
  [/^(PUT|POST|DELETE)$/, /^\/api\/admin\/servicios\/(\d+)(\/[a-z-]+)?$/, 'servicios_cliente'],
  [/^(PUT|POST|DELETE)$/, /^\/api\/admin\/entregas\/(\d+)(\/[a-z-]+)?$/, 'entregas'],
];
const REG_AJUSTES = /^\/api\/admin\/(ajustes-rendimiento|correo-ajustes|canales|ajustes|plazos)/;
const REG_LECTURAS = /^\/api\/admin\/(clientes\/\d+(\/(cartera|relacion|notas|correos|servicios|ficha))?|documentos\/\d+\/descargar|entregas\/\d+\/descargar|diligencias\/\d+\/(documento|descargar)|mensajes\/\d+\/archivo|copias-bd\/\d+\/descargar|registro(\.csv)?)$/;
const REG_LECTURAS_CLIENTE = /^\/api\/propuestas\/[0-9a-f]{32}\/(entregas\/\d+\/descargar|mensajes\/\d+\/archivo)$/;
const ACCIONES = [
  [/^POST \/api\/admin\/login/, (s) => s < 400 ? 'Entrada al panel' : 'Entrada al panel fallida'], [/^POST \/api\/admin\/logout$/, () => 'Salida del panel'],
  [/^POST \/api\/admin\/pin\/desbloquear$/, (s) => s < 400 ? 'Desbloquea el panel con su PIN' : 'PIN incorrecto'], [/^POST \/api\/admin\/pin\/bloquear$/, () => 'Panel bloqueado por inactividad'],
  [/^POST \/api\/admin\/pin\/(crear|cambiar|olvidado)$/, () => 'Crea, cambia o restablece su PIN'], [/^POST \/api\/admin\/asesores\/:id\/pin\/reiniciar$/, () => 'Reinicia el PIN de otra persona'],
  [/^PUT \/api\/admin\/asesores\/:id\/roles$/, () => 'Cambia los roles de una persona'], [/^POST \/api\/admin\/asesores$/, () => 'Da de alta un asesor (clave maestra)'],
  [/^POST \/api\/admin\/asesores\/:id\/rol$/, () => 'Cambia el rol de administrador (clave maestra)'],
  [/^GET \/api\/admin\/clientes\/:id$/, () => 'Abre la ficha de un cliente'], [/^GET \/api\/admin\/clientes\/:id\/cartera$/, () => 'Abre la cartera de un cliente'],
  [/^GET \/api\/admin\/clientes\/:id\/relacion$/, () => 'Abre «Relación con Acros»'], [/^GET \/api\/admin\/clientes\/:id\/notas$/, () => 'Lee las notas de un cliente'],
  [/^GET \/api\/admin\/documentos\/:id\/descargar$/, () => 'Abre un documento del cliente'], [/^GET \/api\/admin\/entregas\/:id\/descargar$/, () => 'Abre un informe'],
  [/^GET \/api\/admin\/diligencias\/:id\/(documento|descargar)$/, () => 'Abre un documento de identidad'], [/^GET \/api\/admin\/mensajes\/:id\/archivo$/, () => 'Abre un archivo del chat'],
  [/^GET \/api\/admin\/registro/, () => 'Consulta el registro maestro'], [/^POST \/api\/admin\/clientes\/:id\/fusionar$/, () => 'Fusiona dos fichas'],
  [/^POST \/api\/admin\/clientes\/:id\/correo$/, () => 'Escribe un correo a un cliente'], [/^PUT \/api\/admin\/clientes\/:id$/, () => 'Edita los datos de un cliente'],
  [/^POST \/api\/admin\/documentos\/:id\/revisar$/, () => 'Revisa un documento'], [/^POST \/api\/admin\/cambios-asesor\/:id\/resolver$/, () => 'Resuelve un cambio de asesor'],
  [/^POST \/api\/propuestas\/:token\/aceptar$/, () => 'El cliente acepta la propuesta'], [/^POST \/api\/propuestas\/:token\/rechazar$/, () => 'El cliente rechaza la propuesta'],
  [/^POST \/api\/propuestas\/:token\/pago$/, () => 'El cliente declara el pago'], [/^POST \/api\/propuestas\/:token\/diligencia$/, () => 'El cliente envía el alta'],
  [/^POST \/api\/propuestas\/:token\/documentos\/:id\/subir$/, () => 'El cliente sube un documento'], [/^POST \/api\/propuestas\/:token\/entregas\/:id\/conformidad$/, () => 'El cliente da el visto bueno'],
  [/^POST \/api\/propuestas\/:token\/entregas\/:id\/cambios$/, () => 'El cliente pide un cambio en el informe'], [/^POST \/api\/propuestas\/:token\/cambio-asesor$/, () => 'El cliente pide cambiar de asesor'],
  [/^POST \/api\/propuestas\/:token\/mensajes$/, () => 'El cliente escribe en el chat'], [/^GET \/api\/propuestas\/:token\/entregas\/:id\/descargar$/, () => 'El cliente descarga un informe'],
  [/^GET \/api\/propuestas\/:token\/mensajes\/:id\/archivo$/, () => 'El cliente descarga un archivo del chat'], [/^POST \/api\/(presupuesto|llamada)/, () => 'Solicitud desde la web'],
];
const detalleSeguro = t => { if (!t) return null; try { return JSON.parse(t); } catch (e) { return { ilegible: true }; } };
const rutaPatron = p => String(p).replace(/[0-9a-f]{32}/g, ':token').replace(/\/\d+/g, '/:id').slice(0, 200);
function accionDe(metodo, ruta, s) { const k = metodo + ' ' + ruta; const a = ACCIONES.find(([re]) => re.test(k)); return a ? a[1](s) : k; }
function tipoDe(actor, metodo, ruta) {
  if (actor === 'sistema') return 'sistema'; if (actor === 'cliente' || actor === 'visitante') return 'cliente'; if (actor === 'clave_maestra') return 'cambio';
  if (/\/(login|logout|pin\/)/.test(ruta)) return 'acceso';
  return metodo === 'GET' ? 'lectura' : 'cambio';
}
function anotarRegistro(r) {
  let detalle = r.detalle && Object.keys(r.detalle).length ? JSON.stringify(r.detalle) : null;
  if (detalle && detalle.length > 8000) detalle = JSON.stringify({ estado: r.detalle.estado, recortado: true, campos_cambiados: r.detalle.cambios ? Object.keys(r.detalle.cambios.antes || {}) : undefined });   // nunca un JSON partido
  pool.execute('INSERT INTO registro (actor_tipo, actor_id, actor_nombre, tipo, accion, metodo, ruta, estado_http, objeto_id, cliente_id, detalle, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [r.actor_tipo, r.actor_id || null, (r.actor_nombre || '').slice(0, 120) || null, r.tipo || tipoDe(r.actor_tipo), String(r.accion || '').slice(0, 200), r.metodo || null, r.ruta || null, r.estado_http || null, r.objeto_id || null, r.cliente_id || null, detalle, r.ip || null])
    .catch(e => console.error('Registro no anotado:', e.message));
}
async function filaReg(tabla, id) { try { const [f] = await pool.query('SELECT * FROM `' + tabla + '` WHERE id = ?', [id]); return f[0] || null; } catch (e) { return null; } }
const valorReg = v => v instanceof Date ? v.toISOString() : Buffer.isBuffer(v) ? '(binario)' : v;
function diferenciasReg(a, b) {
  const out = { antes: {}, despues: {} }, secretos = [];
  new Set([...Object.keys(a || {}), ...Object.keys(b || {})]).forEach(k => {
    if (/^(actualizado_en|creado_en)$/.test(k)) return;
    const x = a ? valorReg(a[k]) : undefined, y = b ? valorReg(b[k]) : undefined;
    if (JSON.stringify(x) === JSON.stringify(y)) return;
    if (CAMPOS_SECRETOS.test(k)) { secretos.push(k); return; }
    if (CAMPOS_CONTENIDO.test(k)) { out.antes[k] = '(contenido)'; out.despues[k] = '(contenido)'; return; }
    out.antes[k] = x === undefined ? null : x; out.despues[k] = y === undefined ? null : y;
  });
  if (!Object.keys(out.antes).length && !secretos.length) return null;
  if (secretos.length) out.cambiados_sin_mostrar = secretos;
  return out;
}
function resumenCuerpo(body) {
  const r = {}; if (!body || typeof body !== 'object') return r;
  Object.keys(body).slice(0, 25).forEach(k => {
    if (CAMPOS_SECRETOS.test(k) || /^(pin|nuevo|actual|codigo|datos_base64|archivo|contrasena|clave_auth)$/i.test(k)) return;
    const v = body[k]; if (v == null || v === '') return;
    r[k] = CAMPOS_CONTENIDO.test(k) ? '(' + String(v).length + ' caracteres)' : typeof v === 'object' ? JSON.stringify(v).slice(0, 200) : String(v).slice(0, 200);
  });
  return r;
}
app.use(async (req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  const t0 = Date.now(), metodo = req.method;
  let tabla = null, idObj = null, antes = null, ajAntes = null;
  try {
    const s = REG_SENSIBLES.find(([m, re]) => m.test(metodo) && re.test(req.path));
    if (s) { tabla = s[2]; idObj = Number(req.path.match(s[1])[1]); antes = await filaReg(tabla, idObj); }
    if (metodo !== 'GET' && REG_AJUSTES.test(req.path)) { const [f] = await pool.query('SELECT clave, valor FROM ajustes'); ajAntes = Object.fromEntries(f.map(x => [x.clave, x.valor])); }
  } catch (e) { /* el registro nunca frena una petición */ }
  if (metodo === 'OPTIONS' || metodo === 'HEAD') return next();
  if (req.path.startsWith('/api/correo-entrante/')) return next();   // su dirección lleva un secreto: la recepción se anota aparte, sin él   // las comprobaciones previas del navegador no son actividad
  res.on('finish', async () => {
    try {
      const est = res.statusCode, ruta = rutaPatron(req.path), admin = req.path.startsWith('/api/admin/');
      let actor = null, actorId = null, actorNombre = null, clienteId = null;
      if (admin) {
        if (/^\/api\/admin\/(login|logout)/.test(req.path)) { if (metodo === 'GET') return; actor = 'asesor'; actorId = req.asesor ? req.asesor.id : null; actorNombre = req.asesor ? req.asesor.nombre : String((req.body || {}).correo || '').slice(0, 120) || 'desconocido'; }
        else if (req.asesor) { if (metodo === 'GET' && !REG_LECTURAS.test(req.path)) return; if (/^\/api\/admin\/(pin\/latido|mensajes\/sin-leer|sesion)/.test(req.path)) return; actor = 'asesor'; actorId = req.asesor.id; actorNombre = req.asesor.nombre; }
        else if (metodo !== 'GET' && /^\/api\/admin\/asesores/.test(req.path)) { actor = 'clave_maestra'; actorNombre = 'Clave maestra'; }
        else return;
        const m = req.path.match(/^\/api\/admin\/clientes\/(\d+)/); if (m) clienteId = Number(m[1]);
      } else {
        if (metodo === 'GET' && !REG_LECTURAS_CLIENTE.test(req.path)) return;
        if (metodo === 'OPTIONS' || metodo === 'HEAD') return;
        const m = req.path.match(/^\/api\/propuestas\/([0-9a-f]{32})/);
        if (m) { const [p] = await pool.query('SELECT cliente_id FROM propuestas WHERE token = ?', [m[1]]); clienteId = p.length ? p[0].cliente_id : null; actor = 'cliente'; actorNombre = clienteId ? 'Cliente' : 'Enlace no válido'; }
        else { actor = 'visitante'; actorNombre = 'Visitante de la web'; }
      }
      const detalle = { estado: est, ms: Date.now() - t0 };
      const cuerpo = resumenCuerpo(req.body); if (Object.keys(cuerpo).length && metodo !== 'GET') detalle.datos = cuerpo;
      if (tabla && est < 400) { const despues = metodo === 'DELETE' ? null : await filaReg(tabla, idObj); const d = diferenciasReg(antes, despues); if (d) detalle.cambios = Object.assign({ tabla }, d); if (!clienteId && (antes || despues)) clienteId = (antes || despues).cliente_id || (tabla === 'clientes' ? idObj : null); }
      if (ajAntes && est < 400) { const [f] = await pool.query('SELECT clave, valor FROM ajustes'); const aD = Object.fromEntries(f.map(x => [x.clave, x.valor])); const ca = {}; new Set([...Object.keys(ajAntes), ...Object.keys(aD)]).forEach(k => { if (ajAntes[k] !== aD[k]) ca[k] = /^ntfy_/.test(k) ? { antes: ajAntes[k] ? '(canal)' : null, despues: aD[k] ? '(canal nuevo)' : null } : { antes: ajAntes[k] == null ? null : ajAntes[k], despues: aD[k] == null ? null : aD[k] }; }); if (Object.keys(ca).length) detalle.ajustes = ca; }
      const ids = (req.path.replace(/[0-9a-f]{32}/g, '').match(/\/(\d+)/g) || []).map(x => Number(x.slice(1))).filter(n => n > 0 && n < 2147483647);   // sin los tokens de cliente
      anotarRegistro({ actor_tipo: actor, actor_id: actorId, actor_nombre: actorNombre, tipo: tipoDe(actor, metodo, ruta), accion: accionDe(metodo, ruta, est), metodo, ruta, estado_http: est, objeto_id: idObj || (ids.length ? ids[0] : null), cliente_id: clienteId, detalle, ip: String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim().slice(0, 64) });
    } catch (e) { console.error('Registro:', e.message); }
  });
  next();
});


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
// 14/10: Railway pone un proxy delante; así req.ip es la IP real del visitante
app.set('trust proxy', 1);
// 14/10 (panel público): máximo 5 contraseñas fallidas por correo y por IP en
// 15 minutos; después, a esperar. Se aplica al login del panel y del Área.
const FALLOS_LOGIN = new Map();
const VENTANA_LOGIN_MS = 15 * 60 * 1000, MAX_FALLOS_LOGIN = 5;
function claveLogin(req, tipo, correo) { return tipo + '|' + String(correo || '').toLowerCase() + '|' + (req.ip || ''); }
function loginBloqueado(clave) { const x = FALLOS_LOGIN.get(clave); if (!x) return false; if (x.hasta < Date.now()) { FALLOS_LOGIN.delete(clave); return false; } return x.n >= MAX_FALLOS_LOGIN; }
function apuntarFalloLogin(clave) { const x = FALLOS_LOGIN.get(clave); if (!x || x.hasta < Date.now()) FALLOS_LOGIN.set(clave, { n: 1, hasta: Date.now() + VENTANA_LOGIN_MS }); else x.n++; }
setInterval(() => { const ahoraMs = Date.now(); for (const [k, x] of FALLOS_LOGIN) if (x.hasta < ahoraMs) FALLOS_LOGIN.delete(k); }, 10 * 60 * 1000).unref();
const MSG_BLOQUEO = 'Demasiados intentos fallidos. Espera 15 minutos y vuelve a probar.';

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
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand } = require('@aws-sdk/client-s3');
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
  if (!R2_BUCKET && process.env.ACROS_PRUEBAS === '1') { R2_MEMORIA.set(clave, { buffer, tipoMime }); return; }   // solo pruebas
  await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: clave, Body: buffer, ContentType: tipoMime }));
}
async function bajarDeR2(clave) {
  if (!R2_BUCKET && process.env.ACROS_PRUEBAS === '1') { const g = R2_MEMORIA.get(clave); if (!g) throw new Error('No existe'); return { buffer: g.buffer, tipoMime: g.tipoMime }; }   // solo pruebas
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

// WHATSAPP (10/09, séptima vuelta) — Twilio. Aparcado hasta hoy a
// propósito: el envío del código de acceso ya estaba separado del resto
// (misma idea que con Brevo), así que añadir un canal más no toca nada
// de la lógica de acceso en sí, solo se suma al envío por correo. Sin
// las 3 variables configuradas, no se intenta nada — sigue funcionando
// exactamente igual que hasta ahora.
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_WHATSAPP_FROM = process.env.TWILIO_WHATSAPP_FROM || ''; // p.ej. 'whatsapp:+14155238886' (sandbox) o el número real en producción
const twilioActivo = () => !!(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_WHATSAPP_FROM);

async function enviarWhatsApp(telefono, mensaje) {
  // Twilio exige el prefijo "whatsapp:" en origen y destino, y el
  // teléfono en formato E.164 (con "+" y prefijo de país) — los
  // clientes lo dan como '600111222', así que si no trae "+" se asume
  // España (+34) por defecto; para otros países habrá que pedirlo con
  // prefijo desde el principio (pendiente menor, no bloquea nada hoy).
  const destino = telefono.trim().startsWith('+') ? telefono.trim() : ('+34' + telefono.trim().replace(/\D/g, ''));
  const url = (process.env.TWILIO_API_URL || `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`);
  const cuerpo = new URLSearchParams({ From: `whatsapp:${TWILIO_WHATSAPP_FROM.replace(/^whatsapp:/, '')}`, To: `whatsapp:${destino}`, Body: mensaje });
  await axios.post(url, cuerpo, { auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN } });
}

// Cómo entran los clientes al área (10/09): "enlace" (solo enlace mágico),
// "contrasena" (correo + contraseña, con el enlace como recuperación) o
// "ambos" (por defecto — para poder probar los dos y decidir). Se cambia
// en Railway sin tocar código. La constante vive aquí arriba para que
// esté definida antes de cualquier ruta que la consulte.
const MODOS_ACCESO_CLIENTE = ['enlace', 'contrasena', 'ambos'];
const MODO_ACCESO_CLIENTE = MODOS_ACCESO_CLIENTE.includes(process.env.MODO_ACCESO_CLIENTE)
  ? process.env.MODO_ACCESO_CLIENTE : 'ambos';
const DIAS_VIGENCIA_SESION_CLIENTE = 7;
const MINUTOS_VIGENCIA_ACCESO = 15;
const brevoActivo = () => !!(BREVO_API_KEY && BREVO_REMITENTE);

async function enviarCorreo(destinatario, asunto, html, texto, opciones = {}) {
  [asunto, html, texto] = await ajustarGeneroCorreo(asunto, html, texto);   // 29/10: «tu asesora» si es ella; sin nombre, «tu equipo»
  const url = process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email';
  const cuerpo = {
    sender: { email: BREVO_REMITENTE, name: opciones.nombre || 'Acros' },
    to: [{ email: destinatario }],
    subject: asunto,
    htmlContent: html,
  };
  if (texto) cuerpo.textContent = texto; // versión en texto plano: mejor entrega y lectores sin HTML
  if (opciones.responderA) cuerpo.replyTo = { email: opciones.responderA, name: opciones.nombre || 'Acros' };   // 30/10
  if (opciones.copiaOculta && opciones.copiaOculta !== destinatario) cuerpo.bcc = [{ email: opciones.copiaOculta }];
  if (opciones.cabeceras) cuerpo.headers = opciones.cabeceras;   // 30/10: In-Reply-To / References
  await axios.post(url, cuerpo, { headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' } });
  anotarRegistro({ actor_tipo: 'sistema', actor_nombre: 'Sistema', tipo: 'sistema', accion: 'Correo enviado', detalle: { para: destinatario, asunto: String(asunto).slice(0, 150), de: opciones.nombre || 'Acros' } });   // 30/10
}

// ================================================================
// PLANTILLA DE CORREO CON LA MARCA (08/10)
// Todos los correos a clientes salen con la misma cara: logo y nombre
// arriba, título, texto cercano, botón naranja con la montaña y, debajo,
// en pequeño y gris, el enlace en claro por si el botón no funciona.
// HTML de correo «a la antigua» (tablas y estilos en línea) para que se
// vea igual en Gmail, Outlook y el móvil. Las imágenes se sirven desde la
// web (SITE_URL/marca/…); si el programa de correo las bloquea, el texto
// ACROS y el botón siguen viéndose. Va con versión en texto plano.
// ================================================================
const ESC_HTML = t => String(t == null ? '' : t).replace(/[&<>"]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
function plantillaCorreo({ titulo, parrafos = [], boton, nota, hilo }) {
  // 29/10 (Vikn): botón centrado y grande, aviso del enlace justificado, pie centrado con el texto de marca y, si hace falta, un hilo
  // de mensajes (lo que pidió el cliente y lo que se le responde). Ancho máximo 600 px: en el móvil ocupa todo el ancho de la pantalla.
  const img = n => SITE_URL ? `${SITE_URL}/marca/${n}` : null;
  const fuenteTit = "Georgia, 'Times New Roman', serif";
  const fuente = 'Helvetica, Arial, sans-serif';
  const logo = img('correo-logo.png');
  const icono = img('correo-boton.png');
  const web = SITE_URL || 'https://acrosfi.es';
  const bloqueHilo = h => `<tr><td style="padding:14px 30px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${h.propio ? '#EEF4EF' : '#F6F2EA'}; border-left:4px solid ${h.propio ? '#2E7A4E' : '#C9BBA3'}; border-radius:8px;"><tr><td style="padding:12px 16px; font-family:${fuente};"><div style="font-size:11.5px; letter-spacing:.04em; text-transform:uppercase; color:#8A8378; padding-bottom:5px;">${ESC_HTML(h.quien)}${h.fecha ? ' · ' + ESC_HTML(h.fecha) : ''}</div><div style="font-size:15px; line-height:1.5; color:#423F3A;">${ESC_HTML(h.texto).replace(/\n/g, '<br>')}</div></td></tr></table></td></tr>`;
  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${ESC_HTML(titulo)}</title></head>
<body style="margin:0; padding:0; background:#FBF8F2;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#FBF8F2;"><tr><td align="center" style="padding:28px 14px;">
  <!--[if mso]><table role="presentation" width="600" align="center" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; background:#FFFFFF; border:1px solid #E6DCCD; border-top:4px solid #D2601F; border-radius:14px;">
    <tr><td style="padding:24px 30px 6px;">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        ${logo ? `<td style="padding-right:10px; vertical-align:middle;"><img src="${logo}" width="30" height="24" alt="" style="display:block; border:0;"></td>` : ''}
        <td style="vertical-align:middle; font-family:${fuenteTit}; font-size:19px; letter-spacing:4px; color:#23402F;">ACROS</td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:18px 30px 0; font-family:${fuenteTit}; font-size:23px; line-height:1.25; color:#23402F;">${ESC_HTML(titulo)}</td></tr>
    ${parrafos.map(p => `<tr><td style="padding:12px 30px 0; font-family:${fuente}; font-size:15px; line-height:1.55; color:#423F3A;">${p}</td></tr>`).join('')}
    ${(hilo || []).map(bloqueHilo).join('')}
    ${boton ? `<tr><td align="center" style="padding:28px 30px 6px;">
      <table role="presentation" align="center" width="100%" cellpadding="0" cellspacing="0" style="max-width:340px;"><tr><td align="center" style="background:#B9541B; border-radius:10px;">
        <a href="${ESC_HTML(boton.url)}" style="display:block; padding:15px 24px; font-family:${fuente}; font-size:16px; font-weight:bold; color:#FFFFFF; text-decoration:none; border-radius:10px; text-align:center;">${icono ? `<img src="${icono}" width="18" height="18" alt="" style="vertical-align:-3px; margin-right:8px; border:0;">` : ''}${ESC_HTML(boton.texto)}</a>
      </td></tr></table>
    </td></tr>
    <tr><td style="padding:16px 30px 0;"><div style="font-family:${fuente}; font-size:11.5px; line-height:1.55; color:#8A8378; text-align:justify;">¿El botón no funciona? Copia este enlace en tu navegador: <a href="${ESC_HTML(boton.url)}" style="color:#8A8378; word-break:break-all;">${ESC_HTML(boton.url)}</a></div></td></tr>` : ''}
    ${nota ? `<tr><td style="padding:18px 30px 0; font-family:${fuente}; font-size:13px; line-height:1.5; color:#6B655C;">${nota}</td></tr>` : ''}
    <tr><td style="padding:24px 30px 24px;"><div style="border-top:1px solid #E6DCCD; padding-top:14px; text-align:center; font-family:${fuente}; font-size:12px; line-height:1.6; color:#8A8378;">Acros, tu asesoría fiscal de criptoactivos.<br>Contacta en: <a href="${web}" style="color:#8A8378;">acrosfi.es</a> / 668 170 020</div></td></tr>
  </table>
  <!--[if mso]></td></tr></table><![endif]-->
</td></tr></table>
</body></html>`;
  const sinEtiquetas = t => String(t).replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
  const texto = [titulo, '', ...parrafos.map(sinEtiquetas), ...(hilo || []).flatMap(h => ['', '> ' + h.quien + (h.fecha ? ' · ' + h.fecha : '') + ':', ...String(h.texto).split('\n').map(l => '> ' + l)]), '', boton ? boton.texto + ': ' + boton.url : '', nota ? '\n' + sinEtiquetas(nota) : '', '', '— Acros, tu asesoría fiscal de criptoactivos. Contacta en: acrosfi.es / 668 170 020'].join('\n');
  return { html, texto };
}

// ================================================================
// AVISOS AL MÓVIL POR NTFY (06/10)
// Decidido en septiembre y nunca programado hasta ahora. Cada aviso lleva
// solo un título genérico, SIN datos personales (ntfy es un servicio
// externo y el canal es público para quien conozca su nombre): para ver
// quién es, se abre el panel. Sin NTFY_TOPIC en Railway no se envía nada.
// Se publica en JSON para que los acentos y emojis lleguen bien. Nunca
// bloquea ni rompe la petición que lo dispara.
// ================================================================
const NTFY_TOPIC = (process.env.NTFY_TOPIC || '').trim();
const NTFY_SERVER = (process.env.NTFY_SERVER || 'https://ntfy.sh').replace(/\/+$/, '');
function avisarEn(topic, titulo, mensaje, { prioridad = 3, etiqueta = 'bell' } = {}) {
  if (!topic) return Promise.resolve(false);
  anotarRegistro({ actor_tipo: 'sistema', actor_nombre: 'Sistema', tipo: 'sistema', accion: 'Aviso al móvil (ntfy)', detalle: { titulo: String(titulo || '').slice(0, 150) } });   // 30/10: sin el nombre del canal
  return axios.post(NTFY_SERVER + '/', { topic, title: titulo, message: mensaje || 'Ábrelo en el panel de Acros.', priority: prioridad, tags: [etiqueta] }, { timeout: 5000 })
    .then(() => true)
    .catch(err => { console.error('Aviso ntfy no enviado:', err.message); return false; });
}
function avisar(titulo, mensaje, opciones) { return avisarEn(canalDe('actividad'), titulo, mensaje, opciones); }   // «Clientes · actividad»
// 15/10: CANALES DE AVISOS (decididos con Vikn). Se configuran en el panel
// («Canales de avisos», tabla `ajustes`). Si uno está vacío, sus avisos van
// al de «Clientes · actividad», que si tampoco está usa NTFY_TOPIC.
//   captacion      → solicitudes, cuestionarios, llamadas, empresas
//   actividad      → todo lo de cada cliente (y siempre lo de los canales de asesor)
//   equipo         → cuentas de asesores: contraseñas, enlaces, códigos, correos
//   admin_clientes → sugerencias, cambios de asesor, valoraciones
//   alertas        → lo técnico (correos que no salen, copias que fallan…)
const NTFY_TOPIC_ADMIN = (process.env.NTFY_TOPIC_ADMIN || '').trim();
const CANALES = { captacion: '', actividad: '', equipo: '', admin_clientes: '', alertas: '', pagos: '' };
function canalDe(clave) {
  const base = CANALES.actividad || NTFY_TOPIC;
  if (clave === 'actividad') return base;
  return CANALES[clave] || (['equipo', 'admin_clientes', 'alertas', 'pagos'].includes(clave) && NTFY_TOPIC_ADMIN) || base;
}
async function cargarCanales() {
  try { const [f] = await pool.execute("SELECT clave, valor FROM ajustes WHERE clave LIKE 'ntfy_%'"); f.forEach(x => { const k = x.clave.slice(5); if (k in CANALES) CANALES[k] = (x.valor || '').trim(); }); }
  catch (e) { /* aún sin tabla */ }
}
const avisarCaptacion = (t, m, o) => avisarEn(canalDe('captacion'), t, m, o);
const avisarEquipo = (t, m, o) => avisarEn(canalDe('equipo'), t, m, o);
const avisarAdminClientes = (t, m, o) => avisarEn(canalDe('admin_clientes'), t, m, o);
const avisarAlerta = (t, m, o) => avisarEn(canalDe('alertas'), t, m, o);
const avisarPagos = (t, m, o) => avisarEn(canalDe('pagos'), t, m, o);   // 15/10: canal 7
function avisarAdmin(titulo, mensaje, opciones) { return avisarEquipo(titulo, mensaje, opciones); }
// Fase B (10/10): lo de un cliente concreto va con el nombre de su asesor
// («💬 Bernardo, un cliente te ha escrito») al canal general (el admin lo
// ve todo) y, además, al canal propio de ese asesor. Sin asesor asignado:
// «💬 Un cliente te ha escrito», solo al general. Nunca bloquea.
async function personaDeCliente(clienteId, conn) {
  const ejecutar = conn || pool;
  const [f] = await ejecutar.execute('SELECT p.* FROM clientes c JOIN personas p ON p.`id` = c.`asesor_persona_id` WHERE c.`id` = ? AND p.`activa` = 1', [clienteId]);
  return f[0] || null;
}
function avisarCliente(clienteId, emoji, accion, mensaje, opciones) {
  (async () => {
    let q = null;
    try { q = clienteId ? await personaDeCliente(clienteId) : null; } catch (e) { q = null; }
    const accionM = accion.charAt(0).toUpperCase() + accion.slice(1), ini = q ? await inicialesDePersona(q.id) : '';
    const titulo = emoji + ' ' + (ini ? ini + ' · ' : '') + accionM;   // 20/10: en los canales generales, las iniciales del asesor (nunca nombres)
    const tituloPropio = emoji + ' ' + accionM;                       // en su propio canal ya sabe que es para él
    if (!(opciones && opciones.soloAsesor)) await avisar(titulo, mensaje, opciones);
    if (q && q.ntfy_topic && q.ntfy_topic !== NTFY_TOPIC) await avisarEn(q.ntfy_topic, tituloPropio, mensaje, opciones);
    // 15/10: y al canal de su equipo (2b), si lo tiene
    if (q && q.id) { const [e] = await pool.execute('SELECT e.ntfy_topic FROM personas p JOIN equipos e ON e.id = p.equipo_id WHERE p.id = ? AND e.activo = 1 AND e.ntfy_topic IS NOT NULL', [q.id]).catch(() => [[]]); if (e.length && e[0].ntfy_topic) await avisarEn(e[0].ntfy_topic, titulo, mensaje, opciones); }
  })().catch(() => {});
}

// 08/10: las páginas tienen direcciones limpias (acrosfi.es/area); los
// nombres antiguos (acros_area.html…) siguen funcionando con páginas de paso.
function enlaceArea(ruta, token, parametro = 'token') {
  // Sin SITE_URL configurada todavía (no hay dominio público real), el
  // correo incluye el token en texto en vez de un enlace clicable — se
  // arregla solo en cuanto Vikn tenga dominio y se configure SITE_URL.
  // "parametro" (10/09): el enlace de reentrada usa ?acceso= en vez de
  // ?token=, para que el área sepa que es un enlace de un solo uso y no
  // el token de una propuesta.
  return SITE_URL ? `${SITE_URL}/${ruta}?${parametro}=${token}` : null;
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

      // Acceso del cliente por contraseña + sesiones de cliente (10/09,
      // quinta vuelta). Conviven las dos formas de entrar — enlace mágico
      // y contraseña — sobre una misma capa de sesión; cuál se ofrece se
      // decide con MODO_ACCESO_CLIENTE (ver más abajo), sin tocar código.
      await agregaColumnaSiFalta('clientes', 'contrasena_hash', 'VARCHAR(100) NULL');
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS sesiones_cliente (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          cliente_id    INT NOT NULL,
          token         CHAR(48) NOT NULL UNIQUE,
          expira_en     DATETIME NOT NULL,
          creado_en     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (cliente_id) REFERENCES clientes(id)
        )
      `);
      await creaIndiceSiFalta('idx_sesiones_cliente_token ON sesiones_cliente (token)');

      // Empresas colaboradoras (28/09): gestorías, asesorías, inmobiliarias
      // y «otro». Solo se registran desde la vista «Empresas» de Inicio;
      // no entran al área ni usan chat — la relación va por teléfono,
      // WhatsApp o correo. El alta NO activa nada: queda «pendiente»
      // hasta que un asesor la valida y se firma el acuerdo B2B (es la
      // puerta de control, porque con empresas no se pide DNI a los
      // clientes finales). Nunca se borra ninguna: se marca «descartada».
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS empresas (
          id                  INT AUTO_INCREMENT PRIMARY KEY,
          razon_social        VARCHAR(160) NOT NULL,
          cif                 VARCHAR(12)  NOT NULL,
          tipo                VARCHAR(20)  NOT NULL,
          tipo_otro           VARCHAR(80)  NULL,
          contacto_nombre     VARCHAR(120) NOT NULL,
          telefono            VARCHAR(30)  NOT NULL,
          correo              VARCHAR(190) NOT NULL,
          canal_preferido     VARCHAR(12)  NOT NULL DEFAULT 'whatsapp',
          comentario          TEXT         NULL,
          idioma              CHAR(2)      NULL,
          utm                 VARCHAR(300) NULL,
          origen              VARCHAR(60)  NULL,
          estado              VARCHAR(20)  NOT NULL DEFAULT 'pendiente',
          asesor_asignado_id  INT NULL,
          estado_cambiado_por_asesor_id INT NULL,
          estado_cambiado_en  DATETIME NULL,
          creado_en           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (asesor_asignado_id) REFERENCES asesores(id),
          FOREIGN KEY (estado_cambiado_por_asesor_id) REFERENCES asesores(id)
        )
      `);
      await creaIndiceSiFalta('idx_empresas_estado ON empresas (estado, creado_en)');

      // Web pública editable desde el panel (05/10): logo, equipo,
      // destacados y ofertas. Un registro por «clave» ('marca' y
      // 'catalogo') con su número de versión; cada guardado deja una
      // copia en el historial (las últimas 30) para poder volver atrás.
      // Las imágenes (logo y fotos) se guardan aquí mismo, ya reducidas
      // en el navegador del administrador: son públicas y pequeñas, así
      // que no van a R2 (que solo guarda documentos cifrados).
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS web_contenido (
          clave                     VARCHAR(20)  PRIMARY KEY,
          datos                     MEDIUMTEXT   NOT NULL,
          version                   INT          NOT NULL,
          actualizado_en            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          actualizado_por_asesor_id INT NULL,
          FOREIGN KEY (actualizado_por_asesor_id) REFERENCES asesores(id)
        )
      `);
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS web_contenido_historial (
          id                     INT AUTO_INCREMENT PRIMARY KEY,
          clave                  VARCHAR(20)  NOT NULL,
          version                INT          NOT NULL,
          datos                  MEDIUMTEXT   NOT NULL,
          guardado_en            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          guardado_por_asesor_id INT NULL,
          FOREIGN KEY (guardado_por_asesor_id) REFERENCES asesores(id)
        )
      `);
      await creaIndiceSiFalta('idx_web_historial ON web_contenido_historial (clave, version)');
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS web_imagenes (
          id                   CHAR(32)     PRIMARY KEY,
          tipo                 VARCHAR(40)  NOT NULL,
          datos                MEDIUMBLOB   NOT NULL,
          bytes                INT          NOT NULL,
          creado_en            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          creado_por_asesor_id INT NULL,
          FOREIGN KEY (creado_por_asesor_id) REFERENCES asesores(id)
        )
      `);

      // Chat cliente–asesor (06/10): un hilo por encargo y servicio. «Borrado
      // espejo» (decisión de septiembre): quien escribe un mensaje puede
      // borrarlo y desaparece para los dos; la conversación no se borra entera.
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS mensajes (
          id            INT AUTO_INCREMENT PRIMARY KEY,
          propuesta_id  INT          NOT NULL,
          cliente_id    INT          NOT NULL,
          servicio      VARCHAR(50)  NOT NULL DEFAULT 'general',
          autor         ENUM('cliente','asesor') NOT NULL,
          asesor_id     INT NULL,
          texto         TEXT         NOT NULL,
          leido_en      DATETIME NULL,
          creado_en     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (propuesta_id) REFERENCES propuestas(id),
          FOREIGN KEY (cliente_id) REFERENCES clientes(id),
          FOREIGN KEY (asesor_id) REFERENCES asesores(id)
        )
      `);
      await creaIndiceSiFalta('idx_mensajes_hilo ON mensajes (propuesta_id, servicio, creado_en)');
      await creaIndiceSiFalta('idx_mensajes_sin_leer ON mensajes (autor, leido_en)');
      // Cuándo se avisó por última vez al cliente de un encargo (06/10): el
      // correo «tu asesor te ha escrito» sale tras un rato sin escribirle.
      await pool.execute(`
        CREATE TABLE IF NOT EXISTS avisos_chat (
          propuesta_id    INT PRIMARY KEY,
          ultimo_aviso_en DATETIME NOT NULL,
          FOREIGN KEY (propuesta_id) REFERENCES propuestas(id)
        )
      `);

      // Registro de las copias de la base de datos (07/10). 08/10: la columna
      // se llamaba «manual», que es palabra reservada en MySQL 8.4+ (Railway)
      // aunque MariaDB la acepte: ahora «es_manual», y todo entre comillas
      // (también los alias: «AS manual» sin comillas rompía la lista).
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS copias_bd (' +
        ' `id`        INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `fecha`     DATE         NOT NULL,' +
        ' `clave_r2`  VARCHAR(200) NULL,' +
        ' `bytes`     INT          NULL,' +
        ' `tablas`    INT          NULL,' +
        ' `filas`     INT          NULL,' +
        " `estado`    ENUM('ok','error') NOT NULL," +
        ' `error`     TEXT         NULL,' +
        ' `es_manual` TINYINT(1)   NOT NULL DEFAULT 0,' +
        ' `creado_en` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP)'
      );
      await creaIndiceSiFalta('idx_copias_fecha ON copias_bd (`fecha`, `estado`)');
      // 09/10: el cuestionario de Empieza aquí puede llegar después de la
      // solicitud; esta clave de un solo uso permite añadirlo sin sesión.
      await agregaColumnaSiFalta('solicitudes_presupuesto', '`token_cuestionario`', 'CHAR(32) NULL');
      await agregaColumnaSiFalta('solicitudes_presupuesto', '`cuestionario_en`', 'DATETIME NULL');
      // Avisos al cliente de documentación pedida, agrupados (10/10)
      await pool.execute('CREATE TABLE IF NOT EXISTS avisos_documentos (`propuesta_id` INT PRIMARY KEY, `ultimo_aviso_en` DATETIME NOT NULL)');
      // Resumen diario para los administradores (10/10): una fila por día enviado
      // Equipo como personas (fase A, 10/10): cada persona del equipo, con o
      // sin cuenta de asesor. De aquí salen Inicio, el asesor de cada cliente
      // y, más adelante, los perfiles y las valoraciones.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS personas (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `nombre` VARCHAR(80) NOT NULL,' +
        ' `puesto_es` VARCHAR(120) NULL, `puesto_en` VARCHAR(120) NULL,' +
        ' `bio_es` VARCHAR(400) NULL, `bio_en` VARCHAR(400) NULL,' +
        ' `foto` CHAR(32) NULL,' +
        ' `especialidades` TEXT NULL,' +
        ' `atiende_clientes` TINYINT(1) NOT NULL DEFAULT 0,' +
        ' `asesor_id` INT NULL UNIQUE,' +
        ' `ntfy_topic` VARCHAR(80) NULL,' +
        ' `activa` TINYINT(1) NOT NULL DEFAULT 1,' +
        ' `orden` INT NOT NULL DEFAULT 0,' +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `actualizado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,' +
        ' FOREIGN KEY (`asesor_id`) REFERENCES asesores(`id`))'
      );
      await migrarEquipoAPersonas();
      await agregaColumnaSiFalta('personas', '`por_defecto`', 'TINYINT(1) NOT NULL DEFAULT 0');
      // 10/10: el cliente pide expresamente que empecemos ya (desistimiento)
      await agregaColumnaSiFalta('propuestas', '`inicio_inmediato_en`', 'DATETIME NULL');
      // 10/10: «borrado espejo» como se decidió en septiembre: ningún mensaje
      // se borra de verdad. El cliente oculta los suyos de su vista (nosotros
      // conservamos la copia); el asesor retira los suyos (dejan de verse en
      // el área del cliente, pero quedan en el panel).
      await agregaColumnaSiFalta('documentos_fiscales', '`revisado_en`', 'DATETIME NULL');   // 13/10: para el historial
      await agregaColumnaSiFalta('clientes', '`preferencias_avisos`', 'TEXT NULL');   // 13/10: «Notificaciones» del Área
      await agregaColumnaSiFalta('clientes', '`telefono2`', 'VARCHAR(40) NULL');   // 14/10: segundo teléfono
      // 16/10: «Mi cartera»
      await pool.execute('CREATE TABLE IF NOT EXISTS cartera_movimientos (`id` INT AUTO_INCREMENT PRIMARY KEY, `cliente_id` INT NOT NULL, `fecha` DATETIME NOT NULL, `tipo` VARCHAR(60) NOT NULL, `buy_amount` DOUBLE NULL, `buy_cur` VARCHAR(30) NULL, `sell_amount` DOUBLE NULL, `sell_cur` VARCHAR(30) NULL, `fee_amount` DOUBLE NULL, `fee_cur` VARCHAR(30) NULL, `exchange` VARCHAR(200) NULL, `grupo` VARCHAR(200) NULL, `comentario` VARCHAR(500) NULL, `txid` VARCHAR(200) NULL, `buy_valor_eur` DOUBLE NULL, `sell_valor_eur` DOUBLE NULL, ' +
        "`origen` ENUM('importado','manual') NOT NULL, `nota` VARCHAR(300) NULL, `sustituye_id` INT NULL, `anulado` TINYINT(1) NOT NULL DEFAULT 0, `anulado_motivo` VARCHAR(300) NULL, `anulado_por` INT NULL, `anulado_en` DATETIME NULL, `creado_por` INT NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, KEY k_cliente (`cliente_id`, `anulado`, `fecha`))");
      await pool.execute("CREATE TABLE IF NOT EXISTS cartera_estado (`cliente_id` INT PRIMARY KEY, `fuente_nombre` VARCHAR(200) NULL, `importado_en` DATETIME NULL, `importado_por` INT NULL, `publicado_en` DATETIME NULL, `publicado_por` INT NULL, `ritmo` VARCHAR(20) NOT NULL DEFAULT 'mensual', `simulador` TINYINT(1) NOT NULL DEFAULT 0, `perdidas_pendientes` TEXT NULL)");
      await pool.execute('CREATE TABLE IF NOT EXISTS cartera_otras (`id` INT AUTO_INCREMENT PRIMARY KEY, `cliente_id` INT NOT NULL, `anio` INT NOT NULL, `plataforma` VARCHAR(80) NOT NULL, `tipo` VARCHAR(80) NULL, `ganancias` DOUBLE NOT NULL DEFAULT 0, `perdidas` DOUBLE NOT NULL DEFAULT 0, `rendimientos` DOUBLE NOT NULL DEFAULT 0, `latente` DOUBLE NULL, `fuente` VARCHAR(120) NULL, `creado_por` INT NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)');
      await pool.execute("CREATE TABLE IF NOT EXISTS activos_catalogo (`simbolo` VARCHAR(30) PRIMARY KEY, `nombre` VARCHAR(80) NULL, `coingecko_id` VARCHAR(120) NULL, `red` VARCHAR(80) NULL, `sector` VARCHAR(80) NULL, `tipo` VARCHAR(20) NULL, `tamano` VARCHAR(20) NULL, `grupo` VARCHAR(80) NULL, `origen` ENUM('sin','coingecko','manual') NOT NULL DEFAULT 'sin', `editado_por` INT NULL, `precio_eur` DOUBLE NULL, `precio_en` DATETIME NULL, `intento_en` DATETIME NULL, `actualizado_en` DATETIME NULL)");
      setTimeout(() => resolverActivosPendientes().then(actualizarPrecios).catch(() => {}), 5000);
      // 15/10: roles y equipos
      await agregaColumnaSiFalta('asesores', '`roles`', 'VARCHAR(120) NULL');
      await agregaColumnaSiFalta('personas', '`equipo_id`', 'INT NULL');
      await pool.execute('CREATE TABLE IF NOT EXISTS equipos (`id` INT AUTO_INCREMENT PRIMARY KEY, `nombre` VARCHAR(80) NOT NULL, `jefe_persona_id` INT NULL, `encargado_persona_id` INT NULL, `ntfy_topic` VARCHAR(80) NULL, `activo` TINYINT(1) NOT NULL DEFAULT 1, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)');
      await agregaColumnaSiFalta('documentos_fiscales', '`nombre_original`', 'VARCHAR(255) NULL');   // 15/10: nombre del archivo tal cual lo subió el cliente
      await pool.execute('CREATE TABLE IF NOT EXISTS ajustes (`clave` VARCHAR(60) PRIMARY KEY, `valor` TEXT NULL, `actualizado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)');   // 15/10
      setTimeout(cargarCanales, 500);
      // 14/10: llaves de documentos por asesor (ver «LLAVES POR ASESOR»)
      for (const [col, def] of [['auth_v2', 'TINYINT(1) NOT NULL DEFAULT 0'], ['auth_sal', 'VARCHAR(64) NULL'], ['llave_sal', 'VARCHAR(64) NULL'], ['llave_publica', 'TEXT NULL'], ['llave_privada_cifrada', 'MEDIUMTEXT NULL'], ['llave_iv', 'VARCHAR(40) NULL'], ['maestra_cifrada', 'MEDIUMTEXT NULL'], ['maestra_iv', 'VARCHAR(40) NULL']])
        await agregaColumnaSiFalta('asesores', '`' + col + '`', def);
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS llaves_documento (' +
        " `id` INT AUTO_INCREMENT PRIMARY KEY, `tipo` ENUM('fiscal','identidad') NOT NULL, `objeto_id` INT NOT NULL, `asesor_id` INT NOT NULL," +
        ' `clave_envuelta` VARCHAR(1200) NOT NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY u_llave (`tipo`, `objeto_id`, `asesor_id`))');
      // 14/10: enlaces para crear o restablecer la contraseña de un asesor
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS enlaces_contrasena (' +
        " `id` INT AUTO_INCREMENT PRIMARY KEY, `asesor_id` INT NOT NULL, `hash` CHAR(64) NOT NULL UNIQUE, `tipo` ENUM('invitacion','restablecer') NOT NULL," +
        ' `expira_en` DATETIME NOT NULL, `usado_en` DATETIME NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)');
      await agregaColumnaSiFalta('enlaces_contrasena', '`auth_sal`', 'VARCHAR(64) NULL');
      await agregaColumnaSiFalta('enlaces_contrasena', '`llave_sal`', 'VARCHAR(64) NULL');
      // 14/10: código de usuario (único) y asignación a los clientes que ya tienen identidad
      if (await agregaColumnaSiFalta('clientes', '`codigo`', 'VARCHAR(16) NULL')) {
        await pool.execute('CREATE UNIQUE INDEX idx_clientes_codigo ON clientes (`codigo`)').catch(() => {});
      }
      setTimeout(() => asignarCodigosPendientes().catch(err => console.error('Códigos de usuario:', err.message)), 2000);
      // Registro de actividad del equipo (13/10): qué hizo cada asesor en el
      // panel (confirmar, aprobar, validar, enviar, entregar…), con fecha.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS actividad (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY, `asesor_id` INT NOT NULL, `metodo` VARCHAR(8) NOT NULL, `ruta` VARCHAR(160) NOT NULL,' +
        ' `objeto_id` INT NULL, `cliente_id` INT NULL, `resumen` VARCHAR(600) NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)');
      // Verificación en dos pasos (10/10): obligatoria para los asesores,
      // opcional para los clientes. Al estrenarla se cierran todas las
      // sesiones de asesor: cada uno la configura al volver a entrar.
      const nueva2FA = await agregaColumnaSiFalta('asesores', '`totp_activo`', 'TINYINT(1) NOT NULL DEFAULT 0');
      await agregaColumnaSiFalta('asesores', '`totp_secreto`', 'VARCHAR(64) NULL');
      await agregaColumnaSiFalta('asesores', '`totp_recuperacion`', 'TEXT NULL');
      await agregaColumnaSiFalta('asesores', '`totp_activado_en`', 'DATETIME NULL');
      if (nueva2FA) { await pool.execute('DELETE FROM sesiones_asesor'); console.log('2FA estrenado: sesiones de asesor cerradas'); }
      await agregaColumnaSiFalta('clientes', '`totp_activo`', 'TINYINT(1) NOT NULL DEFAULT 0');
      await agregaColumnaSiFalta('clientes', '`totp_secreto`', 'VARCHAR(64) NULL');
      await agregaColumnaSiFalta('clientes', '`totp_recuperacion`', 'TEXT NULL');
      await agregaColumnaSiFalta('clientes', '`totp_activado_en`', 'DATETIME NULL');
      await agregaColumnaSiFalta('sesiones_cliente', '`dos_pasos`', 'TINYINT(1) NOT NULL DEFAULT 0');
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS pasos_login (' +
        ' `token` CHAR(48) PRIMARY KEY, `asesor_id` INT NOT NULL, `secreto_pendiente` VARCHAR(64) NULL,' +
        ' `intentos` INT NOT NULL DEFAULT 0, `expira_en` DATETIME NOT NULL)');
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS dispositivos_confianza (' +
        " `id` INT AUTO_INCREMENT PRIMARY KEY, `tipo` ENUM('asesor','cliente') NOT NULL, `usuario_id` INT NOT NULL," +
        ' `hash` CHAR(64) NOT NULL UNIQUE, `expira_en` DATETIME NOT NULL, `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)');
      // Buzón de sugerencias (10/10): desde el Área (con o sin nombre) y desde
      // las páginas públicas. Solo las ven los administradores.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS sugerencias (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        " `tipo` ENUM('idea','fallo','otro') NOT NULL DEFAULT 'idea'," +
        ' `texto` TEXT NOT NULL,' +
        ' `correo` VARCHAR(160) NULL,' +
        ' `cliente_id` INT NULL,' +
        ' `anonima` TINYINT(1) NOT NULL DEFAULT 0,' +
        " `origen` VARCHAR(40) NULL," +
        ' `pagina` VARCHAR(120) NULL,' +
        ' `idioma` VARCHAR(5) NULL,' +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `vista_en` DATETIME NULL, `vista_por` INT NULL)'
      );
      await agregaColumnaSiFalta('mensajes', '`oculto_cliente_en`', 'DATETIME NULL');
      await agregaColumnaSiFalta('mensajes', '`retirado_en`', 'DATETIME NULL');
      await agregaColumnaSiFalta('mensajes', '`retirado_por`', 'INT NULL');
      // Empresas parte 2 (10/10): notas de contacto. Inalterables: no hay
      // ninguna ruta para editarlas ni borrarlas, y solo se escriben con la
      // sesión de un asesor (queda quién y cuándo; la clave maestra no
      // sirve). Van en la copia nocturna como el resto de tablas.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS empresa_notas (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `empresa_id` INT NOT NULL,' +
        ' `asesor_id` INT NOT NULL,' +
        " `canal` ENUM('llamada','correo','whatsapp','reunion','otro') NOT NULL DEFAULT 'otro'," +
        ' `texto` TEXT NOT NULL,' +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' FOREIGN KEY (`empresa_id`) REFERENCES empresas(`id`), FOREIGN KEY (`asesor_id`) REFERENCES asesores(`id`))'
      );
      await agregaColumnaSiFalta('solicitudes_presupuesto', '`asesor_preferido_id`', 'INT NULL');
      // Fase C (10/10): valoración del asesor al terminar el encargo
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS valoraciones (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `propuesta_id` INT NOT NULL UNIQUE,' +
        ' `cliente_id` INT NOT NULL,' +
        ' `persona_id` INT NULL,' +
        ' `atencion` TINYINT NULL, `calidad` TINYINT NULL, `rapidez` TINYINT NULL,' +
        ' `comentario` TEXT NULL, `comentario_revisado` TEXT NULL,' +
        " `nombre_publico` ENUM('completo','nombre_inicial','inicial_apellido','iniciales') NULL," +
        ' `nombre_mostrado` VARCHAR(160) NULL,' +
        " `estado` ENUM('omitida','por_revisar','revisada') NOT NULL," +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `revisado_en` DATETIME NULL, `revisado_por` INT NULL, `recordatorio_en` DATETIME NULL,' +
        ' FOREIGN KEY (`propuesta_id`) REFERENCES propuestas(`id`))'
      );
      // Fase D (10/10): colaboraciones entre asesores en un encargo
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS colaboraciones (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `propuesta_id` INT NOT NULL,' +
        ' `persona_id` INT NOT NULL,' +
        ' `descripcion` VARCHAR(300) NULL,' +
        " `estado` ENUM('pendiente','confirmada') NOT NULL DEFAULT 'pendiente'," +
        ' `anotado_por` INT NULL, `confirmado_por` INT NULL,' +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, `confirmado_en` DATETIME NULL,' +
        ' FOREIGN KEY (`propuesta_id`) REFERENCES propuestas(`id`), FOREIGN KEY (`persona_id`) REFERENCES personas(`id`))'
      );
      // Fase B (10/10): el asesor de cada cliente y los cambios que pide
      await agregaColumnaSiFalta('clientes', '`asesor_persona_id`', 'INT NULL');
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS cambios_asesor (' +
        ' `id` INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `cliente_id` INT NOT NULL,' +
        ' `desde_persona_id` INT NULL,' +
        ' `a_persona_id` INT NOT NULL,' +
        ' `motivo` TEXT NULL,' +
        " `estado` ENUM('pendiente','aceptado','rechazado') NOT NULL DEFAULT 'pendiente'," +
        ' `respuesta` TEXT NULL,' +
        ' `creado_en` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `resuelto_en` DATETIME NULL,' +
        ' `resuelto_por` INT NULL,' +
        ' FOREIGN KEY (`cliente_id`) REFERENCES clientes(`id`))'
      );
      await pool.execute('CREATE TABLE IF NOT EXISTS resumenes_diarios (`fecha` DATE PRIMARY KEY, `enviado_en` DATETIME NOT NULL, `elementos` INT NOT NULL DEFAULT 0)');

      // Informes entregados al cliente (fase 2, 08/10): solo la versión final
      // (los borradores no se guardan). Cada corrección es una versión nueva;
      // el cliente ve la última y las anteriores se conservan. Su conformidad
      // da el servicio por terminado.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS entregas (' +
        ' `id`             INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `propuesta_id`   INT          NOT NULL,' +
        ' `cliente_id`     INT          NOT NULL,' +
        ' `servicio`       VARCHAR(50)  NOT NULL,' +
        ' `version`        INT          NOT NULL DEFAULT 1,' +
        ' `nombre_archivo` VARCHAR(255) NOT NULL,' +
        ' `tipo`           VARCHAR(100) NOT NULL,' +
        ' `bytes`          INT          NOT NULL,' +
        ' `clave_r2`       VARCHAR(300) NOT NULL,' +
        ' `subido_por`     INT          NULL,' +
        ' `subido_en`      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        " `estado`         ENUM('entregado','conforme','cambios') NOT NULL DEFAULT 'entregado'," +
        ' `comentario`     TEXT         NULL,' +
        ' `respondido_en`  DATETIME     NULL,' +
        ' FOREIGN KEY (`propuesta_id`) REFERENCES propuestas(`id`),' +
        ' FOREIGN KEY (`cliente_id`) REFERENCES clientes(`id`))'
      );
      await creaIndiceSiFalta('idx_entregas_servicio ON entregas (`propuesta_id`, `servicio`, `version`)');

      // IA (16/10, Vikn): solo métricas de uso, NUNCA el texto enviado ni el
      // recibido. «sin_ia» = el cliente pidió que no se use IA en su caso.
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS ia_uso (' +
        ' `id`              INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `creado_en`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `funcion`         VARCHAR(40)  NOT NULL,' +
        ' `persona_id`      INT          NULL,' +   // asesores.id de quien lo pidió
        ' `cliente_id`      INT          NULL,' +
        ' `modelo`          VARCHAR(60)  NOT NULL,' +
        ' `tokens_entrada`  INT          NOT NULL DEFAULT 0,' +
        ' `tokens_salida`   INT          NOT NULL DEFAULT 0,' +
        ' `coste_micro_usd` BIGINT       NOT NULL DEFAULT 0,' +
        ' `ok`              TINYINT(1)   NOT NULL DEFAULT 1,' +
        ' `error`           VARCHAR(200) NULL)'
      );
      await creaIndiceSiFalta('idx_ia_uso_fecha ON ia_uso (`creado_en`)');
      await agregaColumnaSiFalta('clientes', '`sin_ia`', 'TINYINT(1) NOT NULL DEFAULT 0');

      // --- Servicios por ejercicio, plazos y cierre a dos bandas (20/10, ACROS 7 · fase 1) ---
      await agregaColumnaSiFalta('propuestas', '`servicios_detalle`', 'TEXT NULL');   // ejercicios que indicó el asesor al enviar la propuesta
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS servicios_cliente (' +
        ' `id`               INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `cliente_id`       INT          NOT NULL,' +
        ' `propuesta_id`     INT          NOT NULL,' +
        ' `servicio`         VARCHAR(50)  NOT NULL,' +   // id en la propuesta: enlaza con documentos, mensajes y entregas
        ' `tipo`             VARCHAR(40)  NOT NULL,' +
        ' `ejercicio_desde`  SMALLINT     NOT NULL,' +
        ' `ejercicio_hasta`  SMALLINT     NOT NULL,' +
        ' `clave`            VARCHAR(80)  NOT NULL,' +   // tipo-ejercicio (renta-2025), única por cliente
        ' `plazo_propio`     DATE         NULL,' +       // solo si se editó a mano; si no, se calcula
        ' `ventana_propia`   SMALLINT     NULL,' +
        ' `presentado_en`    DATE         NULL,' +
        " `estado`           ENUM('abierto','por_confirmar','terminado','cerrado_sin_respuesta') NOT NULL DEFAULT 'abierto'," +
        ' `propuesto_en`     DATETIME     NULL,' +
        ' `propuesto_por`    INT          NULL,' +
        ' `cerrado_en`       DATETIME     NULL,' +
        ' `cerrado_por`      INT          NULL,' +
        " `cierre_via`       ENUM('cliente','informe','asesor') NULL," +
        " `ejercicio_origen` ENUM('asesor','defecto','migracion') NOT NULL DEFAULT 'defecto'," +
        ' `confirmado`       TINYINT(1)   NOT NULL DEFAULT 1,' +   // 0 = deducido en la migración, pendiente de confirmar
        ' `deduccion`        VARCHAR(300) NULL,' +
        ' `confianza`        VARCHAR(10)  NULL,' +
        ' `creado_en`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' `actualizado_en`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,' +
        ' UNIQUE KEY `uq_servicio_propuesta` (`propuesta_id`, `servicio`),' +
        ' UNIQUE KEY `uq_servicio_clave` (`cliente_id`, `clave`),' +
        ' KEY `idx_servicios_estado` (`estado`, `confirmado`),' +
        ' FOREIGN KEY (`cliente_id`) REFERENCES clientes(`id`),' +
        ' FOREIGN KEY (`propuesta_id`) REFERENCES propuestas(`id`))'
      );
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS plazos_defecto (' +
        ' `tipo`           VARCHAR(40) NOT NULL,' +
        ' `ejercicio`      SMALLINT    NOT NULL,' +
        ' `plazo`          DATE        NULL,' +
        ' `ventana_dias`   SMALLINT    NULL,' +
        ' `actualizado_por` INT        NULL,' +
        ' `actualizado_en` DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,' +
        ' PRIMARY KEY (`tipo`, `ejercicio`))'
      );
      await agregaColumnaSiFalta('servicios_cliente', '`aviso_urgencia`', "VARCHAR(40) NULL DEFAULT 'base'");
      await agregaColumnaSiFalta('personas', '`iniciales`', 'VARCHAR(4) NULL');
      await agregaColumnaSiFalta('diligencias', '`heredada_de`', 'INT NULL');   // 21/10: alta una vez por cliente
      await agregaColumnaSiFalta('solicitudes_llamada', '`motivo`', 'VARCHAR(500) NULL');
      await agregaColumnaSiFalta('entregas', '`conformidad_pedida_en`', 'DATETIME NULL');
      await pool.execute('CREATE TABLE IF NOT EXISTS registro (id BIGINT AUTO_INCREMENT PRIMARY KEY, creado_en DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), actor_tipo VARCHAR(16) NOT NULL, actor_id INT NULL, actor_nombre VARCHAR(120) NULL, tipo VARCHAR(12) NOT NULL, accion VARCHAR(200) NOT NULL, metodo VARCHAR(8) NULL, ruta VARCHAR(200) NULL, estado_http SMALLINT NULL, objeto_id INT NULL, cliente_id INT NULL, detalle TEXT NULL, ip VARCHAR(64) NULL, INDEX idx_fecha (creado_en), INDEX idx_cliente (cliente_id), INDEX idx_actor (actor_tipo, actor_id), INDEX idx_tipo (tipo))');   // 30/10: registro maestro
      await pool.execute('DELETE FROM registro WHERE creado_en < NOW() - INTERVAL 15 YEAR').catch(() => {});   // tope de conservación
      await agregaColumnaSiFalta('personas', '`correo_clientes`', 'VARCHAR(190) NULL');   // 30/10: correos desde el panel
      await pool.execute('CREATE TABLE IF NOT EXISTS correos_panel (id INT AUTO_INCREMENT PRIMARY KEY, cliente_id INT NOT NULL, asesor_id INT NULL, persona_id INT NULL, para VARCHAR(190) NOT NULL, asunto VARCHAR(150) NOT NULL, cuerpo TEXT NOT NULL, presentacion VARCHAR(120) NULL, responder_a VARCHAR(190) NULL, copia VARCHAR(190) NULL, ok TINYINT(1) NOT NULL DEFAULT 1, error VARCHAR(300) NULL, enviado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_cliente (cliente_id))');
      for (const [c, t] of [['direccion', "VARCHAR(10) NOT NULL DEFAULT 'saliente'"], ['de', 'VARCHAR(190) NULL'], ['en_respuesta_a', 'INT NULL'], ['mensaje_id', 'VARCHAR(255) NULL'], ['hilo_id', 'INT NULL'], ['respuesta_token', 'VARCHAR(32) NULL'], ['leido_en', 'DATETIME NULL'], ['adjuntos', 'TEXT NULL']]) await agregaColumnaSiFalta('correos_panel', '`' + c + '`', t);   // 30/10: respuestas por correo dentro del panel
      // 30/10: las notas y marcas de cobertura de fichas ya fusionadas se quedaron en la ficha duplicada (inerte): se pasan a la que quedó
      try { const [inertes] = await pool.query("SELECT id, correo FROM clientes WHERE estado = 'inerte' AND correo LIKE 'fusionado-%'"); for (const d of inertes) { const orig = String(d.correo).replace(/^fusionado-\d+-/, ''); const [pr] = await pool.query("SELECT id FROM clientes WHERE correo = ? AND (estado IS NULL OR estado <> 'inerte') ORDER BY id LIMIT 1", [orig]); if (!pr.length) continue; for (const t of ['notas_cliente', 'cobertura_marcas', 'recordatorios_cliente', 'ausencias_cliente']) await pool.execute('UPDATE `' + t + '` SET cliente_id = ? WHERE cliente_id = ?', [pr[0].id, d.id]).catch(() => {}); } } catch (e) { console.error('Recolocar notas de fichas fusionadas:', e.message); }
      await agregaColumnaSiFalta('personas', '`horario`', 'TEXT NULL'); await agregaColumnaSiFalta('mensajes', '`ia_borrador`', 'TINYINT(1) NULL'); await agregaColumnaSiFalta('mensajes', '`ia_cambio_pct`', 'TINYINT NULL');   // 29/10: métricas del equipo
      await pool.execute('CREATE TABLE IF NOT EXISTS ausencias (id INT AUTO_INCREMENT PRIMARY KEY, persona_id INT NOT NULL, desde DATE NOT NULL, hasta DATE NOT NULL, motivo VARCHAR(120) NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_persona (persona_id))');
      await agregaColumnaSiFalta('asesores', '`pin_hash`', 'VARCHAR(100) NULL'); await agregaColumnaSiFalta('asesores', '`pin_intentos`', 'INT NOT NULL DEFAULT 0'); await agregaColumnaSiFalta('asesores', '`pin_pausa_hasta`', 'DATETIME NULL'); await agregaColumnaSiFalta('sesiones_asesor', '`desbloqueada_hasta`', 'DATETIME NULL');   // 29/10: PIN del panel
      for (const [c, t] of [['archivo_clave', 'VARCHAR(255) NULL'], ['archivo_nombre', 'VARCHAR(255) NULL'], ['archivo_tipo', 'VARCHAR(100) NULL'], ['archivo_bytes', 'INT NULL']]) await agregaColumnaSiFalta('mensajes', '`' + c + '`', t);   // 29/10: archivos adjuntos en el chat
      if (await agregaColumnaSiFalta('personas', '`genero`', 'VARCHAR(1) NULL')) { const [ps] = await pool.query('SELECT id, nombre FROM personas WHERE genero IS NULL'); for (const x of ps) await pool.execute('UPDATE personas SET genero = ? WHERE id = ?', [generoPorNombre(x.nombre), x.id]); }   // 29/10: «asesor» o «asesora» en los correos; se deduce del nombre una vez y se puede corregir en Equipo
      await agregaColumnaSiFalta('cambios_asesor', '`texto_cliente`', 'VARCHAR(1000) NULL');   // 29/10: lo que escribió el cliente, para enseñárselo en la respuesta
      await agregaColumnaSiFalta('propuestas', '`cobro`', "VARCHAR(10) NOT NULL DEFAULT 'antes'");   // 29/10: cobrar antes de empezar o pagar después
      for (const t of ['solicitudes_presupuesto', 'solicitudes_llamada']) { await agregaColumnaSiFalta(t, '`atendida_motivo`', 'VARCHAR(500) NULL'); await agregaColumnaSiFalta(t, '`atendida_en`', 'DATETIME NULL'); await agregaColumnaSiFalta(t, '`atendida_por_asesor_id`', 'INT NULL'); }   // 28/10: por qué se atendió
      await pool.execute('CREATE TABLE IF NOT EXISTS notas_cliente (id INT AUTO_INCREMENT PRIMARY KEY, cliente_id INT NOT NULL, asesor_id INT NULL, origen VARCHAR(20) NOT NULL DEFAULT \'ficha\', texto VARCHAR(4000) NOT NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_cliente (cliente_id))');   // 26/10: notas del cliente, como un blog   // 26/10: el visto bueno solo cuando el asesor lo pide   // 21/10: de qué quiere hablar (opcional, desde la web)
      await pool.execute('CREATE TABLE IF NOT EXISTS cobertura_marcas (id INT AUTO_INCREMENT PRIMARY KEY, cliente_id INT NOT NULL, tipo VARCHAR(40) NOT NULL, ejercicio INT NOT NULL, estado VARCHAR(12) NOT NULL, nota VARCHAR(1000) NULL, asesor_id INT NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_cliente (cliente_id))');   // 26/10: cobertura por ejercicio (historial)
      await pool.execute('CREATE TABLE IF NOT EXISTS llamadas_notas (id INT AUTO_INCREMENT PRIMARY KEY, llamada_id INT NOT NULL, asesor_id INT NULL, texto VARCHAR(1000) NOT NULL, creado_en DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_llamada (llamada_id))');   // 20/10: quién en los avisos de ntfy (sin nombres)   // avisos de urgencia: lo existente se da por sabido
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS servicios_historial (' +
        ' `id`          INT AUTO_INCREMENT PRIMARY KEY,' +
        ' `servicio_id` INT          NOT NULL,' +
        " `evento`      VARCHAR(40)  NOT NULL," +
        " `autor`       ENUM('asesor','cliente','sistema') NOT NULL," +
        ' `asesor_id`   INT          NULL,' +
        ' `detalle`     VARCHAR(300) NULL,' +
        ' `creado_en`   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' KEY `idx_servicios_historial` (`servicio_id`, `creado_en`))'
      );
      await pool.execute(
        'CREATE TABLE IF NOT EXISTS recordatorios_cliente (' +
        ' `id`         INT AUTO_INCREMENT PRIMARY KEY,' +
        " `tipo`       VARCHAR(12) NOT NULL," +
        ' `objeto_id`  INT         NOT NULL,' +
        ' `cliente_id` INT         NOT NULL,' +
        ' `asesor_id`  INT         NULL,' +
        ' `creado_en`  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,' +
        ' KEY `idx_recordatorios` (`tipo`, `objeto_id`, `creado_en`))'
      );
      // Los encargos aceptados antes de esto pasan a servicios con el ejercicio deducido (sin confirmar)
      try { await migrarServiciosExistentes(); } catch (err) { console.error('Migración de servicios:', err.message); }

      console.log('Todas las tablas están listas (llamada, presupuesto, propuestas, pagos, diligencias, acceso, documentos fiscales, asesores, sesiones de cliente, empresas, web pública, mensajes, copias, entregas).');
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
// Fase A (10/10): la primera vez, las personas que ya salían en Inicio
// (web_contenido.marca.equipo) pasan a la tabla personas, y cada entrada de
// Inicio queda enlazada con su persona (persona_id). Si no había nada
// guardado, se crean Bernardo y Jorge con los textos de serie.
async function migrarEquipoAPersonas() {
  const [hay] = await pool.execute('SELECT COUNT(*) AS n FROM personas');
  if (hay[0].n > 0) return;
  const [filas] = await pool.execute("SELECT datos, version FROM web_contenido WHERE clave = 'marca'");
  let marca = null; try { marca = filas.length ? JSON.parse(filas[0].datos) : null; } catch (e) { marca = null; }
  const equipo = (marca && Array.isArray(marca.equipo) && marca.equipo.length) ? marca.equipo : [
    { nombre: 'Bernardo', puesto: { es: 'Asesor fiscal cripto · cofundador', en: 'Crypto tax advisor · co-founder' }, bio: { es: 'Lleva todos los casos: tu declaración, tu presupuesto y tus dudas pasan siempre por sus manos.', en: 'Handles every case: your return, your quote and your questions always go through him.' } },
    { nombre: 'Jorge', puesto: { es: 'Asesor financiero · cofundador', en: 'Financial advisor · co-founder' }, bio: { es: 'Se asegura de que Acros sea rápido y cercano.', en: 'Makes sure Acros is fast and close to you.' } },
  ];
  for (let i = 0; i < equipo.length; i++) {
    const q = equipo[i] || {};
    const [r] = await pool.execute(
      'INSERT INTO personas (`nombre`, `puesto_es`, `puesto_en`, `bio_es`, `bio_en`, `foto`, `orden`, `atiende_clientes`) VALUES (?, ?, ?, ?, ?, ?, ?, 1)',
      [String(q.nombre || 'Persona ' + (i + 1)).slice(0, 80), (q.puesto && q.puesto.es) || null, (q.puesto && q.puesto.en) || null,
       (q.bio && q.bio.es) || null, (q.bio && q.bio.en) || null, q.foto || null, i]);
    q.persona_id = r.insertId;
  }
  if (marca && Array.isArray(marca.equipo) && marca.equipo.length) {
    await pool.execute("UPDATE web_contenido SET datos = ? WHERE clave = 'marca'", [JSON.stringify(marca)]);
  }
  console.log('Equipo pasado a personas: ' + equipo.length);
}
// Igual que creaIndiceSiFalta, pero para columnas nuevas en tablas que ya
// existían antes de que esa columna se añadiera al código.
async function agregaColumnaSiFalta(tabla, columna, definicionTipo) {
  try {
    await pool.execute(`ALTER TABLE ${tabla} ADD COLUMN ${columna} ${definicionTipo}`);
    return true;   // 10/10: se ha creado ahora
  } catch (err) {
    if (err.code !== 'ER_DUP_FIELDNAME') throw err;
    return false;
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
  const motivo = String(req.body.motivo || req.body.mensaje || '').trim().slice(0, 500) || null;   // 21/10: opcional (los formularios ya mandaban «mensaje» y se perdía)
  try {
    await pool.execute(
      'INSERT INTO solicitudes_llamada (nombre, telefono, origen, motivo) VALUES (?, ?, ?, ?)',
      [nombre.trim(), telefono.trim(), origen, motivo]
    );
    avisarCaptacion('📞 Alguien pide que le llaméis', 'Tenéis una petición de llamada nueva en el panel.', { prioridad: 5, etiqueta: 'telephone_receiver' });
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Error al guardar la solicitud de llamada:', err);
    res.status(500).json({ error: 'No se pudo guardar la solicitud' });
  }
});

// ================================================================
// 2FA DEL CLIENTE (10/10) — opcional, la activa él desde su área.
// Con ella activada, nada del área (ni por sesión ni por el enlace de la
// propuesta) responde sin una sesión verificada con el código.
// ================================================================
app.use('/api/propuestas/:token', async (req, res, next) => {
  try {
    const [f] = await pool.execute('SELECT c.id, c.totp_activo FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.token = ?', [req.params.token]);
    if (!f.length || !f[0].totp_activo) return next();
    const t = (req.get('x-sesion-cliente') || '').trim();
    if (t) {
      const [ss] = await pool.execute('SELECT id FROM sesiones_cliente WHERE token = ? AND cliente_id = ? AND dos_pasos = 1 AND expira_en > NOW()', [t, f[0].id]);
      if (ss.length) return next();
    }
    res.status(401).json({ error: 'Falta la verificación en dos pasos', requiere_2fa: true });
  } catch (err) { next(err); }
});
const intentos2FA = new Map(); // clave → { n, hasta }: máximo 5 intentos cada 10 minutos
function demasiadosIntentos(clave) {
  const ahoraMs = Date.now(), x = intentos2FA.get(clave);
  if (!x || x.hasta < ahoraMs) { intentos2FA.set(clave, { n: 1, hasta: ahoraMs + 600000 }); return false; }
  x.n++; return x.n > 5;
}
async function comprobarCodigoCliente(conn, cliente, b) {
  if (b.recuperacion) {
    const quedan = gastarRecuperacion(cliente.totp_recuperacion, b.recuperacion);
    if (quedan === null) return 'Ese código de recuperación no es válido o ya se usó';
    await conn.execute('UPDATE clientes SET totp_recuperacion = ? WHERE id = ?', [quedan, cliente.id]);
    return null;
  }
  return totpValido(cliente.totp_secreto, b.codigo) ? null : 'El código no es correcto';
}
// Verificar la sesión recién abierta (entró con enlace o contraseña)
app.post('/api/clientes/2fa/verificar', (req, res, next) => { req.permitirSinDosPasos = true; next(); }, requiereSesionCliente, async (req, res) => {
  if (demasiadosIntentos('s:' + req.cliente.id)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const conn = await pool.getConnection();
  try {
    const [c] = await conn.execute('SELECT * FROM clientes WHERE id = ?', [req.cliente.id]);
    const err = await comprobarCodigoCliente(conn, c[0], req.body || {});
    if (err) return res.status(401).json({ error: err });
    await conn.execute('UPDATE sesiones_cliente SET dos_pasos = 1 WHERE token = ?', [req.cliente.sesionToken]);
    const r = { ok: true };
    if (req.body && req.body.recordar) r.dispositivo = await recordarDispositivo(conn, 'cliente', req.cliente.id);
    res.json(r);
  } finally { conn.release(); }
});
// Entró con el enlace de su propuesta (sin sesión): el código abre una sesión verificada
app.post('/api/clientes/2fa/token', async (req, res) => {
  const b = req.body || {};
  if (demasiadosIntentos('t:' + String(b.propuesta_token || '').slice(0, 12))) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT c.* FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.token = ?', [String(b.propuesta_token || '')]);
    if (!f.length || !f[0].totp_activo) return res.status(404).json({ error: 'No encontrado' });
    if (f[0].estado !== 'activo') return res.status(403).json({ error: 'Esta cuenta ya no está activa.' });
    const err = await comprobarCodigoCliente(conn, f[0], b);
    if (err) return res.status(401).json({ error: err });
    const r = { ok: true, sesion: await crearSesionCliente(conn, f[0].id, 1) };
    if (b.recordar) r.dispositivo = await recordarDispositivo(conn, 'cliente', f[0].id);
    res.json(r);
  } finally { conn.release(); }
});
// Activar / desactivar desde el área (va por el token de la propuesta)
app.post('/api/propuestas/:token/2fa/iniciar', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [c] = await conn.execute('SELECT correo, totp_activo FROM clientes WHERE id = ?', [p.cliente_id]);
    if (c[0].totp_activo) return res.status(409).json({ error: 'Ya la tienes activada' });
    const secreto = nuevoSecretoTOTP();
    await conn.execute('UPDATE clientes SET totp_secreto = ? WHERE id = ?', [secreto, p.cliente_id]);
    res.json({ ok: true, secreto, otpauth: uriTOTP(secreto, c[0].correo) });
  } finally { conn.release(); }
});
app.post('/api/propuestas/:token/2fa/activar', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [c] = await conn.execute('SELECT * FROM clientes WHERE id = ?', [p.cliente_id]);
    if (c[0].totp_activo) return res.status(409).json({ error: 'Ya la tienes activada' });
    if (!totpValido(c[0].totp_secreto, req.body && req.body.codigo)) return res.status(401).json({ error: 'El código no es correcto. Comprueba que la hora del móvil está bien y prueba con el siguiente.' });
    const r = nuevosCodigosRecuperacion();
    await conn.execute('UPDATE clientes SET totp_activo = 1, totp_recuperacion = ?, totp_activado_en = NOW() WHERE id = ?', [r.guardar, p.cliente_id]);
    // Las demás sesiones abiertas dejan de valer; este navegador sigue dentro
    await conn.execute('UPDATE sesiones_cliente SET dos_pasos = 0 WHERE cliente_id = ?', [p.cliente_id]);
    const sesion = await crearSesionCliente(conn, p.cliente_id, 1);
    res.json({ ok: true, codigos_recuperacion: r.codigos, sesion });
  } finally { conn.release(); }
});
app.post('/api/propuestas/:token/2fa/desactivar', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [c] = await conn.execute('SELECT * FROM clientes WHERE id = ?', [p.cliente_id]);
    if (!c[0].totp_activo) return res.status(409).json({ error: 'No la tienes activada' });
    const err = await comprobarCodigoCliente(conn, c[0], req.body || {});
    if (err) return res.status(401).json({ error: err });
    await conn.execute('UPDATE clientes SET totp_activo = 0, totp_secreto = NULL, totp_recuperacion = NULL WHERE id = ?', [p.cliente_id]);
    await conn.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'cliente' AND usuario_id = ?", [p.cliente_id]);
    res.json({ ok: true });
  } finally { conn.release(); }
});
// Panel: un administrador quita la verificación de un cliente (móvil perdido)
app.post('/api/admin/clientes/:id/2fa/reiniciar', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const id = Number(req.params.id);
  const [r] = await pool.execute('UPDATE clientes SET totp_activo = 0, totp_secreto = NULL, totp_recuperacion = NULL WHERE id = ?', [id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Cliente no encontrado' });
  await pool.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'cliente' AND usuario_id = ?", [id]);
  res.json({ ok: true });
});

// ================================================================
// CÓDIGO DE USUARIO (14/10, esquema de Vikn)
//   1.ª letra del nombre + 1.ª del primer apellido
// + día de alta (2 cifras) + letra del mes (enero = A … diciembre = L)
// + último dígito del año de alta
// + letra del documento + último dígito de su parte numérica
// + 1 carácter aleatorio (sin los que se confunden: ni O/0 ni I/1…)
// + 1 letra de control: cada carácter vale 0-9 / A=10…Z=35, se multiplica
//   por su posición (1, 2, 3…), se suma, resto entre 23 → tabla del DNI.
// Ej.: Jordi Ejemplo, 12/03/2026, DNI 12345678Z → JE12C6Z8 + aleatorio + control.
// Único en la base de datos (índice); si coincidiera, se cambia el aleatorio.
// ================================================================
const LETRAS_MES = 'ABCDEFGHIJKL', TABLA_CONTROL = 'TRWAGMYFPDXBNJZSQVHLCKE', ALEATORIOS = 'ACDEFHJKMNPRTUVWXY3479';
const valorCaracter = ch => /[0-9]/.test(ch) ? Number(ch) : ch.charCodeAt(0) - 55;
const sinTildes = t => String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase().replace(/[^A-Z0-9]/g, '');
function letraControl(base) { let suma = 0; [...base].forEach((ch, i) => { suma += valorCaracter(ch) * (i + 1); }); return TABLA_CONTROL[suma % 23]; }
function codigoValido(codigo) { const c = String(codigo || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); return c.length >= 3 && letraControl(c.slice(0, -1)) === c.slice(-1); }
function baseCodigo(c) {
  const nombre = sinTildes(c.nombre), apellido = sinTildes(String(c.apellidos || '').trim().split(/\s+/)[0]), doc = sinTildes(c.numero_documento);
  if (!nombre || !apellido || !doc) return null;
  const f = new Date(new Date(c.creado_en).toLocaleString('en-US', { timeZone: 'Europe/Madrid' }));
  const letrasDoc = doc.replace(/[0-9]/g, ''), cifrasDoc = doc.replace(/[^0-9]/g, '');
  return nombre[0] + apellido[0] + String(f.getDate()).padStart(2, '0') + LETRAS_MES[f.getMonth()] + String(f.getFullYear()).slice(-1) +
    (letrasDoc ? letrasDoc.slice(-1) : 'X') + (cifrasDoc ? cifrasDoc.slice(-1) : '0');
}
async function asignarCodigoCliente(conn, clienteId, rehacer) {
  const [f] = await conn.execute('SELECT id, nombre, apellidos, numero_documento, creado_en, codigo FROM clientes WHERE id = ?', [clienteId]);
  if (!f.length) return null;
  const c = f[0], base = baseCodigo(c);
  if (!base) return c.codigo || null;
  if (c.codigo && !rehacer && c.codigo.startsWith(base)) return c.codigo;   // ya lo tiene y sigue cuadrando
  for (let i = 0; i < 12; i++) {
    const sin = base + ALEATORIOS[crypto.randomInt(ALEATORIOS.length)];
    const codigo = sin + letraControl(sin);
    try { await conn.execute('UPDATE clientes SET codigo = ? WHERE id = ?', [codigo, clienteId]); return codigo; }
    catch (err) { if (err.code !== 'ER_DUP_ENTRY') throw err; }
  }
  return null;
}
async function asignarCodigosPendientes() {
  const [f] = await pool.execute("SELECT id FROM clientes WHERE codigo IS NULL AND nombre IS NOT NULL AND apellidos IS NOT NULL AND numero_documento IS NOT NULL AND estado <> 'inerte'");
  for (const x of f) await asignarCodigoCliente(pool, x.id);
  if (f.length) console.log('Códigos de usuario asignados:', f.length);
}

// ================================================================
// NOTIFICACIONES DEL CLIENTE (13/10)
// El cliente elige, por tipo de aviso, si le llega por correo y/o por
// WhatsApp (este solo si Twilio está activo y tiene teléfono). Lo
// imprescindible (propuesta, enlace de acceso, cambio de asesor…) va
// siempre por correo y no se puede apagar. Por defecto: todo por correo.
// ================================================================
const TIPOS_AVISO = ['mensajes', 'documentos', 'informes', 'recordatorios'];
const AVISOS_POR_DEFECTO = () => Object.fromEntries(TIPOS_AVISO.map(t => [t, { correo: true, whatsapp: false }]));
function leerPreferenciasAvisos(texto) {
  const base = AVISOS_POR_DEFECTO();
  try { const g = JSON.parse(texto || '{}'); TIPOS_AVISO.forEach(t => { if (g[t]) base[t] = { correo: g[t].correo !== false, whatsapp: !!g[t].whatsapp }; }); } catch (e) {}
  return base;
}
// Envía un aviso al cliente según sus preferencias. correoFn() hace el envío
// por correo (ya preparado por quien llama); textoWA es el mensaje corto.
async function notificarCliente(conn, clienteId, tipo, correoFn, textoWA) {   // 14/10: renombrada (chocaba con avisarCliente, el aviso ntfy al equipo)
  const [c] = await conn.execute('SELECT telefono, preferencias_avisos FROM clientes WHERE id = ?', [clienteId]);
  const pref = leerPreferenciasAvisos(c.length ? c[0].preferencias_avisos : null)[tipo] || { correo: true, whatsapp: false };
  let porCorreo = false;
  // Si eligió WhatsApp pero aún no está activo (o no tiene teléfono), se le
  // manda por correo para que no se quede sin aviso.
  const waPosible = twilioActivo() && c.length && c[0].telefono;
  if (pref.correo || (pref.whatsapp && !waPosible)) { await correoFn(); porCorreo = true; }
  if (pref.whatsapp && twilioActivo() && c.length && c[0].telefono && textoWA) {
    enviarWhatsApp(c[0].telefono, textoWA).catch(err => console.error('WhatsApp de aviso no enviado:', err.message));
  }
  return porCorreo;
}
app.get('/api/propuestas/:token/avisos', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [c] = await conn.execute('SELECT telefono, preferencias_avisos FROM clientes WHERE id = ?', [p.cliente_id]);
    res.json({ preferencias: leerPreferenciasAvisos(c[0].preferencias_avisos), whatsapp_disponible: twilioActivo(), tiene_telefono: !!c[0].telefono });
  } finally { conn.release(); }
});
app.put('/api/propuestas/:token/avisos', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const entrada = (req.body && req.body.preferencias) || {};
    const limpio = {};
    TIPOS_AVISO.forEach(t => { const x = entrada[t] || {}; limpio[t] = { correo: x.correo !== false, whatsapp: !!x.whatsapp }; });
    await conn.execute('UPDATE clientes SET preferencias_avisos = ? WHERE id = ?', [JSON.stringify(limpio), p.cliente_id]);
    res.json({ ok: true, preferencias: limpio });
  } finally { conn.release(); }
});

// ================================================================
// ACTIVIDAD, HISTORIAL, ENCARGOS Y FUSIÓN (13/10)
// ================================================================
// Panel (admin): registro de actividad del equipo
app.get('/api/admin/actividad', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const params = []; let where = '';
  if (req.query.asesor_id) { where = 'WHERE a.asesor_id = ?'; params.push(Number(req.query.asesor_id)); }
  if (req.query.cliente_id) { where = (where ? where + ' AND' : 'WHERE') + ' a.cliente_id = ?'; params.push(Number(req.query.cliente_id)); }
  const [filas] = await pool.query(
    `SELECT a.*, s.nombre AS asesor_nombre, c.nombre AS cliente_nombre, c.apellidos AS cliente_apellidos, c.correo AS cliente_correo
     FROM actividad a JOIN asesores s ON s.id = a.asesor_id LEFT JOIN clientes c ON c.id = a.cliente_id ${where} ORDER BY a.id DESC LIMIT 300`, params);
  res.json(filas);
});
// Área: los encargos del cliente (para las pestañas) y el historial de uno
app.get('/api/propuestas/:token/encargos', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [filas] = await conn.execute("SELECT id, token, servicios, estado, creado_en FROM propuestas WHERE cliente_id = ? AND estado IN ('aceptada','enviada') ORDER BY creado_en DESC, id DESC", [p.cliente_id]);
    res.json(filas.map(x => ({ token: x.token, servicios: serviciosDePropuesta(x), estado: x.estado, creado_en: x.creado_en, actual: x.id === p.id })));
  } finally { conn.release(); }
});
app.get('/api/propuestas/:token/historial', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const ev = [];
    const add = (cuando, tipo, datos) => { if (cuando) ev.push(Object.assign({ cuando, tipo }, datos || {})); };
    add(p.creado_en, 'propuesta', { servicios: serviciosDePropuesta(p) });
    if (p.inicio_inmediato_en) add(p.inicio_inmediato_en, 'aceptada');
    else if (p.estado === 'aceptada') add(p.actualizado_en || p.creado_en, 'aceptada');
    if (p.estado === 'rechazada') add(p.actualizado_en || p.creado_en, 'rechazada', { motivo: p.motivo_rechazo });
    const [pagos] = await conn.execute('SELECT metodo, estado, creado_en, confirmado_en FROM pagos WHERE propuesta_id = ?', [p.id]);
    pagos.forEach(x => { add(x.creado_en, 'pago_declarado', { metodo: x.metodo }); if (x.estado === 'confirmado') add(x.confirmado_en, 'pago_confirmado'); });
    const [dils] = await conn.execute('SELECT estado, creado_en, resuelto_en FROM diligencias WHERE propuesta_id = ?', [p.id]);
    dils.forEach(x => { add(x.creado_en, 'alta_enviada'); if (x.resuelto_en) add(x.resuelto_en, x.estado === 'aprobado' ? 'alta_aprobada' : 'alta_rechazada'); });
    const [docs] = await conn.execute('SELECT nombre, servicio, estado, razon_rechazo, creado_en, subido_en, revisado_en FROM documentos_fiscales WHERE propuesta_id = ?', [p.id]);
    docs.forEach(x => { add(x.creado_en, 'doc_pedido', { nombre: x.nombre, servicio: x.servicio }); if (x.subido_en) add(x.subido_en, 'doc_subido', { nombre: x.nombre }); if (x.revisado_en) add(x.revisado_en, x.estado === 'rechazado' ? 'doc_rechazado' : 'doc_validado', { nombre: x.nombre, motivo: x.razon_rechazo }); });
    const [msgs] = await conn.execute('SELECT m.autor, m.servicio, m.creado_en, a.nombre AS asesor FROM mensajes m LEFT JOIN asesores a ON a.id = m.asesor_id WHERE m.propuesta_id = ?', [p.id]);
    msgs.forEach(x => add(x.creado_en, x.autor === 'cliente' ? 'msg_cliente' : 'msg_asesor', { servicio: x.servicio, asesor: x.asesor }));
    const [ents] = await conn.execute('SELECT servicio, version, nombre_archivo, subido_en, estado, respondido_en, comentario FROM entregas WHERE propuesta_id = ?', [p.id]);
    ents.forEach(x => { add(x.subido_en, 'informe', { servicio: x.servicio, version: x.version, nombre: x.nombre_archivo }); if (x.respondido_en) add(x.respondido_en, x.estado === 'conforme' ? 'conforme' : 'cambios', { servicio: x.servicio, motivo: x.comentario }); });
    const [cambs] = await conn.execute('SELECT ca.estado, ca.creado_en, ca.resuelto_en, qa.nombre AS a_nombre FROM cambios_asesor ca LEFT JOIN personas qa ON qa.id = ca.a_persona_id WHERE ca.cliente_id = ? AND ca.creado_en >= ?', [p.cliente_id, p.creado_en]);
    cambs.forEach(x => { add(x.creado_en, 'cambio_pedido', { a: x.a_nombre }); if (x.resuelto_en) add(x.resuelto_en, x.estado === 'aceptado' ? 'cambio_aceptado' : 'cambio_rechazado', { a: x.a_nombre }); });
    const [vals] = await conn.execute("SELECT creado_en, estado FROM valoraciones WHERE propuesta_id = ? AND estado <> 'omitida'", [p.id]);
    vals.forEach(x => add(x.creado_en, 'valoracion'));
    ev.sort((a, b) => new Date(b.cuando) - new Date(a.cuando));
    res.json(ev);
  } finally { conn.release(); }
});
// Panel: ¿hay ya un cliente parecido? (antes de enviar una propuesta)
app.get('/api/admin/clientes/duplicados', requiereSesionAsesor, async (req, res) => {
  const correo = String(req.query.correo || '').trim().toLowerCase(), tel = String(req.query.telefono || '').replace(/\D/g, ''), nombre = String(req.query.nombre || '').trim();
  const [filas] = await pool.execute("SELECT id, correo, telefono, telefono2, nombre, apellidos, codigo, creado_en FROM clientes WHERE estado <> 'inerte'");
  const parecidos = filas.filter(c => c.correo !== correo && (
    (tel.length >= 9 && [c.telefono, c.telefono2].some(t => String(t || '').replace(/\D/g, '').endsWith(tel.slice(-9)))) ||
    (nombre.length >= 5 && [c.nombre, c.apellidos].filter(Boolean).join(' ').toLowerCase() === nombre.toLowerCase())));
  res.json(parecidos.map(c => ({ id: c.id, correo: c.correo, telefono: c.telefono, codigo: c.codigo, creado_en: c.creado_en, nombre: [c.nombre, c.apellidos].filter(Boolean).join(' ') })));
});
// Panel (admin): fusionar dos fichas del mismo cliente. Todo lo del
// duplicado pasa a la ficha principal; el duplicado se desactiva.
app.post('/api/admin/clientes/:id/fusionar', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const principal = Number(req.params.id), duplicado = Number(req.body && req.body.duplicado_id);
  if (!duplicado || duplicado === principal) return res.status(400).json({ error: 'Indica la ficha duplicada' });
  const conn = await pool.getConnection();
  try {
    const [a] = await conn.execute('SELECT * FROM clientes WHERE id IN (?, ?)', [principal, duplicado]);
    if (a.length !== 2) return res.status(404).json({ error: 'Cliente no encontrado' });
    // 13/10: antes de fusionar (es irreversible) se hace una copia completa de
    // la base de datos (no existe copia por cliente). Si la copia falla, no se
    // fusiona.
    let copia = null;
    if (R2_BUCKET) {
      try { copia = await hacerCopiaBaseDeDatos({ manual: true }); }
      catch (err) { return res.status(500).json({ error: 'No se ha fusionado: la copia de seguridad previa ha fallado (' + err.message + ')' }); }
    }
    await conn.beginTransaction();
    await moverServiciosDeCliente(conn, duplicado, principal);   // 20/10: con clave nueva si chocan
    const [conCliente] = await conn.query("SELECT DISTINCT TABLE_NAME AS t FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'cliente_id' AND TABLE_NAME NOT IN ('clientes', 'servicios_cliente')");
    for (const t of [...new Set(['propuestas', 'diligencias', 'documentos_fiscales', 'mensajes', 'entregas', 'valoraciones', 'cambios_asesor', 'sesiones_cliente', 'tokens_acceso', 'sugerencias', 'actividad'].concat(conCliente.map(x => x.t)))]) {
      await conn.execute('UPDATE `' + t + '` SET cliente_id = ? WHERE cliente_id = ?', [principal, duplicado]).catch(() => {});   // 30/10: todas, también notas y cobertura
    }
    const dup = a.find(x => x.id === duplicado), pri = a.find(x => x.id === principal);
    // 14/10: qué dato se queda de cada ficha. Por campo: 'principal',
    // 'duplicado' o 'ninguno' (vacío). Sin indicar: el de la principal y, si
    // la principal no lo tiene, el de la duplicada. El correo es obligatorio.
    const elegido = (req.body && req.body.campos) || {};
    const de = (campo, cols) => {
      let o = elegido[campo];
      if (!['principal', 'duplicado', 'ninguno'].includes(o)) o = cols.some(c => pri[c] != null && pri[c] !== '') ? 'principal' : 'duplicado';
      if (campo === 'correo' && o === 'ninguno') o = 'principal';
      const fuente = o === 'principal' ? pri : o === 'duplicado' ? dup : null;
      return Object.fromEntries(cols.map(c => [c, fuente ? fuente[c] : null]));
    };
    const fin = Object.assign({},
      de('correo', ['correo']), de('nombre', ['nombre']), de('apellidos', ['apellidos']), de('telefono', ['telefono']), de('telefono2', ['telefono2']),
      de('documento', ['tipo_documento', 'numero_documento']), de('asesor', ['asesor_persona_id']), de('codigo', ['codigo']),
      de('contrasena', ['contrasena_hash']), de('dos_pasos', ['totp_activo', 'totp_secreto', 'totp_recuperacion', 'totp_activado_en']),
      de('avisos', ['preferencias_avisos']));
    if (!fin.totp_activo) Object.assign(fin, { totp_activo: 0, totp_secreto: null, totp_recuperacion: null, totp_activado_en: null });
    // «Guardar el teléfono de la otra ficha como segundo teléfono»
    if (elegido.telefono2 === 'telefono_principal') fin.telefono2 = pri.telefono;
    if (elegido.telefono2 === 'telefono_duplicado') fin.telefono2 = dup.telefono;
    // Los dispositivos de confianza solo siguen si se queda la verificación de esa ficha
    const dosPasosDe = (elegido.dos_pasos === 'duplicado') ? duplicado : (elegido.dos_pasos === 'ninguno' ? 0 : principal);
    await conn.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'cliente' AND usuario_id IN (?, ?) AND usuario_id <> ?", [principal, duplicado, dosPasosDe]);
    await conn.execute("UPDATE dispositivos_confianza SET usuario_id = ? WHERE tipo = 'cliente' AND usuario_id = ?", [principal, duplicado]);
    // La duplicada libera su correo y su código antes (son únicos)
    await conn.execute("UPDATE clientes SET estado = 'inerte', correo = CONCAT('fusionado-', id, '-', correo), codigo = NULL WHERE id = ?", [duplicado]);
    await conn.execute('UPDATE clientes SET codigo = NULL WHERE id = ?', [principal]);
    await conn.execute(
      'UPDATE clientes SET correo = ?, nombre = ?, apellidos = ?, telefono = ?, telefono2 = ?, tipo_documento = ?, numero_documento = ?, asesor_persona_id = ?, codigo = ?, contrasena_hash = ?, totp_activo = ?, totp_secreto = ?, totp_recuperacion = ?, totp_activado_en = ?, preferencias_avisos = ? WHERE id = ?',
      [fin.correo, fin.nombre, fin.apellidos, fin.telefono, fin.telefono2, fin.tipo_documento, fin.numero_documento, fin.asesor_persona_id, fin.codigo, fin.contrasena_hash,
       fin.totp_activo ? 1 : 0, fin.totp_secreto, fin.totp_recuperacion, fin.totp_activado_en, fin.preferencias_avisos, principal]);
    await conn.commit();
    if (!fin.codigo) asignarCodigoCliente(pool, principal).catch(() => {});
    res.json({ ok: true, principal: fin.correo, fusionado: dup.correo, copia: copia ? (copia.clave_r2 || copia.clave || true) : null });
  } catch (err) { await conn.rollback(); throw err; } finally { conn.release(); }
});

// ================================================================
// BUZÓN DE SUGERENCIAS (10/10)
// Público (páginas de la web): texto + tipo + correo opcional, con el
// mismo antispam que los demás formularios. Desde el Área, con la sesión o
// el token del cliente: se asocia a él salvo que marque «anónima» (entonces
// no se guarda quién es). Solo los administradores las ven en el panel.
// ================================================================
const TIPOS_SUGERENCIA = ['idea', 'fallo', 'otro'];
async function guardarSugerencia(req, res, clienteId) {
  const b = req.body || {};
  const texto = String(b.texto || '').trim().slice(0, 4000);
  if (texto.length < 3) return res.status(400).json({ error: 'Escribe tu sugerencia' });
  if (esSpam(b)) return res.status(201).json({ ok: true });
  const tipo = TIPOS_SUGERENCIA.includes(b.tipo) ? b.tipo : 'idea';
  const anonima = !!b.anonima;
  const correo = !clienteId && b.correo && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(b.correo).trim()) ? String(b.correo).trim().slice(0, 160) : null;
  await pool.execute('INSERT INTO sugerencias (tipo, texto, correo, cliente_id, anonima, origen, pagina, idioma) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [tipo, texto, correo, clienteId && !anonima ? clienteId : null, anonima ? 1 : 0, clienteId ? 'area' : 'web', String(b.pagina || '').slice(0, 120) || null, String(b.idioma || '').slice(0, 5) || null]);
  avisarAdminClientes('💡 Nueva sugerencia', ({ idea: 'Una idea o mejora', fallo: 'Algo que no funciona', otro: 'Un comentario' })[tipo] + (clienteId ? ' desde el área de un cliente' : ' desde la web') + '. La tienes en «Sugerencias» del panel.', { etiqueta: 'bulb' });
  res.status(201).json({ ok: true });
}
app.post('/api/sugerencias', (req, res) => guardarSugerencia(req, res, null));
app.post('/api/propuestas/:token/sugerencias', async (req, res) => {
  const conn = await pool.getConnection();
  let p; try { p = await propuestaVigente(conn, req.params.token); } finally { conn.release(); }
  if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
  return guardarSugerencia(req, res, p.cliente_id);
});
app.get('/api/admin/sugerencias', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const [filas] = await pool.query(
    'SELECT s.*, c.nombre AS cliente_nombre, c.apellidos AS cliente_apellidos, c.correo AS cliente_correo, a.nombre AS vista_por_nombre ' +
    'FROM sugerencias s LEFT JOIN clientes c ON c.id = s.cliente_id LEFT JOIN asesores a ON a.id = s.vista_por ORDER BY s.vista_en IS NULL DESC, s.creado_en DESC LIMIT 300');
  res.json(filas);
});
app.post('/api/admin/sugerencias/:id/vista', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const [r] = await pool.execute('UPDATE sugerencias SET vista_en = NOW(), vista_por = ? WHERE id = ? AND vista_en IS NULL', [req.asesor.id, Number(req.params.id)]);
  res.json({ ok: true, cambiada: r.affectedRows });
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
  const conCuestionario = !!(cuestionario && Object.keys(cuestionario).length);
  const tokenCuest = conCuestionario ? null : crypto.randomBytes(16).toString('hex');
  try {
    const [ins] = await pool.execute(
      'INSERT INTO solicitudes_presupuesto (servicios, detalle, telefono, correo, utm, origen, cuestionario, `token_cuestionario`, `asesor_preferido_id`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        Array.isArray(servicios) ? JSON.stringify(servicios) : servicios.toString().trim(),
        detalle ? detalle.toString().trim() : null,
        telefono.trim(),
        correo ? correo.toString().trim() : null,
        utm,
        origen,
        conCuestionario ? JSON.stringify(cuestionario) : null,
        tokenCuest,
        Number.isInteger(Number(req.body.asesor_preferido)) && Number(req.body.asesor_preferido) > 0 ? Number(req.body.asesor_preferido) : null,
      ]
    );
    avisarCaptacion('📝 Nueva solicitud de presupuesto', conCuestionario ? 'Está en «Nuevas solicitudes» del panel.' : 'Está en «Nuevas solicitudes» (sin cuestionario por ahora).', { etiqueta: 'memo' });
    // 09/10: confirmación al cliente si dejó su correo; si no rellenó el
    // cuestionario, con un botón para completarlo cuando quiera
    if (correo && brevoActivo()) {
      const lista = Array.isArray(servicios) ? servicios : [String(servicios)];
      const enlaceCuest = (!conCuestionario && SITE_URL) ? `${SITE_URL}/empieza-aqui?completar=${ins.insertId}&clave=${tokenCuest}` : null;
      const c = plantillaCorreo({
        titulo: 'Hemos recibido tu solicitud',
        parrafos: ['Hola:', 'Gracias por confiar en Acros. Hemos recibido tu solicitud de presupuesto para:',
          '<strong>' + lista.map(ESC_HTML).join('<br>') + '</strong>',
          enlaceCuest ? 'Tu asesor te llamará en breve. Si quieres que tu presupuesto llegue antes, cuéntanos un poco más de tu caso: son unas pocas preguntas y no te llevará más de un minuto.'
                      : 'Tu asesor te llamará en breve para comentar tu caso y te enviará tu propuesta a medida en menos de 24 horas.'],
        boton: enlaceCuest ? { texto: 'Completar el cuestionario · 1 min', url: enlaceCuest } : null,
        nota: 'Si no has pedido tú este presupuesto, ignora este correo.',
      });
      enviarCorreo(String(correo).trim(), 'Hemos recibido tu solicitud de presupuesto', c.html, c.texto)
        .catch(err => console.error('Confirmación de solicitud no enviada:', err.message));
    }
    // Sin cuestionario: se devuelve con qué añadirlo luego desde la misma página
    res.status(201).json(conCuestionario ? { ok: true } : { ok: true, id: ins.insertId, token_cuestionario: tokenCuest });
  } catch (err) {
    console.error('Error al guardar la solicitud de presupuesto:', err);
    res.status(500).json({ error: 'No se pudo guardar la solicitud' });
  }
});

// 09/10: desde el enlace del correo de confirmación: qué servicios pidió
// (para hacerle solo sus preguntas). Solo con la clave y si aún falta.
app.get('/api/presupuesto/:id/pendiente', async (req, res) => {
  const [f] = await pool.execute('SELECT servicios FROM solicitudes_presupuesto WHERE id = ? AND `token_cuestionario` = ? AND cuestionario IS NULL',
    [Number(req.params.id), String(req.query.clave || '')]);
  if (!f.length) return res.status(404).json({ error: 'Este cuestionario ya está completado o el enlace no es válido' });
  let servicios; try { servicios = JSON.parse(f[0].servicios); } catch (e) { servicios = [f[0].servicios]; }
  res.json({ servicios });
});
// 09/10: el cliente que dijo «Ahora no» completa el cuestionario después.
// Solo una vez: al guardarlo, la clave deja de valer.
app.post('/api/presupuesto/:id/cuestionario', async (req, res) => {
  const { token, cuestionario } = req.body || {};
  if (!token || !cuestionario || typeof cuestionario !== 'object' || !Object.keys(cuestionario).length) return res.status(400).json({ error: 'Falta el cuestionario' });
  const texto = JSON.stringify(cuestionario);
  if (texto.length > 20000) return res.status(413).json({ error: 'Cuestionario demasiado largo' });
  const [r] = await pool.execute(
    'UPDATE solicitudes_presupuesto SET cuestionario = ?, `token_cuestionario` = NULL, `cuestionario_en` = NOW() WHERE id = ? AND `token_cuestionario` = ? AND cuestionario IS NULL',
    [texto, Number(req.params.id), String(token)]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Esta solicitud ya tiene su cuestionario o no existe' });
  avisarCaptacion('📝 Un cliente ha completado su cuestionario', 'Lo tienes en su solicitud, en «Nuevas solicitudes».', { etiqueta: 'memo' });
  res.json({ ok: true });
});

// ================================================================
// PANEL DEL ASESOR — ver y marcar como atendidas las solicitudes
// entrantes ("Llamadme gratis" y "Pide presupuesto"), 09/09. Hasta
// ahora solo se podían consultar entrando a la base de datos a mano.
// ================================================================
app.get('/api/admin/llamadas', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  // 09/09: antes solo distinguía "pendientes" (atendida=0) de "todas" —
  // pedir expresamente las atendidas (atendida=1) devolvía TODAS sin
  // filtrar, mezclando pendientes y atendidas en el panel.
  const conn = await pool.getConnection();
  try {
    let filas;
    if (req.query.atendida === '0') [filas] = await conn.execute('SELECT * FROM solicitudes_llamada WHERE atendida = 0 ORDER BY creado_en');
    else if (req.query.atendida === '1') [filas] = await conn.execute('SELECT s.*, a.nombre AS atendida_por FROM solicitudes_llamada s LEFT JOIN asesores a ON a.id = s.atendida_por_asesor_id WHERE s.atendida = 1 ORDER BY s.creado_en DESC');
    else [filas] = await conn.execute('SELECT * FROM solicitudes_llamada ORDER BY creado_en DESC LIMIT 100');
    filas.__permitidos = await clientesPermitidos(req).catch(() => null);
    res.json(await enriquecerLlamadas(conn, filas));   // 21/10: contexto y notas
  } finally {
    conn.release();
  }
});
app.post('/api/admin/llamadas/:id/atender', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const motivo = String((req.body || {}).motivo || '').trim().slice(0, 500);
    if (!motivo) return res.status(400).json({ error: 'Di en una línea qué se ha hecho con esta llamada' });
    const [r] = await conn.execute('UPDATE solicitudes_llamada SET atendida = 1, atendida_motivo = ?, atendida_en = NOW(), atendida_por_asesor_id = ? WHERE id = ?', [motivo, req.asesor.id, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de llamada no encontrada' });
    await conn.execute('INSERT INTO llamadas_notas (llamada_id, asesor_id, texto) VALUES (?, ?, ?)', [Number(req.params.id), req.asesor.id, 'Atendida: ' + motivo]);   // 28/10: queda en sus notas (y en las del cliente, si lo es)
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
// "Desatender" (09/09): por si se marcó por error o hace falta retomarla
// — nunca se borra nada, solo se mueve entre pendiente/atendida.
app.post('/api/admin/llamadas/:id/desatender', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute('UPDATE solicitudes_llamada SET atendida = 0 WHERE id = ?', [req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de llamada no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/solicitudes-presupuesto', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    let filas;
    if (req.query.atendida === '0') [filas] = await conn.execute('SELECT * FROM solicitudes_presupuesto WHERE atendida = 0 ORDER BY creado_en');
    else if (req.query.atendida === '1') [filas] = await conn.execute('SELECT s.*, a.nombre AS atendida_por FROM solicitudes_presupuesto s LEFT JOIN asesores a ON a.id = s.atendida_por_asesor_id WHERE s.atendida = 1 ORDER BY s.creado_en DESC');
    else [filas] = await conn.execute('SELECT * FROM solicitudes_presupuesto ORDER BY creado_en DESC LIMIT 100');
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.post('/api/admin/solicitudes-presupuesto/:id/atender', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const motivo = String((req.body || {}).motivo || '').trim().slice(0, 500);
    if (!motivo) return res.status(400).json({ error: 'Di en una línea qué se ha hecho con esta solicitud' });
    const [r] = await conn.execute('UPDATE solicitudes_presupuesto SET atendida = 1, atendida_motivo = ?, atendida_en = NOW(), atendida_por_asesor_id = ? WHERE id = ?', [motivo, req.asesor.id, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solicitud de presupuesto no encontrada' });
    // 28/10: si ya es cliente (por su correo), el motivo entra en su historial de notas
    const [sol] = await conn.execute('SELECT correo FROM solicitudes_presupuesto WHERE id = ?', [req.params.id]);
    if (sol.length && sol[0].correo) { const [c] = await conn.execute('SELECT id FROM clientes WHERE correo = ?', [sol[0].correo.trim().toLowerCase()]); if (c.length) await conn.execute("INSERT INTO notas_cliente (cliente_id, asesor_id, origen, texto) VALUES (?, ?, 'solicitud', ?)", [c[0].id, req.asesor.id, 'Solicitud de presupuesto atendida: ' + motivo]); }
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
app.post('/api/admin/solicitudes-presupuesto/:id/desatender', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
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
// 10/10: validez de la propuesta = 15 días contando el de recepción: hasta
// las 23:59:59 (hora de Madrid) del día D+14. Lo usan el backend, el correo
// («válida hasta el …») y el Área.
function finValidezPropuesta() {
  const d = new Date(fechaMadrid().fecha + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + 15);
  return new Date(inicioDiaMadridUTC(d.toISOString().slice(0, 10)).getTime() - 1000);
}
const fechaLargaES = f => new Date(f).toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'Europe/Madrid' });
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

// ================================================================
// QUÉ VE CADA ASESOR (modelo B, 13/10, decisión de Vikn)
// Un asesor que no es administrador solo ve y toca a SUS clientes (los que
// tienen como asesor a su persona) y los encargos donde figura como
// colaborador. Los administradores lo ven todo. Se aplica en todas las
// rutas /api/admin: las listas se filtran por cliente y las rutas con un
// cliente o encargo concreto se comprueban antes de responder.
// ================================================================
// ================================================================
// ROLES Y EQUIPOS (15/10, acordados con Vikn). Combinables, como en
// Discord; solo los asignan los administradores. «admin» va ligado a es_admin.
//   asesor      → sus clientes y donde colabora
//   jefe        → además, los clientes de su equipo
//   encargado   → además, los de sus equipos; confirma pagos
//   informatico → ningún cliente; copias de seguridad, alertas
//   marketing   → ningún cliente; web pública y valoraciones
//   admin       → todo
// ================================================================
const ROLES_VALIDOS = ['asesor', 'jefe', 'encargado', 'informatico', 'marketing', 'admin'];
function rolesDeFila(f) {
  const r = new Set(String((f && f.roles) || '').split(',').map(x => x.trim()).filter(x => ROLES_VALIDOS.includes(x)));
  if (f && f.es_admin) r.add('admin');
  if (!r.size) r.add('asesor');
  return r;
}
function tieneRol(req, ...roles) { const r = req.asesor && req.asesor.roles; return !!r && (r.has('admin') || roles.some(x => r.has(x))); }
function requiereRol(...roles) {
  return (req, res, next) => tieneRol(req, ...roles) ? next() : res.status(403).json({ error: 'Tu rol no permite hacer esto. Pídeselo a un administrador.' });
}
// Personas (de «Equipo») a cargo de este asesor: las suyas y, si es jefe o
// encargado, las de su equipo o sus equipos
async function personasACargo(asesorId, roles) {
  const [mias] = await pool.execute('SELECT id FROM personas WHERE asesor_id = ?', [asesorId]);
  const ids = new Set(mias.map(x => x.id));
  if (!ids.size || !(roles.has('jefe') || roles.has('encargado') || roles.has('admin'))) return { mias: ids, todas: new Set(ids) };
  const lista = [...ids];
  const [eqs] = await pool.query('SELECT id FROM equipos WHERE activo = 1 AND (' + (roles.has('jefe') || roles.has('admin') ? 'jefe_persona_id IN (?)' : '0') + ' OR ' + (roles.has('encargado') || roles.has('admin') ? 'encargado_persona_id IN (?)' : '0') + ')', [lista, lista]);
  const todas = new Set(ids);
  if (eqs.length) { const [pp] = await pool.query('SELECT id FROM personas WHERE equipo_id IN (?)', [eqs.map(x => x.id)]); pp.forEach(x => todas.add(x.id)); }
  return { mias: ids, todas, equipos: eqs.map(x => x.id) };
}
async function clientesPermitidos(req) {
  // 15/10: según el rol y el ámbito elegido en «Hoy» (x-ambito: mio | equipo | todo)
  const amb = req.method === 'GET' ? (req.get('x-ambito') || '') : '';
  const R = req.asesor.roles || new Set(['asesor']);
  if (R.has('admin') && !['mio', 'equipo'].includes(amb)) return null;   // null = todos
  if (!['asesor', 'jefe', 'encargado', 'admin'].some(x => R.has(x))) return new Set();   // informático o marketing: ningún cliente
  const { mias, todas } = await personasACargo(req.asesor.id, R);
  const personas = [...(amb === 'mio' ? mias : todas)];
  const ids = new Set();
  if (personas.length) { const [f] = await pool.query('SELECT id FROM clientes WHERE asesor_persona_id IN (?)', [personas]); f.forEach(x => ids.add(x.id)); }
  const [c] = await pool.execute('SELECT p.cliente_id AS id FROM colaboraciones co JOIN personas q ON q.id = co.persona_id JOIN propuestas p ON p.id = co.propuesta_id WHERE q.asesor_id = ?', [req.asesor.id]);
  c.forEach(x => ids.add(x.id));
  return ids;
}
// Un encargado solo gestiona las cuentas de los asesores de sus equipos
async function asesorDeMisEquipos(req, res, next) {
  if (req.asesor.roles.has('admin')) return next();
  const { todas } = await personasACargo(req.asesor.id, req.asesor.roles);
  const [f] = await pool.execute('SELECT id FROM personas WHERE asesor_id = ?', [Number(req.params.id)]);
  if (f.some(x => todas.has(x.id))) return next();
  res.status(403).json({ error: 'Ese asesor no es de tus equipos.' });
}
// Jefe: reasigna dentro de su equipo; encargado: entre sus equipos
async function reasignacionDentroDeMiAmbito(req, res, next) {
  if (req.asesor.roles.has('admin')) return next();
  const { todas } = await personasACargo(req.asesor.id, req.asesor.roles);
  const destino = Number(req.body && req.body.persona_id);
  const [c] = await pool.execute('SELECT asesor_persona_id FROM clientes WHERE id = ?', [Number(req.params.id)]);
  const origen = c.length ? c[0].asesor_persona_id : null;
  if ((!destino || todas.has(destino)) && (origen == null || todas.has(origen))) return next();
  res.status(403).json({ error: 'Solo puedes reasignar entre asesores de tu equipo (o de tus equipos).' });
}
// Marketing edita las fichas públicas del equipo, pero no lo que da permisos
async function soloAdminCamposPersona(req, res, next) {
  if (req.asesor.roles.has('admin') || !req.body) return next();
  // Se conservan los valores que ya tenía (la ruta guarda la ficha entera)
  let actual = { atiende_clientes: 0, asesor_id: null, ntfy_topic: null, por_defecto: 0, iniciales: null };
  if (req.params.id) { const [f] = await pool.execute('SELECT atiende_clientes, asesor_id, ntfy_topic, por_defecto, iniciales FROM personas WHERE id = ?', [Number(req.params.id)]); if (f.length) actual = f[0]; }
  Object.assign(req.body, { atiende_clientes: !!actual.atiende_clientes, asesor_id: actual.asesor_id, ntfy_topic: actual.ntfy_topic || '', por_defecto: !!actual.por_defecto, iniciales: actual.iniciales || '' });   // 21/10: las iniciales, también solo un administrador
  next();
}
async function clientesPermitidosAntiguo(req) {
  if (req.asesor.esAdmin && !(req.get('x-ambito') === 'mio' && req.method === 'GET')) return null;   // null = todos (admin con «Ver: lo mío»: solo los suyos)
  const [f] = await pool.execute(
    'SELECT c.id FROM clientes c JOIN personas q ON q.id = c.asesor_persona_id WHERE q.asesor_id = ? ' +
    'UNION SELECT p.cliente_id FROM colaboraciones co JOIN personas q ON q.id = co.persona_id JOIN propuestas p ON p.id = co.propuesta_id WHERE q.asesor_id = ?',
    [req.asesor.id, req.asesor.id]);
  return new Set(f.map(x => x.id));
}
async function clienteDePropuestaId(id) { const [f] = await pool.execute('SELECT cliente_id FROM propuestas WHERE id = ?', [Number(id)]); return f.length ? f[0].cliente_id : null; }
async function clienteDeObjeto(tabla, id) { const [f] = await pool.execute('SELECT cliente_id FROM ' + tabla + ' WHERE id = ?', [Number(id)]); return f.length ? f[0].cliente_id : null; }
const RUTAS_LIBRES_ASESOR = [/^\/api\/admin\/(login|logout|mi-contrasena|asesores|personas|cambios-asesor|sugerencias|valoraciones|rendimiento|resumen-diario|copias-bd|web|avisos|solicitudes|llamadas|empresas|actividad|clientes\/duplicados|contrasena|mi-correo|sesion|pin)/];
async function permisoCliente(req, res, next) {
  try {
    // 15/10: un admin con «Ver: lo mío» (cabecera x-ambito: mio) ve las listas
    // filtradas a sus clientes, pero puede seguir abriendo cualquier ficha
    const soloLoMio = req.asesor.esAdmin && ['mio', 'equipo'].includes(req.get('x-ambito')) && req.method === 'GET';
    if (req.asesor.esAdmin && !soloLoMio) return next();
    const permitidos = await clientesPermitidos(req);
    if (permitidos === null) return next();
    req.clientesPermitidos = permitidos;
    // Rutas con un cliente o encargo concreto
    let clienteId = null; const ruta = req.path;
    let m;
    if ((m = ruta.match(/^\/api\/admin\/clientes\/(\d+)/))) clienteId = Number(m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/propuestas\/(\d+)/))) clienteId = await clienteDePropuestaId(m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/documentos\/(\d+)/))) clienteId = await clienteDeObjeto('documentos_fiscales', m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/entregas\/(\d+)/))) clienteId = await clienteDeObjeto('entregas', m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/servicios\/(\d+)/))) clienteId = await clienteDeObjeto('servicios_cliente', m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/mensajes\/(\d+)/))) clienteId = await clienteDeObjeto('mensajes', m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/diligencias\/(\d+)/))) clienteId = await clienteDeObjeto('diligencias', m[1]);
    else if ((m = ruta.match(/^\/api\/admin\/pagos\/(\d+)/))) { const [f] = await pool.execute('SELECT p.cliente_id FROM pagos pg JOIN propuestas p ON p.id = pg.propuesta_id WHERE pg.id = ?', [Number(m[1])]); clienteId = f.length ? f[0].cliente_id : null; }
    else if (ruta === '/api/admin/documentos' && req.method === 'POST' && req.body) clienteId = await clienteDePropuestaId(req.body.propuesta_id);
    if (clienteId !== null && !permitidos.has(clienteId) && !soloLoMio) return res.status(403).json({ error: 'Este cliente no es tuyo. Pide al titular que te añada como colaborador, o a un administrador.' });
    // Listas: se filtran por cliente_id (o por propuesta_id si no lo traen)
    const jsonOriginal = res.json.bind(res);
    res.json = (datos) => {
      if (Array.isArray(datos) && datos.length && typeof datos[0] === 'object' && datos[0] && ('cliente_id' in datos[0])) datos = datos.filter(x => x.cliente_id == null || permitidos.has(Number(x.cliente_id)));
      return jsonOriginal(datos);
    };
    next();
  } catch (err) { next(err); }
}
// Registro de actividad: todo lo que un asesor cambia desde el panel
const RESUMEN_CLAVES = ['cliente', 'metodo', 'decision', 'razon', 'nombre', 'servicio', 'estado', 'accion', 'importe_centimos', 'activo', 'persona_id', 'correo', 'motivo', 'canal', 'tipo', 'urgente', 'respuesta', 'plazo', 'ejercicio_desde', 'ejercicio_hasta', 'presentado_en', 'ventana_dias'];
function registrarActividad(req, status) {
  // 14/10: además de los cambios, cada descarga de un documento, del DNI, de un
  // informe o de una copia de la base de datos queda registrada
  const esDescarga = req.method === 'GET' && /^\/api\/admin\/(documentos|entregas|diligencias|copias-bd)\/\d+\/(descargar|documento)$/.test(req.path);
  if (!req.asesor || (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) && !esDescarga) || status >= 300) return;
  if (/^\/api\/admin\/(login|logout|mensajes\/sin-leer)/.test(req.path)) return;
  (async () => {
    const ruta = req.path.replace(/\/\d+/g, '/:id').slice(0, 160);
    const ids = (req.path.match(/\/(\d+)/g) || []).map(x => Number(x.slice(1)));
    let clienteId = null;
    try {
      let m;
      if ((m = req.path.match(/^\/api\/admin\/clientes\/(\d+)/))) clienteId = Number(m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/propuestas\/(\d+)/))) clienteId = await clienteDePropuestaId(m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/documentos\/(\d+)/))) clienteId = await clienteDeObjeto('documentos_fiscales', m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/entregas\/(\d+)/))) clienteId = await clienteDeObjeto('entregas', m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/servicios\/(\d+)/))) clienteId = await clienteDeObjeto('servicios_cliente', m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/diligencias\/(\d+)/))) clienteId = await clienteDeObjeto('diligencias', m[1]);
      else if ((m = req.path.match(/^\/api\/admin\/pagos\/(\d+)/))) { const [f] = await pool.execute('SELECT p.cliente_id FROM pagos pg JOIN propuestas p ON p.id = pg.propuesta_id WHERE pg.id = ?', [Number(m[1])]); clienteId = f.length ? f[0].cliente_id : null; }
      else if (req.path === '/api/admin/documentos' && req.body) clienteId = await clienteDePropuestaId(req.body.propuesta_id);
      if (esDescarga) {   // nombre del documento en el resumen
        let m2;
        if ((m2 = req.path.match(/documentos\/(\d+)/))) { const [f] = await pool.execute('SELECT nombre FROM documentos_fiscales WHERE id = ?', [Number(m2[1])]); if (f.length) req.body = Object.assign({}, req.body, { nombre: f[0].nombre }); }
        if ((m2 = req.path.match(/entregas\/(\d+)/))) { const [f] = await pool.execute('SELECT nombre_archivo FROM entregas WHERE id = ?', [Number(m2[1])]); if (f.length) req.body = Object.assign({}, req.body, { nombre: f[0].nombre_archivo }); }
      }
      else if ((req.path === '/api/admin/propuestas' || req.path === '/api/propuestas') && req.body && req.body.correo) { const [f] = await pool.execute('SELECT id FROM clientes WHERE correo = ?', [String(req.body.correo).trim().toLowerCase()]); clienteId = f.length ? f[0].id : null; }
    } catch (e) {}
    const resumen = {}; RESUMEN_CLAVES.forEach(k => { if (req.body && req.body[k] !== undefined && req.body[k] !== null && req.body[k] !== '') resumen[k] = String(req.body[k]).slice(0, 120); });
    await pool.execute('INSERT INTO actividad (asesor_id, metodo, ruta, objeto_id, cliente_id, resumen) VALUES (?, ?, ?, ?, ?, ?)',
      [req.asesor.id, req.method, ruta, ids.length ? ids[0] : null, clienteId, Object.keys(resumen).length ? JSON.stringify(resumen).slice(0, 600) : null]).catch(err => console.error('Actividad no registrada:', err.message));
  })();
}
async function requiereSesionAsesor(req, res, next) {
  const token = (req.get('x-sesion-token') || '').trim();
  if (!token) return res.status(401).json({ error: 'Falta iniciar sesión' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT s.id AS sesion_id, s.expira_en, s.desbloqueada_hasta, a.id, a.nombre, a.correo, a.activo, a.es_admin, a.roles, a.pin_hash
       FROM sesiones_asesor s JOIN asesores a ON a.id = s.asesor_id WHERE s.token = ?`, [token]
    );
    if (!filas.length) return res.status(401).json({ error: 'Sesión no válida. Vuelve a iniciar sesión.' });
    const s = filas[0];
    if (new Date(s.expira_en) < ahora()) return res.status(401).json({ error: 'Tu sesión ha caducado. Vuelve a iniciar sesión.' });
    if (!s.activo) return res.status(403).json({ error: 'Esta cuenta está desactivada.' });
    req.asesor = { id: s.id, nombre: s.nombre, correo: s.correo, esAdmin: !!s.es_admin, roles: rolesDeFila(s), sesionId: s.sesion_id };
    // 29/10: PIN del panel. Sin PIN, hay que crearlo; con la sesión bloqueada (10 min sin actividad), no hay datos hasta escribirlo
    if (pinObligatorio() && !RUTAS_SIN_PIN.some(r => r.test(req.path))) {
      if (!s.pin_hash) return res.status(423).json({ error: 'Crea tu PIN del panel para seguir', codigo: 'pin_crear' });
      if (!s.desbloqueada_hasta || new Date(s.desbloqueada_hasta) <= ahora()) return res.status(423).json({ error: 'El panel está bloqueado: escribe tu PIN', codigo: 'pin' });
    }
    // 13/10: registro de actividad (al terminar la respuesta) y permisos del modelo B
    res.on('finish', () => registrarActividad(req, res.statusCode));
    if ((!req.asesor.esAdmin || (['mio', 'equipo'].includes(req.get('x-ambito')) && req.method === 'GET')) && !RUTAS_LIBRES_ASESOR.some(r => r.test(req.path))) return permisoCliente(req, res, next);   // 15/10: también admin con «lo mío» / «mi equipo»
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
  // 14/10: la contraseña es opcional. Sin ella (lo recomendado), el asesor
  // recibe por correo un enlace para crearla: nadie más la conoce.
  if (contrasena && contrasena.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  const conn = await pool.getConnection();
  try {
    const hash = await bcrypt.hash(contrasena || crypto.randomBytes(32).toString('hex'), 10);
    const [r] = await conn.execute('INSERT INTO asesores (correo, nombre, contrasena_hash, es_admin) VALUES (?,?,?,?)', [correo, nombre, hash, esAdmin]);
    // 14/10: alta sencilla. Si ya hay en «Equipo» una persona con ese nombre
    // sin cuenta, se enlaza; si no, se crea. Con «atiende clientes» y su canal
    // de ntfy propio ya generado. Faltará completar foto, puesto y bio.
    let persona = null;
    try {
      const [ya] = await conn.execute('SELECT id FROM personas WHERE asesor_id IS NULL AND LOWER(nombre) = LOWER(?) LIMIT 1', [nombre]);
      const canal = 'acros-' + crypto.randomBytes(6).toString('hex');
      if (ya.length) {
        await conn.execute('UPDATE personas SET asesor_id = ?, atiende_clientes = 1, ntfy_topic = COALESCE(ntfy_topic, ?) WHERE id = ?', [r.insertId, canal, ya[0].id]);
        persona = { id: ya[0].id, creada: false };
      } else {
        const [ord] = await conn.execute('SELECT COALESCE(MAX(orden), 0) + 1 AS o FROM personas');
        const [pr] = await conn.execute('INSERT INTO personas (nombre, atiende_clientes, asesor_id, ntfy_topic, activa, orden) VALUES (?, 1, ?, ?, 1, ?)', [nombre, r.insertId, canal, ord[0].o]);
        persona = { id: pr.insertId, creada: true };
      }
    } catch (err) { console.error('Alta de asesor: no se pudo crear/enlazar su persona:', err.message); }
    let invitacion = null;
    if (!contrasena) { const inv = await enviarEnlaceContrasena(conn, r.insertId, 'invitacion'); invitacion = inv ? { enviado_a: inv.enviado_a, enlace: inv.enlace || inv.enlace_interno } : null; }
    res.status(201).json({ ok: true, id: r.insertId, persona, invitacion });
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

// ================================================================
// VERIFICACIÓN EN DOS PASOS (10/10)
// Códigos de 6 cifras de una app (Google Authenticator, Microsoft
// Authenticator, 1Password…): TOTP estándar (RFC 6238, SHA-1, 30 s), con
// un margen de ±30 s por si el reloj del móvil va algo desfasado. Diez
// códigos de recuperación de un solo uso (se guardan solo resumidos).
// «Recordar este ordenador 30 días»: un token aleatorio en el navegador,
// del que aquí se guarda solo el resumen.
// ================================================================
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; return out; }
function desdeBase32(t) { const s = String(t || '').toUpperCase().replace(/[^A-Z2-7]/g, ''); let bits = 0, val = 0; const out = []; for (const ch of s) { val = (val << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
function codigoTOTP(secreto, paso) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(paso));
  const h = crypto.createHmac('sha1', desdeBase32(secreto)).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
}
function totpValido(secreto, codigo) {
  const c = String(codigo || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c) || !secreto) return false;
  const ahoraPaso = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some(d => crypto.timingSafeEqual(Buffer.from(codigoTOTP(secreto, ahoraPaso + d)), Buffer.from(c)));
}
const nuevoSecretoTOTP = () => base32(crypto.randomBytes(20));
const uriTOTP = (secreto, cuenta) => 'otpauth://totp/' + encodeURIComponent('Acros:' + cuenta) + '?secret=' + secreto + '&issuer=Acros&algorithm=SHA1&digits=6&period=30';
const resumen = t => crypto.createHash('sha256').update(String(t)).digest('hex');
function nuevosCodigosRecuperacion() {
  const codigos = Array.from({ length: 10 }, () => crypto.randomBytes(5).toString('hex').toUpperCase().replace(/(.{5})/, '$1-'));
  return { codigos, guardar: JSON.stringify(codigos.map(c => resumen(c.replace(/-/g, '')))) };
}
// Gasta un código de recuperación si coincide (devuelve la lista nueva o null)
function gastarRecuperacion(guardados, codigo) {
  let lista = []; try { lista = JSON.parse(guardados || '[]'); } catch (e) {}
  const h = resumen(String(codigo || '').toUpperCase().replace(/[^0-9A-F]/g, ''));
  const i = lista.indexOf(h);
  if (i < 0) return null;
  lista.splice(i, 1);
  return JSON.stringify(lista);
}
async function dispositivoDeConfianza(conn, tipo, usuarioId, token) {
  if (!token) return false;
  const [f] = await conn.execute('SELECT id FROM dispositivos_confianza WHERE tipo = ? AND usuario_id = ? AND hash = ? AND expira_en > NOW()', [tipo, usuarioId, resumen(token)]);
  return f.length > 0;
}
async function recordarDispositivo(conn, tipo, usuarioId) {
  const token = crypto.randomBytes(32).toString('hex');
  await conn.execute('INSERT INTO dispositivos_confianza (tipo, usuario_id, hash, expira_en) VALUES (?, ?, ?, NOW() + INTERVAL 30 DAY)', [tipo, usuarioId, resumen(token)]);
  return token;
}
async function crearSesionAsesor(conn, asesor) {
  const token = crypto.randomBytes(24).toString('hex');
  const expira = new Date(ahora().getTime() + DIAS_VIGENCIA_SESION_ASESOR * 24 * 60 * 60 * 1000);
  await conn.execute('INSERT INTO sesiones_asesor (asesor_id, token, expira_en, desbloqueada_hasta) VALUES (?,?,?,?)', [asesor.id, token, aSQLDatetime(expira), hastaPin()]);   // 29/10: recién entrado con contraseña, desbloqueado
  const [k] = await conn.execute('SELECT llave_sal, llave_publica, llave_privada_cifrada, llave_iv, maestra_cifrada, maestra_iv FROM asesores WHERE id = ?', [asesor.id]);
  return { ok: true, token, nombre: asesor.nombre, correo: asesor.correo, es_admin: !!asesor.es_admin, roles: [...rolesDeFila(asesor)], expira_en: expira.toISOString(), llave: k[0] || null };
}

app.post('/api/admin/login', async (req, res) => {
  const correo = (req.body.correo || '').trim().toLowerCase();
  const contrasena = req.body.contrasena || '';
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM asesores WHERE correo = ?', [correo]);
    // Mismo mensaje tanto si el correo no existe como si la contraseña es
    // incorrecta — no hay que confirmar a quien intenta entrar cuáles de
    // los dos falló.
    const clave = claveLogin(req, 'asesor', correo);
    if (loginBloqueado(clave)) return res.status(429).json({ error: MSG_BLOQUEO });
    const error = () => { apuntarFalloLogin(clave); return res.status(401).json({ error: 'Correo o contraseña incorrectos' }); };
    if (!filas.length) return error();
    const asesor = filas[0];
    if (!asesor.activo) return res.status(403).json({ error: 'Esta cuenta está desactivada' });
    // 14/10: la contraseña no viaja: el navegador manda una clave derivada
    // (clave_auth) y se queda con otra para abrir su llave de documentos.
    // Cuentas antiguas: la primera vez se manda una vez la contraseña para
    // comprobarla y pasan al sistema nuevo.
    const claveAuth = String(req.body.clave_auth || '');
    let ok;
    if (asesor.auth_v2) ok = !!claveAuth && await bcrypt.compare(claveAuth, asesor.contrasena_hash);
    else if (!contrasena) return res.status(409).json({ migrar: true });
    else {
      ok = await bcrypt.compare(contrasena, asesor.contrasena_hash);
      if (ok && /^[0-9a-f]{64}$/.test(claveAuth)) { await conn.execute('UPDATE asesores SET contrasena_hash = ?, auth_v2 = 1 WHERE id = ?', [await bcrypt.hash(claveAuth, 10), asesor.id]); asesor.auth_v2 = 1; }
    }
    if (!ok) return error();
    // 10/10: segundo paso obligatorio. En un ordenador de confianza, directo.
    if (asesor.totp_activo && await dispositivoDeConfianza(conn, 'asesor', asesor.id, req.body.dispositivo)) {
      return res.json(await crearSesionAsesor(conn, asesor));
    }
    const paso = crypto.randomBytes(24).toString('hex');
    if (asesor.totp_activo) {
      await conn.execute('INSERT INTO pasos_login (token, asesor_id, expira_en) VALUES (?, ?, NOW() + INTERVAL 10 MINUTE)', [paso, asesor.id]);
      return res.json({ ok: true, requiere_2fa: true, paso });
    }
    const secreto = nuevoSecretoTOTP();
    await conn.execute('INSERT INTO pasos_login (token, asesor_id, secreto_pendiente, expira_en) VALUES (?, ?, ?, NOW() + INTERVAL 15 MINUTE)', [paso, asesor.id, secreto]);
    res.json({ ok: true, configurar_2fa: true, paso, secreto, otpauth: uriTOTP(secreto, asesor.correo) });
  } finally {
    conn.release();
  }
});

// Segundo paso del login de asesor: el código de la app (o uno de
// recuperación). Si estaba configurándolo, lo deja activado y devuelve los
// códigos de recuperación (solo esta vez).
app.post('/api/admin/login/2fa', async (req, res) => {
  const b = req.body || {};
  const conn = await pool.getConnection();
  try {
    const [ps] = await conn.execute('SELECT * FROM pasos_login WHERE token = ? AND expira_en > NOW()', [String(b.paso || '')]);
    if (!ps.length) return res.status(401).json({ error: 'Ha caducado: vuelve a escribir tu correo y contraseña' });
    const p = ps[0];
    if (p.intentos >= 5) { await conn.execute('DELETE FROM pasos_login WHERE token = ?', [p.token]); return res.status(429).json({ error: 'Demasiados intentos: vuelve a empezar' }); }
    await conn.execute('UPDATE pasos_login SET intentos = intentos + 1 WHERE token = ?', [p.token]);
    const [as] = await conn.execute('SELECT * FROM asesores WHERE id = ? AND activo = 1', [p.asesor_id]);
    if (!as.length) return res.status(403).json({ error: 'Esta cuenta está desactivada' });
    const asesor = as[0];
    let recuperacion = null;
    if (p.secreto_pendiente) {
      if (!totpValido(p.secreto_pendiente, b.codigo)) return res.status(401).json({ error: 'El código no es correcto. Comprueba que la hora del móvil está bien y prueba con el siguiente.' });
      const r = nuevosCodigosRecuperacion(); recuperacion = r.codigos;
      await conn.execute('UPDATE asesores SET totp_secreto = ?, totp_activo = 1, totp_recuperacion = ?, totp_activado_en = NOW() WHERE id = ?', [p.secreto_pendiente, r.guardar, asesor.id]);
    } else if (b.recuperacion) {
      const quedan = gastarRecuperacion(asesor.totp_recuperacion, b.recuperacion);
      if (quedan === null) return res.status(401).json({ error: 'Ese código de recuperación no es válido o ya se usó' });
      await conn.execute('UPDATE asesores SET totp_recuperacion = ? WHERE id = ?', [quedan, asesor.id]);
      avisarAdmin('🔐 ' + quienIni(await inicialesDeAsesor(asesor.id)) + ' ha entrado con un código de recuperación', 'Si no ha sido esa persona, desactiva su cuenta.', { prioridad: 4, etiqueta: 'closed_lock_with_key' });
    } else if (!totpValido(asesor.totp_secreto, b.codigo)) {
      return res.status(401).json({ error: 'El código no es correcto' });
    }
    await conn.execute('DELETE FROM pasos_login WHERE token = ? OR expira_en < NOW()', [p.token]);
    const sesion = await crearSesionAsesor(conn, asesor);
    if (b.recordar) sesion.dispositivo = await recordarDispositivo(conn, 'asesor', asesor.id);
    if (recuperacion) sesion.codigos_recuperacion = recuperacion;
    res.json(sesion);
  } finally { conn.release(); }
});
// ================================================================
// MI CARTERA (16/10, versión 1) — idea de Vikn
// Expediente de movimientos por cliente (importado del Excel de
// movimientos en formato de importación de CoinTracking/DFPro + lo añadido
// o corregido a mano) → FIFO por activo (criterio español) → posiciones,
// lotes, ganancias realizadas por año e ingresos. Precios de CoinGecko
// cacheados. El cliente ve «Mi cartera» en su Área (opción C: resumen y
// posiciones para todos; simulador para la asesoría continuada).
// Son cálculos orientativos de escenarios, nunca recomendaciones.
// ================================================================
const ESCALA_AHORRO = [[6000, 0.19], [50000, 0.21], [200000, 0.23], [300000, 0.27], [null, 0.30]];   // escala vigente; revisar cada año
const TIPOS_ADQ_TRADE = new Set(['Trade', 'Margin Trade', 'Derivatives / Futures Trade']);
const TIPOS_INGRESO = new Set(['Income', 'Gift / Tip', 'Reward / Bonus', 'Mining', 'Airdrop', 'Airdrop (non taxable)', 'Staking', 'Masternode', 'Minting', 'Mining (commercial)', 'Dividends Income', 'Lending Income', 'Interest Income', 'Other Income', 'Income (non taxable)', 'LP Rewards']);
const TIPOS_RENDIMIENTO_AHORRO = new Set(['Staking', 'Lending Income', 'Interest Income', 'Dividends Income', 'LP Rewards']);
const TIPOS_SIN_EFECTO = new Set(['Deposit', 'Withdrawal']);
const TIPOS_CANJE_SIN_IMPUESTO = new Set(['Swap (non taxable)', 'Provide Liquidity', 'Return LP Token', 'Receive LP Token', 'Remove Liquidity']);
const TIPOS_SALIDA_SIN_GANANCIA = new Set(['Gift', 'Donation', 'Lost', 'Stolen', 'Send Collateral', 'Repay Loan', 'Expense (non taxable)']);
const TIPOS_SALIDA_A_VALOR = new Set(['Spend', 'Other Expense', 'Other Fee', 'Borrowing Fee', 'Settlement Fee', 'Margin Fee']);
const TIPOS_GANANCIA_DIRECTA = new Set(['Derivatives / Futures Profit', 'Margin Profit']);
const TIPOS_PERDIDA_DIRECTA = new Set(['Derivatives / Futures Loss', 'Margin Loss', 'Liquidation']);
const TIPOS_ENTRADA_A_VALOR = new Set(['Receive Loan', 'Receive Collateral']);
const TIPOS_REVISAR = new Set(['Provide Liquidity', 'Return LP Token', 'Receive LP Token', 'Remove Liquidity', 'Receive Loan', 'Repay Loan', 'Receive Collateral', 'Send Collateral', 'Lost', 'Stolen', 'Liquidation']);
const esEUR = c => String(c || '').toUpperCase() === 'EUR';
const num = v => { if (v === null || v === undefined || v === '') return null; const n = Number(String(v).replace(',', '.')); return isFinite(n) ? n : null; };

// Motor FIFO. movs ordenados por fecha. Devuelve posiciones, lotes, realizado por año, ingresos y avisos.
function calcularFifo(movs) {
  const lotes = {}, realizado = {}, ingresos = {}, avisos = [];
  const anioDe = f => String(f).slice(0, 4);
  const reg = (anio) => (realizado[anio] = realizado[anio] || { ganancias: 0, perdidas: 0, por_activo: {} });
  const apuntar = (anio, sym, g) => { const r = reg(anio); if (g >= 0) r.ganancias += g; else r.perdidas += -g; const a = r.por_activo[sym] = r.por_activo[sym] || { ganancia: 0 }; a.ganancia += g; };
  const entrar = (sym, cant, coste, fecha) => { if (!sym || esEUR(sym) || !(cant > 0)) return; (lotes[sym] = lotes[sym] || []).push({ cantidad: cant, coste_unit: coste / cant, fecha }); };
  // saca cantidad por FIFO; devuelve el coste de lo sacado (o null si no había bastante)
  const sacar = (sym, cant, m) => {
    if (!sym || esEUR(sym) || !(cant > 0)) return 0;
    const q = lotes[sym] || []; let falta = cant, coste = 0;
    while (falta > 1e-12 && q.length) { const l = q[0]; const t = Math.min(l.cantidad, falta); coste += t * l.coste_unit; l.cantidad -= t; falta -= t; if (l.cantidad <= 1e-12) q.shift(); }
    if (falta > 1e-9) avisos.push({ mov_id: m.id, tipo: 'saldo', texto: 'Se venden ' + cant + ' ' + sym + ' pero solo había ' + (cant - falta).toFixed(8) + ': falta alguna compra anterior.' });
    return coste;
  };
  for (const m of movs) {
    const t = m.tipo, f = m.fecha, anio = anioDe(f);
    const bA = num(m.buy_amount), sA = num(m.sell_amount), fA = num(m.fee_amount);
    const bC = (m.buy_cur || '').toUpperCase(), sC = (m.sell_cur || '').toUpperCase(), fC = (m.fee_cur || '').toUpperCase();
    let valor = esEUR(sC) && sA ? sA : esEUR(bC) && bA ? bA : (num(m.buy_valor_eur) ?? num(m.sell_valor_eur));
    if (TIPOS_REVISAR.has(t)) avisos.push({ mov_id: m.id, tipo: 'revisar', texto: 'Tipo «' + t + '»: revisa su tratamiento fiscal.' });
    if (TIPOS_SIN_EFECTO.has(t)) continue;
    if (TIPOS_ADQ_TRADE.has(t)) {
      if (valor == null && !(esEUR(bC) || esEUR(sC))) { avisos.push({ mov_id: m.id, tipo: 'sin_valor', texto: 'Permuta sin valor en euros: añádelo en la consola.' }); valor = 0; }
      let coste = valor, ingreso = valor;
      if (esEUR(fC) && fA) { if (esEUR(sC)) coste += fA; else if (esEUR(bC)) ingreso -= fA; }
      if (sC && !esEUR(sC)) { const c = sacar(sC, sA, m); apuntar(anio, sC, ingreso - c); }
      entrar(bC, bA, coste, f);
    } else if (TIPOS_INGRESO.has(t)) {
      if (valor == null) { avisos.push({ mov_id: m.id, tipo: 'sin_valor', texto: 'Ingreso («' + t + '») sin valor en euros: añádelo en la consola.' }); valor = 0; }
      entrar(bC, bA, valor, f);
      const i = ingresos[anio] = ingresos[anio] || { ahorro: 0, otros: 0 };
      if (TIPOS_RENDIMIENTO_AHORRO.has(t)) i.ahorro += valor; else if (!/non taxable/.test(t)) i.otros += valor;
    } else if (TIPOS_CANJE_SIN_IMPUESTO.has(t)) {
      const c = sacar(sC, sA, m); entrar(bC, bA, c, f);
    } else if (TIPOS_SALIDA_SIN_GANANCIA.has(t)) {
      sacar(sC, sA, m);
    } else if (TIPOS_SALIDA_A_VALOR.has(t)) {
      if (valor == null) { avisos.push({ mov_id: m.id, tipo: 'sin_valor', texto: 'Salida («' + t + '») sin valor en euros.' }); valor = 0; }
      const c = sacar(sC, sA, m); apuntar(anio, sC, valor - c);
    } else if (TIPOS_GANANCIA_DIRECTA.has(t)) {
      if (valor == null) { avisos.push({ mov_id: m.id, tipo: 'sin_valor', texto: 'Beneficio de derivados sin valor en euros.' }); valor = 0; }
      apuntar(anio, bC || 'DERIVADOS', valor); entrar(bC, bA, valor, f);
    } else if (TIPOS_PERDIDA_DIRECTA.has(t)) {
      if (valor == null) { avisos.push({ mov_id: m.id, tipo: 'sin_valor', texto: 'Pérdida de derivados sin valor en euros.' }); valor = 0; }
      sacar(sC, sA, m); apuntar(anio, sC || 'DERIVADOS', -valor);
    } else if (TIPOS_ENTRADA_A_VALOR.has(t)) {
      entrar(bC, bA, valor || 0, f);
    } else avisos.push({ mov_id: m.id, tipo: 'desconocido', texto: 'Tipo desconocido «' + t + '»: no se ha tenido en cuenta.' });
    // comisión en cripto (no EUR) en cualquier movimiento: sale sin ganancia
    if (fA && fC && !esEUR(fC) && !TIPOS_SALIDA_A_VALOR.has(t)) sacar(fC, fA, m);
  }
  const posiciones = {};
  for (const [sym, q] of Object.entries(lotes)) {
    const cant = q.reduce((a, l) => a + l.cantidad, 0);
    if (cant > 1e-10) posiciones[sym] = { cantidad: cant, coste: q.reduce((a, l) => a + l.cantidad * l.coste_unit, 0), lotes: q.map(l => ({ cantidad: +l.cantidad.toFixed(12), coste_unit: l.coste_unit, fecha: l.fecha })) };
  }
  return { posiciones, realizado, ingresos, avisos };
}

// --- CoinGecko (precios y catálogo). Sin clave funciona con límites; con COINGECKO_API_KEY (demo) va mejor.
const COINGECKO_URL = (process.env.COINGECKO_API_URL || 'https://api.coingecko.com/api/v3').replace(/\/+$/, '');
const cgCabeceras = () => process.env.COINGECKO_API_KEY ? { 'x-cg-demo-api-key': process.env.COINGECKO_API_KEY } : {};
const cg = (ruta) => axios.get(COINGECKO_URL + ruta, { headers: cgCabeceras(), timeout: 15000 }).then(r => r.data);
const FIAT_A_COINGECKO = { USD: 'usd-coin' };
const RED_DE_PLATAFORMA = { ethereum: 'Ethereum', solana: 'Solana', 'binance-smart-chain': 'BNB Chain', 'polygon-pos': 'Polygon', 'arbitrum-one': 'Arbitrum', base: 'Base', 'optimistic-ethereum': 'Optimism', avalanche: 'Avalanche', tron: 'Tron', 'the-open-network': 'TON', sui: 'Sui', cardano: 'Cardano' };
function sectorDe(cats, simbolo) {
  const c = (cats || []).join(' | ').toLowerCase();
  if (/stablecoin/.test(c)) return 'Estables';
  if (/meme/.test(c)) return 'Memes';
  if (/privacy/.test(c)) return 'Privacidad';
  if (/artificial intelligence|\bai\b/.test(c)) return 'IA';
  if (/decentralized finance|defi|decentralized exchange/.test(c)) return 'DeFi';
  if (['BTC'].includes(simbolo) || /store of value/.test(c)) return 'Reserva de valor';
  if (/layer 1|smart contract platform|layer 2/.test(c)) return 'Plataformas';
  if (/gaming|metaverse|nft/.test(c)) return 'Juegos y NFT';
  return 'Otros';
}
let RESOLVIENDO = false;
async function resolverActivosPendientes() {
  if (RESOLVIENDO) return; RESOLVIENDO = true;
  try {
    const [f] = await pool.execute("SELECT simbolo FROM activos_catalogo WHERE coingecko_id IS NULL AND origen <> 'manual' AND (intento_en IS NULL OR intento_en < NOW() - INTERVAL 1 DAY) LIMIT 20");
    for (const { simbolo } of f) {
      await pool.execute('UPDATE activos_catalogo SET intento_en = NOW() WHERE simbolo = ?', [simbolo]);
      try {
        if (FIAT_A_COINGECKO[simbolo]) { await pool.execute("UPDATE activos_catalogo SET coingecko_id = ?, nombre = COALESCE(nombre, ?), sector = COALESCE(sector, 'Estables'), tipo = 'estable', origen = 'coingecko' WHERE simbolo = ?", [FIAT_A_COINGECKO[simbolo], simbolo, simbolo]); continue; }
        const s = await cg('/search?query=' + encodeURIComponent(simbolo));
        const c = (s.coins || []).find(x => String(x.symbol).toUpperCase() === simbolo);
        if (!c) continue;
        await new Promise(r => setTimeout(r, Number(process.env.COINGECKO_PAUSA_MS) || 2500));   // límite de la API gratuita
        const d = await cg('/coins/' + encodeURIComponent(c.id) + '?localization=false&tickers=false&market_data=false&community_data=false&developer_data=false');
        const plat = d.asset_platform_id, cats = d.categories || [];
        const red = plat ? (RED_DE_PLATAFORMA[plat] || plat) : (d.name || simbolo);
        const rank = d.market_cap_rank || c.market_cap_rank || null;
        const sector = sectorDe(cats, simbolo);
        await pool.execute("UPDATE activos_catalogo SET coingecko_id = ?, nombre = ?, red = COALESCE(red, ?), sector = COALESCE(sector, ?), tipo = COALESCE(tipo, ?), tamano = COALESCE(tamano, ?), origen = IF(origen = 'manual', 'manual', 'coingecko'), actualizado_en = NOW() WHERE simbolo = ?",
          [c.id, d.name || c.name, red, sector, sector === 'Estables' ? 'estable' : plat ? 'token' : 'nativa', rank && rank <= 20 ? 'grande' : rank && rank <= 200 ? 'mediana' : 'pequena', simbolo]);
        await new Promise(r => setTimeout(r, Number(process.env.COINGECKO_PAUSA_MS) || 2500));   // límite de la API gratuita
      } catch (e) { console.error('CoinGecko (' + simbolo + '):', e.message); }
    }
  } finally { RESOLVIENDO = false; }
}
async function actualizarPrecios() {
  try {
    const [f] = await pool.execute('SELECT DISTINCT a.simbolo, a.coingecko_id FROM activos_catalogo a WHERE a.coingecko_id IS NOT NULL AND EXISTS (SELECT 1 FROM cartera_movimientos m WHERE m.anulado = 0 AND (m.buy_cur = a.simbolo OR m.sell_cur = a.simbolo))');
    for (let i = 0; i < f.length; i += 200) {
      const trozo = f.slice(i, i + 200);
      const d = await cg('/simple/price?vs_currencies=eur&ids=' + encodeURIComponent([...new Set(trozo.map(x => x.coingecko_id))].join(',')));
      for (const x of trozo) if (d[x.coingecko_id] && d[x.coingecko_id].eur != null) await pool.execute('UPDATE activos_catalogo SET precio_eur = ?, precio_en = NOW() WHERE simbolo = ?', [d[x.coingecko_id].eur, x.simbolo]);
    }
  } catch (e) { console.error('Precios de CoinGecko:', e.message); }
}
async function asegurarCatalogo(simbolos) {
  for (const s of new Set(simbolos.filter(x => x && !esEUR(x)).map(x => x.toUpperCase()))) await pool.execute("INSERT IGNORE INTO activos_catalogo (simbolo, origen) VALUES (?, 'sin')", [s]);
  setTimeout(() => resolverActivosPendientes().then(actualizarPrecios), 200);
}

// --- Datos de la cartera de un cliente
async function movimientosVigentes(clienteId) {
  const [f] = await pool.execute("SELECT id, DATE_FORMAT(fecha, '%Y-%m-%d %H:%i:%s') AS fecha, tipo, buy_amount, buy_cur, sell_amount, sell_cur, fee_amount, fee_cur, exchange, grupo, comentario, txid, buy_valor_eur, sell_valor_eur FROM cartera_movimientos WHERE cliente_id = ? AND anulado = 0 ORDER BY fecha, id", [clienteId]);
  return f;
}
async function datosCartera(clienteId, { conLotes = true } = {}) {
  const movs = await movimientosVigentes(clienteId);
  const r = calcularFifo(movs);
  const anio = String(new Date().getFullYear());
  const [est] = await pool.execute('SELECT e.*, a.nombre AS publicado_por_nombre FROM cartera_estado e LEFT JOIN asesores a ON a.id = e.publicado_por WHERE e.cliente_id = ?', [clienteId]);
  const [otras] = await pool.execute('SELECT * FROM cartera_otras WHERE cliente_id = ? AND anio = ? ORDER BY id', [clienteId, Number(anio)]);
  const syms = Object.keys(r.posiciones);
  const [cat] = syms.length ? await pool.query('SELECT * FROM activos_catalogo WHERE simbolo IN (?)', [syms]) : [[]];
  const C = Object.fromEntries(cat.map(x => [x.simbolo, x]));
  const posiciones = syms.map(s => {
    const p = r.posiciones[s], c = C[s] || {}, precio = c.precio_eur != null ? Number(c.precio_eur) : null;
    return { simbolo: s, nombre: c.nombre || s, red: c.red || null, sector: c.sector || null, tipo: c.tipo || null, tamano: c.tamano || null, grupo: c.grupo || null,
      cantidad: p.cantidad, coste: p.coste, precio, valor: precio != null ? p.cantidad * precio : null, precio_en: c.precio_en || null, lotes: conLotes ? p.lotes : undefined };
  }).sort((a, b) => (b.valor || 0) - (a.valor || 0));
  const e = est[0] || {};
  return {
    anio, posiciones, avisos: r.avisos, n_movimientos: movs.length,
    realizado: r.realizado[anio] || { ganancias: 0, perdidas: 0, por_activo: {} },
    ingresos: r.ingresos[anio] || { ahorro: 0, otros: 0 },
    otras: otras.map(o => ({ id: o.id, plataforma: o.plataforma, tipo: o.tipo, ganancias: Number(o.ganancias) || 0, perdidas: Number(o.perdidas) || 0, rendimientos: Number(o.rendimientos) || 0, latente: o.latente == null ? null : Number(o.latente), fuente: o.fuente })),
    perdidas_pendientes: (() => { try { return JSON.parse(e.perdidas_pendientes || '[]'); } catch (x) { return []; } })(),
    escala: ESCALA_AHORRO, simulador: !!e.simulador, ritmo: e.ritmo || 'mensual',
    fuente: e.fuente_nombre || null, importado_en: e.importado_en || null, publicado_en: e.publicado_en || null, publicado_por: e.publicado_por_nombre || null, recalculado_en: new Date().toISOString(),
  };
}
const CAMPOS_MOV = ['fecha', 'tipo', 'buy_amount', 'buy_cur', 'sell_amount', 'sell_cur', 'fee_amount', 'fee_cur', 'exchange', 'grupo', 'comentario', 'txid', 'buy_valor_eur', 'sell_valor_eur'];
function normalizarMov(o) {
  const fechaTxt = String(o.fecha || '').trim().replace('T', ' ');
  const fecha = /^\d{4}-\d{2}-\d{2}/.test(fechaTxt) ? fechaTxt.slice(0, 19).padEnd(19, fechaTxt.length <= 10 ? ' 00:00:00'.slice(0, 19 - fechaTxt.length) : '0') : null;
  const m = { fecha: fecha && fecha.length === 10 ? fecha + ' 00:00:00' : fecha, tipo: String(o.tipo || '').trim() };
  for (const k of ['buy_amount', 'sell_amount', 'fee_amount', 'buy_valor_eur', 'sell_valor_eur']) m[k] = num(o[k]);
  for (const k of ['buy_cur', 'sell_cur', 'fee_cur']) m[k] = o[k] ? String(o[k]).trim().toUpperCase().slice(0, 30) : null;
  for (const k of ['exchange', 'grupo', 'comentario', 'txid']) m[k] = o[k] ? String(o[k]).slice(0, k === 'comentario' ? 500 : 200) : null;
  return m;
}
async function guardarEstadoCartera(clienteId, campos) {
  await pool.execute('INSERT IGNORE INTO cartera_estado (cliente_id) VALUES (?)', [clienteId]);
  const ks = Object.keys(campos); if (!ks.length) return;
  await pool.execute('UPDATE cartera_estado SET ' + ks.map(k => '`' + k + '` = ?').join(', ') + ' WHERE cliente_id = ?', [...ks.map(k => campos[k]), clienteId]);
}
async function correoAlAsesorDelCliente(clienteId, asunto, parrafos, boton) {
  if (!brevoActivo()) return;
  const [f] = await pool.execute('SELECT a.correo, a.nombre FROM clientes c JOIN personas q ON q.id = c.asesor_persona_id JOIN asesores a ON a.id = q.asesor_id WHERE c.id = ? AND a.activo = 1', [clienteId]);
  if (!f.length) return;
  const c = plantillaCorreo({ titulo: asunto, parrafos: ['Hola, ' + ESC_HTML(f[0].nombre) + ':', ...parrafos], boton });
  enviarCorreo(f[0].correo, asunto, c.html, c.texto).catch(err => console.error('Correo al asesor:', err.message));
}
const ruta = (sufijo) => '/api/admin/clientes/:id/cartera' + sufijo;
app.get(ruta(''), requiereSesionAsesor, async (req, res) => {
  const d = await datosCartera(Number(req.params.id));
  res.json(d);
});
app.post(ruta('/importar'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), b = req.body || {};
  const filas = Array.isArray(b.filas) ? b.filas : [];
  if (!filas.length) return res.status(400).json({ error: 'El archivo no tiene movimientos' });
  if (filas.length > 50000) return res.status(400).json({ error: 'Demasiados movimientos en un solo archivo (máx. 50.000)' });
  const malos = []; const buenos = [];
  filas.forEach((o, i) => { const m = normalizarMov(o); if (!m.fecha || !m.tipo || (!m.buy_cur && !m.sell_cur)) malos.push(i + 2); else buenos.push(m); });
  if (!buenos.length) return res.status(400).json({ error: 'No se ha podido leer ninguna fila. ¿Es el Excel de movimientos (formato de importación de CoinTracking)?' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // lo importado antes se sustituye; lo manual se queda
    await conn.execute("UPDATE cartera_movimientos SET anulado = 1, anulado_motivo = 'Sustituido por una importación nueva', anulado_por = ?, anulado_en = NOW() WHERE cliente_id = ? AND origen = 'importado' AND anulado = 0", [req.asesor.id, id]);
    for (let i = 0; i < buenos.length; i += 500) {
      const t = buenos.slice(i, i + 500);
      await conn.query('INSERT INTO cartera_movimientos (cliente_id, origen, creado_por, ' + CAMPOS_MOV.join(', ') + ') VALUES ?', [t.map(m => [id, 'importado', req.asesor.id, ...CAMPOS_MOV.map(k => m[k])])]);
    }
    await conn.commit();
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
  await guardarEstadoCartera(id, { fuente_nombre: String(b.nombre_archivo || 'movimientos.xlsx').slice(0, 200), importado_en: aSQLDatetime(ahora()), importado_por: req.asesor.id });
  await asegurarCatalogo(buenos.flatMap(m => [m.buy_cur, m.sell_cur, m.fee_cur]));
  req.body = { nombre_archivo: b.nombre_archivo, movimientos: buenos.length };   // para «Actividad»
  res.json({ ok: true, importados: buenos.length, descartadas: malos.slice(0, 50), n_descartadas: malos.length });
});
app.get(ruta('/movimientos'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), q = req.query, por = 25, pag = Math.max(0, Number(q.pagina) || 0);
  const w = ['cliente_id = ?'], v = [id];
  if (q.anulados !== '1') w.push('anulado = 0');
  if (q.anio) { w.push('YEAR(fecha) = ?'); v.push(Number(q.anio)); }
  if (q.activo) { w.push('(buy_cur = ? OR sell_cur = ? OR fee_cur = ?)'); v.push(q.activo, q.activo, q.activo); }
  if (q.tipo) { w.push('tipo = ?'); v.push(q.tipo); }
  if (q.origen === 'manual') w.push("(origen = 'manual')");
  if (q.buscar) { w.push('(comentario LIKE ? OR exchange LIKE ? OR txid LIKE ? OR buy_cur LIKE ? OR sell_cur LIKE ?)'); const t = '%' + q.buscar + '%'; v.push(t, t, t, t, t); }
  let idsAviso = null;
  if (q.avisos === '1') { idsAviso = [...new Set(calcularFifo(await movimientosVigentes(id)).avisos.map(a => a.mov_id))]; if (!idsAviso.length) idsAviso = [0]; w.push('id IN (' + idsAviso.map(Number).join(',') + ')'); }
  const donde = ' WHERE ' + w.join(' AND ');
  const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM cartera_movimientos' + donde, v);
  const [filas] = await pool.query("SELECT m.*, DATE_FORMAT(m.fecha, '%Y-%m-%d %H:%i:%s') AS fecha, a.nombre AS creado_por_nombre, x.nombre AS anulado_por_nombre FROM cartera_movimientos m LEFT JOIN asesores a ON a.id = m.creado_por LEFT JOIN asesores x ON x.id = m.anulado_por" + donde.replace(/\b(cliente_id|anulado|fecha|buy_cur|sell_cur|fee_cur|tipo|origen|comentario|exchange|txid|id)\b/g, 'm.$1') + ' ORDER BY m.fecha DESC, m.id DESC LIMIT ? OFFSET ?', [...v, por, pag * por]);
  const avisos = calcularFifo(await movimientosVigentes(id)).avisos;
  const porMov = {}; avisos.forEach(a => { (porMov[a.mov_id] = porMov[a.mov_id] || []).push(a.texto); });
  const [[{ manuales }]] = await pool.query("SELECT COUNT(*) AS manuales FROM cartera_movimientos WHERE cliente_id = ? AND anulado = 0 AND origen = 'manual'", [id]);
  res.json({ total: Number(n), pagina: pag, por_pagina: por, movimientos: filas.map(m => Object.assign(m, { avisos: porMov[m.id] || [] })), n_avisos: new Set(avisos.map(a => a.mov_id)).size, n_manuales: Number(manuales) });
});
app.get(ruta('/excel'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  const movs = await movimientosVigentes(id);
  const [cambios] = await pool.execute("SELECT m.id, DATE_FORMAT(m.creado_en, '%Y-%m-%d %H:%i') AS cuando, a.nombre AS quien, m.origen, m.sustituye_id, m.anulado, m.anulado_motivo, x.nombre AS anulado_por, m.tipo, DATE_FORMAT(m.fecha, '%Y-%m-%d %H:%i:%s') AS fecha, m.buy_amount, m.buy_cur, m.sell_amount, m.sell_cur, m.nota FROM cartera_movimientos m LEFT JOIN asesores a ON a.id = m.creado_por LEFT JOIN asesores x ON x.id = m.anulado_por WHERE m.cliente_id = ? AND (m.origen = 'manual' OR (m.anulado = 1 AND m.anulado_motivo NOT LIKE 'Sustituido por una importación%')) ORDER BY m.creado_en", [id]);
  const [cli] = await pool.execute('SELECT codigo, nombre, apellidos FROM clientes WHERE id = ?', [id]);
  res.json({ cliente: cli[0] || {}, movimientos: movs, cambios });
});
async function insertarMovManual(req, id, m, extra) {
  const [r] = await pool.execute('INSERT INTO cartera_movimientos (cliente_id, origen, creado_por, nota, sustituye_id, ' + CAMPOS_MOV.join(', ') + ') VALUES (?, ?, ?, ?, ?, ' + CAMPOS_MOV.map(() => '?').join(', ') + ')',
    [id, 'manual', req.asesor.id, extra.nota || null, extra.sustituye_id || null, ...CAMPOS_MOV.map(k => m[k] === undefined ? null : m[k])]);
  await asegurarCatalogo([m.buy_cur, m.sell_cur, m.fee_cur]);
  return r.insertId;
}
app.post(ruta('/movimientos'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), m = normalizarMov(req.body || {});
  if (!m.fecha || !m.tipo || (!m.buy_cur && !m.sell_cur)) return res.status(400).json({ error: 'Faltan la fecha, el tipo o el activo' });
  const nuevo = await insertarMovManual(req, id, m, { nota: String((req.body || {}).nota || '').slice(0, 300) });
  res.status(201).json({ ok: true, id: nuevo });
});
app.put(ruta('/movimientos/:mid'), requiereSesionAsesor, async (req, res) => {
  // corregir = anular el original (se conserva) y crear uno nuevo que lo sustituye
  const id = Number(req.params.id), mid = Number(req.params.mid);
  const [o] = await pool.execute('SELECT * FROM cartera_movimientos WHERE id = ? AND cliente_id = ? AND anulado = 0', [mid, id]);
  if (!o.length) return res.status(404).json({ error: 'Movimiento no encontrado' });
  const base = Object.fromEntries(CAMPOS_MOV.map(k => [k, k === 'fecha' ? aSQLDatetime(new Date(o[0].fecha)) : o[0][k]]));
  const m = normalizarMov(Object.assign(base, req.body || {}));
  const nota = String((req.body || {}).nota || '').slice(0, 300);
  if (!nota) return res.status(400).json({ error: 'Explica en la nota por qué lo corriges' });
  await pool.execute("UPDATE cartera_movimientos SET anulado = 1, anulado_motivo = 'Corregido', anulado_por = ?, anulado_en = NOW() WHERE id = ?", [req.asesor.id, mid]);
  const nuevo = await insertarMovManual(req, id, m, { nota, sustituye_id: mid });
  res.json({ ok: true, id: nuevo });
});
app.delete(ruta('/movimientos/:mid'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), motivo = String((req.body || {}).motivo || req.query.motivo || '').slice(0, 300);
  if (!motivo) return res.status(400).json({ error: 'Indica el motivo' });
  const [r] = await pool.execute('UPDATE cartera_movimientos SET anulado = 1, anulado_motivo = ?, anulado_por = ?, anulado_en = NOW() WHERE id = ? AND cliente_id = ? AND anulado = 0', [motivo, req.asesor.id, Number(req.params.mid), id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Movimiento no encontrado' });
  res.json({ ok: true });
});
app.put(ruta('/ajustes'), requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, campos = {};
  if (Array.isArray(b.perdidas_pendientes)) campos.perdidas_pendientes = JSON.stringify(b.perdidas_pendientes.map(x => ({ anio: Number(x.anio) || null, importe: Math.abs(num(x.importe) || 0) })).filter(x => x.anio && x.importe));
  if (['semanal', 'quincenal', 'mensual', 'trimestral'].includes(b.ritmo)) campos.ritmo = b.ritmo;
  if (typeof b.simulador === 'boolean') campos.simulador = b.simulador ? 1 : 0;
  await guardarEstadoCartera(Number(req.params.id), campos);
  res.json({ ok: true });
});
app.post(ruta('/publicar'), requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  await guardarEstadoCartera(id, { publicado_en: aSQLDatetime(ahora()), publicado_por: req.asesor.id });
  // aviso al cliente (por correo, según sus preferencias de «informes»)
  const conn = await pool.getConnection();
  try {
    await notificarCliente(conn, id, 'informes', async () => {
      const [c] = await conn.execute('SELECT correo, nombre FROM clientes WHERE id = ?', [id]);
      const [p] = await conn.execute("SELECT token FROM propuestas WHERE cliente_id = ? AND estado = 'aceptada' ORDER BY id DESC LIMIT 1", [id]);
      if (!c.length || !brevoActivo()) return;
      const t = plantillaCorreo({ titulo: 'Tu cartera está al día', parrafos: ['Hola' + (c[0].nombre ? ', ' + ESC_HTML(c[0].nombre) : '') + ':', 'Tu asesor ha revisado tus posiciones. Entra en «Mi cartera» para ver tu situación fiscal de este año con los precios de hoy.'], boton: p.length ? { texto: 'Ver mi cartera', url: enlaceArea('area', p[0].token) + '&vista=cartera' } : undefined });
      await enviarCorreo(c[0].correo, 'Tu cartera está al día', t.html, t.texto);
    }, 'Tu asesor ha revisado tu cartera. Entra en tu área de Acros para verla.');
  } catch (e) { console.error('Aviso de cartera publicada:', e.message); } finally { conn.release(); }
  res.json({ ok: true });
});
// Otras inversiones (acciones, ETF, fondos…), por año
app.post(ruta('/otras'), requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, id = Number(req.params.id);
  if (!String(b.plataforma || '').trim()) return res.status(400).json({ error: 'Falta la plataforma' });
  const v = [String(b.plataforma).trim().slice(0, 80), String(b.tipo || '').slice(0, 80), num(b.ganancias) || 0, Math.abs(num(b.perdidas) || 0), num(b.rendimientos) || 0, num(b.latente), String(b.fuente || '').slice(0, 120)];
  if (b.id) await pool.execute('UPDATE cartera_otras SET plataforma = ?, tipo = ?, ganancias = ?, perdidas = ?, rendimientos = ?, latente = ?, fuente = ? WHERE id = ? AND cliente_id = ?', [...v, Number(b.id), id]);
  else await pool.execute('INSERT INTO cartera_otras (cliente_id, anio, plataforma, tipo, ganancias, perdidas, rendimientos, latente, fuente, creado_por) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [id, new Date().getFullYear(), ...v, req.asesor.id]);
  res.json({ ok: true });
});
app.delete(ruta('/otras/:oid'), requiereSesionAsesor, async (req, res) => {
  await pool.execute('DELETE FROM cartera_otras WHERE id = ? AND cliente_id = ?', [Number(req.params.oid), Number(req.params.id)]);
  res.json({ ok: true });
});
// Catálogo de activos (Sistema): encargados y admins
app.get('/api/admin/activos', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const [f] = await pool.execute("SELECT a.*, (SELECT COUNT(DISTINCT m.cliente_id) FROM cartera_movimientos m WHERE m.anulado = 0 AND (m.buy_cur = a.simbolo OR m.sell_cur = a.simbolo)) AS clientes FROM activos_catalogo a ORDER BY (a.origen = 'sin') DESC, clientes DESC, a.simbolo");
  res.json(f);
});
app.put('/api/admin/activos/:simbolo', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const b = req.body || {}, s = String(req.params.simbolo).toUpperCase();
  const vals = ['nombre', 'coingecko_id', 'red', 'sector', 'tipo', 'tamano', 'grupo'].map(k => b[k] === undefined ? undefined : (String(b[k] || '').trim().slice(0, 80) || null));
  await pool.execute("UPDATE activos_catalogo SET nombre = COALESCE(?, nombre), coingecko_id = COALESCE(?, coingecko_id), red = ?, sector = ?, tipo = ?, tamano = ?, grupo = ?, origen = 'manual', editado_por = ?, actualizado_en = NOW() WHERE simbolo = ?",
    [vals[0] ?? null, vals[1] ?? null, vals[2] ?? null, vals[3] ?? null, vals[4] ?? null, vals[5] ?? null, vals[6] ?? null, req.asesor.id, s]);
  if (vals[1]) setTimeout(actualizarPrecios, 100);
  res.json({ ok: true });
});
// Cliente: su cartera (si su asesor la ha publicado)
app.get('/api/propuestas/:token/cartera', exigirAlgunPagoConfirmado, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [e] = await conn.execute('SELECT publicado_en FROM cartera_estado WHERE cliente_id = ?', [p.cliente_id]);
    if (!e.length || !e[0].publicado_en) return res.json({ disponible: false });
    const d = await datosCartera(p.cliente_id);
    delete d.avisos; delete d.n_movimientos; delete d.fuente; delete d.importado_en;
    res.json(Object.assign({ disponible: true }, d));
  } finally { conn.release(); }
});
// Revisiones pendientes: correo al asesor (con detalle) y ntfy sin datos de clientes
async function avisarRevisionesDeCartera() {
  const dias = { semanal: 7, quincenal: 14, mensual: 30, trimestral: 91 };
  const [f] = await pool.execute("SELECT e.cliente_id, e.ritmo, e.publicado_en, c.nombre, c.apellidos, c.correo, q.id AS persona_id, q.nombre AS asesor, a.correo AS asesor_correo FROM cartera_estado e JOIN clientes c ON c.id = e.cliente_id JOIN personas q ON q.id = c.asesor_persona_id LEFT JOIN asesores a ON a.id = q.asesor_id WHERE e.publicado_en IS NOT NULL AND c.estado <> 'inerte'");
  const porAsesor = {};
  for (const x of f) if ((Date.now() - new Date(x.publicado_en).getTime()) / 86400000 >= (dias[x.ritmo] || 30)) (porAsesor[x.persona_id] = porAsesor[x.persona_id] || { asesor: x.asesor, correo: x.asesor_correo, clientes: [] }).clientes.push([x.nombre, x.apellidos].filter(Boolean).join(' ') || x.correo);
  for (const [pid, g] of Object.entries(porAsesor)) {
    const [q] = await pool.execute('SELECT ntfy_topic FROM personas WHERE id = ?', [pid]);
    if (q.length && q[0].ntfy_topic) avisarEn(q[0].ntfy_topic, '🗓️ Tienes ' + g.clientes.length + (g.clientes.length === 1 ? ' cartera' : ' carteras') + ' por revisar', 'Te hemos mandado el detalle por correo. Están en el panel.', { etiqueta: 'calendar' });
    if (g.correo && brevoActivo()) { const c = plantillaCorreo({ titulo: 'Carteras por revisar', parrafos: ['Hola, ' + ESC_HTML(g.asesor) + ':', 'Según su ritmo de revisión, toca actualizar la cartera de:', '<ul>' + g.clientes.map(n => '<li>' + ESC_HTML(n) + '</li>').join('') + '</ul>'] }); enviarCorreo(g.correo, 'Carteras por revisar', c.html, c.texto).catch(() => {}); }
  }
}
setInterval(() => { resolverActivosPendientes().then(actualizarPrecios).catch(() => {}); }, 10 * 60 * 1000).unref();
setInterval(() => { const h = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Madrid' })); if (h.getHours() === 9 && h.getMinutes() < 10) avisarRevisionesDeCartera().catch(e => console.error('Revisiones de cartera:', e.message)); }, 10 * 60 * 1000).unref();

// 15/10: EQUIPOS, ROLES Y «MIS CANALES»
app.get('/api/admin/equipos', requiereSesionAsesor, async (req, res) => {
  const [e] = await pool.execute('SELECT e.*, j.nombre AS jefe_nombre, n.nombre AS encargado_nombre, (SELECT COUNT(*) FROM personas p WHERE p.equipo_id = e.id) AS miembros FROM equipos e LEFT JOIN personas j ON j.id = e.jefe_persona_id LEFT JOIN personas n ON n.id = e.encargado_persona_id ORDER BY e.activo DESC, e.nombre');
  // 21/10: el canal del equipo solo lo ven los administradores y su jefe o encargado
  if (!req.asesor.roles.has('admin')) {
    const [mias] = await pool.execute('SELECT id FROM personas WHERE asesor_id = ?', [req.asesor.id]);
    const ids = new Set(mias.map(x => x.id));
    e.forEach(x => { if (!ids.has(x.jefe_persona_id) && !ids.has(x.encargado_persona_id)) { x.ntfy_topic = null; x.ntfy_oculto = true; } });
  }
  res.json(e);
});
// 15/10 (Vikn): un único jefe por equipo, y solo puede serlo un miembro del equipo
async function cambiarRolAsesorDePersona(personaId, rol, poner) {
  if (!personaId) return;
  const [a] = await pool.execute('SELECT a.id, a.roles, a.es_admin FROM personas p JOIN asesores a ON a.id = p.asesor_id WHERE p.id = ?', [personaId]);
  if (!a.length) return;
  const r = rolesDeFila(a[0]);
  if (poner) r.add(rol); else { r.delete(rol); if (!r.size) r.add('asesor'); }
  await pool.execute('UPDATE asesores SET roles = ? WHERE id = ?', [[...r].filter(x => x !== 'admin').concat(a[0].es_admin ? ['admin'] : []).join(','), a[0].id]);
}
async function guardarEquipo(req, res, id) {
  const b = req.body || {};
  const nombre = String(b.nombre || '').trim().slice(0, 80);
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre del equipo' });
  const topic = String(b.ntfy_topic || '').trim();
  if (topic && !/^[A-Za-z0-9_-]{6,64}$/.test(topic)) return res.status(400).json({ error: 'El canal solo puede llevar letras, números, - y _ (de 6 a 64)' });
  const v = [nombre, b.jefe_persona_id ? Number(b.jefe_persona_id) : null, b.encargado_persona_id ? Number(b.encargado_persona_id) : null, topic || null, b.activo === false ? 0 : 1];
  let jefeAnterior = null;
  if (v[1]) {
    // el jefe tiene que ser miembro de este equipo
    const [m] = await pool.execute('SELECT equipo_id FROM personas WHERE id = ?', [v[1]]);
    if (!id || !m.length || m[0].equipo_id !== id) return res.status(400).json({ error: 'El jefe tiene que ser miembro del equipo. Añádelo primero como miembro y después hazlo jefe.' });
  }
  if (id) { const [e] = await pool.execute('SELECT jefe_persona_id FROM equipos WHERE id = ?', [id]); jefeAnterior = e.length ? e[0].jefe_persona_id : null; }
  // quien deja de ser jefe pierde ese rol (solo se puede ser jefe del propio equipo)
  if (jefeAnterior && jefeAnterior !== v[1]) await cambiarRolAsesorDePersona(jefeAnterior, 'jefe', false);
  // 15/10: quien se pone de jefe o encargado de un equipo recibe ese rol si no lo tenía
  for (const [pid, rol] of [[v[1], 'jefe'], [v[2], 'encargado']]) {
    if (!pid) continue;
    const [a] = await pool.execute('SELECT a.id, a.roles, a.es_admin FROM personas p JOIN asesores a ON a.id = p.asesor_id WHERE p.id = ?', [pid]);
    if (a.length) { const r = rolesDeFila(a[0]); if (!r.has(rol)) { r.add(rol); await pool.execute('UPDATE asesores SET roles = ? WHERE id = ?', [[...r].join(','), a[0].id]); } }
  }
  if (id) { await pool.execute('UPDATE equipos SET nombre = ?, jefe_persona_id = ?, encargado_persona_id = ?, ntfy_topic = ?, activo = ? WHERE id = ?', [...v, id]); return res.json({ ok: true, id }); }
  const [r] = await pool.execute('INSERT INTO equipos (nombre, jefe_persona_id, encargado_persona_id, ntfy_topic, activo) VALUES (?, ?, ?, ?, ?)', v);
  res.status(201).json({ ok: true, id: r.insertId });
}
app.get('/api/admin/equipos/:id', requiereSesionAsesor, async (req, res) => {
  const [e] = await pool.execute('SELECT e.*, j.nombre AS jefe_nombre, n.nombre AS encargado_nombre FROM equipos e LEFT JOIN personas j ON j.id = e.jefe_persona_id LEFT JOIN personas n ON n.id = e.encargado_persona_id WHERE e.id = ?', [Number(req.params.id)]);
  if (!e.length) return res.status(404).json({ error: 'Equipo no encontrado' });
  const [m] = await pool.execute("SELECT p.id, p.nombre, a.id AS asesor_id, a.correo, a.roles, a.es_admin, (SELECT COUNT(*) FROM clientes c WHERE c.asesor_persona_id = p.id AND c.estado <> 'inerte') AS clientes FROM personas p LEFT JOIN asesores a ON a.id = p.asesor_id WHERE p.equipo_id = ? ORDER BY p.nombre", [e[0].id]);
  res.json(Object.assign(e[0], { miembros: m.map(x => ({ id: x.id, nombre: x.nombre, asesor_id: x.asesor_id, correo: x.correo, clientes: Number(x.clientes) || 0, roles: x.correo ? [...rolesDeFila(x)] : [] })) }));
});
app.post('/api/admin/equipos', requiereSesionAsesor, requiereAdminWeb, (req, res) => guardarEquipo(req, res, null));
app.put('/api/admin/equipos/:id', requiereSesionAsesor, requiereAdminWeb, (req, res) => guardarEquipo(req, res, Number(req.params.id)));
app.put('/api/admin/personas/:id/equipo', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const eq = req.body && req.body.equipo_id ? Number(req.body.equipo_id) : null, pid = Number(req.params.id);
  const [antes] = await pool.execute('SELECT equipo_id FROM personas WHERE id = ?', [pid]);
  const anterior = antes.length ? antes[0].equipo_id : null;
  await pool.execute('UPDATE personas SET equipo_id = ? WHERE id = ?', [eq, pid]);
  let dejaDeSerJefe = false;
  if (anterior && anterior !== eq) {
    const [r] = await pool.execute('UPDATE equipos SET jefe_persona_id = NULL WHERE id = ? AND jefe_persona_id = ?', [anterior, pid]);
    if (r.affectedRows) { dejaDeSerJefe = true; await cambiarRolAsesorDePersona(pid, 'jefe', false); }
  }
  res.json({ ok: true, deja_de_ser_jefe: dejaDeSerJefe });
});
app.put('/api/admin/asesores/:id/roles', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const roles = [...new Set((Array.isArray(req.body && req.body.roles) ? req.body.roles : []).filter(r => ROLES_VALIDOS.includes(r)))];
  if (!roles.length) return res.status(400).json({ error: 'Elige al menos un rol' });
  const id = Number(req.params.id), admin = roles.includes('admin') ? 1 : 0;
  if (!admin) { const [a] = await pool.execute('SELECT COUNT(*) AS n FROM asesores WHERE es_admin = 1 AND activo = 1 AND id <> ?', [id]); if (!a[0].n) return res.status(400).json({ error: 'Tiene que quedar al menos un administrador' }); }
  // 15/10: «Jefe de equipo» va ligado a ser el jefe de su equipo
  const [ps] = await pool.execute('SELECT p.id, p.equipo_id, e.nombre AS equipo, e.jefe_persona_id, j.nombre AS jefe_nombre FROM personas p LEFT JOIN equipos e ON e.id = p.equipo_id LEFT JOIN personas j ON j.id = e.jefe_persona_id WHERE p.asesor_id = ?', [id]);
  const yaEraJefe = ps.some(x => x.jefe_persona_id === x.id);
  if (roles.includes('jefe') && !yaEraJefe) {
    const p = ps.find(x => x.equipo_id);
    if (!p) return res.status(400).json({ error: 'Para ser jefe de equipo tiene que estar en un equipo. Asígnale primero su equipo.' });
    if (p.jefe_persona_id && p.jefe_persona_id !== p.id) {
      // 15/10 (Vikn): se puede quitar de jefe al actual para promocionar al nuevo
      if (!req.body.reemplazar_jefe) return res.status(409).json({ error: 'El equipo ' + p.equipo + ' ya tiene jefe (' + (p.jefe_nombre || 'otra persona') + ').', ya_tiene_jefe: true, equipo: p.equipo, jefe_actual: p.jefe_nombre });
      await cambiarRolAsesorDePersona(p.jefe_persona_id, 'jefe', false);
    }
    await pool.execute('UPDATE equipos SET jefe_persona_id = ? WHERE id = ?', [p.id, p.equipo_id]);
  }
  if (!roles.includes('jefe') && yaEraJefe) for (const x of ps) if (x.jefe_persona_id === x.id) await pool.execute('UPDATE equipos SET jefe_persona_id = NULL WHERE id = ?', [x.equipo_id]);
  await pool.execute('UPDATE asesores SET roles = ?, es_admin = ? WHERE id = ?', [roles.join(','), admin, id]);
  res.json({ ok: true, roles });
});
// Los canales que le tocan a cada uno según sus roles y su equipo
app.get('/api/admin/mis-canales', requiereSesionAsesor, async (req, res) => {
  await cargarCanales();
  const R = req.asesor.roles, lista = [];
  const add = (clave, titulo, canal, desc) => { if (canal && !lista.some(x => x.clave === clave)) lista.push({ clave, titulo, canal, desc }); };
  const admin = R.has('admin');
  if (admin || R.has('jefe') || R.has('encargado')) add('captacion', '1 · Clientes · captación', canalDe('captacion'), 'Solicitudes, cuestionarios, llamadas y empresas.');
  if (admin) add('actividad', '2 · Clientes · actividad (general)', canalDe('actividad'), 'Todo lo de todos los clientes.');
  const [mias] = await pool.execute('SELECT id, ntfy_topic, equipo_id FROM personas WHERE asesor_id = ?', [req.asesor.id]);
  const misIds = mias.map(x => x.id);
  if (misIds.length && (admin || R.has('jefe') || R.has('encargado'))) {
    const [eqs] = await pool.query('SELECT nombre, ntfy_topic FROM equipos WHERE activo = 1 AND ntfy_topic IS NOT NULL AND (' + (admin ? '1' : '0') + ' OR ' + (R.has('jefe') ? 'jefe_persona_id IN (?)' : '0') + ' OR ' + (R.has('encargado') ? 'encargado_persona_id IN (?)' : '0') + ')', [misIds, misIds]);
    eqs.forEach(e => add('equipo_' + e.nombre, '2b · Equipo ' + e.nombre, e.ntfy_topic, 'La actividad de los clientes de ese equipo.'));
  } else if (admin) { const [eqs] = await pool.execute('SELECT nombre, ntfy_topic FROM equipos WHERE activo = 1 AND ntfy_topic IS NOT NULL'); eqs.forEach(e => add('equipo_' + e.nombre, '2b · Equipo ' + e.nombre, e.ntfy_topic, 'La actividad de los clientes de ese equipo.')); }
  if (admin || R.has('encargado')) { add('equipo', '3 · Admin · equipo', canalDe('equipo'), 'Cuentas de los asesores.'); add('admin_clientes', '4 · Admin · clientes', canalDe('admin_clientes'), 'Sugerencias, cambios de asesor y valoraciones.'); }
  if (admin || R.has('informatico')) add('alertas', '5 · Admin · alertas', canalDe('alertas'), 'Lo técnico.');
  if (['asesor', 'jefe', 'encargado', 'admin'].some(x => R.has(x))) mias.forEach(m => add('propio', '6 · Tu canal de asesor', m.ntfy_topic, 'Lo de tus clientes.'));
  if (admin) { const [todos] = await pool.execute('SELECT nombre, ntfy_topic FROM personas WHERE ntfy_topic IS NOT NULL AND activa = 1 AND asesor_id <> ?', [req.asesor.id]); todos.forEach(t => add('asesor_' + t.nombre, '6 · Canal de ' + t.nombre, t.ntfy_topic, 'Lo de los clientes de ' + t.nombre + '.')); }
  if (admin || R.has('encargado')) add('pagos', '7 · Pagos', canalDe('pagos'), 'Pagos declarados, con tarjeta y confirmaciones.');
  res.json({ servidor: NTFY_SERVER, canales: lista, roles: [...R] });
});

// 15/10: «Canales de avisos» (solo admins)
app.get('/api/admin/canales', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  await cargarCanales();
  res.json({ canales: CANALES, efectivos: Object.fromEntries(Object.keys(CANALES).map(k => [k, canalDe(k)])), general_railway: NTFY_TOPIC, servidor: NTFY_SERVER });
});
app.put('/api/admin/canales', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const b = (req.body && req.body.canales) || {};
  for (const k of Object.keys(CANALES)) {
    if (!(k in b)) continue;
    const v = String(b[k] || '').trim();
    if (v && !/^[A-Za-z0-9_-]{6,64}$/.test(v)) return res.status(400).json({ error: 'El nombre del canal «' + k + '» solo puede llevar letras, números, - y _ (de 6 a 64)' });
    await pool.execute('INSERT INTO ajustes (clave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)', ['ntfy_' + k, v]);
  }
  await cargarCanales();
  res.json({ ok: true, canales: CANALES });
});
app.post('/api/admin/canales/prueba', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const k = String((req.body && req.body.canal) || '');
  if (!(k in CANALES)) return res.status(400).json({ error: 'Canal desconocido' });
  const nombres = { captacion: 'Clientes · captación', actividad: 'Clientes · actividad', equipo: 'Admin · equipo', admin_clientes: 'Admin · clientes', alertas: 'Admin · alertas', pagos: 'Pagos' };
  const ok = await avisarEn(canalDe(k), '🔔 Prueba · ' + nombres[k], 'Si ves esto, este canal funciona.', { etiqueta: 'tada' });
  if (!ok) return res.status(502).json({ error: 'ntfy no ha aceptado el aviso.' });
  res.json({ ok: true, canal: canalDe(k) });
});

// 14/10: «Cerrar sesión y olvidar este ordenador»: este navegador vuelve a pedir el código
app.post('/api/admin/olvidar-dispositivo', requiereSesionAsesor, async (req, res) => {
  const t = String((req.body && req.body.dispositivo) || '');
  if (t) await pool.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'asesor' AND usuario_id = ? AND hash = ?", [req.asesor.id, resumen(t)]);
  res.json({ ok: true });
});
// Un administrador reinicia la verificación de otro asesor (móvil perdido):
// al volver a entrar, la configura de nuevo. Se cierran sus sesiones.
app.post('/api/admin/asesores/:id/2fa/reiniciar', requiereSesionAsesor, requiereRol('encargado'), asesorDeMisEquipos, async (req, res) => {
  const id = Number(req.params.id);
  const [r] = await pool.execute('UPDATE asesores SET totp_activo = 0, totp_secreto = NULL, totp_recuperacion = NULL WHERE id = ?', [id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Asesor no encontrado' });
  await pool.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'asesor' AND usuario_id = ?", [id]);
  await pool.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ?', [id]);
  res.json({ ok: true });
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
// ================================================================
// CREAR / RESTABLECER LA CONTRASEÑA DE UN ASESOR (14/10)
// Enlace de un solo uso al panel (?clave=…): invitación al darle de alta
// (48 h) o restablecer (1 h si lo pide él, 48 h si lo manda un admin).
// Solo se guarda el resumen del enlace. Al usarlo se cierran sus sesiones.
// La verificación en dos pasos se sigue pidiendo al entrar.
// ================================================================
const PANEL_URL = (process.env.PANEL_URL || 'https://panel.acrosfi.es').replace(/\/+$/, '');
async function enviarEnlaceContrasena(conn, asesorId, tipo, horas) {
  const [f] = await conn.execute('SELECT id, nombre, correo FROM asesores WHERE id = ?', [asesorId]);
  if (!f.length) return null;
  const token = crypto.randomBytes(32).toString('hex');
  const h = horas || (tipo === 'invitacion' ? 48 : 48);
  await conn.execute("UPDATE enlaces_contrasena SET usado_en = NOW() WHERE asesor_id = ? AND usado_en IS NULL", [asesorId]);   // solo vale el último
  await conn.execute('INSERT INTO enlaces_contrasena (asesor_id, hash, tipo, expira_en) VALUES (?, ?, ?, NOW() + INTERVAL ? HOUR)', [asesorId, resumen(token), tipo, h]);
  const enlace = PANEL_URL + '/?clave=' + token;
  const titulo = tipo === 'invitacion' ? 'Crea tu contraseña para entrar en el panel de Acros' : 'Restablece tu contraseña del panel de Acros';
  if (brevoActivo()) {
    const c = plantillaCorreo({ titulo, parrafos: ['Hola, ' + ESC_HTML(f[0].nombre) + ':',
      tipo === 'invitacion' ? 'Ya tienes cuenta en el panel de Acros. Pulsa el botón para crear tu contraseña; después, al entrar, configurarás la verificación en dos pasos con tu móvil.' : 'Alguien ha pedido restablecer la contraseña de tu cuenta del panel. Si has sido tú, pulsa el botón para poner una nueva. Si no, ignora este correo: tu contraseña no cambia.',
      'El enlace sirve una sola vez y caduca en ' + h + (h === 1 ? ' hora.' : ' horas.')],
      boton: { texto: tipo === 'invitacion' ? 'Crear mi contraseña' : 'Poner una contraseña nueva', url: enlace } });
    enviarCorreo(f[0].correo, titulo, c.html, c.texto).catch(err => console.error('Enlace de contraseña no enviado:', err.message));
    return { enviado_a: f[0].correo, enlace_interno: enlace };
  }
  return { enviado_a: null, enlace };   // sin correo configurado, el admin lo pasa a mano
}
const PETICIONES_OLVIDO = new Map();
app.post('/api/admin/contrasena/olvidada', async (req, res) => {
  const correo = String((req.body && req.body.correo) || '').trim().toLowerCase();
  const generico = { ok: true, mensaje: 'Si ese correo es de una cuenta del panel, te hemos enviado un enlace para poner una contraseña nueva.' };
  const clave = correo + '|' + (req.ip || ''), x = PETICIONES_OLVIDO.get(clave);
  if (x && x.hasta > Date.now() && x.n >= 3) return res.json(generico);
  PETICIONES_OLVIDO.set(clave, x && x.hasta > Date.now() ? { n: x.n + 1, hasta: x.hasta } : { n: 1, hasta: Date.now() + 3600000 });
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT id, nombre FROM asesores WHERE correo = ? AND activo = 1', [correo]);
    if (f.length) { await enviarEnlaceContrasena(conn, f[0].id, 'restablecer', 1); avisarAdmin('🔑 ' + quienIni(await inicialesDeAsesor(f[0].id)) + ' ha pedido restablecer su contraseña', 'Le hemos enviado un enlace a su correo.', { etiqueta: 'key' }); }
    res.json(generico);
  } finally { conn.release(); }
});
app.post('/api/admin/asesores/:id/restablecer', requiereSesionAsesor, requiereRol('encargado'), asesorDeMisEquipos, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await enviarEnlaceContrasena(conn, Number(req.params.id), 'restablecer', 48);
    if (!r) return res.status(404).json({ error: 'Asesor no encontrado' });
    // 15/10: al admin se le devuelve también el enlace, por si el correo no llega (spam…) y se lo pasa por otro canal
    res.json({ ok: true, enviado_a: r.enviado_a, enlace: r.enlace || r.enlace_interno });
  } finally { conn.release(); }
});
async function enlaceVigente(conn, token) {
  const [f] = await conn.execute('SELECT e.id, e.tipo, e.asesor_id, e.auth_sal, e.llave_sal, a.nombre, a.correo, a.activo FROM enlaces_contrasena e JOIN asesores a ON a.id = e.asesor_id WHERE e.hash = ? AND e.usado_en IS NULL AND e.expira_en > NOW()', [resumen(String(token || ''))]);
  return f.length && f[0].activo ? f[0] : null;
}
app.get('/api/admin/contrasena/enlace/:token', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const e = await enlaceVigente(conn, req.params.token);
    if (!e) return res.status(404).json({ error: 'Este enlace ya no es válido: ha caducado o ya se usó. Pide uno nuevo.' });
    let auth_sal = e.auth_sal, llave_sal = e.llave_sal;
    if (!auth_sal || !llave_sal) { auth_sal = salAleatoria(); llave_sal = salAleatoria(); await conn.execute('UPDATE enlaces_contrasena SET auth_sal = ?, llave_sal = ? WHERE id = ?', [auth_sal, llave_sal, e.id]); }
    res.json({ ok: true, tipo: e.tipo, nombre: e.nombre, correo: e.correo, auth_sal, llave_sal });
  } finally { conn.release(); }
});
app.post('/api/admin/contrasena/enlace/:token', async (req, res) => {
  const b = req.body || {};
  const v2 = /^[0-9a-f]{64}$/.test(String(b.clave_auth || ''));
  const nueva = String(b.contrasena || '');
  if (!v2 && nueva.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  if (v2 && (!b.llave_publica || !b.llave_privada_cifrada || !b.llave_iv)) return res.status(400).json({ error: 'Falta tu llave de documentos' });
  const conn = await pool.getConnection();
  try {
    const e = await enlaceVigente(conn, req.params.token);
    if (!e) return res.status(404).json({ error: 'Este enlace ya no es válido: ha caducado o ya se usó. Pide uno nuevo.' });
    if (v2) {
      // Contraseña nueva = llave nueva: la antigua ya no se puede abrir. Se le
      // retiran sus accesos y el panel de un administrador se los vuelve a dar.
      await conn.execute('UPDATE asesores SET contrasena_hash = ?, auth_v2 = 1, auth_sal = ?, llave_sal = ?, llave_publica = ?, llave_privada_cifrada = ?, llave_iv = ?, maestra_cifrada = NULL, maestra_iv = NULL WHERE id = ?',
        [await bcrypt.hash(String(b.clave_auth), 10), e.auth_sal, e.llave_sal, b.llave_publica, b.llave_privada_cifrada, b.llave_iv, e.asesor_id]);
      await conn.execute('DELETE FROM llaves_documento WHERE asesor_id = ?', [e.asesor_id]);
    } else await conn.execute('UPDATE asesores SET contrasena_hash = ?, auth_v2 = 0 WHERE id = ?', [await bcrypt.hash(nueva, 10), e.asesor_id]);
    await conn.execute('UPDATE enlaces_contrasena SET usado_en = NOW() WHERE asesor_id = ? AND usado_en IS NULL', [e.asesor_id]);
    await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ?', [e.asesor_id]);
    for (const [k] of FALLOS_LOGIN) if (k.startsWith('asesor|' + e.correo + '|')) FALLOS_LOGIN.delete(k);
    avisarAdmin('🔑 ' + quienIni(await inicialesDeAsesor(e.asesor_id)) + (e.tipo === 'invitacion' ? ' ha creado su contraseña' : ' ha restablecido su contraseña'), 'Ya puede entrar en el panel.', { etiqueta: 'key' });
    res.json({ ok: true, correo: e.correo });
  } finally { conn.release(); }
});

// ================================================================
// LLAVES POR ASESOR (14/10, opción B decidida con Vikn)
// - Cada asesor tiene su par de llaves RSA, creado en su navegador. La
//   privada se guarda aquí solo CERRADA con una llave que su navegador saca
//   de su contraseña (PBKDF2, «llave_sal»); este servidor nunca la puede
//   abrir: la contraseña no viaja (llega «clave_auth», derivada con otra sal).
// - La clave AES de cada documento va cerrada con la llave maestra (como
//   siempre) y, además, con la llave de cada asesor que lleve a ese cliente
//   o colabore con él («llaves_documento»). Las concede el panel de un
//   administrador (el único que tiene la maestra) y se retiran solas si deja
//   de llevarlo. Los administradores guardan la maestra cerrada igual.
// ================================================================
const salAleatoria = () => crypto.randomBytes(16).toString('hex');
// Antes de entrar: las sales de esa cuenta (si no existe, unas falsas pero
// estables, para no revelar qué correos tienen cuenta)
app.get('/api/admin/login/sales', async (req, res) => {
  const correo = String(req.query.correo || '').trim().toLowerCase();
  const [f] = await pool.execute('SELECT id, auth_sal, llave_sal FROM asesores WHERE correo = ?', [correo]);
  if (!f.length) {
    const h = crypto.createHmac('sha256', String(process.env.ADMIN_KEY || 'acros')).update(correo).digest('hex');
    return res.json({ auth_sal: h.slice(0, 32), llave_sal: h.slice(32, 64) });
  }
  let { auth_sal, llave_sal } = f[0];
  if (!auth_sal || !llave_sal) { auth_sal = auth_sal || salAleatoria(); llave_sal = llave_sal || salAleatoria(); await pool.execute('UPDATE asesores SET auth_sal = ?, llave_sal = ? WHERE id = ?', [auth_sal, llave_sal, f[0].id]); }
  res.json({ auth_sal, llave_sal });
});
// Su llave (cerrada), para desbloquearla en otra pestaña o navegador
app.get('/api/admin/mi-llave', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT auth_v2, llave_sal, llave_publica, llave_privada_cifrada, llave_iv, maestra_cifrada, maestra_iv FROM asesores WHERE id = ?', [req.asesor.id]);
  res.json(f[0]);
});
// Primera vez: guarda su llave nueva (solo si no tenía)
app.post('/api/admin/mi-llave', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {};
  if (!b.llave_publica || !b.llave_privada_cifrada || !b.llave_iv) return res.status(400).json({ error: 'Falta la llave' });
  const [r] = await pool.execute('UPDATE asesores SET llave_publica = ?, llave_privada_cifrada = ?, llave_iv = ? WHERE id = ? AND llave_publica IS NULL', [b.llave_publica, b.llave_privada_cifrada, b.llave_iv, req.asesor.id]);
  if (!r.affectedRows) return res.status(409).json({ error: 'Ya tienes una llave' });
  res.json({ ok: true });
});
// Administradores: guardar la llave maestra cerrada con su contraseña
app.post('/api/admin/mi-maestra', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const b = req.body || {};
  if (!b.maestra_cifrada || !b.maestra_iv) return res.status(400).json({ error: 'Falta la llave maestra' });
  await pool.execute('UPDATE asesores SET maestra_cifrada = ?, maestra_iv = ? WHERE id = ?', [b.maestra_cifrada, b.maestra_iv, req.asesor.id]);
  res.json({ ok: true });
});
// Quién tiene derecho a cada documento (sus asesores, sin contar admins)
const SQL_DOCS = "SELECT 'fiscal' AS tipo, d.id AS objeto_id, d.cliente_id, d.documento_clave_cifrada AS clave_cifrada FROM documentos_fiscales d WHERE d.documento_clave_cifrada IS NOT NULL " +
  "UNION ALL SELECT 'identidad', g.id, g.cliente_id, g.documento_clave_cifrada FROM diligencias g WHERE g.documento_clave_cifrada IS NOT NULL";
const SQL_DERECHO = 'SELECT c.id AS cliente_id, q.asesor_id FROM clientes c JOIN personas q ON q.id = c.asesor_persona_id WHERE q.asesor_id IS NOT NULL ' +
  'UNION SELECT p.cliente_id, q.asesor_id FROM colaboraciones co JOIN personas q ON q.id = co.persona_id JOIN propuestas p ON p.id = co.propuesta_id WHERE q.asesor_id IS NOT NULL ' +
  // 20/10 (fase 4): el jefe del equipo del titular y el encargado de ese equipo (los que ya ven al cliente en el panel)
  'UNION SELECT c.id, j.asesor_id FROM clientes c JOIN personas t ON t.id = c.asesor_persona_id JOIN equipos e ON e.id = t.equipo_id AND e.activo = 1 ' +
  "JOIN personas j ON j.id = e.jefe_persona_id JOIN asesores aj ON aj.id = j.asesor_id WHERE FIND_IN_SET('jefe', REPLACE(aj.roles, ' ', '')) > 0 " +
  'UNION SELECT c.id, n.asesor_id FROM clientes c JOIN personas t ON t.id = c.asesor_persona_id JOIN equipos e ON e.id = t.equipo_id AND e.activo = 1 ' +
  "JOIN personas n ON n.id = e.encargado_persona_id JOIN asesores an ON an.id = n.asesor_id WHERE FIND_IN_SET('encargado', REPLACE(an.roles, ' ', '')) > 0";
app.get('/api/admin/llaves/pendientes', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  // Se retiran las que ya no tocan (cliente reasignado, colaboración quitada…)
  await pool.query(`DELETE l FROM llaves_documento l JOIN (${SQL_DOCS}) x ON x.tipo = l.tipo AND x.objeto_id = l.objeto_id
    LEFT JOIN (${SQL_DERECHO}) t ON t.cliente_id = x.cliente_id AND t.asesor_id = l.asesor_id WHERE t.asesor_id IS NULL`);
  const [f] = await pool.query(`SELECT x.tipo, x.objeto_id, x.clave_cifrada, a.id AS asesor_id, a.llave_publica FROM (${SQL_DOCS}) x
    JOIN (${SQL_DERECHO}) t ON t.cliente_id = x.cliente_id
    JOIN asesores a ON a.id = t.asesor_id AND a.activo = 1 AND a.es_admin = 0 AND a.llave_publica IS NOT NULL
    LEFT JOIN llaves_documento l ON l.tipo = x.tipo AND l.objeto_id = x.objeto_id AND l.asesor_id = a.id
    WHERE l.id IS NULL LIMIT 300`);
  res.json(f);
});
app.post('/api/admin/llaves/conceder', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const lista = Array.isArray(req.body && req.body.llaves) ? req.body.llaves.slice(0, 300) : [];
  const [der] = await pool.query(`SELECT x.tipo, x.objeto_id, t.asesor_id FROM (${SQL_DOCS}) x JOIN (${SQL_DERECHO}) t ON t.cliente_id = x.cliente_id`);
  const vale = new Set(der.map(d => d.tipo + '|' + d.objeto_id + '|' + d.asesor_id));
  let n = 0;
  for (const l of lista) {
    if (!vale.has(l.tipo + '|' + l.objeto_id + '|' + l.asesor_id) || !l.clave_envuelta) continue;
    const [r] = await pool.execute('INSERT IGNORE INTO llaves_documento (tipo, objeto_id, asesor_id, clave_envuelta) VALUES (?, ?, ?, ?)', [l.tipo, Number(l.objeto_id), Number(l.asesor_id), String(l.clave_envuelta).slice(0, 1200)]);
    n += r.affectedRows;
  }
  res.json({ ok: true, concedidas: n });
});
async function claveDeAsesor(tipo, objetoId, asesorId) {
  const [f] = await pool.execute('SELECT clave_envuelta FROM llaves_documento WHERE tipo = ? AND objeto_id = ? AND asesor_id = ?', [tipo, objetoId, asesorId]);
  return f.length ? f[0].clave_envuelta : null;
}

// 14/10: cambiar el correo de un asesor. El propio asesor, con su contraseña
// y el código de su app; un administrador, para otro asesor, con el código
// de su propia app. Aviso a la dirección antigua y a la nueva; se cierran
// las demás sesiones. La cuenta es la misma: no se pierde nada.
async function cambiarCorreoAsesor(conn, asesorId, nuevo, req) {
  const [f] = await conn.execute('SELECT id, nombre, correo FROM asesores WHERE id = ?', [asesorId]);
  if (!f.length) return { status: 404, error: 'Asesor no encontrado' };
  const antiguo = f[0].correo;
  if (antiguo === nuevo) return { status: 400, error: 'Es el mismo correo' };
  try { await conn.execute('UPDATE asesores SET correo = ? WHERE id = ?', [nuevo, asesorId]); }
  catch (err) { if (err.code === 'ER_DUP_ENTRY') return { status: 409, error: 'Ya hay una cuenta con ese correo' }; throw err; }
  const tokenActual = req.get('x-sesion-token');
  if (asesorId === req.asesor.id) await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ? AND token != ?', [asesorId, tokenActual]);
  else await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ?', [asesorId]);
  await conn.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'asesor' AND usuario_id = ?", [asesorId]);
  if (brevoActivo()) {
    const quien = asesorId === req.asesor.id ? 'tú mismo' : req.asesor.nombre;
    const c = plantillaCorreo({ titulo: 'Ha cambiado el correo de tu cuenta de Acros',
      parrafos: ['Hola, ' + ESC_HTML(f[0].nombre) + ':', 'El correo con el que entras en el panel de Acros ha pasado de <b>' + ESC_HTML(antiguo) + '</b> a <b>' + ESC_HTML(nuevo) + '</b>. Lo ha cambiado ' + ESC_HTML(quien) + '.', 'Si no sabías nada de este cambio, avisa enseguida a un administrador.'] });
    for (const dest of [antiguo, nuevo]) enviarCorreo(dest, 'Ha cambiado el correo de tu cuenta de Acros', c.html, c.texto).catch(err => console.error('Aviso de cambio de correo no enviado:', err.message));
  }
  avisarAdmin('✉️ Cambio de correo de ' + quienIni(await inicialesDeAsesor(f[0].id)), 'Lo ha hecho ' + quienIni(await inicialesDeAsesor(req.asesor.id)) + '. Se ha avisado al correo antiguo y al nuevo.', { etiqueta: 'envelope' });
  return { ok: true, antiguo, nuevo };
}
const correoValido = c => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c);
app.post('/api/admin/mi-correo', requiereSesionAsesor, async (req, res) => {
  const nuevo = String((req.body && req.body.correo_nuevo) || '').trim().toLowerCase();
  if (!correoValido(nuevo)) return res.status(400).json({ error: 'Escribe un correo válido' });
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT contrasena_hash, totp_secreto, totp_activo, auth_v2 FROM asesores WHERE id = ?', [req.asesor.id]);
    const prueba = f[0].auth_v2 ? String(req.body.clave_auth || '') : String(req.body.contrasena || '');
    if (!prueba || !(await bcrypt.compare(prueba, f[0].contrasena_hash))) return res.status(401).json({ error: 'Tu contraseña no es correcta' });
    if (f[0].totp_activo && !totpValido(f[0].totp_secreto, req.body.codigo)) return res.status(401).json({ error: 'El código de tu app no es correcto' });
    const r = await cambiarCorreoAsesor(conn, req.asesor.id, nuevo, req);
    if (r.error) return res.status(r.status).json({ error: r.error });
    res.json(r);
  } finally { conn.release(); }
});
app.post('/api/admin/asesores/:id/correo', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const nuevo = String((req.body && req.body.correo_nuevo) || '').trim().toLowerCase();
  if (!correoValido(nuevo)) return res.status(400).json({ error: 'Escribe un correo válido' });
  const conn = await pool.getConnection();
  try {
    const [yo] = await conn.execute('SELECT totp_secreto, totp_activo FROM asesores WHERE id = ?', [req.asesor.id]);
    if (yo[0].totp_activo && !totpValido(yo[0].totp_secreto, req.body.codigo)) return res.status(401).json({ error: 'El código de tu app no es correcto' });
    const r = await cambiarCorreoAsesor(conn, Number(req.params.id), nuevo, req);
    if (r.error) return res.status(r.status).json({ error: r.error });
    res.json(r);
  } finally { conn.release(); }
});

app.post('/api/admin/mi-contrasena', requiereSesionAsesor, async (req, res, next) => {
  const b = req.body || {};
  if (!b.clave_auth_actual) return next();   // cuentas antiguas: la ruta de siempre (abajo)
  if (!/^[0-9a-f]{64}$/.test(String(b.clave_auth_nueva || '')) || !b.auth_sal_nueva || !b.llave_sal_nueva) return res.status(400).json({ error: 'Faltan datos de la contraseña nueva' });
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT contrasena_hash, auth_v2, llave_publica FROM asesores WHERE id = ?', [req.asesor.id]);
    if (!f[0].auth_v2 || !(await bcrypt.compare(String(b.clave_auth_actual), f[0].contrasena_hash))) return res.status(401).json({ error: 'Tu contraseña actual no es correcta' });
    if (f[0].llave_publica && (!b.llave_privada_cifrada || !b.llave_iv)) return res.status(400).json({ error: 'Falta tu llave de documentos recerrada' });
    await conn.execute('UPDATE asesores SET contrasena_hash = ?, auth_sal = ?, llave_sal = ?, llave_privada_cifrada = COALESCE(?, llave_privada_cifrada), llave_iv = COALESCE(?, llave_iv), maestra_cifrada = ?, maestra_iv = ? WHERE id = ?',
      [await bcrypt.hash(String(b.clave_auth_nueva), 10), b.auth_sal_nueva, b.llave_sal_nueva, b.llave_privada_cifrada || null, b.llave_iv || null, b.maestra_cifrada || null, b.maestra_iv || null, req.asesor.id]);
    await conn.execute('DELETE FROM sesiones_asesor WHERE asesor_id = ? AND token != ?', [req.asesor.id, req.get('x-sesion-token')]);
    avisarAdmin('🔑 ' + quienIni(await inicialesDeAsesor(req.asesor.id)) + ' ha cambiado su contraseña', 'Desde «Mi cuenta» del panel. Si no ha sido esa persona, desactiva su cuenta.', { etiqueta: 'key' });   // 15/10
    res.json({ ok: true });
  } finally { conn.release(); }
});
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
    avisarAdmin('🔑 ' + quienIni(await inicialesDeAsesor(req.asesor.id)) + ' ha cambiado su contraseña', 'Desde «Mi cuenta» del panel. Si no ha sido esa persona, desactiva su cuenta.', { etiqueta: 'key' });
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
    const [filas] = await conn.execute('SELECT a.id, a.nombre, a.correo, a.activo, a.es_admin, a.creado_en, a.totp_activo, a.roles, (SELECT GROUP_CONCAT(p.equipo_id) FROM personas p WHERE p.asesor_id = a.id) AS equipo_ids FROM asesores a ORDER BY a.nombre');
    res.json(filas.map(a => Object.assign(a, { roles: [...rolesDeFila(a)] })));
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

// ================================================================
// EMPRESAS COLABORADORAS (28/09) — alta pública desde la vista
// «Empresas» de Inicio + cola en el panel del asesor.
// ================================================================
const TIPOS_EMPRESA = ['gestoria', 'asesoria', 'inmobiliaria', 'otro'];
const CANALES_EMPRESA = ['whatsapp', 'telefono', 'correo'];
const ESTADOS_EMPRESA = ['pendiente', 'acuerdo_firmado', 'activa', 'descartada'];

// NIF/NIE/CIF español con su dígito o letra de control. Acepta CIF de
// sociedad (B12345678…) y también NIF de persona física o NIE, porque
// hay gestores y asesores que trabajan como autónomos. La MISMA función
// está copiada en acros_inicio.html (validación en el navegador): si se
// toca una, tocar la otra.
function validarNifCif(valor) {
  const v = (valor || '').toString().toUpperCase().replace(/[\s.\-]/g, '');
  const LETRAS_DNI = 'TRWAGMYFPDXBNJZSQVHLCKE';
  let m = v.match(/^(\d{8})([A-Z])$/);
  if (m) return LETRAS_DNI[Number(m[1]) % 23] === m[2] ? v : null;
  m = v.match(/^([XYZ])(\d{7})([A-Z])$/);
  if (m) return LETRAS_DNI[Number('XYZ'.indexOf(m[1]) + m[2]) % 23] === m[3] ? v : null;
  m = v.match(/^([ABCDEFGHJNPQRSUVW])(\d{7})([0-9A-J])$/);
  if (!m) return null;
  const d = m[2].split('').map(Number);
  let suma = d[1] + d[3] + d[5];
  for (const i of [0, 2, 4, 6]) { const x = d[i] * 2; suma += Math.floor(x / 10) + (x % 10); }
  const c = (10 - (suma % 10)) % 10;
  const letra = 'JABCDEFGHI'[c];
  if ('ABEH'.includes(m[1])) return m[3] === String(c) ? v : null;      // siempre número
  if ('KPQSNW'.includes(m[1])) return m[3] === letra ? v : null;        // siempre letra
  return (m[3] === String(c) || m[3] === letra) ? v : null;             // cualquiera de los dos
}
function datosEmpresaValidos(b) {
  const texto = (x, max) => { const t = (x || '').toString().trim(); return t && t.length <= max ? t : null; };
  const razon = texto(b.razon_social, 160);
  const cif = validarNifCif(b.cif);
  const tipo = TIPOS_EMPRESA.includes(b.tipo) ? b.tipo : null;
  const tipoOtro = tipo === 'otro' ? texto(b.tipo_otro, 80) : null;
  const contacto = texto(b.contacto_nombre, 120);
  const telefono = texto(b.telefono, 30);
  const correo = texto(b.correo, 190);
  const canal = CANALES_EMPRESA.includes(b.canal_preferido) ? b.canal_preferido : 'whatsapp';
  const comentario = (b.comentario || '').toString().trim().slice(0, 2000) || null;
  const errores = [];
  if (!razon) errores.push('razón social');
  if (!cif) errores.push('CIF/NIF');
  if (!tipo || (tipo === 'otro' && !tipoOtro)) errores.push('tipo de empresa');
  if (!contacto) errores.push('persona de contacto');
  if (!telefono || telefono.replace(/\D/g, '').length < 9) errores.push('teléfono');
  if (!correo || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) errores.push('correo');
  if (errores.length) return { errores };
  return { datos: { razon, cif, tipo, tipoOtro, contacto, telefono, correo: correo.toLowerCase(), canal, comentario } };
}
app.post('/api/empresas', async (req, res) => {
  const { errores, datos } = datosEmpresaValidos(req.body || {});
  if (errores) return res.status(400).json({ error: 'Revisa estos datos: ' + errores.join(', '), campos: errores });
  if (esSpam(req.body)) return res.status(201).json({ ok: true }); // honeypot: no se guarda, pero no se delata
  const { utm, origen } = resolverAtribucion(req.body);
  const idioma = (req.body.idioma || '').toString().toLowerCase() === 'en' ? 'en' : 'es';
  try {
    await pool.execute(
      `INSERT INTO empresas (razon_social, cif, tipo, tipo_otro, contacto_nombre, telefono, correo, canal_preferido, comentario, idioma, utm, origen)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [datos.razon, datos.cif, datos.tipo, datos.tipoOtro, datos.contacto, datos.telefono, datos.correo, datos.canal, datos.comentario, idioma, utm, origen]
    );
    avisarCaptacion('🏢 Nueva empresa registrada', 'Está en el bloque «Empresas» del panel.', { etiqueta: 'office' });
    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Error al guardar el alta de empresa:', err);
    res.status(500).json({ error: 'No se pudo guardar el alta' });
  }
});
app.get('/api/admin/empresas', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const estado = req.query.estado;
  const conn = await pool.getConnection();
  try {
    const base = `SELECT e.*, aa.nombre AS asesor_asignado_nombre, ac.nombre AS estado_cambiado_por_nombre,
                  (SELECT COUNT(*) FROM empresa_notas n WHERE n.empresa_id = e.id) AS n_notas,
                  (SELECT MAX(n.creado_en) FROM empresa_notas n WHERE n.empresa_id = e.id) AS ultima_nota_en
                  FROM empresas e
                  LEFT JOIN asesores aa ON aa.id = e.asesor_asignado_id
                  LEFT JOIN asesores ac ON ac.id = e.estado_cambiado_por_asesor_id`;
    let filas;
    if (ESTADOS_EMPRESA.includes(estado)) [filas] = await conn.execute(base + ' WHERE e.estado = ? ORDER BY e.creado_en DESC', [estado]);
    else [filas] = await conn.execute(base + ' ORDER BY e.creado_en DESC LIMIT 500');
    res.json(filas);
  } finally {
    conn.release();
  }
});
// Cambiar de estado: cualquier asesor, en cualquier dirección (para poder
// corregir un error), dejando siempre quién y cuándo. Nunca se borra.
app.post('/api/admin/empresas/:id/estado', requiereSesionAsesor, async (req, res) => {
  const estado = (req.body || {}).estado;
  if (!ESTADOS_EMPRESA.includes(estado)) return res.status(400).json({ error: 'Estado no válido' });
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute(
      'UPDATE empresas SET estado = ?, estado_cambiado_por_asesor_id = ?, estado_cambiado_en = NOW() WHERE id = ?',
      [estado, req.asesor.id, req.params.id]
    );
    if (!r.affectedRows) return res.status(404).json({ error: 'Empresa no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
// Asesor asignado: la persona de Acros a la que esa empresa manda los
// casos y la documentación. null = sin asignar. Solo cuentas activas.
app.post('/api/admin/empresas/:id/asesor', requiereSesionAsesor, async (req, res) => {
  const bruto = (req.body || {}).asesor_id;
  const asesorId = bruto === null || bruto === '' || bruto === undefined ? null : Number(bruto);
  const conn = await pool.getConnection();
  try {
    if (asesorId !== null) {
      const [a] = await conn.execute('SELECT id FROM asesores WHERE id = ? AND activo = 1', [asesorId]);
      if (!a.length) return res.status(400).json({ error: 'Ese asesor no existe o está desactivado' });
    }
    const [r] = await conn.execute('UPDATE empresas SET asesor_asignado_id = ? WHERE id = ?', [asesorId, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Empresa no encontrada' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// Notas de contacto (Empresas parte 2, 10/10): solo leer y añadir.
const CANALES_NOTA = ['llamada', 'correo', 'whatsapp', 'reunion', 'otro'];
app.get('/api/admin/empresas/:id/notas', requiereSesionAsesor, async (req, res) => {
  const [filas] = await pool.execute('SELECT n.id, n.canal, n.texto, n.creado_en, a.nombre AS asesor_nombre FROM empresa_notas n JOIN asesores a ON a.id = n.asesor_id WHERE n.empresa_id = ? ORDER BY n.creado_en DESC, n.id DESC', [Number(req.params.id)]);
  res.json(filas);
});
app.post('/api/admin/empresas/:id/notas', requiereSesionAsesor, async (req, res) => {
  const texto = String((req.body && req.body.texto) || '').trim().slice(0, 4000);
  if (!texto) return res.status(400).json({ error: 'Escribe la nota' });
  const canal = CANALES_NOTA.includes(req.body.canal) ? req.body.canal : 'otro';
  const [e] = await pool.execute('SELECT id FROM empresas WHERE id = ?', [Number(req.params.id)]);
  if (!e.length) return res.status(404).json({ error: 'Empresa no encontrada' });
  const [r] = await pool.execute('INSERT INTO empresa_notas (empresa_id, asesor_id, canal, texto) VALUES (?, ?, ?, ?)', [Number(req.params.id), req.asesor.id, canal, texto]);
  res.status(201).json({ ok: true, id: r.insertId });
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
  const cobro = (req.body && req.body.cobro === 'despues') ? 'despues' : 'antes';   // 29/10: cobrar antes de empezar o pagar después
  const normalizado = correo ? normalizarServiciosPropuesta(servicios, importe_centimos) : null;
  if (!correo || !normalizado) {
    return res.status(400).json({ error: 'Faltan datos: correo, y servicios — o bien un array de ids + importe_centimos, o bien un array de {id, precio_centimos} con el desglose' });
  }
  // 20/10: ejercicio (o rango) y plazo por servicio, opcionales: { renta: 2025, pganterior: { desde: 2021, hasta: 2024 } }
  const ejerciciosN = normalizarEjerciciosPropuesta(req.body.ejercicios, serviciosDePropuesta({ servicios: JSON.stringify(normalizado.servicios) }));
  if (ejerciciosN.error) return res.status(400).json({ error: ejerciciosN.error });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const cliente = await obtenerOCrearCliente(conn, { correo, telefono });
    // Fase B (10/10): sin asesor todavía → el que le envía la propuesta (si es
    // una persona del equipo que atiende clientes)
    await conn.execute(
      'UPDATE clientes c JOIN personas q ON q.`asesor_id` = ? AND q.`atiende_clientes` = 1 AND q.`activa` = 1 SET c.`asesor_persona_id` = q.`id` WHERE c.`id` = ? AND c.`asesor_persona_id` IS NULL',
      [req.asesor.id, cliente.id]);
    // 10/10: si quien envía no atiende clientes, el asesor por defecto
    await conn.execute(
      'UPDATE clientes c JOIN personas q ON q.`por_defecto` = 1 AND q.`atiende_clientes` = 1 AND q.`activa` = 1 SET c.`asesor_persona_id` = q.`id` WHERE c.`id` = ? AND c.`asesor_persona_id` IS NULL',
      [cliente.id]);
    const token = generarToken();
    const expira = finValidezPropuesta();
    const [r] = await conn.execute(
      'INSERT INTO propuestas (cliente_id, servicios, importe_centimos, token, token_expira_en, creado_por_asesor_id, servicios_detalle, cobro) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [cliente.id, JSON.stringify(normalizado.servicios), normalizado.importe_centimos, token, aSQLDatetime(expira), req.asesor.id, ejerciciosN.detalle ? JSON.stringify(ejerciciosN.detalle) : null, cobro]
    );
    const retirar = (Array.isArray(req.body.retirar) ? req.body.retirar : []).map(Number).filter(n => Number.isInteger(n) && n > 0 && n !== r.insertId);   // 21/10
    if (retirar.length) await conn.query("UPDATE propuestas SET estado = 'caducada', token_expira_en = NOW() WHERE id IN (?) AND cliente_id = ? AND estado = 'enviada'", [retirar, cliente.id]);
    await conn.commit();
    if (brevoActivo()) {
      const enlace = enlaceArea('area', token);
      const importeTexto = (normalizado.importe_centimos / 100).toFixed(2) + ' €';
      const asesorP = await personaDeCliente(cliente.id).catch(() => null);
      const quienP = asesorP ? `${ESC_HTML(asesorP.nombre)}, tu asesor de Acros,` : 'Tu asesor de Acros';
      const correoP = plantillaCorreo(enlace ? {
        titulo: 'Tu propuesta está lista',
        parrafos: [
          'Hola:',
          `${quienP} ha preparado tu propuesta, por <strong>${ESC_HTML(importeTexto.replace('.', ','))}</strong>. Ábrela para ver qué incluye y, si te encaja, acéptala en un par de clics.`,
        ],
        boton: { texto: 'Ver mi propuesta', url: enlace },
        nota: `La propuesta es válida 15 días: hasta el ${fechaLargaES(expira)}, incluido. Si tienes cualquier duda, escríbenos a <a href="mailto:hola@acrosfi.es" style="color:#A84C18;">hola@acrosfi.es</a> o llámanos al 668 170 020.`,
      } : {
        titulo: 'Tu propuesta está lista',
        parrafos: ['Hola:', `${quienP} ha preparado tu propuesta, por <strong>${ESC_HTML(importeTexto)}</strong>. Tu código de acceso es: <strong>${ESC_HTML(token)}</strong>`],
        nota: `La propuesta es válida 15 días: hasta el ${fechaLargaES(expira)}, incluido.`,
      });
      try {
        await enviarCorreo(correo, 'Tu propuesta de Acros está lista', correoP.html, correoP.texto);

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
    const [clientes] = await conn.execute('SELECT correo, telefono, nombre, apellidos, tipo_documento, numero_documento, creado_en, codigo FROM clientes WHERE id = ?', [p.cliente_id]);
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
    const subidasHoy = await subidasDeHoy(conn, p.cliente_id);   // 15/10
    const [entregasCli] = await conn.execute(
      'SELECT e.`id`, e.`propuesta_id`, e.`servicio`, e.`version`, e.`nombre_archivo`, e.`bytes`, e.`subido_en`, e.`estado`, e.`comentario`, e.`respondido_en`, p2.`creado_en` AS propuesta_creada ' +
      'FROM entregas e JOIN propuestas p2 ON p2.`id` = e.`propuesta_id` ' +
      'WHERE e.`cliente_id` = ? AND e.`id` = (SELECT MAX(e2.`id`) FROM entregas e2 WHERE e2.`propuesta_id` = e.`propuesta_id` AND e2.`servicio` = e.`servicio`) ' +
      'ORDER BY e.`subido_en` DESC', [p.cliente_id]);
    const asesorCli = await personaDeCliente(p.cliente_id, conn).catch(() => null);
    const [dispoTodas] = await conn.query('SELECT * FROM personas WHERE `activa` = 1 AND `atiende_clientes` = 1 ORDER BY `orden`, `id`');
    const [camb] = await conn.execute("SELECT `a_persona_id`, `creado_en` FROM cambios_asesor WHERE `cliente_id` = ? AND `estado` = 'pendiente' ORDER BY `id` DESC LIMIT 1", [p.cliente_id]);
    const personaPublica = q => { if (!q) return null; let esp = []; try { esp = JSON.parse(q.especialidades || '[]'); } catch (e) {} return { id: q.id, nombre: q.nombre, puesto: { es: q.puesto_es || '', en: q.puesto_en || '' }, bio: { es: q.bio_es || '', en: q.bio_en || '' }, foto: q.foto, especialidades: Array.isArray(esp) ? esp : [] }; };
    const [valor] = await conn.execute('SELECT `estado` FROM valoraciones WHERE `propuesta_id` = ?', [p.id]);
    res.json({
      asesor: personaPublica(asesorCli),
      asesores_disponibles: dispoTodas.filter(x => !asesorCli || !asesorCli.equipo_id || x.equipo_id === asesorCli.equipo_id || x.id === asesorCli.id || (camb[0] && camb[0].a_persona_id === x.id)).map(personaPublica),   // 29/10: los de su equipo
      cambio_asesor_pendiente: camb[0] || null,
      valoracion: valor[0] ? valor[0].estado : null,
      dos_pasos_activo: !!(await conn.execute('SELECT totp_activo FROM clientes WHERE id = ?', [p.cliente_id]))[0][0].totp_activo,
      colaboradores: (await conn.execute("SELECT q.nombre FROM colaboraciones co JOIN personas q ON q.id = co.persona_id WHERE co.propuesta_id = ? AND co.estado = 'confirmada' ORDER BY co.id", [p.id]))[0].map(x => x.nombre),
      entregas: pagos.some(g => g.estado === 'confirmado') ? entregasCli.filter(e => e.propuesta_id === p.id) : [],
      informes_bloqueados: pagos.some(g => g.estado === 'confirmado') ? 0 : entregasCli.filter(e => e.propuesta_id === p.id).length,
      entregas_anteriores: entregasCli.filter(e => e.propuesta_id !== p.id),
      cobro: p.cobro || 'antes', pago_confirmado: pagos.some(g => g.estado === 'confirmado'), plazo_pago: plazoPagoDe(p),
      propuesta: { estado: p.estado, servicios: JSON.parse(p.servicios), importe_centimos: p.importe_centimos, motivo_rechazo: p.motivo_rechazo, expira_en: p.token_expira_en, creado_en: p.creado_en, inicio_inmediato_en: p.inicio_inmediato_en },
      cliente: clientes[0] || null,
      pago: pagos[0] || null,
      diligencia: diligencias[0] || null,
      documentos, subidas_hoy: subidasHoy, limite_subidas: LIMITE_SUBIDAS_DIA,
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
  // Contraseña opcional en el primer acceso (10/09): si el modo de acceso
  // la contempla y el cliente la rellena, queda puesta desde el primer
  // día y ya puede entrar con ella la próxima vez. Si no la rellena (o el
  // modo es solo "enlace"), no pasa nada — siempre puede ponerla después
  // desde dentro del área, o seguir entrando por enlace.
  const contrasena = req.body.contrasena || '';
  if (contrasena && contrasena.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    await conn.execute(
      'UPDATE clientes SET nombre = ?, apellidos = ?, tipo_documento = ?, numero_documento = ? WHERE id = ?',
      [req.body.nombre.trim(), req.body.apellidos.trim(), req.body.tipo_documento, req.body.numero_documento.trim(), p.cliente_id]
    );
    await asignarCodigoCliente(conn, p.cliente_id).catch(err => console.error('Código de usuario:', err.message));
    if (contrasena && MODO_ACCESO_CLIENTE !== 'enlace') {
      const hash = await bcrypt.hash(contrasena, 10);
      await conn.execute('UPDATE clientes SET contrasena_hash = ? WHERE id = ?', [hash, p.cliente_id]);
    }
    res.json({ ok: true, contrasena_puesta: !!(contrasena && MODO_ACCESO_CLIENTE !== 'enlace') });
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
    // 10/10: sin la petición expresa de inicio inmediato no se puede aceptar
    // (art. 98.8 y 103.a TRLGDCU: es lo que permite empezar antes de que
    // acaben los 14 días de desistimiento). Se guarda cuándo lo marcó.
    if (!(req.body && req.body.inicio_inmediato === true)) return res.status(400).json({ error: 'Para aceptar, marca la casilla de inicio inmediato del servicio' });
    await conn.execute('UPDATE propuestas SET estado = ?, `inicio_inmediato_en` = NOW() WHERE id = ?', ['aceptada', p.id]);
    // 20/10: cada servicio contratado pasa a tener su ejercicio, plazo y estado (si falla, se completa al reiniciar)
    await crearServiciosDePropuesta(conn, p).catch(err => console.error('Servicios del encargo ' + p.id + ':', err.message));
    await heredarAlta(conn, Object.assign({}, p, { estado: 'aceptada' })).catch(err => console.error('Alta heredada del encargo ' + p.id + ':', err.message));   // 21/10
    avisarCliente(p.cliente_id, '✅', 'un cliente ha aceptado su propuesta', 'El siguiente paso es su pago.', { etiqueta: 'white_check_mark' });
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
    avisarCliente(p.cliente_id, '❌', 'un cliente ha rechazado su propuesta', 'Mira el motivo en su ficha.', { etiqueta: 'x' });
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
    avisarPagos('💶 Un cliente ha declarado un pago', 'Confírmalo en «Pagos pendientes de confirmar».', { prioridad: 4, etiqueta: 'euro' });
    avisarCliente(p.cliente_id, '💶', 'un cliente ha declarado un pago', 'Lo confirmará un encargado o un administrador.', { prioridad: 4, etiqueta: 'euro' });
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
          `SELECT pg.*, p.token, c.correo, c.id AS cliente_id FROM pagos pg
           JOIN propuestas p ON p.id = pg.propuesta_id
           JOIN clientes c ON c.id = p.cliente_id
           WHERE pg.estado = ? ORDER BY pg.creado_en`, [estado])
      : await conn.execute(
          `SELECT pg.*, p.token, c.correo, c.id AS cliente_id FROM pagos pg
           JOIN propuestas p ON p.id = pg.propuesta_id
           JOIN clientes c ON c.id = p.cliente_id
           ORDER BY pg.creado_en`);
    res.json(filas);
  } finally {
    conn.release();
  }
});

app.post('/api/admin/pagos/:id/confirmar', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM pagos WHERE id = ?', [req.params.id]);
    if (!filas.length) return res.status(404).json({ error: 'Pago no encontrado' });
    if (filas[0].estado === 'confirmado') return res.status(409).json({ error: 'Ese pago ya estaba confirmado' });
    await conn.execute('UPDATE pagos SET estado = ?, confirmado_en = ?, confirmado_por_asesor_id = ? WHERE id = ?', ['confirmado', aSQLDatetime(ahora()), req.asesor.id, req.params.id]);
    // 15/10: para el registro de actividad (quién, cliente, método, importe) y el canal de pagos
    const [inf] = await conn.execute('SELECT c.nombre, c.apellidos, c.correo, p.importe_centimos FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.id = ?', [filas[0].propuesta_id]);
    if (inf.length) {
      const cli = [inf[0].nombre, inf[0].apellidos].filter(Boolean).join(' ') || inf[0].correo;
      req.body = Object.assign({}, req.body, { cliente: cli, metodo: filas[0].metodo, importe_centimos: inf[0].importe_centimos });
      avisarPagos('✅ Pago confirmado', 'Lo ha confirmado ' + quienIni(await inicialesDeAsesor(req.asesor.id)) + ' (' + filas[0].metodo + ').', { etiqueta: 'white_check_mark' });
    }
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
      clave_asesor: await claveDeAsesor('identidad', Number(req.params.id), req.asesor.id),
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
app.get('/api/admin/sesion', requiereSesionAsesor, (req, res) => {   // 29/10: lo que dice la base de datos ahora, no lo de cuando entró
  res.json({ es_admin: !!req.asesor.esAdmin, roles: [...req.asesor.roles] });
});
app.get('/api/admin/documentos/backup', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {   // 14/10: solo admin (con el modelo B un asesor no puede bajarse lo de todos)
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
    // Web pública (05/10): contenido editable e imágenes, sin cifrar (son públicos).
    try {
      const [web] = await conn.execute('SELECT clave, datos, version, actualizado_en FROM web_contenido');
      zip.append(JSON.stringify(web.map(f => ({ ...f, datos: JSON.parse(f.datos) })), null, 2), { name: 'web/contenido.json' });
      const [imgs] = await conn.execute('SELECT id, tipo, datos FROM web_imagenes');
      imgs.forEach(i => zip.append(i.datos, { name: `web/imagenes/${i.id}.${TIPOS_IMAGEN_WEB[i.tipo] || 'bin'}` }));
    } catch (err) {
      console.error('No se pudo incluir la web pública en el backup:', err.message);
    }
    const leeme = 'La carpeta web/ guarda el contenido editable de la web pública (logo, equipo, destacados, ofertas) y sus imágenes, sin cifrar porque ya son públicos. ' +
      'Cada archivo .enc está cifrado — para abrirlo, pega tu clave privada en el panel de Acros ' +
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
  if (req.body && req.body.documento_anterior === true) await rellenarDocumentoAnterior(req);   // 21/10: renovación con el mismo documento
  const errores = validarDiligencia(req.body);
  if (errores.length) return res.status(400).json({ error: 'Faltan o son inválidos: ' + errores.join(', ') });
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [pagos] = await conn.execute('SELECT * FROM pagos WHERE propuesta_id = ?', [p.id]);
    if (!pagos.length && p.cobro !== 'despues') return res.status(409).json({ error: 'No hay ningún pago registrado para esta propuesta todavía' });   // 29/10: con «pagar después», el alta va antes del pago

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
    // 10/10: antes ponía el número a NULL si el cuestionario no lo traía
    // (el Área no lo manda aquí) y se perdía el que dio al darse de alta.
    await conn.execute('UPDATE clientes SET tipo_documento = COALESCE(NULLIF(?, \'\'), tipo_documento), numero_documento = COALESCE(NULLIF(?, \'\'), numero_documento) WHERE id = ?',
      [b.tipo_documento || '', (b.numero_documento || '').trim(), p.cliente_id]);
    await asignarCodigoCliente(conn, p.cliente_id).catch(() => {});
    if (req.renovacionDe) await conn.execute("UPDATE diligencias SET nota_asesor = ? WHERE propuesta_id = ? AND estado = 'revision'", ['Renovación del alta: reutiliza el documento de la aprobada (n.º ' + req.renovacionDe + ')', p.id]);   // 21/10
    avisarCliente(p.cliente_id, '🪪', req.renovacionDe ? 'un cliente ha renovado su alta' : 'un cliente ha enviado su cuestionario de alta', 'Revísalo en «Diligencias pendientes».', { etiqueta: 'identification_card' });
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
  if (accion !== 'aprobar' && !tieneRol(req, 'jefe', 'encargado')) return res.status(403).json({ error: 'Activar el examen especial o rechazar un alta es cosa del jefe de equipo, el encargado o un administrador.' });
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
    if (estadoResultante === 'aprobado') await heredarAltasDeCliente(conn, d.cliente_id).catch(err => console.error('Altas heredadas:', err.message));   // 21/10
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
// Lista real de encargos para la tabla principal del panel (06/10): una
// fila por propuesta con su cliente y en qué punto está (pago, diligencia,
// documentos). Sustituye a los clientes de demostración que traía el HTML.
// La etapa y el porcentaje los calcula el panel a partir de estos estados.
app.get('/api/admin/clientes', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.query(
      `SELECT p.id AS propuesta_id, p.servicios, p.importe_centimos, p.estado AS estado_propuesta,
              p.creado_en, p.actualizado_en,
              c.id AS cliente_id, c.nombre, c.apellidos, c.correo, c.telefono, c.codigo,
              (SELECT q.nombre FROM personas q WHERE q.id = c.asesor_persona_id) AS asesor_nombre,
              (SELECT q.asesor_id FROM personas q WHERE q.id = c.asesor_persona_id) AS asesor_cuenta_id,
              (SELECT pg.estado FROM pagos pg WHERE pg.propuesta_id = p.id ORDER BY pg.id DESC LIMIT 1) AS estado_pago,
              (SELECT d.estado FROM diligencias d WHERE d.propuesta_id = p.id ORDER BY d.id DESC LIMIT 1) AS estado_diligencia,
              (SELECT COUNT(*) FROM documentos_fiscales df WHERE df.propuesta_id = p.id) AS docs_total,
              (SELECT COUNT(*) FROM documentos_fiscales df WHERE df.propuesta_id = p.id AND df.estado IN ('pendiente','rechazado')) AS docs_pendientes, -- rechazado = hay que volver a subirlo
              (SELECT COUNT(*) FROM documentos_fiscales df WHERE df.propuesta_id = p.id AND df.estado = 'enviado') AS docs_por_revisar,
              (SELECT COUNT(*) FROM documentos_fiscales df WHERE df.propuesta_id = p.id AND df.estado = 'valido') AS docs_validos,
              (SELECT COUNT(*) FROM mensajes ms WHERE ms.propuesta_id = p.id AND ms.autor = 'cliente' AND ms.leido_en IS NULL) AS mensajes_sin_leer
       FROM propuestas p JOIN clientes c ON c.id = p.cliente_id
       ORDER BY p.creado_en DESC
       LIMIT 500`
    );
    // Última entrega de cada servicio (fase 2): cuántos servicios están
    // esperando conformidad, con cambios pedidos o terminados
    if (filas.length) {
      const [ult] = await conn.query(
        'SELECT e.`propuesta_id`, e.`estado` FROM entregas e WHERE e.`propuesta_id` IN (?) AND e.`id` = (SELECT MAX(e2.`id`) FROM entregas e2 WHERE e2.`propuesta_id` = e.`propuesta_id` AND e2.`servicio` = e.`servicio`)',
        [filas.map(f => f.propuesta_id)]);
      filas.forEach(f => {
        const suyas = ult.filter(u => u.propuesta_id === f.propuesta_id);
        f.entregas_esperando = suyas.filter(u => u.estado === 'entregado').length;
        f.entregas_cambios = suyas.filter(u => u.estado === 'cambios').length;
        f.entregas_conformes = suyas.filter(u => u.estado === 'conforme').length;
      });
    }
    filas.forEach(f => { f.es_mio = f.asesor_cuenta_id === req.asesor.id; });
    // 30/10 (Vikn): el mismo progreso que la ficha y el Área
    const idsP = filas.map(f => f.propuesta_id);
    if (idsP.length) {
      const [svF] = await conn.query(SQL_SERVICIOS + ' WHERE s.propuesta_id IN (?) AND s.confirmado IN (0, 1)', [idsP]);   // con los recuentos de documentos, como la ficha
      const vs = await vistasDeFilas(conn, svF), enc = await estadoEncargos(conn, idsP);
      const media = l => l.length ? Math.round(l.reduce((a, v) => a + v.progreso, 0) / l.length) : null;
      const porCli = {};
      filas.forEach(f => {
        const suyos = vs.filter(v => v.propuesta_id === f.propuesta_id), enCurso = suyos.filter(v => v.en_curso);
        f.progreso = suyos.length ? media(enCurso.length ? enCurso : suyos) : progresoServicio({ en_curso: true }, enc[f.propuesta_id], 0);
        (porCli[f.cliente_id] = porCli[f.cliente_id] || []).push(...enCurso);
      });
      filas.forEach(f => { const l = porCli[f.cliente_id] || []; f.progreso_cliente = l.length ? media(l) : null; });
    }
    res.json(filas);
  } catch (err) {
    console.error('Error al listar los encargos:', err);
    res.status(500).json({ error: 'No se pudo cargar la lista de clientes' });
  } finally {
    conn.release();
  }
});

// Ficha de un cliente (06/10): su expediente completo en una sola
// llamada — datos, cada encargo con sus pagos, diligencia y documentos, y
// las solicitudes que hizo desde la web (por su correo o su teléfono).
// No incluye nada cifrado: los documentos se abren desde sus colas, con
// la clave privada del navegador del asesor.
app.get('/api/admin/clientes/:id', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Cliente no válido' });
  await caducarPropuestas(id);   // 20/10
  const conn = await pool.getConnection();
  try {
    const [cli] = await conn.execute(
      'SELECT id, correo, telefono, telefono2, nombre, apellidos, tipo_documento, numero_documento, estado, creado_en, `asesor_persona_id`, `sin_ia`, `totp_activo`, `codigo`, (`contrasena_hash` IS NOT NULL) AS tiene_contrasena, (`preferencias_avisos` IS NOT NULL) AS avisos_personalizados FROM clientes WHERE id = ?', [id]);
    if (!cli.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const cliente = cli[0];
    const [propuestas] = await conn.execute(
      `SELECT id, servicios, importe_centimos, estado, motivo_rechazo, creado_en, token_expira_en, inicio_inmediato_en, cobro
       FROM propuestas WHERE cliente_id = ? ORDER BY creado_en DESC`, [id]);
    const ids = propuestas.map(p => p.id);
    let pagos = [], diligencias = [], documentos = [], entregasF = [];
    if (ids.length) {
      [pagos] = await conn.query('SELECT id, propuesta_id, metodo, estado, creado_en FROM pagos WHERE propuesta_id IN (?) ORDER BY id', [ids]);
      [diligencias] = await conn.query('SELECT id, propuesta_id, estado, coherencia, nota_asesor, resuelto_en, creado_en FROM diligencias WHERE propuesta_id IN (?) ORDER BY id', [ids]);
      [documentos] = await conn.query(
        `SELECT id, propuesta_id, servicio, nombre, urgente, estado, razon_rechazo, subido_en, creado_en, revisado_en, nombre_original, (documento_ref IS NOT NULL) AS tiene_archivo,
           (SELECT COUNT(*) FROM llaves_documento l WHERE l.tipo = 'fiscal' AND l.objeto_id = documentos_fiscales.id AND l.asesor_id = ?) AS mi_llave
         FROM documentos_fiscales WHERE propuesta_id IN (?) ORDER BY creado_en`, [req.asesor.id, ids]);
      [entregasF] = await conn.query('SELECT `id`, `propuesta_id`, `servicio`, `version`, `nombre_archivo`, `bytes`, `subido_en`, `estado`, `comentario`, `respondido_en` FROM entregas WHERE `propuesta_id` IN (?) ORDER BY `servicio`, `version` DESC', [ids]);
    }
    const telefonoLimpio = String(cliente.telefono || '').replace(/\D/g, '').slice(-9);
    const [solicitudes] = await conn.query(
      `SELECT id, servicios, detalle, cuestionario, telefono, correo, atendida, creado_en
       FROM solicitudes_presupuesto
       WHERE (correo IS NOT NULL AND LOWER(correo) = LOWER(?))
          OR (? <> '' AND RIGHT(REGEXP_REPLACE(telefono, '[^0-9]', ''), 9) = ?)
       ORDER BY creado_en DESC LIMIT 50`, [cliente.correo, telefonoLimpio, telefonoLimpio]);
    res.json({
      cliente,
      encargos: propuestas.map(p => ({
        ...p,
        pagos: pagos.filter(x => x.propuesta_id === p.id),
        diligencia: diligencias.filter(x => x.propuesta_id === p.id).pop() || null,
        documentos: documentos.filter(x => x.propuesta_id === p.id),
        entregas: entregasF.filter(x => x.propuesta_id === p.id),
      })),
      solicitudes,
      servicios: await listarServiciosCliente(conn, id),
      colaboraciones: (await conn.query('SELECT co.*, q.nombre AS persona_nombre, a.nombre AS anotado_nombre FROM colaboraciones co JOIN personas q ON q.id = co.persona_id LEFT JOIN asesores a ON a.id = co.anotado_por WHERE co.propuesta_id IN (SELECT id FROM propuestas WHERE cliente_id = ?) ORDER BY co.id', [id]))[0],
      cambios_asesor: (await conn.execute('SELECT ca.*, qd.nombre AS desde_nombre, qa.nombre AS a_nombre FROM cambios_asesor ca LEFT JOIN personas qd ON qd.id = ca.desde_persona_id LEFT JOIN personas qa ON qa.id = ca.a_persona_id WHERE ca.cliente_id = ? ORDER BY ca.id DESC LIMIT 10', [id]))[0],
    });
  } catch (err) {
    console.error('Error al cargar la ficha del cliente:', err);
    res.status(500).json({ error: 'No se pudo cargar la ficha' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/clientes-activos', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT c.id AS cliente_id, c.correo, c.nombre, c.apellidos, d.propuesta_id, (SELECT pr.servicios FROM propuestas pr WHERE pr.id = d.propuesta_id) AS servicios, (SELECT pr.creado_en FROM propuestas pr WHERE pr.id = d.propuesta_id) AS propuesta_creado_en
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
    const [propuestas] = await conn.execute('SELECT id, cliente_id, servicios FROM propuestas WHERE id = ?', [propuesta_id]);
    if (!propuestas.length) return res.status(404).json({ error: 'Propuesta no encontrada' });
    // 10/10: solo servicios de ese encargo (o ninguno = para todos sus servicios)
    if (servicio && !serviciosDePropuesta(propuestas[0]).includes(String(servicio))) {
      return res.status(400).json({ error: 'Ese servicio no está en este encargo' });
    }
    // 10/10: el mismo documento ya pedido y sin subir (p. ej. doble clic)
    const [iguales] = await conn.execute(
      "SELECT id FROM documentos_fiscales WHERE propuesta_id = ? AND LOWER(TRIM(nombre)) = LOWER(TRIM(?)) AND estado = 'pendiente' AND (servicio <=> ?)",
      [propuesta_id, nombre, servicio || null]);
    if (iguales.length) return res.status(409).json({ error: 'Ese documento ya está pedido y pendiente de que lo suba' });
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
    const columnas = `d.id, d.cliente_id, d.propuesta_id, d.servicio, d.nombre AS nombre_doc, d.nombre_original, d.urgente,
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
// 15/10: límite de subidas por cliente y día (hora de Madrid)
const LIMITE_SUBIDAS_DIA = 20;
async function subidasDeHoy(conn, clienteId) {
  const [f] = await conn.execute('SELECT COUNT(*) AS n FROM documentos_fiscales WHERE cliente_id = ? AND subido_en >= ?', [clienteId, aSQLDatetime(inicioDiaMadridUTC(fechaMadrid().fecha))]);
  return Number(f[0].n) || 0;
}
const MSG_LIMITE_SUBIDAS = 'Has llegado al límite de hoy (' + LIMITE_SUBIDAS_DIA + ' documentos). Mañana podrás subir más; si te corre prisa, escribe a tu asesor.';
// 15/10: el cliente sube un documento que no se le ha pedido (botón «Subir
// documento» → «Otro documento»). Se guarda igual que los pedidos.
app.post('/api/propuestas/:token/documentos-nuevo', async (req, res) => {
  const b = req.body || {};
  const nombre = String(b.nombre || '').trim().slice(0, 200);
  if (nombre.length < 4) return res.status(400).json({ error: 'Indica qué documento es' });
  if (!b.archivo_cifrado || !b.iv || !b.clave_cifrada) return res.status(400).json({ error: 'Falta el archivo' });
  if (!limiteTamanoOk(b.archivo_cifrado, 15 * 1024 * 1024)) return res.status(400).json({ error: 'El archivo no puede superar los 15 MB' });
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const servicios = serviciosDePropuesta(p);
    const servicio = servicios.includes(b.servicio) ? b.servicio : 'general';
    if (await subidasDeHoy(conn, p.cliente_id) >= LIMITE_SUBIDAS_DIA) return res.status(429).json({ error: MSG_LIMITE_SUBIDAS });
    const clave = `docs/${p.cliente_id}/${generarToken()}.enc`;
    await subirAR2(clave, Buffer.from(b.archivo_cifrado, 'base64'), 'application/octet-stream');
    const [r] = await conn.execute(
      "INSERT INTO documentos_fiscales (cliente_id, propuesta_id, servicio, nombre, estado, documento_ref, documento_iv, documento_clave_cifrada, documento_tipo_mime, subido_en, nombre_original) VALUES (?, ?, ?, ?, 'enviado', ?, ?, ?, ?, ?, ?)",
      [p.cliente_id, p.id, servicio, nombre, clave, b.iv, b.clave_cifrada, b.tipo_mime || 'application/octet-stream', aSQLDatetime(ahora()), String(b.nombre_original || '').slice(0, 255) || null]);
    avisarCliente(p.cliente_id, '📄', 'un cliente ha subido un documento', 'Revísalo en «Documentos fiscales pendientes de revisión».', { etiqueta: 'page_facing_up' });
    res.status(201).json({ ok: true, id: r.insertId, subidas_hoy: await subidasDeHoy(conn, p.cliente_id), limite: LIMITE_SUBIDAS_DIA });
  } finally { conn.release(); }
});
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
    if (await subidasDeHoy(conn, p.cliente_id) >= LIMITE_SUBIDAS_DIA) return res.status(429).json({ error: MSG_LIMITE_SUBIDAS });
    if (req.body.nombre_original) await conn.execute('UPDATE documentos_fiscales SET nombre_original = ? WHERE id = ?', [String(req.body.nombre_original).slice(0, 255), req.params.id]);
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
    avisarCliente(p.cliente_id, '📄', 'un cliente ha subido un documento', 'Revísalo en «Documentos fiscales pendientes de revisión».', { etiqueta: 'page_facing_up' });
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
      clave_asesor: await claveDeAsesor('fiscal', Number(req.params.id), req.asesor.id),
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
      'UPDATE documentos_fiscales SET estado = ?, razon_rechazo = ?, resuelto_por_asesor_id = ?, revisado_en = NOW() WHERE id = ?',
      [estadoResultante, accion === 'rechazar' ? razon.trim() : null, req.asesor.id, req.params.id]
    );
    res.json({ ok: true, estado: estadoResultante });
  } finally {
    conn.release();
  }
});
// ================================================================
// ACCESO DE CLIENTES (10/09, quinta vuelta): DOS formas de entrar que
// conviven — enlace mágico de un solo uso y correo + contraseña — sobre
// una misma capa de sesión de cliente. Cuál se ofrece en pantalla lo
// decide MODO_ACCESO_CLIENTE (Railway): "enlace", "contrasena" o
// "ambos" (por defecto). El enlace mágico NO desaparece nunca del
// código aunque se elija "contrasena": es la única forma sensata de
// "he olvidado mi contraseña" (entras con el enlace, y desde dentro te
// pones una nueva).
//
// Cómo encaja con lo que ya había: toda la API del área sigue colgando
// del token de propuesta (/api/propuestas/:token/...). Una sesión de
// cliente simplemente RESUELVE a ese token (GET /api/clientes/sesion)
// y el área continúa igual que siempre a partir de ahí — sin tener que
// reescribir los diez endpoints que ya funcionan. El token de propuesta
// deja de ir en la barra de direcciones para quien entra por sesión
// (solo sigue en el enlace inicial de alta, que es inevitable).
// ================================================================

// Lo que el área necesita saber antes de pintar la pantalla de entrada.
app.get('/api/configuracion-publica', (req, res) => {
  res.json({ modo_acceso_cliente: MODO_ACCESO_CLIENTE });
});

async function crearSesionCliente(conn, clienteId, dosPasos = 0) {
  const token = generarToken();
  const expira = new Date(ahora().getTime() + DIAS_VIGENCIA_SESION_CLIENTE * 24 * 60 * 60 * 1000);
  await conn.execute('INSERT INTO sesiones_cliente (cliente_id, token, expira_en, dos_pasos) VALUES (?,?,?,?)', [clienteId, token, aSQLDatetime(expira), dosPasos ? 1 : 0]);
  return { token, expira_en: expira.toISOString() };
}
// 10/10: si el cliente tiene la verificación en dos pasos, la sesión nace
// sin verificar (salvo en un dispositivo de confianza) y hay que dar el
// código antes de ver nada.
async function sesionClienteTrasEntrar(conn, cliente, tokenDispositivo) {
  if (!cliente.totp_activo) return { sesion: await crearSesionCliente(conn, cliente.id, 1) };
  if (await dispositivoDeConfianza(conn, 'cliente', cliente.id, tokenDispositivo)) return { sesion: await crearSesionCliente(conn, cliente.id, 1) };
  return { sesion: await crearSesionCliente(conn, cliente.id, 0), requiere_2fa: true };
}

async function requiereSesionCliente(req, res, next) {
  const token = (req.get('x-sesion-cliente') || '').trim();
  if (!token) return res.status(401).json({ error: 'Falta iniciar sesión' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT s.expira_en, s.dos_pasos, c.totp_activo, c.id, c.correo, c.nombre, c.apellidos, c.estado, c.contrasena_hash IS NOT NULL AS tiene_contrasena
       FROM sesiones_cliente s JOIN clientes c ON c.id = s.cliente_id WHERE s.token = ?`, [token]
    );
    if (!filas.length) return res.status(401).json({ error: 'Sesión no válida. Vuelve a entrar.' });
    const s = filas[0];
    if (new Date(s.expira_en) < ahora()) return res.status(401).json({ error: 'Tu sesión ha caducado. Vuelve a entrar.' });
    if (s.estado !== 'activo') return res.status(403).json({ error: 'Esta cuenta ya no está activa.' });
    if (s.totp_activo && !s.dos_pasos && !req.permitirSinDosPasos) return res.status(401).json({ error: 'Falta la verificación en dos pasos', requiere_2fa: true });
    req.cliente = { id: s.id, correo: s.correo, nombre: s.nombre, apellidos: s.apellidos, tieneContrasena: !!s.tiene_contrasena, sesionToken: token };
    next();
  } finally {
    conn.release();
  }
}

// --- Opción A: enlace mágico de un solo uso (reentrada) ---
app.post('/api/acceso/solicitar', async (req, res) => {
  const correo = (req.body.correo || '').trim().toLowerCase();
  if (!correo) return res.status(400).json({ error: 'Falta el correo' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM clientes WHERE correo = ?', [correo]);
    if (filas.length && filas[0].estado === 'activo') {
      const cliente = filas[0];
      const token = generarToken();
      const expira = sumarMinutos(ahora(), MINUTOS_VIGENCIA_ACCESO);
      await conn.execute(
        'INSERT INTO tokens_acceso (cliente_id, token, expira_en) VALUES (?, ?, ?)',
        [cliente.id, token, aSQLDatetime(expira)]
      );
      const enlace = enlaceArea('area', token, 'acceso');
      let algunCanalReal = false;
      if (brevoActivo()) {
        const saludo = cliente.nombre ? `Hola, ${ESC_HTML(cliente.nombre)}:` : 'Hola:';
        const correoA = plantillaCorreo(enlace ? {
          titulo: 'Entra en tu área',
          parrafos: [saludo, 'Aquí tienes tu enlace para entrar en tu área de cliente de Acros. Es personal, sirve una sola vez y caduca en 15 minutos.'],
          boton: { texto: 'Entra en tu área', url: enlace },
          nota: 'Si no lo has pedido tú, no tienes que hacer nada: sin este correo nadie puede entrar en tu área.',
        } : {
          titulo: 'Entra en tu área',
          parrafos: [saludo, `Tu código de acceso es <strong>${ESC_HTML(token)}</strong>. Sirve una sola vez y caduca en 15 minutos.`],
        });
        try {
          await enviarCorreo(correo, 'Tu enlace para entrar en Acros', correoA.html, correoA.texto);

          algunCanalReal = true;
        } catch (err) {
          console.error('Error al enviar el correo de acceso (Brevo):', err.response?.data || err.message);
        }
      }
      // WhatsApp (10/09): canal aparte del de correo, no lo sustituye —
      // se manda por los dos si los dos están configurados y el cliente
      // tiene teléfono. Nunca bloquea la respuesta: si Twilio falla (o
      // en el sandbox, si ese número no se vinculó primero desde el
      // móvil con "join..."), el correo (o el token_demo) siguen
      // funcionando igual que si esto no existiera.
      if (twilioActivo() && cliente.telefono) {
        const texto = enlace
          ? `Tu acceso a Acros (válido 15 minutos): ${enlace}`
          : `Tu código de acceso a Acros (válido 15 minutos) es: ${token}`;
        try {
          await enviarWhatsApp(cliente.telefono, texto);
          algunCanalReal = true;
        } catch (err) {
          console.error('Error al enviar el acceso por WhatsApp (Twilio):', err.response?.data || err.message);
        }
      }
      if (algunCanalReal) return res.json({ ok: true, expira_en: expira.toISOString() });
      // 06/10 — FALLO DE SEGURIDAD CORREGIDO: si el correo no salía (Brevo
      // sin configurar o con error), se devolvía el código de acceso a quien
      // lo pidiera, y cualquiera que escribiera el correo de un cliente
      // podía entrar en su área. Ahora el código solo se devuelve en modo
      // de pruebas explícito (MODO_DEMO=1, nunca en producción); si no,
      // la respuesta es la misma que para un correo desconocido, queda en
      // el registro y os llega un aviso para revisar el correo.
      if (process.env.MODO_DEMO === '1') return res.json({ ok: true, token_demo: token, expira_en: expira.toISOString() });
      console.error('ACCESO: el enlace de un cliente no ha salido por ningún canal (¿Brevo sin configurar o con error?).');
      avisarAlerta('⚠️ Un cliente no ha recibido su enlace de acceso', 'El correo no ha salido: revisa Brevo en Railway (BREVO_API_KEY y BREVO_REMITENTE) y el registro.', { prioridad: 4, etiqueta: 'warning' });
      return res.json({ ok: true });
    }
    // Mismo "ok" tanto si el correo existe como si no: no hay que confirmar
    // a un desconocido qué correos son clientes.
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// Consumir el enlace: además de marcarlo como usado, ahora abre una
// sesión de cliente (antes solo devolvía los datos del cliente y el área
// no sabía qué hacer con ellos — la reentrada estaba a medias).
app.get('/api/acceso/:token', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM tokens_acceso WHERE token = ?', [req.params.token]);
    if (!filas.length) return res.status(404).json({ error: 'Enlace no válido' });
    const t = filas[0];
    if (t.usado) return res.status(410).json({ error: 'Este enlace ya se ha usado' });
    if (new Date(t.expira_en) < ahora()) return res.status(410).json({ error: 'Este enlace ha caducado' });
    await conn.execute('UPDATE tokens_acceso SET usado = 1 WHERE id = ?', [t.id]);
    const [cliente] = await conn.execute('SELECT id, correo, nombre, apellidos, totp_activo FROM clientes WHERE id = ?', [t.cliente_id]);
    const r = await sesionClienteTrasEntrar(conn, cliente[0], req.get('x-dispositivo-2fa'));
    res.json({ ok: true, cliente: { id: cliente[0].id, correo: cliente[0].correo, nombre: cliente[0].nombre, apellidos: cliente[0].apellidos }, sesion: r.sesion, requiere_2fa: !!r.requiere_2fa });
  } finally {
    conn.release();
  }
});

// --- Opción B: correo + contraseña ---
app.post('/api/clientes/login', async (req, res) => {
  if (MODO_ACCESO_CLIENTE === 'enlace') {
    return res.status(403).json({ error: 'El acceso por contraseña no está activado; usa el enlace de acceso.' });
  }
  const correo = (req.body.correo || '').trim().toLowerCase();
  const contrasena = req.body.contrasena || '';
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT * FROM clientes WHERE correo = ?', [correo]);
    // Mismo mensaje siempre — ni si existe el correo, ni si tiene o no
    // contraseña puesta: no hay que dar pistas a quien prueba a ciegas.
    const claveC = claveLogin(req, 'cliente', correo);
    if (loginBloqueado(claveC)) return res.status(429).json({ error: MSG_BLOQUEO });
    const error = () => { apuntarFalloLogin(claveC); return res.status(401).json({ error: 'Correo o contraseña incorrectos' }); };
    if (!filas.length || !filas[0].contrasena_hash) return error();
    const cliente = filas[0];
    if (cliente.estado !== 'activo') return res.status(403).json({ error: 'Esta cuenta ya no está activa' });
    const ok = await bcrypt.compare(contrasena, cliente.contrasena_hash);
    if (!ok) return error();
    const r = await sesionClienteTrasEntrar(conn, cliente, req.get('x-dispositivo-2fa'));
    res.json({ ok: true, cliente: { correo: cliente.correo, nombre: cliente.nombre, apellidos: cliente.apellidos }, sesion: r.sesion, requiere_2fa: !!r.requiere_2fa });
  } finally {
    conn.release();
  }
});

// Con sesión: a qué propuesta hay que llevar al cliente. Su encargo más
// reciente — si en el futuro hubiera varios en marcha a la vez, esto es
// lo que habría que ampliar (un selector), no la sesión en sí.
app.get('/api/clientes/sesion', requiereSesionCliente, async (req, res) => {
  await caducarPropuestas(req.cliente.id);   // 20/10
  const conn = await pool.getConnection();
  try {
    const [propuestas] = await conn.execute(
      SQL_PROPUESTA_DE_ENTRADA, [req.cliente.id]
    );
    res.json({
      ok: true,
      cliente: { correo: req.cliente.correo, nombre: req.cliente.nombre, apellidos: req.cliente.apellidos, tiene_contrasena: req.cliente.tieneContrasena },
      propuesta_token: propuestas.length ? propuestas[0].token : null,
      modo_acceso_cliente: MODO_ACCESO_CLIENTE,
    });
  } finally {
    conn.release();
  }
});

// Poner o cambiar la contraseña desde dentro del área. Si el cliente
// todavía no tiene ninguna (entró por enlace), no se le pide la actual;
// si ya tiene, sí. Al cambiarla se cierran sus demás sesiones abiertas
// (mismo criterio que con los asesores).
app.post('/api/clientes/contrasena', requiereSesionCliente, async (req, res) => {
  if (MODO_ACCESO_CLIENTE === 'enlace') {
    return res.status(403).json({ error: 'El acceso por contraseña no está activado.' });
  }
  const nueva = req.body.contrasena_nueva || '';
  const actual = req.body.contrasena_actual || '';
  if (nueva.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  const conn = await pool.getConnection();
  try {
    if (req.cliente.tieneContrasena) {
      const [filas] = await conn.execute('SELECT contrasena_hash FROM clientes WHERE id = ?', [req.cliente.id]);
      const ok = await bcrypt.compare(actual, filas[0].contrasena_hash);
      if (!ok) return res.status(401).json({ error: 'Tu contraseña actual no es correcta' });
    }
    const hash = await bcrypt.hash(nueva, 10);
    await conn.execute('UPDATE clientes SET contrasena_hash = ? WHERE id = ?', [hash, req.cliente.id]);
    await conn.execute('DELETE FROM sesiones_cliente WHERE cliente_id = ? AND token != ?', [req.cliente.id, req.get('x-sesion-cliente')]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

app.post('/api/clientes/logout', requiereSesionCliente, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.body && req.body.todos === true) {   // 20/10: «En todos los dispositivos»
      await conn.execute('DELETE FROM sesiones_cliente WHERE cliente_id = ?', [req.cliente.id]);
      await conn.execute("DELETE FROM dispositivos_confianza WHERE tipo = 'cliente' AND usuario_id = ?", [req.cliente.id]).catch(() => {});
      return res.json({ ok: true, todos: true });
    }
    await conn.execute('DELETE FROM sesiones_cliente WHERE token = ?', [req.get('x-sesion-cliente')]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// Entrar por el enlace inicial de la propuesta también abre sesión:
// tener ese token ya demuestra la identidad al mismo nivel que el enlace
// mágico (ambos llegan por correo), y así el cliente puede ponerse
// contraseña desde dentro y volver luego sin necesitar el enlace.
app.post('/api/propuestas/:token/sesion', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const sesion = await crearSesionCliente(conn, p.cliente_id);
    res.json({ ok: true, sesion });
  } finally {
    conn.release();
  }
});

// ================================================================
// WEB PÚBLICA EDITABLE DESDE EL PANEL (05/10)
// Dos bloques de contenido, cada uno un JSON con versión:
//   - 'marca':    logo (id de imagen), título/subtítulo del equipo y las
//                 personas (nombre, foto, puesto y bio en ES/EN).
//   - 'catalogo': destacados (lista de ids de servicio) y ofertas
//                 ({ id: { descuento, fin } }).
// La web lo lee de /api/web/contenido (público). Si este servidor no
// responde, cada página tira de acros_marca.js y de su propio HTML, así
// que nunca se queda una sección vacía. Solo un administrador escribe.
// Cada guardado comprueba la versión de partida (dos personas editando a
// la vez no se pisan: la segunda recibe un aviso y recarga).
// ================================================================
const CLAVES_WEB = ['marca', 'catalogo'];
const HISTORIAL_WEB_MAX = 30;
const TIPOS_IMAGEN_WEB = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/svg+xml': 'svg' };
const MAX_BYTES_IMAGEN_WEB = 600 * 1024;
const RE_ID_IMAGEN = /^[0-9a-f]{32}$/;
const RE_ID_SERVICIO = /^[a-z0-9_-]{1,40}$/;

function requiereAdminWeb(req, res, next) {
  if (!req.asesor || !req.asesor.esAdmin) return res.status(403).json({ error: 'Solo un administrador puede cambiar la web pública' });
  next();
}
function textoWeb(v, max) {
  // Sin caracteres de control (salvo saltos de línea); recortado al máximo.
  return typeof v === 'string' ? v.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, '').trim().slice(0, max) : '';
}
function bilingueWeb(v, max) {
  const o = v && typeof v === 'object' ? v : {};
  return { es: textoWeb(o.es, max), en: textoWeb(o.en, max) };
}
function errorWeb(mensaje) { const e = new Error(mensaje); e.esValidacion = true; return e; }

function validarMarcaWeb(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw errorWeb('Formato de marca no válido');
  const logo = d.logo === null || d.logo === undefined || d.logo === '' ? null : String(d.logo);
  if (logo && !RE_ID_IMAGEN.test(logo)) throw errorWeb('Logo no válido');
  const equipo = Array.isArray(d.equipo) ? d.equipo : [];
  if (equipo.length > 12) throw errorWeb('Como mucho 12 personas en el equipo');
  return {
    logo,
    equipo_titulo: bilingueWeb(d.equipo_titulo, 120),
    equipo_subtitulo: bilingueWeb(d.equipo_subtitulo, 300),
    equipo: equipo.map((p, i) => {
      const persona = p && typeof p === 'object' ? p : {};
      const nombre = textoWeb(persona.nombre, 80);
      if (!nombre) throw errorWeb('Falta el nombre de la persona ' + (i + 1));
      const foto = persona.foto ? String(persona.foto) : null;
      if (foto && !RE_ID_IMAGEN.test(foto)) throw errorWeb('Foto no válida en la persona ' + (i + 1));
      const persona_id = Number.isInteger(Number(persona.persona_id)) && Number(persona.persona_id) > 0 ? Number(persona.persona_id) : undefined;
      return { persona_id, nombre, foto, puesto: bilingueWeb(persona.puesto, 120), bio: bilingueWeb(persona.bio, 400) };
    }),
  };
}
function validarCatalogoWeb(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw errorWeb('Formato de catálogo no válido');
  const destacados = Array.isArray(d.destacados) ? [...new Set(d.destacados.map(String))] : [];
  if (destacados.length > 20) throw errorWeb('Demasiados destacados');
  destacados.forEach(id => { if (!RE_ID_SERVICIO.test(id)) throw errorWeb('Servicio no válido: ' + id); });
  const ofertasEntrada = d.ofertas && typeof d.ofertas === 'object' && !Array.isArray(d.ofertas) ? d.ofertas : {};
  const ids = Object.keys(ofertasEntrada);
  if (ids.length > 20) throw errorWeb('Demasiadas ofertas');
  const ofertas = {};
  ids.forEach(id => {
    if (!RE_ID_SERVICIO.test(id)) throw errorWeb('Servicio no válido: ' + id);
    const o = ofertasEntrada[id] || {};
    const descuento = Number(o.descuento);
    if (!Number.isInteger(descuento) || descuento < 1 || descuento > 90) throw errorWeb('El descuento de «' + id + '» tiene que ser un número entero entre 1 y 90');
    const fin = new Date(o.fin);
    if (!o.fin || isNaN(fin.getTime())) throw errorWeb('Falta la fecha de fin de la oferta de «' + id + '»');
    ofertas[id] = { descuento, fin: fin.toISOString() };
  });
  return { destacados, ofertas };
}
async function imagenesExistenWeb(conn, ids) {
  const unicos = [...new Set(ids.filter(Boolean))];
  if (!unicos.length) return true;
  const [filas] = await conn.query('SELECT id FROM web_imagenes WHERE id IN (?)', [unicos]);
  return filas.length === unicos.length;
}
// Guardar una versión nueva (también la usa «restaurar»). Transacción con
// bloqueo de la fila: comprueba la versión de partida, escribe, deja copia
// en el historial y poda las copias más antiguas.
async function guardarContenidoWeb(conn, clave, datos, versionBase, asesorId) {
  await conn.beginTransaction();
  try {
    const [actual] = await conn.execute('SELECT version FROM web_contenido WHERE clave = ? FOR UPDATE', [clave]);
    const versionActual = actual.length ? actual[0].version : 0;
    if (Number(versionBase) !== versionActual) {
      await conn.rollback();
      return { conflicto: true, versionActual };
    }
    const nueva = versionActual + 1;
    const texto = JSON.stringify(datos);
    if (actual.length) {
      await conn.execute('UPDATE web_contenido SET datos = ?, version = ?, actualizado_en = NOW(), actualizado_por_asesor_id = ? WHERE clave = ?', [texto, nueva, asesorId, clave]);
    } else {
      await conn.execute('INSERT INTO web_contenido (clave, datos, version, actualizado_por_asesor_id) VALUES (?,?,?,?)', [clave, texto, nueva, asesorId]);
    }
    await conn.execute('INSERT INTO web_contenido_historial (clave, version, datos, guardado_por_asesor_id) VALUES (?,?,?,?)', [clave, nueva, texto, asesorId]);
    await conn.execute('DELETE FROM web_contenido_historial WHERE clave = ? AND version <= ?', [clave, nueva - HISTORIAL_WEB_MAX]);
    await conn.commit();
    return { version: nueva };
  } catch (err) {
    await conn.rollback();
    throw err;
  }
}
async function validarContenidoWeb(conn, clave, datos) {
  const limpio = clave === 'marca' ? validarMarcaWeb(datos) : validarCatalogoWeb(datos);
  if (clave === 'marca' && !(await imagenesExistenWeb(conn, [limpio.logo, ...limpio.equipo.map(p => p.foto)]))) {
    throw errorWeb('Alguna imagen no está subida. Vuelve a elegirla.');
  }
  return limpio;
}

// --- Público: lo que lee la web ---
app.get('/api/web/contenido', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT clave, datos, version FROM web_contenido');
    const salida = { marca: null, catalogo: null, versiones: {} };
    filas.forEach(f => {
      if (!CLAVES_WEB.includes(f.clave)) return;
      try { salida[f.clave] = JSON.parse(f.datos); salida.versiones[f.clave] = f.version; } catch (e) { /* fila corrupta: se ignora */ }
    });
    // Fase A (10/10): las personas de Inicio se leen al día de la tabla
    // personas (lo que se edite en «Equipo» se ve sin volver a publicar);
    // las desactivadas no salen.
    if (salida.marca && Array.isArray(salida.marca.equipo) && salida.marca.equipo.some(x => x && x.persona_id)) {
      const [pers] = await conn.query('SELECT * FROM personas');
      const porId = {}; pers.forEach(x => { porId[x.id] = x; });
      salida.marca.equipo = salida.marca.equipo.map(x => {
        if (!x || !x.persona_id) return x;
        const q = porId[x.persona_id];
        if (!q || !q.activa) return null;
        return { persona_id: q.id, nombre: q.nombre, foto: q.foto, puesto: { es: q.puesto_es || '', en: q.puesto_en || '' }, bio: { es: q.bio_es || '', en: q.bio_en || '' } };
      }).filter(Boolean);
    }
    res.set('Cache-Control', 'no-cache'); // el navegador revalida siempre (ETag), así los cambios se ven al momento
    res.json(salida);
  } catch (err) {
    console.error('Error al leer el contenido de la web:', err);
    res.status(500).json({ error: 'No se pudo leer el contenido' });
  } finally {
    conn.release();
  }
});
app.get('/api/web/imagen/:id', async (req, res) => {
  const id = String(req.params.id || '').replace(/\.[a-z]+$/, '');
  if (!RE_ID_IMAGEN.test(id)) return res.status(404).end();
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT tipo, datos FROM web_imagenes WHERE id = ?', [id]);
    if (!filas.length) return res.status(404).end();
    // El id es la huella del contenido: una imagen nueva siempre tiene id
    // nuevo, así que esta puede guardarse en caché para siempre.
    res.set('Content-Type', filas[0].tipo);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    if (filas[0].tipo === 'image/svg+xml') res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox");
    res.end(filas[0].datos);
  } catch (err) {
    console.error('Error al servir una imagen de la web:', err);
    res.status(500).end();
  } finally {
    conn.release();
  }
});

// --- Panel (solo administradores) ---
app.get('/api/admin/web', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT w.clave, w.datos, w.version, w.actualizado_en, a.nombre AS actualizado_por
       FROM web_contenido w LEFT JOIN asesores a ON a.id = w.actualizado_por_asesor_id`
    );
    const salida = {};
    CLAVES_WEB.forEach(c => { salida[c] = { datos: null, version: 0, actualizado_en: null, actualizado_por: null }; });
    filas.forEach(f => {
      if (!CLAVES_WEB.includes(f.clave)) return;
      salida[f.clave] = { datos: JSON.parse(f.datos), version: f.version, actualizado_en: f.actualizado_en, actualizado_por: f.actualizado_por };
    });
    res.json(salida);
  } finally {
    conn.release();
  }
});
app.put('/api/admin/web/:clave', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  const clave = req.params.clave;
  if (!CLAVES_WEB.includes(clave)) return res.status(404).json({ error: 'Bloque desconocido' });
  const cuerpo = req.body || {};
  const conn = await pool.getConnection();
  try {
    const limpio = await validarContenidoWeb(conn, clave, cuerpo.datos);
    const r = await guardarContenidoWeb(conn, clave, limpio, cuerpo.version_base, req.asesor.id);
    if (r.conflicto) return res.status(409).json({ error: 'Alguien ha guardado cambios mientras editabas. Recarga para ver la versión actual.', version_actual: r.versionActual });
    res.json({ ok: true, version: r.version, datos: limpio });
  } catch (err) {
    if (err.esValidacion) return res.status(400).json({ error: err.message });
    console.error('Error al guardar el contenido de la web:', err);
    res.status(500).json({ error: 'No se pudo guardar' });
  } finally {
    conn.release();
  }
});
// ================================================================
// Historial de la web pública: qué cambió en cada versión (20/10)
// El panel pintaba solo versión, fecha y autor, y el resumen salía vacío
// hasta pulsar «Ver» (que enseñaba la versión entera, no lo que cambió). Ahora
// cada versión llega con la lista de cambios respecto a la anterior, ya
// estructurada (el panel pone las palabras y los nombres de servicio).
// ================================================================
function cambiosWeb(clave, antes, despues) {
  const a = antes && typeof antes === 'object' ? antes : {}, d = despues && typeof despues === 'object' ? despues : {};
  const cambios = [];
  const igual = (x, y) => JSON.stringify(x === undefined ? null : x) === JSON.stringify(y === undefined ? null : y);
  if (clave === 'marca') {
    const la = a.logo || null, ld = d.logo || null;
    if (la !== ld) cambios.push({ k: !la ? 'logo_pone' : !ld ? 'logo_quita' : 'logo_cambia' });
    const idDe = p => (p && p.persona_id) ? 'p' + p.persona_id : 'n' + (p && p.nombre);
    const ea = new Map((a.equipo || []).map(p => [idDe(p), p])), ed = new Map((d.equipo || []).map(p => [idDe(p), p]));
    for (const [k, p] of ed) if (!ea.has(k)) cambios.push({ k: 'equipo_alta', nombre: p.nombre });
    for (const [k, p] of ea) if (!ed.has(k)) cambios.push({ k: 'equipo_baja', nombre: p.nombre });
    for (const [k, p] of ed) {
      if (!ea.has(k)) continue;
      const q = ea.get(k), campos = [];
      if (p.nombre !== q.nombre) campos.push('nombre');
      if ((p.foto || null) !== (q.foto || null)) campos.push('foto');
      if (!igual(p.puesto, q.puesto)) campos.push('puesto');
      if (!igual(p.bio, q.bio)) campos.push('bio');
      if (campos.length) cambios.push({ k: 'equipo_edita', nombre: p.nombre, campos });
    }
    const comunes = [...ed.keys()].filter(k => ea.has(k)), ordenAntes = [...ea.keys()].filter(k => ed.has(k));
    if (!igual(comunes, ordenAntes)) cambios.push({ k: 'equipo_orden' });
    if (!igual(a.equipo_titulo, d.equipo_titulo) || !igual(a.equipo_subtitulo, d.equipo_subtitulo)) cambios.push({ k: 'equipo_textos' });
  } else {
    const da = new Set(a.destacados || []), dd = new Set(d.destacados || []);
    for (const id of dd) if (!da.has(id)) cambios.push({ k: 'dest_alta', id });
    for (const id of da) if (!dd.has(id)) cambios.push({ k: 'dest_baja', id });
    const oa = a.ofertas || {}, od = d.ofertas || {};
    for (const id of Object.keys(od)) {
      if (!oa[id]) cambios.push({ k: 'oferta_alta', id, descuento: od[id].descuento, fin: od[id].fin });
      else if (oa[id].descuento !== od[id].descuento || oa[id].fin !== od[id].fin) cambios.push({ k: 'oferta_cambia', id, antes: { descuento: oa[id].descuento, fin: oa[id].fin }, despues: { descuento: od[id].descuento, fin: od[id].fin } });
    }
    for (const id of Object.keys(oa)) if (!od[id]) cambios.push({ k: 'oferta_baja', id });
  }
  return cambios.length ? cambios : [{ k: 'sin_cambios' }];
}

app.get('/api/admin/web/:clave/historial', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  if (!CLAVES_WEB.includes(req.params.clave)) return res.status(404).json({ error: 'Bloque desconocido' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT h.version, h.guardado_en, h.datos, a.nombre AS guardado_por
       FROM web_contenido_historial h LEFT JOIN asesores a ON a.id = h.guardado_por_asesor_id
       WHERE h.clave = ? ORDER BY h.version DESC`, [req.params.clave]
    );
    const leer = t => { try { return JSON.parse(t); } catch (e) { return null; } };
    // Cada versión se compara con la inmediatamente anterior; si esa ya se podó (solo se guardan 30), no hay con qué comparar
    res.json(filas.map((f, i) => {
      const previa = filas[i + 1];
      const cambios = f.version === 1 ? [{ k: 'inicial' }] : (previa && previa.version === f.version - 1) ? cambiosWeb(req.params.clave, leer(previa.datos), leer(f.datos)) : null;
      return { version: f.version, guardado_en: f.guardado_en, guardado_por: f.guardado_por, cambios };
    }));
  } finally {
    conn.release();
  }
});
app.get('/api/admin/web/:clave/historial/:version', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  if (!CLAVES_WEB.includes(req.params.clave)) return res.status(404).json({ error: 'Bloque desconocido' });
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT datos FROM web_contenido_historial WHERE clave = ? AND version = ?', [req.params.clave, Number(req.params.version)]);
    if (!filas.length) return res.status(404).json({ error: 'Esa versión ya no está en el historial' });
    res.json({ datos: JSON.parse(filas[0].datos) });
  } finally {
    conn.release();
  }
});
app.post('/api/admin/web/:clave/restaurar', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  const clave = req.params.clave;
  if (!CLAVES_WEB.includes(clave)) return res.status(404).json({ error: 'Bloque desconocido' });
  const cuerpo = req.body || {};
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute('SELECT datos FROM web_contenido_historial WHERE clave = ? AND version = ?', [clave, Number(cuerpo.version)]);
    if (!filas.length) return res.status(404).json({ error: 'Esa versión ya no está en el historial' });
    const limpio = await validarContenidoWeb(conn, clave, JSON.parse(filas[0].datos));
    const r = await guardarContenidoWeb(conn, clave, limpio, cuerpo.version_base, req.asesor.id);
    if (r.conflicto) return res.status(409).json({ error: 'Alguien ha guardado cambios mientras tanto. Recarga y vuelve a intentarlo.', version_actual: r.versionActual });
    res.json({ ok: true, version: r.version, datos: limpio });
  } catch (err) {
    if (err.esValidacion) return res.status(400).json({ error: err.message });
    console.error('Error al restaurar el contenido de la web:', err);
    res.status(500).json({ error: 'No se pudo restaurar' });
  } finally {
    conn.release();
  }
});
// Subida de una imagen (logo o foto), ya reducida en el navegador. Se
// comprueba que el contenido sea de verdad la imagen que dice ser; un SVG
// con código dentro se rechaza (y aun así se sirve con una política que
// impide ejecutar nada). El id es la huella SHA-256: subir dos veces la
// misma imagen no la duplica.
app.post('/api/admin/web/imagen', requiereSesionAsesor, requiereRol('marketing'), async (req, res) => {
  const cuerpo = req.body || {};
  const tipo = String(cuerpo.tipo || '');
  if (!TIPOS_IMAGEN_WEB[tipo]) return res.status(400).json({ error: 'Formato no admitido. Usa JPG, PNG, WebP o SVG.' });
  let buffer;
  try { buffer = Buffer.from(String(cuerpo.datos_base64 || ''), 'base64'); } catch (e) { buffer = null; }
  if (!buffer || !buffer.length) return res.status(400).json({ error: 'La imagen llegó vacía' });
  if (buffer.length > MAX_BYTES_IMAGEN_WEB) return res.status(400).json({ error: 'La imagen pesa demasiado (máximo 600 KB tras reducirla).' });
  const firma = buffer.subarray(0, 12);
  const esJpg = firma[0] === 0xFF && firma[1] === 0xD8 && firma[2] === 0xFF;
  const esPng = firma.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));
  const esWebp = firma.subarray(0, 4).toString('latin1') === 'RIFF' && firma.subarray(8, 12).toString('latin1') === 'WEBP';
  if (tipo === 'image/jpeg' && !esJpg) return res.status(400).json({ error: 'El archivo no es un JPG válido' });
  if (tipo === 'image/png' && !esPng) return res.status(400).json({ error: 'El archivo no es un PNG válido' });
  if (tipo === 'image/webp' && !esWebp) return res.status(400).json({ error: 'El archivo no es un WebP válido' });
  if (tipo === 'image/svg+xml') {
    const texto = buffer.toString('utf8');
    if (!/<svg[\s>]/i.test(texto)) return res.status(400).json({ error: 'El archivo no es un SVG válido' });
    if (/<script|javascript:|<foreignObject|<iframe|<embed|<object|<!ENTITY|\son[a-z]+\s*=/i.test(texto)) {
      return res.status(400).json({ error: 'Ese SVG lleva código o elementos no permitidos. Expórtalo de nuevo como imagen simple.' });
    }
  }
  const id = crypto.createHash('sha256').update(buffer).digest('hex').slice(0, 32);
  const conn = await pool.getConnection();
  try {
    await conn.execute('INSERT IGNORE INTO web_imagenes (id, tipo, datos, bytes, creado_por_asesor_id) VALUES (?,?,?,?,?)', [id, tipo, buffer, buffer.length, req.asesor.id]);
    res.json({ ok: true, id, bytes: buffer.length });
  } catch (err) {
    console.error('Error al guardar una imagen de la web:', err);
    res.status(500).json({ error: 'No se pudo guardar la imagen' });
  } finally {
    conn.release();
  }
});

// ================================================================
// CHAT CLIENTE–ASESOR (06/10)
// Antes solo existía en la maqueta del Área. Un hilo por encargo
// (propuesta) y servicio. El cliente entra con el token de su propuesta,
// como en el resto del Área; el asesor, con su sesión. Cuando el cliente
// escribe: aviso ntfy (sin datos, y como mucho uno cada 5 minutos por
// encargo). Cuando el asesor contesta: correo al cliente con el enlace a
// su área, sin el texto del mensaje.
// ================================================================
const MAX_TEXTO_MENSAJE = 4000;
const ultimoAvisoMensaje = new Map(); // propuesta_id → ms del último aviso
function serviciosDePropuesta(p) {
  let lista; try { lista = JSON.parse(p.servicios); } catch (e) { lista = []; }
  return (Array.isArray(lista) ? lista : []).map(x => typeof x === 'string' ? x : (x && x.id)).filter(Boolean);
}
function servicioDeHilo(p, servicio) {
  const s = String(servicio || '').trim();
  const lista = serviciosDePropuesta(p);
  if (s && (lista.includes(s) || s === 'general')) return s;
  return lista[0] || 'general';
}
function textoMensaje(t) {
  return typeof t === 'string' ? t.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, MAX_TEXTO_MENSAJE) : '';
}

// --- Cliente ---
app.get('/api/propuestas/:token/mensajes', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [filas] = await conn.execute(
      `SELECT m.id, m.servicio, m.autor, m.texto, m.creado_en, m.leido_en, a.nombre AS asesor, m.archivo_nombre, m.archivo_tipo, m.archivo_bytes
       FROM mensajes m LEFT JOIN asesores a ON a.id = m.asesor_id
       WHERE m.propuesta_id = ? AND m.oculto_cliente_en IS NULL AND m.retirado_en IS NULL ORDER BY m.creado_en, m.id`, [p.id]);
    // Al abrir el chat, lo que escribió el asesor queda leído
    await conn.execute("UPDATE mensajes SET leido_en = NOW() WHERE propuesta_id = ? AND autor = 'asesor' AND leido_en IS NULL", [p.id]);
    res.json({ servicios: serviciosDePropuesta(p), mensajes: filas });
  } finally {
    conn.release();
  }
});
app.post('/api/propuestas/:token/mensajes', async (req, res) => {
  const texto = textoMensaje(req.body && req.body.texto);
  if (!texto) return res.status(400).json({ error: 'El mensaje está vacío' });
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (p.estado === 'rechazada' || p.estado === 'caducada') return res.status(409).json({ error: 'Esta propuesta ya no está activa' });
    const servicio = servicioDeHilo(p, req.body.servicio);
    const [r] = await conn.execute(
      "INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, texto) VALUES (?, ?, ?, 'cliente', ?)",
      [p.id, p.cliente_id, servicio, texto]);
    const ahoraMs = Date.now();
    if (ahoraMs - (ultimoAvisoMensaje.get(p.id) || 0) > 5 * 60 * 1000) {
      ultimoAvisoMensaje.set(p.id, ahoraMs);
      avisarCliente(p.cliente_id, '💬', 'un cliente te ha escrito', 'Contéstale desde «Mensajes sin leer» en el panel.', { prioridad: 4, etiqueta: 'speech_balloon' });
    }
    res.status(201).json({ ok: true, id: r.insertId, servicio });
  } finally {
    conn.release();
  }
});
app.delete('/api/propuestas/:token/mensajes/:id', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [r] = await conn.execute("UPDATE mensajes SET oculto_cliente_en = NOW() WHERE id = ? AND propuesta_id = ? AND autor = 'cliente' AND oculto_cliente_en IS NULL", [Number(req.params.id), p.id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solo puedes ocultar tus propios mensajes' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});

// --- Asesor ---
app.get('/api/admin/mensajes/sin-leer', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.query(
      `SELECT m.propuesta_id, m.servicio, c.id AS cliente_id, c.nombre, c.apellidos, c.correo,
              COUNT(*) AS sin_leer, MAX(m.creado_en) AS ultimo,
              SUBSTRING((SELECT m2.texto FROM mensajes m2 WHERE m2.propuesta_id = m.propuesta_id AND m2.servicio = m.servicio
                         AND m2.autor = 'cliente' ORDER BY m2.creado_en DESC, m2.id DESC LIMIT 1), 1, 140) AS extracto
       FROM mensajes m JOIN clientes c ON c.id = m.cliente_id
       WHERE m.autor = 'cliente' AND m.leido_en IS NULL
       GROUP BY m.propuesta_id, m.servicio, c.id, c.nombre, c.apellidos, c.correo
       ORDER BY ultimo DESC`);
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.get('/api/admin/clientes/:id/mensajes', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute(
      `SELECT m.id, m.propuesta_id, m.servicio, m.autor, m.texto, m.creado_en, m.leido_en, m.asesor_id, a.nombre AS asesor, m.archivo_nombre, m.archivo_tipo, m.archivo_bytes,
              m.oculto_cliente_en, m.retirado_en, ar.nombre AS retirado_por_nombre
       FROM mensajes m LEFT JOIN asesores a ON a.id = m.asesor_id LEFT JOIN asesores ar ON ar.id = m.retirado_por
       WHERE m.cliente_id = ? ORDER BY m.creado_en, m.id`, [Number(req.params.id)]);
    res.json(filas);
  } finally {
    conn.release();
  }
});
app.post('/api/admin/propuestas/:id/mensajes/leidos', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const servicio = req.body && req.body.servicio ? String(req.body.servicio) : null;
    await conn.execute(
      "UPDATE mensajes SET leido_en = NOW() WHERE propuesta_id = ? AND autor = 'cliente' AND leido_en IS NULL" + (servicio ? ' AND servicio = ?' : ''),
      servicio ? [Number(req.params.id), servicio] : [Number(req.params.id)]);
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
app.post('/api/admin/propuestas/:id/mensajes', requiereSesionAsesor, async (req, res) => {
  const texto = textoMensaje(req.body && req.body.texto) || '';
  const adj = req.body && req.body.archivo;
  if (!texto && !adj) return res.status(400).json({ error: 'El mensaje está vacío' });
  const archivo = adj ? validarAdjuntoChat(adj) : null;   // 29/10: archivo adjunto
  if (archivo && archivo.error) return res.status(archivo.error[0]).json({ error: archivo.error[1] });
  const conn = await pool.getConnection();
  try {
    const [ps] = await conn.execute('SELECT p.*, c.correo FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.id = ?', [Number(req.params.id)]);
    if (!ps.length) return res.status(404).json({ error: 'Encargo no encontrado' });
    const p = ps[0];
    const servicio = servicioDeHilo(p, req.body.servicio);
    const [r] = await conn.execute(
      "INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, asesor_id, texto) VALUES (?, ?, ?, 'asesor', ?, ?)",
      [p.id, p.cliente_id, servicio, req.asesor.id, texto]);
    if (archivo) {
      const clave = `entregas/chat/${p.id}/${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${archivo.ext}`;
      await subirAR2(clave, archivo.buffer, archivo.tipo);
      await conn.execute('UPDATE mensajes SET archivo_clave = ?, archivo_nombre = ?, archivo_tipo = ?, archivo_bytes = ? WHERE id = ?', [clave, archivo.nombre, archivo.tipo, archivo.buffer.length, r.insertId]);
    }
    if (req.body && req.body.ia && req.body.ia.borrador) await conn.execute('UPDATE mensajes SET ia_borrador = 1, ia_cambio_pct = ? WHERE id = ?', [Math.max(0, Math.min(100, Math.round(Number(req.body.ia.cambio_pct) || 0))), r.insertId]);   // 29/10
    // Contestar implica haber leído lo del cliente en ese hilo
    await conn.execute("UPDATE mensajes SET leido_en = NOW() WHERE propuesta_id = ? AND servicio = ? AND autor = 'cliente' AND leido_en IS NULL", [p.id, servicio]);
    // El correo de aviso ya no sale al momento (06/10): lo envía la tarea
    // de avisos cuando lleváis un rato sin escribirle y él no lo ha leído,
    // así tres mensajes seguidos = un solo correo.
    const correo = p.correo ? 'programado' : 'sin_correo';
    res.status(201).json({ ok: true, id: r.insertId, servicio, correo, minutos_aviso: Math.round(SEGUNDOS_AVISO_CHAT / 60) });
  } finally {
    conn.release();
  }
});
app.delete('/api/admin/mensajes/:id', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.execute("UPDATE mensajes SET retirado_en = NOW(), retirado_por = ? WHERE id = ? AND autor = 'asesor' AND retirado_en IS NULL", [req.asesor.id, Number(req.params.id)]);
    if (!r.affectedRows) return res.status(404).json({ error: 'Solo se pueden retirar mensajes del asesor' });
    res.json({ ok: true });
  } finally {
    conn.release();
  }
});
// =====================================================================
// IA (16/10, Vikn) — apoyo para el asesor con la API de Claude
// ---------------------------------------------------------------------
// Capa OPCIONAL: sin ANTHROPIC_API_KEY, apagada desde el panel, sin
// créditos o con el tope del mes alcanzado, los botones de IA no aparecen
// y todo funciona como siempre. La clave vive solo en Railway.
// Datos: a la IA nunca le llegan nombre, correo, teléfono, documento,
// IBAN ni direcciones de monederos (seudonimizarTexto); los documentos del
// cliente no se leen (siguen cifrados). En la base de datos solo quedan
// métricas de uso (ia_uso), nunca los textos.
// Variables: ANTHROPIC_API_KEY (obligatoria para usarla),
// IA_MODELO_BORRADOR (por defecto claude-sonnet-5-5).
// =====================================================================
const IA_CLAVE = (process.env.ANTHROPIC_API_KEY || '').trim();
const IA_URL = (process.env.IA_URL || 'https://api.anthropic.com/v1/messages').trim();   // solo se cambia para pruebas
const IA_MODELO_BORRADOR = (process.env.IA_MODELO_BORRADOR || 'claude-sonnet-5-5').trim();
const IA_MODELO_ASISTENTE = (process.env.IA_MODELO_ASISTENTE || 'claude-sonnet-5-5').trim();   // 19/10: Asistente Acros (chat interno)
const IA_MAX_CONOCIMIENTO = 30000;
const IA_PRECIO_BUSQUEDA_MICRO = 10000;   // búsqueda web: 10 $ por 1.000 = 0,01 $ (en micro-dólares)   // caracteres de «Instrucciones y conocimiento de Acros»
// Dólares por millón de tokens (entrada, salida). Si cambian, IA_PRECIOS='{"modelo":[ent,sal]}'.
const IA_PRECIOS = Object.assign({ 'claude-sonnet-5-5': [2, 10], 'claude-haiku-5-5': [0.10, 0.50] },
  (() => { try { return JSON.parse(process.env.IA_PRECIOS || '{}'); } catch (e) { return {}; } })());
const IA_TOPE_POR_DEFECTO = 60;   // USD/mes; los créditos del plan Max son 100
let iaUltimaAlerta = 0;

async function iaAjustes() {
  const a = { activa: true, borradores: true, asistente: true, web: true, tope_usd: IA_TOPE_POR_DEFECTO, conocimiento: '', conocimiento_anterior: null };
  try {
    const [f] = await pool.execute("SELECT clave, valor FROM ajustes WHERE clave IN ('ia_activa','ia_borradores','ia_asistente','ia_web','ia_tope_usd','ia_conocimiento','ia_conocimiento_anterior')");
    f.forEach(x => {
      if (x.clave === 'ia_activa') a.activa = x.valor !== '0';
      if (x.clave === 'ia_borradores') a.borradores = x.valor !== '0';
      if (x.clave === 'ia_asistente') a.asistente = x.valor !== '0';
      if (x.clave === 'ia_web') a.web = x.valor !== '0';
      if (x.clave === 'ia_conocimiento') a.conocimiento = x.valor || '';
      if (x.clave === 'ia_conocimiento_anterior') a.conocimiento_anterior = x.valor;
      if (x.clave === 'ia_tope_usd') { const n = Number(x.valor); if (Number.isFinite(n) && n >= 0) a.tope_usd = n; }
    });
  } catch (e) { /* sin tabla aún */ }
  return a;
}
async function iaGastoMes() {
  try {
    const [f] = await pool.execute("SELECT COALESCE(SUM(`coste_micro_usd`),0) AS c, COUNT(*) AS n, COALESCE(SUM(`ok` = 0),0) AS e FROM ia_uso WHERE `creado_en` >= DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-01')");
    return { usd: Number(f[0].c) / 1e6, llamadas: Number(f[0].n), errores: Number(f[0].e) };
  } catch (e) { return { usd: 0, llamadas: 0, errores: 0 }; }
}
// ¿Se puede usar ahora mismo esta función? Devuelve null si sí, o el motivo.
async function iaMotivoNo(funcion) {
  if (!IA_CLAVE) return 'La IA no está configurada';
  const a = await iaAjustes();
  if (!a.activa) return 'La IA está apagada';
  if (funcion === 'borrador' && !a.borradores) return 'Los borradores con IA están apagados';
  if (funcion === 'asistente' && !a.asistente) return 'El Asistente Acros está apagado';
  const g = await iaGastoMes();
  if (g.usd >= a.tope_usd) return 'Se ha alcanzado el tope de IA de este mes';
  return null;
}
async function iaRegistrar(d) {
  try {
    await pool.execute('INSERT INTO ia_uso (`funcion`, `persona_id`, `cliente_id`, `modelo`, `tokens_entrada`, `tokens_salida`, `coste_micro_usd`, `ok`, `error`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [d.funcion, d.persona_id || null, d.cliente_id || null, d.modelo, d.ent || 0, d.sal || 0, d.coste || 0, d.ok ? 1 : 0, d.error ? String(d.error).slice(0, 200) : null]);
  } catch (e) { console.error('No se pudo registrar el uso de IA:', e.message); }
}
// Una llamada a la API de mensajes. Lanza Error con .publico (texto para el panel).
async function iaLlamar({ funcion, modelo, sistema, mensajes, maxTokens, personaId, clienteId, herramientas, completo }) {
  const fallo = (publico, tecnico) => { const e = new Error(tecnico || publico); e.publico = publico; return e; };
  let r;
  try {
    r = await axios.post(IA_URL, Object.assign({ model: modelo, max_tokens: maxTokens || 700, system: sistema, messages: mensajes }, herramientas ? { tools: herramientas } : {}),
      { timeout: 45000, headers: { 'x-api-key': IA_CLAVE, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, validateStatus: () => true });
  } catch (e) {
    await iaRegistrar({ funcion, persona_id: personaId, cliente_id: clienteId, modelo, ok: false, error: 'red: ' + e.message });
    throw fallo('La IA no responde ahora mismo. Escribe la respuesta como siempre.', e.message);
  }
  const cuerpo = r.data || {};
  if (r.status !== 200) {
    const msg = (cuerpo.error && cuerpo.error.message) || ('HTTP ' + r.status);
    await iaRegistrar({ funcion, persona_id: personaId, cliente_id: clienteId, modelo, ok: false, error: r.status + ': ' + msg });
    const sinCredito = /credit|balance|billing/i.test(msg);
    if ((r.status === 401 || r.status === 403 || sinCredito) && Date.now() - iaUltimaAlerta > 6 * 3600e3) {
      iaUltimaAlerta = Date.now();
      avisarAlerta('✨ IA sin servicio', sinCredito ? 'Se han agotado los créditos de la API de Claude. Los botones de IA seguirán fallando hasta el próximo ciclo; el panel funciona igual.' : 'La clave ANTHROPIC_API_KEY de Railway no es válida o fue revocada.', { prioridad: 4, etiqueta: 'warning' });
    }
    if (sinCredito) throw fallo('Se han agotado los créditos de IA de este mes. Escribe la respuesta como siempre.', msg);
    if (r.status === 429 || r.status === 529 || r.status >= 500) throw fallo('La IA está saturada. Prueba otra vez en un momento.', msg);
    throw fallo('La IA no está disponible ahora mismo.', msg);
  }
  const texto = (cuerpo.content || []).filter(b => b.type === 'text').map(b => b.text).join('').trim();
  const u = cuerpo.usage || {}, precio = IA_PRECIOS[modelo] || [0, 0];
  const ent = (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0), sal = u.output_tokens || 0;
  const busquedas = Number((u.server_tool_use && u.server_tool_use.web_search_requests) || 0);
  const coste = Math.round(ent * precio[0] + sal * precio[1]) + busquedas * IA_PRECIO_BUSQUEDA_MICRO;   // tokens × $/MTok = micro-dólares
  await iaRegistrar({ funcion, persona_id: personaId, cliente_id: clienteId, modelo, ent, sal, coste, ok: true });
  return completo ? { texto, cuerpo, busquedas } : texto;
}
// Quita lo que identifica al cliente antes de mandar nada a la IA.
function seudonimizarTexto(t, cli) {
  let s = String(t || '');
  const esc = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // datos propios del cliente (exactos), del más largo al más corto
  const propios = [];
  if (cli) {
    if (cli.correo) propios.push([cli.correo, '[correo]']);
    if (cli.numero_documento) propios.push([cli.numero_documento, '[documento]']);
    [cli.nombre, cli.apellidos].filter(Boolean).join(' ').split(/\s+/).filter(w => w.length >= 3).forEach(w => propios.push([w, '[nombre]']));
  }
  propios.sort((a, b) => b[0].length - a[0].length).forEach(([v, r]) => { s = s.replace(new RegExp('(?<![\\p{L}\\d])' + esc(v) + '(?![\\p{L}\\d])', 'giu'), r); });
  s = s.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[correo]')
    .replace(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g, '[IBAN]')
    .replace(/\b0x[a-fA-F0-9]{40,64}\b/g, '[dirección o hash]')
    .replace(/\b(?:bc1|tb1)[a-z0-9]{20,80}\b/gi, '[dirección]')
    .replace(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, '[dirección]')
    .replace(/\b[TX][a-km-zA-HJ-NP-Z1-9]{33}\b/g, '[dirección]')
    .replace(/\b[XYZ]?\d{7,8}[-\s]?[A-Z]\b/gi, '[documento]')
    .replace(/(?:\+|00)\d[\d\s.-]{7,16}\d|\b[6789]\d{2}[\s.-]?\d{2,3}[\s.-]?\d{2,3}(?:[\s.-]?\d{1,3})?\b/g, m => (m.replace(/\D/g, '').length >= 9 ? '[teléfono]' : m));
  return s;
}
const IA_SISTEMA_BORRADOR = [
  'Eres el asistente de redacción de los asesores de Acros, una asesoría fiscal española especializada en criptoactivos (particulares y empresas).',
  'Tu tarea: redactar un BORRADOR de respuesta al último mensaje del cliente en el chat de su área privada. Un asesor lo revisará y corregirá antes de enviarlo; tú nunca hablas directamente con el cliente.',
  'Estilo: tutea al cliente, tono cercano y profesional, frases cortas, sin tecnicismos innecesarios. Breve: lo justo para responder (normalmente 2-6 frases). Sin saludos largos ni despedidas formales, sin firma.',
  'Nunca inventes datos, importes, plazos, fechas ni conclusiones fiscales sobre su caso concreto. Si para responder hace falta algo que no está en el contexto, deja un hueco así: [COMPLETAR: qué falta], para que el asesor lo rellene.',
  'No prometas resultados ante Hacienda. Si la respuesta depende de revisar su documentación, dilo con naturalidad («lo reviso y te digo»).',
  'Los datos identificativos vienen sustituidos por marcadores como [nombre], [correo] o [documento]. No intentes adivinarlos; si quieres dirigirte al cliente por su nombre, escribe [nombre].',
  'Responde solo con el texto del mensaje, sin comillas, sin explicaciones y sin encabezados. Escribe en el mismo idioma que use el cliente.'
].join('\n');

app.get('/api/admin/ia/estado', requiereSesionAsesor, async (req, res) => {
  const motivo = await iaMotivoNo('borrador'), motivoAs = await iaMotivoNo('asistente');
  res.json({ configurada: !!IA_CLAVE, borradores: !motivo, asistente: !motivoAs, motivo: motivo || null, motivo_asistente: motivoAs || null });
});
app.get('/api/admin/ia/ajustes', requiereSesionAsesor, requiereRol('admin'), async (req, res) => {
  const a = await iaAjustes(), g = await iaGastoMes();
  let porFuncion = [], ultimos = [];
  try {
    [porFuncion] = await pool.execute("SELECT `funcion`, COUNT(*) AS llamadas, COALESCE(SUM(`coste_micro_usd`),0) AS coste, COALESCE(SUM(`ok`=0),0) AS errores FROM ia_uso WHERE `creado_en` >= DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-01') GROUP BY `funcion`");
    [ultimos] = await pool.execute('SELECT u.`creado_en`, u.`funcion`, u.`modelo`, u.`tokens_entrada`, u.`tokens_salida`, u.`coste_micro_usd`, u.`ok`, u.`error`, p.`nombre` AS persona FROM ia_uso u LEFT JOIN asesores p ON p.`id` = u.`persona_id` ORDER BY u.`id` DESC LIMIT 15');
  } catch (e) { /* tabla aún vacía */ }
  res.json({ configurada: !!IA_CLAVE, modelo_borrador: IA_MODELO_BORRADOR, modelo_asistente: IA_MODELO_ASISTENTE, activa: a.activa, borradores: a.borradores, asistente: a.asistente, web: a.web, tope_usd: a.tope_usd,
    conocimiento: a.conocimiento, hay_conocimiento_anterior: a.conocimiento_anterior !== null, max_conocimiento: IA_MAX_CONOCIMIENTO,
    mes: { gasto_usd: g.usd, llamadas: g.llamadas, errores: g.errores, por_funcion: porFuncion.map(x => ({ funcion: x.funcion, llamadas: Number(x.llamadas), gasto_usd: Number(x.coste) / 1e6, errores: Number(x.errores) })) },
    ultimos: ultimos.map(x => ({ creado_en: x.creado_en, funcion: x.funcion, modelo: x.modelo, tokens_entrada: x.tokens_entrada, tokens_salida: x.tokens_salida, gasto_usd: Number(x.coste_micro_usd) / 1e6, ok: !!x.ok, error: x.error, persona: x.persona })) });
});
app.put('/api/admin/ia/ajustes', requiereSesionAsesor, requiereRol('admin'), async (req, res) => {
  const b = req.body || {}, filas = [];
  if (typeof b.activa === 'boolean') filas.push(['ia_activa', b.activa ? '1' : '0']);
  if (typeof b.borradores === 'boolean') filas.push(['ia_borradores', b.borradores ? '1' : '0']);
  if (typeof b.asistente === 'boolean') filas.push(['ia_asistente', b.asistente ? '1' : '0']);
  if (typeof b.web === 'boolean') filas.push(['ia_web', b.web ? '1' : '0']);
  // 19/10: «Instrucciones y conocimiento de Acros». Se guarda la versión anterior para poder deshacer.
  if (typeof b.conocimiento === 'string' || b.deshacer_conocimiento) {
    const a = await iaAjustes();
    let nuevo = b.deshacer_conocimiento ? a.conocimiento_anterior : b.conocimiento.replace(/\r\n/g, '\n').trim();
    if (nuevo === null) return res.status(400).json({ error: 'No hay ninguna versión anterior' });
    if (nuevo.length > IA_MAX_CONOCIMIENTO) return res.status(400).json({ error: 'El texto es demasiado largo (máximo ' + IA_MAX_CONOCIMIENTO + ' caracteres)' });
    if (nuevo !== a.conocimiento) { filas.push(['ia_conocimiento_anterior', a.conocimiento]); filas.push(['ia_conocimiento', nuevo]); }
  }
  if (b.tope_usd !== undefined) {
    const n = Number(b.tope_usd);
    if (!Number.isFinite(n) || n < 0 || n > 1000) return res.status(400).json({ error: 'El tope debe ser un número entre 0 y 1000' });
    filas.push(['ia_tope_usd', String(Math.round(n * 100) / 100)]);
  }
  for (const [k, v] of filas) await pool.execute('INSERT INTO ajustes (clave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)', [k, v]);
  res.json({ ok: true });
});
// Instrucciones fijas + las del despacho (editables en Sistema → IA). Se envían con
// caché: el texto largo de conocimiento solo se cobra entero la primera vez.
function iaSistemaCon(base, conocimiento) {
  const bloques = [{ type: 'text', text: base }];
  if (conocimiento && conocimiento.trim()) bloques.push({ type: 'text', text: 'INSTRUCCIONES Y CONOCIMIENTO DE ACROS (escritas por el despacho; si chocan con lo anterior en estilo o criterio, mandan estas, salvo las reglas sobre no inventar datos y sobre datos personales):\n\n' + conocimiento.trim() });
  bloques[bloques.length - 1].cache_control = { type: 'ephemeral' };
  return bloques;
}
const IA_SISTEMA_ASISTENTE = [
  'Eres «Asistente Acros», el asistente interno del equipo de Acros, una asesoría fiscal española especializada en criptoactivos (IRPF, modelo 721, origen de fondos, certificados de valoración, informes de pérdidas y ganancias, empresas con criptoactivos). Hablas con asesores y personal del despacho, nunca con clientes.',
  'Ayudas con: dudas de fiscalidad española de criptoactivos y su aplicación práctica; redacción de textos (correos y explicaciones para clientes, publicaciones); procedimientos internos y uso del panel cuando te los hayan explicado en las instrucciones; y revisión de razonamientos.',
  'Solo atiendes temas de Acros: fiscalidad (sobre todo de criptoactivos), los clientes y el trabajo del despacho, el uso del panel y textos para el despacho. Si te preguntan otra cosa (cultura general, datos de población, deportes, recetas, programación ajena al despacho…), dilo en una frase («Solo puedo ayudarte con temas del despacho») y no la contestes, aunque la sepas.',
  'Estilo: español (o el idioma en que te escriban), directo y concreto. Usa Markdown sencillo (listas, **negritas**) solo cuando ayude a leer.',
  'Fiscalidad: distingue lo que dice la norma, lo que es criterio administrativo (consultas vinculantes de la DGT, doctrina del TEAC) y lo que es interpretación. Cita la norma o la consulta solo si estás seguro de ella. No inventes cifras, plazos, tipos ni números de consulta. El criterio final es siempre del asesor.',
  'Datos personales: los datos identificativos que te lleguen vienen sustituidos por marcadores como [correo], [documento] o [IBAN]; no intentes reconstruirlos. Si alguien pega datos de un cliente, recuérdale en una frase que no hace falta para que puedas ayudar.'
].join('\n');
const IA_ASISTENTE_SIN_WEB = 'No puedes consultar internet y tu conocimiento tiene fecha de corte: avisa cuando algo pueda haber cambiado.';
const IA_ASISTENTE_CON_WEB = [
  'Puedes buscar en internet con la herramienta web_search. Úsala cuando algo pueda haber cambiado o haya que confirmarlo (normativa, plazos, tipos, criterios recientes, consultas de la DGT, novedades de exchanges); para lo que sabes con seguridad, no hace falta.',
  'Prefiere siempre fuentes oficiales: boe.es, agenciatributaria.es y sede.agenciatributaria.gob.es, petete.tributos.hacienda.gob.es (consultas de la DGT), hacienda.gob.es, eur-lex.europa.eu, cnmv.es, bde.es. Después, despachos y publicaciones profesionales reconocidas. Evita foros y blogs anónimos; si no hay otra cosa, dilo.',
  'Di de dónde sale cada dato importante. No busques información sobre personas concretas.'
].join(' ');
const IA_HERRAMIENTA_WEB = { type: 'web_search_20250305', name: 'web_search', max_uses: 5, user_location: { type: 'approximate', country: 'ES', city: 'Madrid', region: 'Madrid', timezone: 'Europe/Madrid' } };
// Fuentes citadas en la respuesta (enlaces únicos, como mucho 8)
function iaFuentes(cuerpo) {
  const vistas = new Map();
  (cuerpo.content || []).forEach(b => (b.type === 'text' && Array.isArray(b.citations) ? b.citations : []).forEach(c => {
    if (c && c.url && /^https?:\/\//.test(c.url) && !vistas.has(c.url)) vistas.set(c.url, String(c.title || '').slice(0, 140));
  }));
  return [...vistas].slice(0, 8).map(([url, titulo]) => ({ url, titulo }));
}
// =====================================================================
// HERRAMIENTAS DEL ASISTENTE SOBRE EL PANEL (19/10, Vikn)
// La IA puede consultar chats y equipo. Reglas:
//  1) Solo ve los clientes que ve quien pregunta (mismo cálculo que el
//     panel: rol + «Ver» de la cabecera x-ambito).
//  2) A Anthropic no le llegan nombres: cada cliente va como su código
//     (clientes.codigo) y los textos pasan por seudonimizarTexto. El
//     panel cambia el código por el nombre al enseñar la respuesta.
// =====================================================================
const IA_HERRAMIENTAS_PANEL = [
  { name: 'chats_esperando_respuesta', description: 'Conversaciones del chat en las que el cliente ha escrito y nadie del despacho le ha contestado todavía (el último mensaje es del cliente). Devuelve, de más antiguo a más reciente, el código del cliente, su asesor, el servicio, desde cuándo espera, cuántos mensajes sin contestar y un extracto del último.',
    input_schema: { type: 'object', properties: { asesor: { type: 'string', description: 'Opcional: nombre (o parte) del asesor para filtrar' }, limite: { type: 'integer', description: 'Máximo de resultados (por defecto 30)' } } } },
  { name: 'clientes_sin_contestarnos', description: 'Conversaciones en las que el despacho escribió lo último y el cliente no ha respondido. Devuelve, de más días a menos, el código del cliente, su asesor, el servicio, cuántos días lleva sin contestar, si ha leído nuestro último mensaje y un extracto de ese mensaje.',
    input_schema: { type: 'object', properties: { asesor: { type: 'string', description: 'Opcional: nombre (o parte) del asesor para filtrar' }, dias_minimos: { type: 'integer', description: 'Opcional: solo los que llevan al menos estos días' }, limite: { type: 'integer', description: 'Máximo de resultados (por defecto 30)' } } } },
  { name: 'mensajes_de_clientes', description: 'Mensajes que han escrito los clientes en el chat en un periodo, para analizar de qué preguntan o de qué se quejan. Puede filtrarse por asesor. Devuelve los más recientes primero (texto recortado y sin datos identificativos) y el total del periodo.',
    input_schema: { type: 'object', properties: { dias: { type: 'integer', description: 'Últimos N días (por defecto 30, máximo 365)' }, asesor: { type: 'string', description: 'Opcional: nombre (o parte) del asesor' }, maximo: { type: 'integer', description: 'Máximo de mensajes (por defecto 150, máximo 300)' } } } },
  { name: 'equipo', description: 'Personas del despacho que atienden clientes (las que puede ver quien pregunta): nombre, equipo y cuántos clientes y conversaciones pendientes tiene cada una.',
    input_schema: { type: 'object', properties: {} } }
];
const sinAcentos = t => String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const recorte = (t, n) => { t = String(t || '').replace(/\s+/g, ' ').trim(); return t.length > n ? t.slice(0, n) + '…' : t; };
async function iaAlcance(req) {
  // el «Ver» de la cabecera también vale aquí aunque la petición sea POST
  return clientesPermitidos({ method: 'GET', get: n => req.get(n), asesor: req.asesor });
}
// Hilos (encargo + servicio) visibles, con sus mensajes (máx. un año)
async function iaHilos(permitidos, filtroAsesor) {
  const [ms] = await pool.query(
    "SELECT m.id, m.propuesta_id, m.servicio, m.cliente_id, m.autor, m.texto, m.leido_en, m.creado_en, " +
    "c.codigo, c.nombre AS c_nombre, c.apellidos AS c_apellidos, c.correo AS c_correo, c.numero_documento AS c_documento, q.nombre AS asesor " +
    "FROM mensajes m JOIN clientes c ON c.id = m.cliente_id LEFT JOIN personas q ON q.id = c.asesor_persona_id " +
    "WHERE m.retirado_en IS NULL AND m.creado_en >= UTC_TIMESTAMP() - INTERVAL 365 DAY ORDER BY m.creado_en, m.id LIMIT 20000");
  const f = filtroAsesor ? sinAcentos(filtroAsesor) : '';
  const hilos = new Map();
  for (const m of ms) {
    if (permitidos && !permitidos.has(m.cliente_id)) continue;
    if (f && !sinAcentos(m.asesor).includes(f)) continue;
    const k = m.propuesta_id + '|' + m.servicio;
    if (!hilos.has(k)) hilos.set(k, { cliente_id: m.cliente_id, codigo: m.codigo || ('C' + m.cliente_id), asesor: m.asesor || 'sin asignar', servicio: m.servicio, cli: { nombre: m.c_nombre, apellidos: m.c_apellidos, correo: m.c_correo, numero_documento: m.c_documento }, mensajes: [] });
    hilos.get(k).mensajes.push(m);
  }
  return [...hilos.values()];
}
const horasDesde = d => Math.round((Date.now() - new Date(d).getTime()) / 36e5);
async function iaEjecutarHerramienta(nombre, entrada, req, usados) {
  const permitidos = await iaAlcance(req), e = entrada || {};
  const apunta = h => { usados.set(h.codigo, h.cliente_id); };
  if (nombre === 'chats_esperando_respuesta' || nombre === 'clientes_sin_contestarnos') {
    const hilos = await iaHilos(permitidos, e.asesor), filas = [];
    for (const h of hilos) {
      const ult = h.mensajes[h.mensajes.length - 1];
      if (nombre === 'chats_esperando_respuesta' && ult.autor === 'cliente') {
        let i = h.mensajes.length - 1; while (i > 0 && h.mensajes[i - 1].autor === 'cliente') i--;
        filas.push({ codigo: h.codigo, asesor: h.asesor, servicio: h.servicio, esperando_desde: h.mensajes[i].creado_en, horas_esperando: horasDesde(h.mensajes[i].creado_en), mensajes_sin_contestar: h.mensajes.length - i, ultimo_mensaje: recorte(seudonimizarTexto(ult.texto, h.cli), 300) });
      }
      if (nombre === 'clientes_sin_contestarnos' && ult.autor === 'asesor') {
        const dias = Math.floor(horasDesde(ult.creado_en) / 24);
        if (e.dias_minimos && dias < Number(e.dias_minimos)) continue;
        filas.push({ codigo: h.codigo, asesor: h.asesor, servicio: h.servicio, nuestro_ultimo_mensaje: ult.creado_en, dias_sin_contestar: dias, lo_ha_leido: !!ult.leido_en, extracto: recorte(seudonimizarTexto(ult.texto, h.cli), 200) });
      }
    }
    filas.sort((a, b) => nombre === 'chats_esperando_respuesta' ? b.horas_esperando - a.horas_esperando : b.dias_sin_contestar - a.dias_sin_contestar);
    const lim = Math.min(100, Math.max(1, Number(e.limite) || 30)), sel = filas.slice(0, lim);
    sel.forEach(x => apunta(hilos.find(h => h.codigo === x.codigo)));
    return { total: filas.length, mostrados: sel.length, ahora: new Date().toISOString(), resultados: sel };
  }
  if (nombre === 'mensajes_de_clientes') {
    const dias = Math.min(365, Math.max(1, Number(e.dias) || 30)), max = Math.min(300, Math.max(1, Number(e.maximo) || 150));
    const desde = Date.now() - dias * 864e5, lista = [];
    for (const h of await iaHilos(permitidos, e.asesor)) h.mensajes.forEach(m => { if (m.autor === 'cliente' && new Date(m.creado_en).getTime() >= desde) lista.push({ h, m }); });
    lista.sort((a, b) => new Date(b.m.creado_en) - new Date(a.m.creado_en));
    const sel = lista.slice(0, max);
    sel.forEach(x => apunta(x.h));
    return { periodo_dias: dias, total: lista.length, mostrados: sel.length, mensajes: sel.map(x => ({ codigo: x.h.codigo, asesor: x.h.asesor, servicio: x.h.servicio, fecha: x.m.creado_en, texto: recorte(seudonimizarTexto(x.m.texto, x.h.cli), 400) })) };
  }
  if (nombre === 'equipo') {
    const [ps] = await pool.query('SELECT q.id, q.nombre, e.nombre AS equipo FROM personas q LEFT JOIN equipos e ON e.id = q.equipo_id WHERE q.activa = 1 AND q.atiende_clientes = 1 ORDER BY q.nombre');
    const [cs] = await pool.query('SELECT id, asesor_persona_id FROM clientes');
    const hilos = await iaHilos(permitidos, null);
    const res = ps.map(q => {
      const suyos = cs.filter(c => c.asesor_persona_id === q.id && (!permitidos || permitidos.has(c.id)));
      const pend = hilos.filter(h => h.asesor === q.nombre && h.mensajes[h.mensajes.length - 1].autor === 'cliente').length;
      return { nombre: q.nombre, equipo: q.equipo || null, clientes: suyos.length, chats_esperando_respuesta: pend };
    }).filter(x => !permitidos || x.clientes > 0);
    return { personas: res };
  }
  return { error: 'Herramienta desconocida' };
}
const IA_ASISTENTE_CON_PANEL = 'Tienes herramientas para consultar el panel de Acros (chats, equipo, servicios con sus plazos y si su año está sin confirmar, propuestas sin respuesta, pagos por confirmar, documentos y altas). Si para contestar te falta algo que no está en ellas, dilo claramente en vez de suponerlo. Úsalas cuando te pregunten por clientes, conversaciones o asesores; no te lo inventes. Los clientes aparecen con un código (por ejemplo LF19J6Z8XE): menciónalos siempre por ese código exacto, tal cual, sin añadir nombres; el panel lo cambiará por el nombre al enseñárselo a la persona. Solo ves los clientes que puede ver quien pregunta: si algo no aparece, puede ser por eso. Las fechas vienen en UTC; habla en hora de España.';
const IA_ASISTENTE_LIMITE_HORA = 60;
const iaAsistenteUso = new Map();   // asesor id → marcas de tiempo (última hora)
app.post('/api/admin/ia/asistente', requiereSesionAsesor, async (req, res) => {
  const motivo = await iaMotivoNo('asistente');
  if (motivo) return res.status(503).json({ error: motivo, sin_ia: true });
  const lista = Array.isArray(req.body && req.body.mensajes) ? req.body.mensajes : [];
  const limpios = lista.slice(-20).map(m => ({ role: m && m.role === 'assistant' ? 'assistant' : 'user', content: String((m && m.content) || '').slice(0, 8000) })).filter(m => m.content.trim());
  if (!limpios.length || limpios[limpios.length - 1].role !== 'user') return res.status(400).json({ error: 'Falta tu pregunta' });
  while (limpios.length && limpios[0].role !== 'user') limpios.shift();   // la API exige empezar por el usuario
  const yo = req.asesor && req.asesor.id, ahora = Date.now();
  const marcas = (iaAsistenteUso.get(yo) || []).filter(t => ahora - t < 3600e3);
  if (marcas.length >= IA_ASISTENTE_LIMITE_HORA) return res.status(429).json({ error: 'Has llegado al máximo de ' + IA_ASISTENTE_LIMITE_HORA + ' preguntas por hora. Prueba un poco más tarde.' });
  marcas.push(ahora); iaAsistenteUso.set(yo, marcas);
  // lo que escribe el equipo también pasa por el filtro (correos, DNI, IBAN, teléfonos, monederos)
  const mensajes = limpios.map(m => m.role === 'user' ? { role: 'user', content: seudonimizarTexto(m.content, null) } : m);
  const a = await iaAjustes();
  const base = IA_SISTEMA_ASISTENTE + '\nHablas con: ' + ((req.asesor && req.asesor.nombre) || 'una persona del equipo') + '. Fecha de hoy: ' + new Date().toISOString().slice(0, 10) + '.\n';
  const usados = new Map();   // código → id de cliente de lo que ha consultado (para poner nombres en el panel)
  const conPanel = !!(req.asesor && req.asesor.roles && ['asesor', 'jefe', 'encargado', 'admin'].some(x => req.asesor.roles.has(x)));
  const llamar = async conWeb => {
    const sistema = iaSistemaCon(base + (conWeb ? IA_ASISTENTE_CON_WEB : IA_ASISTENTE_SIN_WEB) + (conPanel ? '\n' + IA_ASISTENTE_CON_PANEL : ''), a.conocimiento);
    let conv = mensajes, textos = [], fuentes = [], busquedas = 0, consultas = [];
    const herramientas = (conWeb ? [IA_HERRAMIENTA_WEB] : []).concat(conPanel ? IA_HERRAMIENTAS_PANEL.filter(h => h.name !== 'registro' || (req && req.asesor && req.asesor.esAdmin)) : []);   // 30/10: el registro, solo para administradores
    // Vueltas: «pause_turn» (búsquedas largas) o «tool_use» (consultas al panel). Máx. 8.
    for (let vuelta = 0; vuelta < 8; vuelta++) {
      const r = await iaLlamar({ funcion: 'asistente', modelo: IA_MODELO_ASISTENTE, sistema, mensajes: conv, maxTokens: 1500, personaId: yo, clienteId: null, herramientas: herramientas.length ? herramientas : null, completo: true });
      const parada = r.cuerpo.stop_reason;
      if (parada !== 'tool_use') textos.push((r.cuerpo.content || []).filter(b => b.type === 'text').map(b => b.text).join(''));   // sin recortar: tras una pausa el texto continúa
      fuentes = fuentes.concat(iaFuentes(r.cuerpo)); busquedas += r.busquedas;
      if (parada === 'pause_turn') { conv = conv.concat([{ role: 'assistant', content: r.cuerpo.content }]); continue; }
      if (parada !== 'tool_use') break;
      const resultados = [];
      for (const b of (r.cuerpo.content || []).filter(x => x.type === 'tool_use')) {
        let salida;
        try { salida = await iaEjecutarHerramienta(b.name, b.input, req, usados); consultas.push(b.name); }
        catch (err) { console.error('Herramienta IA', b.name, err.message); salida = { error: 'No se pudo consultar: ' + err.message }; }
        resultados.push({ type: 'tool_result', tool_use_id: b.id, content: JSON.stringify(salida).slice(0, 60000) });
      }
      conv = conv.concat([{ role: 'assistant', content: r.cuerpo.content }, { role: 'user', content: resultados }]);
    }
    const unicas = []; fuentes.forEach(f => { if (!unicas.some(x => x.url === f.url)) unicas.push(f); });
    return { texto: textos.join('').trim(), fuentes: unicas.slice(0, 8), busquedas, consultas };
  };
  try {
    let r, sinWeb = false;
    if (a.web) {
      try { r = await llamar(true); }
      catch (e) {
        // Si la organización no tiene activada la búsqueda web, se responde sin ella (y se avisa)
        if (!/web.?search|tool|server_tool/i.test(String(e.message || ''))) throw e;
        sinWeb = true; r = await llamar(false);
      }
    } else r = await llamar(false);
    if (!r.texto) return res.status(503).json({ error: 'La IA no ha devuelto nada. Prueba otra vez.', sin_ia: true });
    // Nombres de los clientes que salen en la respuesta (solo para el panel; a la IA no le han llegado)
    const clientes = {};
    const codigos = [...usados.keys()].filter(c => r.texto.includes(c));
    if (codigos.length) {
      const [cs] = await pool.query('SELECT id, codigo, nombre, apellidos, correo FROM clientes WHERE id IN (?)', [codigos.map(c => usados.get(c))]);
      cs.forEach(c => { const cod = c.codigo || ('C' + c.id); clientes[cod] = { id: c.id, nombre: [c.nombre, c.apellidos].filter(Boolean).join(' ') || c.correo }; });
    }
    res.json({ texto: r.texto, fuentes: r.fuentes, busquedas: r.busquedas, consultas: r.consultas, clientes, sin_web: sinWeb || undefined });
  } catch (e) {
    const det = req.asesor && req.asesor.esAdmin && e.message && e.message !== e.publico ? ' (Motivo: ' + String(e.message).slice(0, 160) + ')' : '';
    res.status(503).json({ error: (e.publico || 'La IA no está disponible ahora mismo.') + det, sin_ia: true });
  }
});

// El cliente pidió que no se use IA en su caso (lo marca su asesor).
app.put('/api/admin/clientes/:id/sin-ia', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Cliente no válido' });
  const [r] = await pool.execute('UPDATE clientes SET `sin_ia` = ? WHERE id = ?', [req.body && req.body.sin_ia ? 1 : 0, id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json({ ok: true });
});
// «Proponer respuesta»: borrador para el hilo (encargo + servicio). No envía nada.
app.post('/api/admin/propuestas/:id/ia-borrador', requiereSesionAsesor, async (req, res) => {
  const motivo = await iaMotivoNo('borrador');
  if (motivo) return res.status(503).json({ error: motivo, sin_ia: true });
  const conn = await pool.getConnection();
  try {
    const [ps] = await conn.execute('SELECT p.id, p.cliente_id, p.servicios, p.estado, p.creado_en, c.nombre, c.apellidos, c.correo, c.numero_documento, c.`sin_ia` FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.id = ?', [Number(req.params.id)]);
    if (!ps.length) return res.status(404).json({ error: 'Encargo no encontrado' });
    const p = ps[0];
    if (p.sin_ia) return res.status(409).json({ error: 'Este cliente ha pedido que no se use IA en su caso', sin_ia: true });
    const servicio = servicioDeHilo(p, req.body && req.body.servicio);
    const [msgs] = await conn.execute("SELECT autor, texto, creado_en FROM mensajes WHERE propuesta_id = ? AND servicio = ? AND retirado_en IS NULL ORDER BY creado_en DESC, id DESC LIMIT 20", [p.id, servicio]);
    if (!msgs.length) return res.status(400).json({ error: 'Todavía no hay mensajes en este hilo' });
    msgs.reverse();
    const [docs] = await conn.execute("SELECT nombre, estado, razon_rechazo FROM documentos_fiscales WHERE propuesta_id = ? AND (servicio = ? OR servicio IS NULL) ORDER BY creado_en", [p.id, servicio]);
    const [ents] = await conn.execute("SELECT `version`, `estado`, `subido_en` FROM entregas WHERE `propuesta_id` = ? AND `servicio` = ? ORDER BY `version`", [p.id, servicio]);
    const fecha = d => d ? new Date(d).toISOString().slice(0, 10) : '';
    const sz = t => seudonimizarTexto(t, p);
    const contexto = [
      'CONTEXTO DEL ENCARGO (datos del panel; los identificativos van sustituidos):',
      '- Servicios del encargo: ' + (serviciosDePropuesta(p).join(', ') || 'sin detallar'),
      '- Hilo de chat: ' + servicio,
      '- Estado de la propuesta: ' + p.estado + ' (creada el ' + fecha(p.creado_en) + ')',
      '- Documentación pedida al cliente: ' + (docs.length ? docs.map(d => sz(d.nombre) + ' → ' + d.estado + (d.razon_rechazo ? ' (motivo: ' + sz(d.razon_rechazo) + ')' : '')).join('; ') : 'ninguna todavía'),
      '- Informe entregado: ' + (ents.length ? ents.map(e => 'versión ' + e.version + ' el ' + fecha(e.subido_en) + ' → ' + e.estado).join('; ') : 'aún no'),
      '- Fecha de hoy: ' + fecha(new Date()),
      '',
      'CONVERSACIÓN (de la más antigua a la más reciente):',
      ...msgs.map(m => (m.autor === 'cliente' ? 'Cliente' : 'Asesor') + ' (' + fecha(m.creado_en) + '): ' + sz(m.texto)),
      '',
      msgs[msgs.length - 1].autor === 'cliente'
        ? 'Redacta el borrador de la respuesta del asesor al último mensaje del cliente.'
        : 'El último mensaje es del asesor. Redacta un mensaje breve de seguimiento coherente con la conversación.'
    ].join('\n');
    let texto;
    try {
      texto = await iaLlamar({ funcion: 'borrador', modelo: IA_MODELO_BORRADOR, sistema: iaSistemaCon(IA_SISTEMA_BORRADOR, (await iaAjustes()).conocimiento), mensajes: [{ role: 'user', content: contexto }], maxTokens: 700, personaId: req.asesor && req.asesor.id, clienteId: p.cliente_id });
    } catch (e) {
      // 19/10: a los administradores se les dice también el motivo técnico (clave, permisos, modelo…)
      const det = req.asesor && req.asesor.esAdmin && e.message && e.message !== e.publico ? ' (Motivo: ' + String(e.message).slice(0, 160) + ')' : '';
      return res.status(503).json({ error: (e.publico || 'La IA no está disponible ahora mismo.') + det, sin_ia: true });
    }
    if (!texto) return res.status(503).json({ error: 'La IA no ha devuelto nada. Prueba otra vez.', sin_ia: true });
    res.json({ texto: textoMensaje(texto) || texto.slice(0, 4000), servicio });
  } finally {
    conn.release();
  }
});

app.post('/api/admin/resumen-diario/prueba', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const r = await enviarResumenDiario({ forzarFecha: fechaMadrid().fecha });
  res.json(r || { error: 'No se pudo preparar el resumen' });
});
// 10/10: el asesor corrige los datos del cliente desde su ficha (lo que el
// cliente pide con «Pedir un cambio a mi asesor», o un número que falte).
// El correo no se cambia aquí: es con lo que entra en su área.
app.put('/api/admin/clientes/:id/datos', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {};
  const limpio = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
  const tipos = ['dni', 'nie', 'pasaporte'];
  if (!limpio(b.nombre, 120) || !limpio(b.apellidos, 160)) return res.status(400).json({ error: 'Nombre y apellidos no pueden quedar vacíos' });
  if (b.tipo_documento && !tipos.includes(String(b.tipo_documento).toLowerCase())) return res.status(400).json({ error: 'Tipo de documento no válido' });
  const [r] = await pool.execute(
    'UPDATE clientes SET nombre = ?, apellidos = ?, telefono = ?, telefono2 = ?, tipo_documento = ?, numero_documento = ? WHERE id = ?',
    [limpio(b.nombre, 120), limpio(b.apellidos, 160), limpio(b.telefono, 40) || null, limpio(b.telefono2, 40) || null,
     b.tipo_documento ? String(b.tipo_documento).toLowerCase() : null, limpio(b.numero_documento, 20).toUpperCase() || null, Number(req.params.id)]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Cliente no encontrado' });
  const codigo = await asignarCodigoCliente(pool, Number(req.params.id)).catch(() => null);
  res.json({ ok: true, codigo });
});

// ================================================================
// EQUIPO: PERSONAS (fase A, 10/10)
// Cualquier asesor puede ver la lista (la necesita para asignar y para la
// ficha); solo un administrador crea o cambia personas.
// ================================================================
const RE_TOPIC_NTFY = /^[A-Za-z0-9_-]{6,64}$/;
function personaParaPanel(q) {
  let esp = []; try { esp = JSON.parse(q.especialidades || '[]'); } catch (e) {}
  return { id: q.id, nombre: q.nombre, puesto: { es: q.puesto_es || '', en: q.puesto_en || '' }, bio: { es: q.bio_es || '', en: q.bio_en || '' },
    foto: q.foto, especialidades: Array.isArray(esp) ? esp : [], atiende_clientes: !!q.atiende_clientes, asesor_id: q.asesor_id,
    asesor_nombre: q.asesor_nombre || null, asesor_correo: q.asesor_correo || null, ntfy_topic: q.ntfy_topic || '', activa: !!q.activa, orden: q.orden, por_defecto: !!q.por_defecto };
}
app.get('/api/admin/personas', requiereSesionAsesor, async (req, res) => {
  const [filas] = await pool.query('SELECT p.*, a.`nombre` AS asesor_nombre, a.`correo` AS asesor_correo FROM personas p LEFT JOIN asesores a ON a.`id` = p.`asesor_id` ORDER BY p.`activa` DESC, p.`orden`, p.`id`');
  const mi = await mapaIniciales().catch(() => ({ porPersona: new Map() }));
  const veCanales = req.asesor.roles.has('admin');   // 21/10: el canal propio solo lo ven esa persona y los administradores
  res.json(filas.map(f => Object.assign(personaParaPanel(f), { iniciales: f.iniciales || '', genero: f.genero || null, correo_clientes: f.correo_clientes || null, horario: (() => { try { return f.horario ? JSON.parse(f.horario) : null; } catch (e) { return null; } })(), iniciales_avisos: mi.porPersona.get(f.id) || '' }, (veCanales || f.asesor_id === req.asesor.id) ? {} : { ntfy_topic: '', ntfy_oculto: true })));
});
async function guardarPersona(req, res, id) {
  const b = req.body || {};
  const nombre = textoWeb(b.nombre, 80);
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre' });
  const puesto = bilingueWeb(b.puesto, 120), bio = bilingueWeb(b.bio, 400);
  const foto = b.foto ? String(b.foto) : null;
  if (foto && !RE_ID_IMAGEN.test(foto)) return res.status(400).json({ error: 'Foto no válida' });
  const conn = await pool.getConnection();
  try {
    if (foto && !(await imagenesExistenWeb(conn, [foto]))) return res.status(400).json({ error: 'La foto no existe' });
    const esp = (Array.isArray(b.especialidades) ? b.especialidades : []).map(String).filter(x => RE_ID_SERVICIO.test(x)).slice(0, 30);
    const asesorId = b.asesor_id ? Number(b.asesor_id) : null;
    if (asesorId) {
      const [a] = await conn.execute('SELECT id FROM asesores WHERE id = ?', [asesorId]);
      if (!a.length) return res.status(400).json({ error: 'Esa cuenta de asesor no existe' });
      const [otra] = await conn.execute('SELECT nombre FROM personas WHERE asesor_id = ? AND id <> ?', [asesorId, id || 0]);
      if (otra.length) return res.status(409).json({ error: 'Esa cuenta ya está enlazada con ' + otra[0].nombre });
    }
    const topic = String(b.ntfy_topic || '').trim();
    if (topic && !RE_TOPIC_NTFY.test(topic)) return res.status(400).json({ error: 'El canal de ntfy solo admite letras, números, «-» y «_» (6 a 64)' });
    // 20/10: iniciales para los avisos (vacío = automáticas); únicas entre las personas activas
    const iniciales = b.iniciales ? normalizarIniciales(b.iniciales) : '';
    if (b.iniciales && !iniciales) return res.status(400).json({ error: 'Las iniciales son de 1 a 4 letras' });
    if (iniciales) { const [rep] = await conn.execute('SELECT nombre FROM personas WHERE iniciales = ? AND activa = 1 AND id <> ?', [iniciales, id || 0]); if (rep.length) return res.status(409).json({ error: 'Esas iniciales ya las usa ' + rep[0].nombre + '. Elige otras.' }); }
    CACHE_INICIALES.hasta = 0;
    const valores = [nombre, puesto.es || null, puesto.en || null, bio.es || null, bio.en || null, foto, JSON.stringify(esp),
      b.atiende_clientes ? 1 : 0, asesorId, topic || null, b.activa === false ? 0 : 1, Number.isInteger(b.orden) ? b.orden : 0];
    if (b.por_defecto && b.atiende_clientes && b.activa !== false) await conn.execute('UPDATE personas SET `por_defecto` = 0 WHERE `id` <> ?', [id || 0]);
    const porDefecto = b.por_defecto && b.atiende_clientes && b.activa !== false ? 1 : 0;
    if (id) {
      await conn.execute('UPDATE personas SET `por_defecto` = ? WHERE `id` = ?', [porDefecto, id]);
      const [r] = await conn.execute('UPDATE personas SET `nombre`=?, `puesto_es`=?, `puesto_en`=?, `bio_es`=?, `bio_en`=?, `foto`=?, `especialidades`=?, `atiende_clientes`=?, `asesor_id`=?, `ntfy_topic`=?, `activa`=?, `orden`=? WHERE `id`=?', [...valores, id]);
      if (!r.affectedRows) return res.status(404).json({ error: 'Persona no encontrada' });
      await conn.execute('UPDATE personas SET iniciales = ? WHERE id = ?', [iniciales || null, id]);
      if (['m', 'f'].includes(b.genero)) { await conn.execute('UPDATE personas SET genero = ? WHERE id = ?', [b.genero, id]); CACHE_GENERO.hasta = 0; }
      if (b.correo_clientes !== undefined) { const cc = String(b.correo_clientes || '').trim().toLowerCase(); if (cc && !correoValido(cc)) return res.status(400).json({ error: 'El «Correo para clientes» no es válido' }); await conn.execute('UPDATE personas SET correo_clientes = ? WHERE id = ?', [cc || null, id]); }   // 30/10
      return res.json({ ok: true, id });
    }
    const [r] = await conn.execute('INSERT INTO personas (`nombre`, `puesto_es`, `puesto_en`, `bio_es`, `bio_en`, `foto`, `especialidades`, `atiende_clientes`, `asesor_id`, `ntfy_topic`, `activa`, `orden`, `por_defecto`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', [...valores, porDefecto]);
    await conn.execute('UPDATE personas SET iniciales = ? WHERE id = ?', [iniciales || null, r.insertId]);
    await conn.execute('UPDATE personas SET genero = ? WHERE id = ?', [['m', 'f'].includes(b.genero) ? b.genero : generoPorNombre(nombre), r.insertId]); CACHE_GENERO.hasta = 0;
    if (correoValido(b.correo_clientes)) await conn.execute('UPDATE personas SET correo_clientes = ? WHERE id = ?', [String(b.correo_clientes).trim().toLowerCase(), r.insertId]);   // 30/10
    res.status(201).json({ ok: true, id: r.insertId });
  } finally { conn.release(); }
}
app.post('/api/admin/personas', requiereSesionAsesor, requiereRol('marketing'), soloAdminCamposPersona, (req, res) => guardarPersona(req, res, null));
app.put('/api/admin/personas/:id', requiereSesionAsesor, requiereRol('marketing'), soloAdminCamposPersona, (req, res) => guardarPersona(req, res, Number(req.params.id)));

// ================================================================
// ASESOR ASIGNADO (fase B, 10/10)
// El cliente pide el cambio desde su área; se confirma desde el panel; al
// resolverlo, el cliente recibe un correo. Un administrador también puede
// asignar directamente desde la ficha.
// ================================================================
async function personaAtiende(conn, id) {
  const [f] = await conn.execute('SELECT * FROM personas WHERE `id` = ? AND `activa` = 1 AND `atiende_clientes` = 1', [Number(id)]);
  return f[0] || null;
}
app.post('/api/propuestas/:token/cambio-asesor', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const actual = await personaDeCliente(p.cliente_id, conn);
    const candidatas = await candidatasCambioAsesor(conn, actual);
    const azar = String(req.body && req.body.persona_id) === 'azar';   // 29/10: «que lo elija Acros, dentro de mi equipo»
    let destino;
    if (azar) {
      if (!candidatas.length) return res.status(400).json({ error: 'Ahora mismo no hay nadie más disponible en tu equipo' });
      destino = candidatas[Math.floor(Math.random() * candidatas.length)];
    } else {
      destino = await personaAtiende(conn, req.body && req.body.persona_id);
      if (!destino) return res.status(400).json({ error: 'Esa persona no está disponible' });
      if (actual && actual.id === destino.id) return res.status(400).json({ error: 'Ya es tu asesor' });
      if (!candidatas.some(x => x.id === destino.id)) return res.status(400).json({ error: 'Esa persona no está disponible' });
    }
    const [pend] = await conn.execute("SELECT id FROM cambios_asesor WHERE cliente_id = ? AND estado = 'pendiente'", [p.cliente_id]);
    if (pend.length) return res.status(409).json({ error: 'Ya tienes un cambio pendiente de confirmar' });
    const motivoCliente = textoMensaje(req.body.motivo || '').slice(0, 1000);   // lo que escribió el cliente, tal cual (para enseñárselo en la respuesta)
    const motivo = ((azar ? 'Ha pedido que se elija al azar dentro de su equipo. ' : '') + motivoCliente).trim() || null;
    await conn.execute('INSERT INTO cambios_asesor (cliente_id, desde_persona_id, a_persona_id, motivo, texto_cliente) VALUES (?, ?, ?, ?, ?)', [p.cliente_id, actual ? actual.id : null, destino.id, motivo, motivoCliente || null]);
    avisarAdminClientes('🔁 Un cliente pide cambiar de asesor', (actual ? 'De ' + quienIni(await inicialesDePersona(actual.id)) + ' a ' : 'A ') + quienIni(await inicialesDePersona(destino.id)) + '. Confírmalo en «Cambios de asesor pendientes».', { prioridad: 4, etiqueta: 'arrows_counterclockwise' });
    correoCambioAsesor(conn, p.cliente_id, actual, destino, motivo, azar).catch(err => console.error('Correo de cambio de asesor:', err.message));   // 29/10: también por correo a los administradores
    res.status(201).json({ ok: true });
  } finally { conn.release(); }
});
app.get('/api/admin/cambios-asesor', requiereSesionAsesor, async (req, res) => {
  const [filas] = await pool.query(
    `SELECT ca.id, ca.cliente_id, ca.motivo, ca.creado_en, c.nombre, c.apellidos, c.correo, qd.nombre AS desde_nombre, qa.nombre AS a_nombre
     FROM cambios_asesor ca JOIN clientes c ON c.id = ca.cliente_id
     LEFT JOIN personas qd ON qd.id = ca.desde_persona_id LEFT JOIN personas qa ON qa.id = ca.a_persona_id
     WHERE ca.estado = 'pendiente' ORDER BY ca.creado_en`);
  res.json(filas);
});
async function asignarAsesor(conn, clienteId, persona, motivoTexto) {
  await conn.execute('UPDATE clientes SET `asesor_persona_id` = ? WHERE id = ?', [persona ? persona.id : null, clienteId]);
  if (persona) {
    const t = '🤝 Tienes un cliente nuevo', tGen = '🤝 ' + quienIni(await inicialesDePersona(persona.id)) + ' · Tiene un cliente nuevo';
    const m = (motivoTexto || 'Te lo han asignado') + '. Lo tienes en «Clientes y encargos».';
    avisar(tGen, m, { etiqueta: 'handshake' });
    if (persona.ntfy_topic && persona.ntfy_topic !== NTFY_TOPIC) avisarEn(persona.ntfy_topic, t, m, { etiqueta: 'handshake' });
  }
}
app.post('/api/admin/cambios-asesor/:id/resolver', requiereSesionAsesor, requiereRol('jefe', 'encargado'), async (req, res) => {
  const accion = req.body && req.body.accion;
  if (!['aceptar', 'rechazar'].includes(accion)) return res.status(400).json({ error: 'Acción no válida' });
  const respuesta = textoMensaje((req.body && req.body.respuesta) || '').slice(0, 1000) || null;
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute("SELECT ca.*, c.correo, c.nombre AS cliente_nombre FROM cambios_asesor ca JOIN clientes c ON c.id = ca.cliente_id WHERE ca.id = ? AND ca.estado = 'pendiente'", [Number(req.params.id)]);
    if (!f.length) return res.status(404).json({ error: 'Ese cambio ya está resuelto o no existe' });
    const cambio = f[0];
    const destino = await personaAtiende(conn, cambio.a_persona_id);
    if (accion === 'aceptar' && !destino) return res.status(409).json({ error: 'Esa persona ya no atiende clientes: recházalo o asígnale otra desde su ficha' });
    await conn.execute("UPDATE cambios_asesor SET estado = ?, respuesta = ?, resuelto_en = NOW(), resuelto_por = ? WHERE id = ?", [accion === 'aceptar' ? 'aceptado' : 'rechazado', respuesta, req.asesor.id, cambio.id]);
    if (accion === 'aceptar') await asignarAsesor(conn, cambio.cliente_id, destino, 'El cliente lo pidió');
    if (cambio.correo && brevoActivo()) {
      const actual = await personaDeCliente(cambio.cliente_id, conn);
      const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
      const c = plantillaCorreo(accion === 'aceptar' ? {
        titulo: `${destino.nombre} es tu nuevo asesor`,
        parrafos: [cambio.cliente_nombre ? `Hola, ${ESC_HTML(cambio.cliente_nombre)}:` : 'Hola:', `Hemos atendido tu petición: a partir de ahora te atenderá <strong>${ESC_HTML(destino.nombre)}</strong>. Tu documentación, tus mensajes y tus informes siguen donde estaban.`],
        hilo: hiloCambioAsesor(cambio, destino, respuesta),
        boton: enlace ? { texto: 'Ir a mi área', url: enlace } : null,
      } : {
        titulo: 'Sobre tu cambio de asesor',
        parrafos: [cambio.cliente_nombre ? `Hola, ${ESC_HTML(cambio.cliente_nombre)}:` : 'Hola:', `Por ahora no hemos podido hacer el cambio que pediste${actual ? ` y seguirá atendiéndote <strong>${ESC_HTML(actual.nombre)}</strong>` : ''}.`],
        hilo: hiloCambioAsesor(cambio, destino, respuesta),
        nota: 'Si quieres comentarlo, escríbenos desde tu área o llámanos al 668 170 020.',
        boton: enlace ? { texto: 'Ir a mi área', url: enlace } : null,
      });
      enviarCorreo(cambio.correo, accion === 'aceptar' ? `${destino.nombre} es tu nuevo asesor de Acros` : 'Sobre tu cambio de asesor en Acros', c.html, c.texto).catch(err => console.error('Correo de cambio de asesor no enviado:', err.message));
    }
    res.json({ ok: true });
  } finally { conn.release(); }
});
app.put('/api/admin/clientes/:id/asesor', requiereSesionAsesor, requiereRol('jefe', 'encargado'), reasignacionDentroDeMiAmbito, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const pid = req.body && req.body.persona_id;
    const persona = pid ? await personaAtiende(conn, pid) : null;
    if (pid && !persona) return res.status(400).json({ error: 'Esa persona no atiende clientes' });
    await asignarAsesor(conn, Number(req.params.id), persona, 'Te lo ha asignado ' + quienIni(await inicialesDeAsesor(req.asesor.id)));
    // Un cambio pendiente queda resuelto por la asignación directa
    await conn.execute("UPDATE cambios_asesor SET estado = 'rechazado', respuesta = 'Asignado directamente desde el panel', resuelto_en = NOW(), resuelto_por = ? WHERE cliente_id = ? AND estado = 'pendiente'", [req.asesor.id, Number(req.params.id)]);
    res.json({ ok: true });
  } finally { conn.release(); }
});

// ================================================================
// COLABORACIONES (fase D, 10/10)
// Cualquiera del equipo puede apuntar que ayudó en un encargo (o el titular
// apuntar quién le ayudó). Si la apunta el titular del encargo (el asesor
// del cliente) o un administrador, queda confirmada; si la apunta otro (p.
// ej. el propio colaborador), queda pendiente hasta que el titular o un
// administrador la confirme. Al colaborador le cuenta la calidad del
// trabajo de ese encargo al 33 % (ver «Rendimiento»).
// ================================================================
async function personaDeAsesor(conn, asesorId) {
  const [f] = await conn.execute('SELECT * FROM personas WHERE asesor_id = ?', [asesorId]);
  return f[0] || null;
}
async function titularDePropuesta(conn, propuestaId) {
  const [f] = await conn.execute('SELECT c.asesor_persona_id AS pid FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.id = ?', [propuestaId]);
  return f.length ? f[0].pid : undefined;
}
app.post('/api/admin/propuestas/:id/colaboraciones', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const pid = Number(req.params.id);
    const titular = await titularDePropuesta(conn, pid);
    if (titular === undefined) return res.status(404).json({ error: 'Encargo no encontrado' });
    const [q] = await conn.execute('SELECT id, nombre FROM personas WHERE id = ? AND activa = 1', [Number(req.body && req.body.persona_id)]);
    if (!q.length) return res.status(400).json({ error: 'Elige una persona del equipo' });
    if (q[0].id === titular) return res.status(400).json({ error: 'Es el titular del encargo: no cuenta como colaboración' });
    const [ya] = await conn.execute('SELECT id FROM colaboraciones WHERE propuesta_id = ? AND persona_id = ?', [pid, q[0].id]);
    if (ya.length) return res.status(409).json({ error: q[0].nombre + ' ya figura como colaborador de este encargo' });
    const yo = await personaDeAsesor(conn, req.asesor.id);
    const confirmada = req.asesor.esAdmin || (yo && yo.id === titular);
    const descripcion = textoWeb(req.body.descripcion, 300) || null;
    await conn.execute('INSERT INTO colaboraciones (propuesta_id, persona_id, descripcion, estado, anotado_por, confirmado_por, confirmado_en) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [pid, q[0].id, descripcion, confirmada ? 'confirmada' : 'pendiente', req.asesor.id, confirmada ? req.asesor.id : null, confirmada ? aSQLDatetime(ahora()) : null]);
    if (!confirmada && titular) {
      const [t] = await conn.execute('SELECT * FROM personas WHERE id = ?', [titular]);
      if (t.length) {
        const titulo = '🤝 Confirma una colaboración', tituloGen = '🤝 ' + quienIni(await inicialesDePersona(t[0].id)) + ' · Confirma una colaboración';
        const msg = quienIni(await inicialesDeAsesor(req.asesor.id)) + ' dice que ha colaborado en un encargo tuyo. Confírmalo en la ficha del cliente.';
        avisar(tituloGen, msg, { etiqueta: 'handshake' });
        if (t[0].ntfy_topic && t[0].ntfy_topic !== NTFY_TOPIC) avisarEn(t[0].ntfy_topic, titulo, msg, { etiqueta: 'handshake' });
      }
    }
    res.status(201).json({ ok: true, estado: confirmada ? 'confirmada' : 'pendiente' });
  } finally { conn.release(); }
});
async function colaboracionGestionable(conn, req, id) {
  const [f] = await conn.execute('SELECT * FROM colaboraciones WHERE id = ?', [Number(id)]);
  if (!f.length) return { error: [404, 'No encontrada'] };
  const titular = await titularDePropuesta(conn, f[0].propuesta_id);
  const yo = await personaDeAsesor(conn, req.asesor.id);
  const puede = req.asesor.esAdmin || (yo && yo.id === titular);
  return puede ? { c: f[0], yo } : { error: [403, 'Solo el titular del encargo o un administrador'] };
}
app.post('/api/admin/colaboraciones/:id/confirmar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await colaboracionGestionable(conn, req, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    await conn.execute("UPDATE colaboraciones SET estado = 'confirmada', confirmado_por = ?, confirmado_en = NOW() WHERE id = ?", [req.asesor.id, r.c.id]);
    res.json({ ok: true });
  } finally { conn.release(); }
});
app.delete('/api/admin/colaboraciones/:id', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await colaboracionGestionable(conn, req, req.params.id);
    // El propio colaborador también puede retirar la suya
    const [f] = await conn.execute('SELECT persona_id FROM colaboraciones WHERE id = ?', [Number(req.params.id)]);
    const yo = await personaDeAsesor(conn, req.asesor.id);
    if (r.error && !(f.length && yo && f[0].persona_id === yo.id)) return res.status(r.error[0]).json({ error: r.error[1] });
    await conn.execute('DELETE FROM colaboraciones WHERE id = ?', [Number(req.params.id)]);
    res.json({ ok: true });
  } finally { conn.release(); }
});

// ================================================================
// RENDIMIENTO (fase D, 10/10) — solo administradores
// Por persona y mes. Criterios (para que el equipo los conozca):
//  · Informes entregados: versiones 1 subidas por esa persona en el mes.
//  · Servicios terminados: conformidades del mes en encargos de sus clientes.
//  · Valoraciones como titular: media de cada atributo.
//  · Calidad ponderada: su calidad como titular al 100 % + la de los
//    encargos donde colaboró (confirmado) al 33 %.
//  · Colaboraciones hechas (confirmadas) y recibidas en sus encargos.
//  · Respuesta en el chat: horas medias desde un mensaje del cliente hasta
//    la primera respuesta de un asesor (se atribuye a quien responde).
//  · Pago → entrega: días medios entre el pago y la primera versión.
//  · Cambios pedidos: informes suyos a los que el cliente pidió cambios.
// ================================================================
const PESO_COLABORACION = 0.33; // 10/10: decisión de Vikn (antes 30 %)
app.get('/api/admin/rendimiento', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const mes = /^\d{4}-\d{2}$/.test(String(req.query.mes || '')) ? req.query.mes : fechaMadrid().fecha.slice(0, 7);
  const ini = inicioDiaMadridUTC(mes + '-01');
  const [a, m] = mes.split('-').map(Number);
  const sig = new Date(Date.UTC(a, m, 1)).toISOString().slice(0, 10);
  const fin = inicioDiaMadridUTC(sig);
  const rango = [sqlFecha(ini), sqlFecha(fin)];
  const conn = await pool.getConnection();
  try {
    const [personas] = await conn.query('SELECT id, nombre, asesor_id, activa, atiende_clientes, equipo_id FROM personas ORDER BY orden, id');
    const porAsesor = {}; personas.forEach(q => { if (q.asesor_id) porAsesor[q.asesor_id] = q.id; });
    const filas = {}; personas.forEach(q => { filas[q.id] = { persona_id: q.id, nombre: q.nombre, activa: !!q.activa, atiende_clientes: !!q.atiende_clientes, equipo_id: q.equipo_id || null,
      informes: 0, terminados: 0, valoraciones: 0, atencion: null, calidad: null, rapidez: null, calidad_ponderada: null,
      colab_hechas: 0, colab_recibidas: 0, respuesta_horas: null, dias_entrega: null, cambios: 0, piden_cambio: 0, _resp: [], _dias: [], _cal: [] }; });
    // Informes entregados (v1) y días pago → entrega
    const [ents] = await conn.execute('SELECT e.subido_por, e.version, e.subido_en, (SELECT COALESCE(MIN(pg.confirmado_en), MIN(pg.creado_en)) FROM pagos pg WHERE pg.propuesta_id = e.propuesta_id) AS pagado_en FROM entregas e WHERE e.subido_en >= ? AND e.subido_en < ?', rango);
    ents.forEach(e => { const f = filas[porAsesor[e.subido_por]]; if (!f || e.version !== 1) return; f.informes++; if (e.pagado_en) f._dias.push((new Date(e.subido_en) - new Date(e.pagado_en)) / 86400000); });
    // Cambios pedidos en informes suyos
    const [cams] = await conn.execute("SELECT subido_por FROM entregas WHERE comentario IS NOT NULL AND respondido_en >= ? AND respondido_en < ?", rango);
    cams.forEach(e => { const f = filas[porAsesor[e.subido_por]]; if (f) f.cambios++; });
    // Servicios terminados (conformidad del mes) en encargos de sus clientes
    const [conf] = await conn.execute("SELECT c.asesor_persona_id AS pid FROM entregas e JOIN clientes c ON c.id = e.cliente_id WHERE e.estado = 'conforme' AND e.respondido_en >= ? AND e.respondido_en < ?", rango);
    conf.forEach(x => { if (filas[x.pid]) filas[x.pid].terminados++; });
    // Valoraciones del mes (titular) y calidad ponderada con las colaboraciones
    const [vals] = await conn.execute("SELECT v.propuesta_id, v.persona_id, v.atencion, v.calidad, v.rapidez FROM valoraciones v WHERE v.estado <> 'omitida' AND v.creado_en >= ? AND v.creado_en < ?", rango);
    const [colabsV] = vals.length ? await conn.query("SELECT propuesta_id, persona_id FROM colaboraciones WHERE estado = 'confirmada' AND propuesta_id IN (?)", [vals.map(v => v.propuesta_id)]) : [[]];
    const media = l => l.length ? Math.round(l.reduce((x, y) => x + y, 0) / l.length * 10) / 10 : null;
    const acum = {};
    vals.forEach(v => {
      const f = filas[v.persona_id];
      if (f) { f.valoraciones++; (acum[f.persona_id] = acum[f.persona_id] || { at: [], ca: [], ra: [] }); acum[f.persona_id].at.push(v.atencion); acum[f.persona_id].ca.push(v.calidad); acum[f.persona_id].ra.push(v.rapidez); f._cal.push([v.calidad, 1]); }
      colabsV.filter(c => c.propuesta_id === v.propuesta_id).forEach(c => { if (filas[c.persona_id]) filas[c.persona_id]._cal.push([v.calidad, PESO_COLABORACION]); });
    });
    Object.keys(acum).forEach(k => { filas[k].atencion = media(acum[k].at); filas[k].calidad = media(acum[k].ca); filas[k].rapidez = media(acum[k].ra); });
    // Colaboraciones confirmadas del mes
    const [cols] = await conn.execute("SELECT co.persona_id, c.asesor_persona_id AS titular FROM colaboraciones co JOIN propuestas p ON p.id = co.propuesta_id JOIN clientes c ON c.id = p.cliente_id WHERE co.estado = 'confirmada' AND co.confirmado_en >= ? AND co.confirmado_en < ?", rango);
    cols.forEach(c => { if (filas[c.persona_id]) filas[c.persona_id].colab_hechas++; if (filas[c.titular]) filas[c.titular].colab_recibidas++; });
    // Clientes que pidieron dejar a esta persona como asesor (10/10)
    const [pcs] = await conn.execute('SELECT desde_persona_id AS pid FROM cambios_asesor WHERE desde_persona_id IS NOT NULL AND creado_en >= ? AND creado_en < ?', rango);
    pcs.forEach(x => { if (filas[x.pid]) filas[x.pid].piden_cambio++; });
    // Respuesta en el chat
    const [msgs] = await conn.execute('SELECT propuesta_id, servicio, autor, asesor_id, creado_en FROM mensajes WHERE creado_en >= ? AND creado_en < ? + INTERVAL 7 DAY ORDER BY propuesta_id, servicio, creado_en, id', rango);
    let pendiente = null;
    msgs.forEach((x, i) => {
      const hilo = x.propuesta_id + '|' + x.servicio;
      if (pendiente && pendiente.hilo !== hilo) pendiente = null;
      if (x.autor === 'cliente') { if (!pendiente && new Date(x.creado_en) < fin) pendiente = { hilo, t: new Date(x.creado_en) }; }
      else if (pendiente) { const f = filas[porAsesor[x.asesor_id]]; if (f) f._resp.push((new Date(x.creado_en) - pendiente.t) / 3600000); pendiente = null; }
    });
    const extra = await ampliarRendimiento(conn, filas, porAsesor, ini, fin);   // 29/10: métricas del equipo
    const salida = Object.values(filas).map(f => {
      const pesos = f._cal.reduce((x, c) => x + c[1], 0);
      f.calidad_ponderada = pesos ? Math.round(f._cal.reduce((x, c) => x + c[0] * c[1], 0) / pesos * 10) / 10 : null;
      f.respuesta_horas = f._resp.length ? Math.round(f._resp.reduce((x, y) => x + y, 0) / f._resp.length * 10) / 10 : null;
      f.dias_entrega = f._dias.length ? Math.round(f._dias.reduce((x, y) => x + y, 0) / f._dias.length * 10) / 10 : null;
      delete f._resp; delete f._dias; delete f._cal;
      return f;
    }).filter(f => f.activa || f.informes || f.valoraciones || f.colab_hechas || f.piden_cambio);
    res.json(Object.assign({ mes, personas: salida }, extra));
  } finally { conn.release(); }
});

// ================================================================
// VALORACIONES (fase C, 10/10)
// Al dar la conformidad al último informe de un encargo, el cliente valora
// a su asesor: atención y trato, calidad del trabajo, rapidez y plazos (1-5)
// y un comentario opcional, y elige cómo saldría su nombre. Puede decir
// «Prefiero no valorar»: entonces recibe UN recordatorio a los 3 días. Los
// comentarios pasan por revisión (tachado de palabras malsonantes) y, por
// ahora, son internos. Nunca bloquea nada: la conformidad ya está dada.
// ================================================================
const MALSONANTES = ['joder', 'jodido', 'jodida', 'mierda', 'puta', 'puto', 'putada', 'gilipollas', 'gilipollez', 'cabron', 'cabrón', 'cabrona', 'coño', 'hostia', 'hostias', 'imbecil', 'imbécil', 'idiota', 'subnormal', 'capullo', 'pendejo', 'cojones', 'carajo', 'mamon', 'mamón', 'zorra', 'maricon', 'maricón', 'estupido', 'estúpido', 'estafadores', 'ladrones', 'chorizos', 'fuck', 'shit', 'bitch', 'asshole', 'bastard'];
function nombreParaMostrar(c, forma) {
  const n = String(c.nombre || '').trim(), a = String(c.apellidos || '').trim();
  const ini = t => t ? t.charAt(0).toUpperCase() + '.' : '';
  const primerApellido = a.split(/\s+/)[0] || '';
  if (forma === 'completo') return [n, a].filter(Boolean).join(' ');
  if (forma === 'nombre_inicial') return [n, ini(primerApellido)].filter(Boolean).join(' ');
  if (forma === 'inicial_apellido') return [ini(n), primerApellido].filter(Boolean).join(' ');
  return [ini(n), ini(primerApellido)].filter(Boolean).join(' ');
}
async function encargoTerminado(conn, p) {
  const servicios = serviciosDePropuesta(p);
  if (!servicios.length) return false;
  const [ult] = await conn.execute('SELECT e.`servicio`, e.`estado` FROM entregas e WHERE e.`propuesta_id` = ? AND e.`id` = (SELECT MAX(e2.`id`) FROM entregas e2 WHERE e2.`propuesta_id` = e.`propuesta_id` AND e2.`servicio` = e.`servicio`)', [p.id]);
  // 20/10: un servicio también está terminado si el cliente lo confirmó («Sí, terminado») sin informe de por medio
  const [cerr] = await conn.execute("SELECT `servicio` FROM servicios_cliente WHERE `propuesta_id` = ? AND `estado` = 'terminado'", [p.id]);
  return servicios.every(sv => ult.some(u => u.servicio === sv && u.estado === 'conforme') || cerr.some(c => c.servicio === sv));
}
app.post('/api/propuestas/:token/valoracion', exigirPagoConfirmado, async (req, res) => {
  const b = req.body || {};
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (!(await encargoTerminado(conn, p))) return res.status(409).json({ error: 'Podrás valorar cuando hayas dado tu conformidad a todos tus informes' });
    const [ya] = await conn.execute('SELECT `estado` FROM valoraciones WHERE `propuesta_id` = ?', [p.id]);
    if (ya.length && ya[0].estado !== 'omitida') return res.status(409).json({ error: 'Ya valoraste este encargo. ¡Gracias!' });
    const asesor = await personaDeCliente(p.cliente_id, conn);
    if (b.omitir) {
      if (!ya.length) await conn.execute("INSERT INTO valoraciones (`propuesta_id`, `cliente_id`, `persona_id`, `estado`) VALUES (?, ?, ?, 'omitida')", [p.id, p.cliente_id, asesor ? asesor.id : null]);
      return res.json({ ok: true, estado: 'omitida' });
    }
    const nota = v => { const n = Number(v); return Number.isInteger(n) && n >= 1 && n <= 5 ? n : null; };
    const at = nota(b.atencion), ca = nota(b.calidad), ra = nota(b.rapidez);
    if (!at || !ca || !ra) return res.status(400).json({ error: 'Puntúa las tres preguntas (de 1 a 5 estrellas)' });
    const forma = ['completo', 'nombre_inicial', 'inicial_apellido', 'iniciales'].includes(b.nombre_publico) ? b.nombre_publico : 'iniciales';
    const [cl] = await conn.execute('SELECT nombre, apellidos FROM clientes WHERE id = ?', [p.cliente_id]);
    const comentario = textoMensaje(b.comentario || '').slice(0, 2000) || null;
    const valores = [asesor ? asesor.id : null, at, ca, ra, comentario, forma, nombreParaMostrar(cl[0] || {}, forma), comentario ? 'por_revisar' : 'revisada'];
    if (ya.length) await conn.execute('UPDATE valoraciones SET `persona_id`=?, `atencion`=?, `calidad`=?, `rapidez`=?, `comentario`=?, `nombre_publico`=?, `nombre_mostrado`=?, `estado`=?, `creado_en`=NOW() WHERE `propuesta_id`=?', [...valores, p.id]);
    else await conn.execute('INSERT INTO valoraciones (`persona_id`, `atencion`, `calidad`, `rapidez`, `comentario`, `nombre_publico`, `nombre_mostrado`, `estado`, `propuesta_id`, `cliente_id`) VALUES (?,?,?,?,?,?,?,?,?,?)', [...valores, p.id, p.cliente_id]);
    const media = ((at + ca + ra) / 3).toFixed(1).replace('.', ',');
    (async () => { const q = await personaDeCliente(p.cliente_id).catch(() => null); avisarAdminClientes('⭐ Nueva valoración' + (q ? ' para ' + quienIni(await inicialesDePersona(q.id)) : ''), 'Media ' + media + '/5' + (comentario ? ' · con comentario por revisar' : '') + '.', { etiqueta: 'star' }); })();   // 15/10: las valoraciones solo a los admins
    res.status(201).json({ ok: true });
  } finally { conn.release(); }
});
// Panel: revisión de comentarios y listado (solo administradores)
app.get('/api/admin/valoraciones', requiereSesionAsesor, requiereRol('encargado', 'marketing'), async (req, res) => {
  const soloRevisar = req.query.estado === 'por_revisar';
  const [filas] = await pool.query(
    'SELECT v.*, q.nombre AS asesor_nombre, c.nombre AS cliente_nombre, c.apellidos AS cliente_apellidos, c.correo FROM valoraciones v ' +
    'LEFT JOIN personas q ON q.id = v.persona_id JOIN clientes c ON c.id = v.cliente_id ' +
    "WHERE v.estado <> 'omitida'" + (soloRevisar ? " AND v.estado = 'por_revisar'" : '') + ' ORDER BY v.creado_en DESC LIMIT 200');
  res.json({ valoraciones: filas, malsonantes: MALSONANTES });
});
app.post('/api/admin/valoraciones/:id/revisar', requiereSesionAsesor, requiereRol('encargado', 'marketing'), async (req, res) => {
  const tachar = Array.isArray(req.body && req.body.tachar) ? req.body.tachar.map(Number).filter(Number.isInteger) : [];
  const [f] = await pool.execute("SELECT comentario FROM valoraciones WHERE id = ? AND estado = 'por_revisar'", [Number(req.params.id)]);
  if (!f.length) return res.status(404).json({ error: 'Esa valoración ya está revisada' });
  // Solo se tachan palabras enteras (por su posición): el texto no se puede editar
  let k = -1;
  const revisado = String(f[0].comentario || '').replace(/[\p{L}\p{N}]+/gu, w => { k++; return tachar.includes(k) ? w.charAt(0) + '*'.repeat(Math.max(1, w.length - 1)) : w; });
  await pool.execute("UPDATE valoraciones SET comentario_revisado = ?, estado = 'revisada', revisado_en = NOW(), revisado_por = ? WHERE id = ?", [revisado, req.asesor.id, Number(req.params.id)]);
  res.json({ ok: true, comentario_revisado: revisado });
});
// Recordatorio único a quien dijo «Prefiero no valorar» (a los 3 días)
async function enviarRecordatoriosValoracion() {
  if (!brevoActivo()) return;
  let conn;
  try {
    conn = await pool.getConnection();
    const [filas] = await conn.query("SELECT v.id, v.cliente_id, c.correo, c.nombre FROM valoraciones v JOIN clientes c ON c.id = v.cliente_id WHERE v.estado = 'omitida' AND v.recordatorio_en IS NULL AND v.creado_en <= NOW() - INTERVAL ? SECOND",
      [Math.max(60, Number(process.env.VALORACION_RECORDATORIO_SEGUNDOS) || 3 * 24 * 3600)]);
    for (const f of filas) {
      await conn.execute('UPDATE valoraciones SET recordatorio_en = NOW() WHERE id = ?', [f.id]);
      if (!f.correo) continue;
      const asesor = await personaDeCliente(f.cliente_id, conn).catch(() => null);
      const quien = asesor ? asesor.nombre : 'tu asesor';
      const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
      const c = plantillaCorreo({
        titulo: `¿Qué tal con ${quien}?`,
        parrafos: [f.nombre ? `Hola, ${ESC_HTML(f.nombre)}:` : 'Hola:', `Hace unos días terminamos tu encargo. Si tienes un minuto, nos ayudaría mucho saber qué tal te ha atendido ${ESC_HTML(quien)}: son tres preguntas de estrellas.`],
        boton: enlace ? { texto: 'Valorar en un minuto', url: enlace } : null,
        nota: 'Es el único recordatorio que te enviaremos.',
      });
      notificarCliente(conn, f.cliente_id, 'recordatorios', () => enviarCorreo(f.correo, `¿Qué tal con ${quien}? · Acros`, c.html, c.texto),
        `Acros: hace unos días terminamos tu encargo. ¿Nos cuentas qué tal te ha atendido ${quien}? Son tres preguntas.` + (enlace ? ' ' + enlace : ''))
        .catch(err => console.error('Recordatorio de valoración no enviado:', err.message));
    }
  } catch (err) { console.error('Recordatorios de valoración:', err.message); }
  finally { if (conn) conn.release(); }
}
setInterval(enviarRecordatoriosValoracion, Math.max(5000, Number(process.env.CHAT_TAREA_MS) || 60000) * 30);

// Página pública «Equipo» (fase C): las personas activas, sin datos internos
app.get('/api/web/equipo', async (req, res) => {
  const [filas] = await pool.query('SELECT * FROM personas WHERE `activa` = 1 ORDER BY `orden`, `id`');
  res.set('Cache-Control', 'no-cache');
  res.json(filas.map(q => { let esp = []; try { esp = JSON.parse(q.especialidades || '[]'); } catch (e) {}
    return { id: q.id, nombre: q.nombre, puesto: { es: q.puesto_es || '', en: q.puesto_en || '' }, bio: { es: q.bio_es || '', en: q.bio_en || '' }, foto: q.foto, especialidades: Array.isArray(esp) ? esp : [], atiende_clientes: !!q.atiende_clientes }; }));
});

// ================================================================
// INFORMES ENTREGADOS (fase 2, 08/10)
// El asesor sube la versión final de cada servicio desde la ficha; el
// cliente la descarga en su área y da su conformidad («Todo correcto»,
// el servicio queda terminado) o pide un cambio (su comentario va al chat
// de ese servicio y el informe vuelve al asesor). Los archivos se guardan
// en R2 en privado (sin enlace público): solo se descargan con la sesión
// del cliente o desde el panel. Los clientes ven siempre sus informes,
// también los de encargos anteriores.
// ================================================================
const TIPOS_ENTREGA = { 'application/pdf': 'pdf', 'application/zip': 'zip', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx', 'application/vnd.ms-excel': 'xls', 'text/csv': 'csv', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx' };
const MAX_BYTES_ENTREGA = 10 * 1024 * 1024; // en base64 ocupa ~13,4 MB: cabe en el límite de 15 MB de express.json
const nombreSeguro = n => String(n || 'informe').replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 180);

app.post('/api/admin/propuestas/:id/entregas', requiereSesionAsesor, async (req, res) => {
  const { servicio, nombre, tipo, datos_base64 } = req.body || {};
  if (!TIPOS_ENTREGA[tipo]) return res.status(400).json({ error: 'Formato no admitido (PDF, Excel, Word, CSV o ZIP)' });
  const buffer = Buffer.from(String(datos_base64 || ''), 'base64');
  if (!buffer.length) return res.status(400).json({ error: 'El archivo está vacío' });
  if (buffer.length > MAX_BYTES_ENTREGA) return res.status(413).json({ error: 'El archivo supera los 10 MB' });
  if (!R2_BUCKET) return res.status(500).json({ error: 'El almacenamiento (R2) no está configurado' });
  const conn = await pool.getConnection();
  try {
    const [ps] = await conn.execute('SELECT p.*, c.`correo`, c.`nombre` AS cliente_nombre FROM propuestas p JOIN clientes c ON c.`id` = p.`cliente_id` WHERE p.`id` = ?', [Number(req.params.id)]);
    if (!ps.length) return res.status(404).json({ error: 'Encargo no encontrado' });
    const p = ps[0];
    const serv = servicioDeHilo(p, servicio);
    const [v] = await conn.execute('SELECT COALESCE(MAX(`version`), 0) + 1 AS v FROM entregas WHERE `propuesta_id` = ? AND `servicio` = ?', [p.id, serv]);
    const version = v[0].v;
    const nombreArch = nombreSeguro(nombre);
    const clave = `entregas/${p.id}/${serv}/v${version}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${TIPOS_ENTREGA[tipo]}`;
    await subirAR2(clave, buffer, tipo);
    const [r] = await conn.execute(
      'INSERT INTO entregas (`propuesta_id`, `cliente_id`, `servicio`, `version`, `nombre_archivo`, `tipo`, `bytes`, `clave_r2`, `subido_por`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [p.id, p.cliente_id, serv, version, nombreArch, tipo, buffer.length, clave, req.asesor.id]);
    let correo = 'sin_correo';
    if (p.correo && brevoActivo()) {
      const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
      const asesorE = await personaDeCliente(p.cliente_id, conn).catch(() => null);
      const quienE = asesorE ? ESC_HTML(asesorE.nombre) : 'Tu asesor';
      const c = plantillaCorreo({
        titulo: version > 1 ? 'Tu informe corregido está listo' : 'Tu informe está listo',
        parrafos: [p.cliente_nombre ? `Hola, ${ESC_HTML(p.cliente_nombre)}:` : 'Hola:',
          (version > 1 ? `${quienE} ha subido la versión corregida de tu informe.` : `${quienE} ha terminado tu informe y ya lo tienes en tu área de cliente.`) +
          ' Descárgalo, revísalo y, si todo está bien, danos tu conformidad con un clic. Si tienes cualquier duda, pídenos el cambio desde ahí mismo.'],
        boton: enlace ? { texto: 'Ver mi informe', url: enlace } : null,
        nota: 'Por tu privacidad, el informe no viaja por correo: está guardado en tu área y podrás descargarlo siempre que lo necesites.',
      });
      try {
        const porCorreo = await notificarCliente(conn, p.cliente_id, 'informes', () => enviarCorreo(p.correo, version > 1 ? 'Tu informe corregido de Acros está listo' : 'Tu informe de Acros está listo', c.html, c.texto),
          'Acros: ' + (version > 1 ? 'tu informe corregido está listo' : 'tu informe está listo') + ' en tu área de cliente.' + (enlace ? ' ' + enlace : ''));
        correo = porCorreo ? 'enviado' : 'desactivado_por_cliente';
      }
      catch (err) { console.error('Correo de entrega no enviado:', err.message); correo = 'fallo'; }
    }
    res.status(201).json({ ok: true, id: r.insertId, version, servicio: serv, correo });
  } finally { conn.release(); }
});
async function enviarArchivoEntrega(res, e) {
  const { buffer, tipoMime } = await bajarDeR2(e.clave_r2);
  res.set('Content-Type', tipoMime || e.tipo || 'application/octet-stream');
  res.set('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(e.nombre_archivo));
  res.send(buffer);
}
app.get('/api/admin/entregas/:id/descargar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT * FROM entregas WHERE `id` = ?', [Number(req.params.id)]);
    if (!f.length) return res.status(404).json({ error: 'No encontrado' });
    await enviarArchivoEntrega(res, f[0]);
  } finally { conn.release(); }
});
// Cliente: descargar cualquiera de SUS informes (de este encargo o de anteriores)
app.get('/api/propuestas/:token/entregas/:id/descargar', exigirPagoConfirmado, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [f] = await conn.execute('SELECT * FROM entregas WHERE `id` = ? AND `cliente_id` = ?', [Number(req.params.id), p.cliente_id]);
    if (!f.length) return res.status(404).json({ error: 'No encontrado' });
    await enviarArchivoEntrega(res, f[0]);
  } finally { conn.release(); }
});
async function entregaDelCliente(conn, token, id) {
  const p = await propuestaVigente(conn, token);
  if (!p) return { error: [404, 'Propuesta no encontrada'] };
  const [f] = await conn.execute('SELECT * FROM entregas WHERE `id` = ? AND `propuesta_id` = ?', [Number(id), p.id]);
  if (!f.length) return { error: [404, 'Informe no encontrado'] };
  const [ult] = await conn.execute('SELECT MAX(`id`) AS m FROM entregas WHERE `propuesta_id` = ? AND `servicio` = ?', [p.id, f[0].servicio]);
  if (ult[0].m !== f[0].id) return { error: [409, 'Hay una versión más reciente de este informe'] };
  if (f[0].estado !== 'entregado') return { error: [409, 'Ya respondiste a este informe'] };
  return { p, e: f[0] };
}
app.post('/api/propuestas/:token/entregas/:id/conformidad', exigirPagoConfirmado, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await entregaDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    if (!r.e.conformidad_pedida_en) return res.status(409).json({ error: 'Tu asesor aún no te ha pedido el visto bueno de este informe' });   // 26/10
    await conn.execute("UPDATE entregas SET `estado` = 'conforme', `respondido_en` = NOW() WHERE `id` = ?", [r.e.id]);
    await cerrarServicioPorInforme(conn, r.p, r.e.servicio).catch(err => console.error('Cierre del servicio por informe:', err.message));
    avisarCliente(r.e.cliente_id, '✅', 'un cliente ha dado su conformidad a su informe', 'Ese servicio queda terminado.', { etiqueta: 'white_check_mark' });
    res.json({ ok: true, estado: 'conforme' });
  } finally { conn.release(); }
});
app.post('/api/propuestas/:token/entregas/:id/cambios', exigirPagoConfirmado, async (req, res) => {
  const comentario = textoMensaje(req.body && req.body.comentario);
  if (!comentario) return res.status(400).json({ error: 'Cuéntanos qué quieres cambiar' });
  const conn = await pool.getConnection();
  try {
    const r = await entregaDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    await conn.execute("UPDATE entregas SET `estado` = 'cambios', `comentario` = ?, `respondido_en` = NOW() WHERE `id` = ?", [comentario, r.e.id]);
    await reabrirServicioPorCambios(conn, r.p, r.e.servicio).catch(err => console.error('Reapertura del servicio por cambios:', err.message));
    // El comentario va también al chat de ese servicio, para hablarlo ahí
    await conn.execute("INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, texto) VALUES (?, ?, ?, 'cliente', ?)",
      [r.p.id, r.p.cliente_id, r.e.servicio, 'Sobre el informe entregado (versión ' + r.e.version + '): ' + comentario]);
    avisarCliente(r.p.cliente_id, '✏️', 'un cliente pide un cambio en su informe', 'Lo tienes en «Mensajes sin leer» y en su ficha.', { prioridad: 4, etiqueta: 'pencil2' });
    res.json({ ok: true, estado: 'cambios' });
  } finally { conn.release(); }
});

// --- Aviso por correo al cliente, agrupado (06/10) ---
// Cada minuto: para cada encargo con mensajes del asesor SIN LEER cuyo
// último mensaje tiene ya más de SEGUNDOS_AVISO_CHAT (5 min por defecto)
// y que no se le ha avisado desde entonces, sale un único correo «Tu
// asesor te ha escrito». Si el cliente los lee antes (entra a su área), no
// recibe nada. Se guarda en la base (avisos_chat), así que un reinicio de
// Railway no pierde ni repite avisos.
const SEGUNDOS_AVISO_CHAT = Math.max(1, Number(process.env.CHAT_AVISO_SEGUNDOS) || 300);
const MS_TAREA_AVISOS = Math.max(1000, Number(process.env.CHAT_TAREA_MS) || 60000);
let tareaAvisosEnMarcha = false;
async function enviarAvisosChatPendientes() {
  if (tareaAvisosEnMarcha) return;
  tareaAvisosEnMarcha = true;
  const conn = await pool.getConnection();
  try {
    const [pendientes] = await conn.query(
      `SELECT m.propuesta_id, c.id AS cliente_id, c.correo, MAX(m.creado_en) AS ultimo, a.ultimo_aviso_en
       FROM mensajes m
       JOIN clientes c ON c.id = m.cliente_id
       LEFT JOIN avisos_chat a ON a.propuesta_id = m.propuesta_id
       WHERE m.autor = 'asesor' AND m.leido_en IS NULL AND m.retirado_en IS NULL
       GROUP BY m.propuesta_id, c.id, c.correo, a.ultimo_aviso_en
       HAVING MAX(m.creado_en) <= NOW() - INTERVAL ? SECOND
          AND (a.ultimo_aviso_en IS NULL OR MAX(m.creado_en) > a.ultimo_aviso_en)`, [SEGUNDOS_AVISO_CHAT]);
    for (const f of pendientes) {
      // Se marca antes de enviar: si el correo fallara, no se reintenta en bucle cada minuto
      await conn.execute(
        'INSERT INTO avisos_chat (propuesta_id, ultimo_aviso_en) VALUES (?, NOW()) ON DUPLICATE KEY UPDATE ultimo_aviso_en = NOW()', [f.propuesta_id]);
      if (!f.correo) continue;
      const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
      try {
        const asesorC = await personaDeCliente(f.cliente_id, conn).catch(() => null);
        const correoC = plantillaCorreo({
          titulo: asesorC ? `${asesorC.nombre} te ha escrito` : 'Tienes un mensaje de tu asesor',
          parrafos: ['Hola:', (asesorC ? `${ESC_HTML(asesorC.nombre)}, tu asesor de Acros,` : 'Tu asesor de Acros') + ' te ha escrito en tu área de cliente. Por tu privacidad, los mensajes no viajan por correo: entra para leerlo y contestarle.'],
          boton: enlace ? { texto: 'Leer el mensaje', url: enlace } : null,
          nota: enlace ? null : 'Entra en tu área de cliente desde acrosfi.es para leerlo.',
        });
        await notificarCliente(conn, f.cliente_id, 'mensajes', () => enviarCorreo(f.correo, asesorC ? `${asesorC.nombre}, tu asesor de Acros, te ha escrito` : 'Tu asesor de Acros te ha escrito', correoC.html, correoC.texto),
          'Acros: ' + (asesorC ? asesorC.nombre : 'tu asesor') + ' te ha escrito en tu área de cliente.' + (enlace ? ' ' + enlace : ''));
      } catch (err) {
        console.error('Correo de aviso de chat no enviado (encargo ' + f.propuesta_id + '):', err.message);
      }
    }
  } catch (err) {
    console.error('Tarea de avisos del chat:', err.message);
  } finally {
    conn.release();
    tareaAvisosEnMarcha = false;
  }
}
setInterval(enviarAvisosChatPendientes, MS_TAREA_AVISOS);

// --- Documentación pedida: aviso por correo agrupado (10/10) ---
// Igual que el chat: si se piden varios documentos seguidos, un solo correo
// a los SEGUNDOS_AVISO_CHAT de la última petición, con la lista de lo que
// falta. Si para entonces ya los ha subido todos, no se envía.
let tareaDocsEnMarcha = false;
async function enviarAvisosDocumentosPendientes() {
  if (tareaDocsEnMarcha) return;
  tareaDocsEnMarcha = true;
  const conn = await pool.getConnection();
  try {
    const [props] = await conn.query(
      `SELECT d.propuesta_id, c.id AS cliente_id, c.correo, c.nombre AS cliente_nombre, MAX(d.creado_en) AS ultimo, a.ultimo_aviso_en
       FROM documentos_fiscales d JOIN clientes c ON c.id = d.cliente_id
       LEFT JOIN avisos_documentos a ON a.propuesta_id = d.propuesta_id
       WHERE d.estado = 'pendiente'
       GROUP BY d.propuesta_id, c.id, c.correo, c.nombre, a.ultimo_aviso_en
       HAVING MAX(d.creado_en) <= NOW() - INTERVAL ? SECOND
          AND (a.ultimo_aviso_en IS NULL OR MAX(d.creado_en) > a.ultimo_aviso_en)`, [SEGUNDOS_AVISO_CHAT]);
    for (const f of props) {
      await conn.execute('INSERT INTO avisos_documentos (propuesta_id, ultimo_aviso_en) VALUES (?, NOW()) ON DUPLICATE KEY UPDATE ultimo_aviso_en = NOW()', [f.propuesta_id]);
      if (!f.correo || !brevoActivo()) continue;
      const [docs] = await conn.execute("SELECT nombre, urgente FROM documentos_fiscales WHERE propuesta_id = ? AND estado = 'pendiente' ORDER BY creado_en", [f.propuesta_id]);
      if (!docs.length) continue;
      const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
      const asesorD = await personaDeCliente(f.cliente_id, conn).catch(() => null);
      const quienD = asesorD ? ESC_HTML(asesorD.nombre) : 'tu asesor';
      const c = plantillaCorreo({
        titulo: asesorD ? `${asesorD.nombre} necesita documentación` : 'Tu asesor necesita documentación',
        parrafos: [f.cliente_nombre ? `Hola, ${ESC_HTML(f.cliente_nombre)}:` : 'Hola:',
          docs.length === 1 ? `Para seguir con tu encargo, ${quienD} necesita este documento:` : `Para seguir con tu encargo, ${quienD} necesita estos documentos:`,
          '<strong>' + docs.map(d => ESC_HTML(d.nombre) + (d.urgente ? ' (urgente)' : '')).join('<br>') + '</strong>',
          'Súbelos desde tu área de cliente; viajan y se guardan cifrados.'],
        boton: enlace ? { texto: 'Subir documentación', url: enlace } : null,
        nota: 'Por tu privacidad, no envíes documentos por correo: súbelos siempre desde tu área.',
      });
      try { await notificarCliente(conn, f.cliente_id, 'documentos', () => enviarCorreo(f.correo, asesorD ? `${asesorD.nombre}, tu asesor de Acros, necesita documentación` : 'Tu asesor de Acros necesita documentación', c.html, c.texto),
        'Acros: ' + (asesorD ? asesorD.nombre : 'tu asesor') + ' necesita ' + (docs.length === 1 ? 'un documento' : docs.length + ' documentos') + ' para seguir con tu encargo. Súbelos desde tu área.' + (enlace ? ' ' + enlace : '')); }
      catch (err) { console.error('Correo de documentación pedida no enviado:', err.message); }
    }
  } catch (err) {
    console.error('Tarea de avisos de documentación:', err.message);
  } finally { conn.release(); tareaDocsEnMarcha = false; }
}
setInterval(enviarAvisosDocumentosPendientes, MS_TAREA_AVISOS);

// --- Resumen diario para los administradores (10/10) ---
// Cada día desde las 08:00 (Madrid), un correo con lo que entró el día
// anterior: solicitudes de presupuesto (con o sin cuestionario), llamadas,
// empresas y cuestionarios completados después. Si no hubo nada, no se
// envía. Se apunta en resumenes_diarios para no repetirlo con reinicios.
function inicioDiaMadridUTC(fechaISO) {
  // medianoche de Madrid de esa fecha, en UTC (sirve en verano e invierno)
  const prueba = new Date(fechaISO + 'T00:00:00Z');
  const desfase = (new Date(prueba.toLocaleString('en-US', { timeZone: 'Europe/Madrid' })) - new Date(prueba.toLocaleString('en-US', { timeZone: 'UTC' }))) / 60000;
  return new Date(prueba.getTime() - desfase * 60000);
}
const sqlFecha = d => d.toISOString().slice(0, 19).replace('T', ' ');
let resumenEnMarcha = false;
async function enviarResumenDiario({ forzarFecha } = {}) {
  if (resumenEnMarcha) return null;
  const ahoraM = fechaMadrid();
  if (!forzarFecha && ahoraM.hora < 8) return null;
  resumenEnMarcha = true;
  const conn = await pool.getConnection();
  try {
    const hoy = forzarFecha || ahoraM.fecha;
    if (!forzarFecha) { const [ya] = await conn.execute('SELECT fecha FROM resumenes_diarios WHERE fecha = ?', [hoy]); if (ya.length) return null; }
    const fin = inicioDiaMadridUTC(hoy), inicio = new Date(fin.getTime() - 24 * 3600 * 1000);
    const ayer = new Date(inicio.getTime() + 12 * 3600 * 1000).toISOString().slice(0, 10);
    // creado_en se guarda en la hora del servidor de la base (UTC en Railway)
    const rango = [sqlFecha(inicio), sqlFecha(fin)];
    const [sols] = await conn.execute('SELECT servicios, telefono, correo, cuestionario IS NOT NULL AS con_cuest FROM solicitudes_presupuesto WHERE creado_en >= ? AND creado_en < ? ORDER BY creado_en', rango);
    const [llams] = await conn.execute('SELECT nombre, telefono FROM solicitudes_llamada WHERE creado_en >= ? AND creado_en < ? ORDER BY creado_en', rango);
    const [emps] = await conn.execute('SELECT razon_social, contacto_nombre AS contacto FROM empresas WHERE creado_en >= ? AND creado_en < ? ORDER BY creado_en', rango).catch(() => [[]]);
    const [cuests] = await conn.execute('SELECT telefono, correo FROM solicitudes_presupuesto WHERE `cuestionario_en` >= ? AND `cuestionario_en` < ?', rango);
    const [cambs] = await conn.execute('SELECT c.nombre, c.apellidos, c.correo, qd.nombre AS desde_nombre, qa.nombre AS a_nombre, ca.estado FROM cambios_asesor ca JOIN clientes c ON c.id = ca.cliente_id LEFT JOIN personas qd ON qd.id = ca.desde_persona_id LEFT JOIN personas qa ON qa.id = ca.a_persona_id WHERE ca.creado_en >= ? AND ca.creado_en < ?', rango);
    const [sugs] = await conn.execute('SELECT tipo, texto, origen FROM sugerencias WHERE creado_en >= ? AND creado_en < ?', rango);
    // 14/10: además de lo nuevo de ayer, lo que sigue pendiente ahora mismo
    const [chats] = await conn.execute("SELECT c.nombre, c.apellidos, c.correo, COUNT(*) AS n, MIN(m.creado_en) AS desde FROM mensajes m JOIN clientes c ON c.id = m.cliente_id WHERE m.autor = 'cliente' AND m.leido_en IS NULL AND m.oculto_cliente_en IS NULL GROUP BY c.id, c.nombre, c.apellidos, c.correo ORDER BY desde");
    const [docsP] = await conn.execute("SELECT c.nombre, c.apellidos, c.correo, d.nombre AS doc FROM documentos_fiscales d JOIN clientes c ON c.id = d.cliente_id WHERE d.estado = 'enviado' ORDER BY d.subido_en").catch(() => [[]]);
    const [pagosP] = await conn.execute("SELECT c.correo, pg.metodo FROM pagos pg JOIN propuestas p ON p.id = pg.propuesta_id JOIN clientes c ON c.id = p.cliente_id WHERE pg.estado = 'autodeclarado'").catch(() => [[]]);
    const [altasP] = await conn.execute("SELECT c.nombre, c.apellidos, c.correo FROM diligencias g JOIN clientes c ON c.id = g.cliente_id WHERE g.estado IN ('pendiente','examen_especial')").catch(() => [[]]);
    const plazosP = await plazosParaResumen(conn).catch(err => { console.error('Plazos del resumen:', err.message); return []; });   // 20/10
    const pendientes = chats.length + docsP.length + pagosP.length + altasP.length + plazosP.length;
    const total = sols.length + llams.length + emps.length + cuests.length + cambs.length + sugs.length + pendientes;
    await conn.execute('INSERT INTO resumenes_diarios (fecha, enviado_en, elementos) VALUES (?, NOW(), ?) ON DUPLICATE KEY UPDATE enviado_en = NOW(), elementos = ?', [hoy, total, total]);
    if (!total || !brevoActivo()) return { total, enviado: false };
    const servs = x => { try { const l = JSON.parse(x); return Array.isArray(l) ? l.join(', ') : String(x); } catch (e) { return String(x || ''); } };
    const bloque = (titulo, filas) => filas.length ? `<p style="margin:18px 0 6px;"><strong>${titulo} (${filas.length})</strong></p><ul style="margin:0; padding-left:20px;">${filas.map(f => '<li style="margin:3px 0;">' + f + '</li>').join('')}</ul>` : '';
    const fechaBonita = new Date(ayer + 'T12:00:00Z').toLocaleDateString('es-ES', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'Europe/Madrid' });
    const html = bloque('Solicitudes de presupuesto', sols.map(x => ESC_HTML(servs(x.servicios)) + ' · ' + ESC_HTML(x.telefono || '') + (x.correo ? ' · ' + ESC_HTML(x.correo) : '') + (x.con_cuest ? ' · con cuestionario' : ' · <em>sin cuestionario</em>'))) +
      bloque('Peticiones de llamada', llams.map(x => ESC_HTML(x.nombre || '') + ' · ' + ESC_HTML(x.telefono || ''))) +
      bloque('Empresas registradas', emps.map(x => ESC_HTML(x.razon_social || '') + (x.contacto ? ' · ' + ESC_HTML(x.contacto) : ''))) +
      bloque('Cuestionarios completados después', cuests.map(x => ESC_HTML(x.telefono || '') + (x.correo ? ' · ' + ESC_HTML(x.correo) : ''))) +
      bloque('Sugerencias', sugs.map(x => '<em>' + ({ idea: 'Idea', fallo: 'Algo no funciona', otro: 'Otro' })[x.tipo] + (x.origen === 'area' ? ' · desde el área' : ' · desde la web') + ':</em> ' + ESC_HTML(String(x.texto).slice(0, 220)) + (String(x.texto).length > 220 ? '…' : ''))) +
      bloque('Cambios de asesor pedidos', cambs.map(x => ESC_HTML([x.nombre, x.apellidos].filter(Boolean).join(' ') || x.correo) + ' · de ' + ESC_HTML(x.desde_nombre || 'sin asesor') + ' a ' + ESC_HTML(x.a_nombre || '?') + (x.estado === 'pendiente' ? ' · <em>pendiente</em>' : ' · ' + x.estado))) +
      (pendientes ? '<p style="margin:22px 0 0;"><strong>Pendiente ahora mismo</strong></p>' : '') +
      bloque('💬 Chats de clientes sin contestar', chats.map(x => ESC_HTML([x.nombre, x.apellidos].filter(Boolean).join(' ') || x.correo) + ' · ' + x.n + ' mensaje' + (x.n == 1 ? '' : 's'))) +
      bloque('📄 Documentos por revisar', docsP.map(x => ESC_HTML([x.nombre, x.apellidos].filter(Boolean).join(' ') || x.correo) + ' · ' + ESC_HTML(x.doc || ''))) +
      bloque('💶 Pagos por confirmar', pagosP.map(x => ESC_HTML(x.correo) + ' · ' + ESC_HTML(x.metodo || ''))) +
      bloque('🪪 Altas por revisar', altasP.map(x => ESC_HTML([x.nombre, x.apellidos].filter(Boolean).join(' ') || x.correo))) +
      bloque('⏰ Plazos que vencen', plazosP);
    const nuevos = total - pendientes;
    const c = plantillaCorreo({ titulo: 'Resumen de Acros', parrafos: [nuevos ? 'Esto es lo que entró el ' + fechaBonita + ':' : 'Ayer (' + fechaBonita + ') no entró nada nuevo.', html, 'Lo tenéis todo en el panel: panel.acrosfi.es'] });
    const [admins] = await conn.execute('SELECT correo FROM asesores WHERE es_admin = 1 AND activo = 1');
    for (const a of admins) {
      try { await enviarCorreo(a.correo, 'Resumen de Acros · ' + fechaBonita + ' (' + total + ')', c.html, c.texto); }
      catch (err) { console.error('Resumen diario no enviado a ' + a.correo + ':', err.message); }
    }
    return { total, enviado: true };
  } catch (err) {
    console.error('Resumen diario:', err.message);
    return null;
  } finally { conn.release(); resumenEnMarcha = false; }
}
setInterval(enviarResumenDiario, 10 * 60 * 1000);
setTimeout(enviarResumenDiario, 90 * 1000);

// ================================================================
// COPIA DE LA BASE DE DATOS FUERA DE RAILWAY (07/10)
// Cada noche (a partir de las 03:30, hora de Madrid) se exportan TODAS las
// tablas a JSON, se comprimen y se cifran con la clave pública de los
// documentos (la misma de acros_area.html): AES-256-GCM con una clave al
// azar, y esa clave cifrada con RSA-OAEP/SHA-256. Solo la clave privada de
// Vikn la abre. Se guarda en Cloudflare R2 (proveedor distinto de Railway)
// en copias-bd/, se conservan las últimas 30 y se registra en copias_bd.
// Si falla: aviso ntfy y correo a los administradores (sin datos). La
// tarea revisa cada 10 minutos, así que un reinicio no se salta la noche.
// Restaurar: herramientas/restaurar_copia_bd.js (ver su cabecera).
// ================================================================
const CLAVE_PUBLICA_COPIAS = (process.env.CLAVE_PUBLICA_DOCUMENTOS || `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuzFJ8P/sO7sXP7HQOb+h
D6DsyVWJkulZjMOfENXWmCP2HgKckHsAktiHLzIASMKZZo7ACl1HFU5e8aKhOceN
MMmckwlKtL2/TnCx7aXRlj0W/w2PGvimTnTnQ1AR7bhiwFIKu78DM17ToiltrOH1
eLg1njzE9p73ehwB0s3J3GUBzIFNNQtaP2kHh4PKy8Jmq38YtxisFcEpAbj1i8W0
i0llwvs710c5Dc1/mrsyHM/J3tXgx5K26zr7rpX0wMwqlLP8AVFosPv8BHCgjWeF
K2icGTb3fWjd1ll1whgjoR0f5dSf+tI0TKEe2N1icFgnqI02AVzPpOc6wIIAnMcI
kwA2VPRLOV4v3jdCmfzvHX3nV4IKEtjKINv7mC6Vx7WxhF+mOZmhoz5ViykL65XB
ssKuKI23YWH7PnmUgQhFwB8873UGD7AzmZDDBn+/fyDojwd4l5Ie5XpsH0QFrNMt
7bsRaCf56EaCGGweSCNxy+aF+gZpyojBAxVektfxfvPMJ5TxFR+JE9kw39ECCTem
9ogvE9NFdzAisOI/tY0r+OHwYMjPW4rFOb8aw6zn8n33mQASEPBAaD6K3CLNV9E8
+UhjJZEWY0XhNyRIbKsgH6YOxAd3dDZGRibtIGBtgBzzt5YaemixS4ASozdq/+kk
c/gQd8O27Q13qdk2E3RYKecCAwEAAQ==
-----END PUBLIC KEY-----`).replace(/\\n/g, '\n');
const COPIAS_A_CONSERVAR = 30;
let copiaEnMarcha = false;

function fechaMadrid(d = new Date()) {
  const partes = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(d);
  const v = t => partes.find(p => p.type === t).value;
  return { fecha: `${v('year')}-${v('month')}-${v('day')}`, hora: Number(v('hour')) % 24, minuto: Number(v('minute')) };
}
async function exportarBaseDeDatos(conn) {
  const [tablas] = await conn.query('SHOW TABLES');
  const salida = { formato: 'acros-bd-v1', creado_en: new Date().toISOString(), tablas: {} };
  let filasTotal = 0;
  for (const t of tablas) {
    const nombre = Object.values(t)[0];
    const [filas] = await conn.query({ sql: 'SELECT * FROM `' + nombre.replace(/`/g, '') + '`', dateStrings: true });
    salida.tablas[nombre] = filas.map(f => {
      const o = {};
      for (const [k, v] of Object.entries(f)) o[k] = Buffer.isBuffer(v) ? { __b64: v.toString('base64') } : v;
      return o;
    });
    filasTotal += filas.length;
  }
  return { datos: salida, tablas: tablas.length, filas: filasTotal };
}
function cifrarCopia(buffer) {
  const claveAES = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const cifrador = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
  const cifrado = Buffer.concat([cifrador.update(buffer), cifrador.final(), cifrador.getAuthTag()]); // como Web Crypto: etiqueta al final
  const claveCifrada = crypto.publicEncrypt({ key: CLAVE_PUBLICA_COPIAS, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, claveAES);
  return Buffer.from(JSON.stringify({
    formato: 'acros-copia-bd-cifrada-v1', algoritmo: 'AES-256-GCM + RSA-OAEP/SHA-256 (gzip dentro)',
    creado_en: new Date().toISOString(), iv: iv.toString('base64'), clave_cifrada: claveCifrada.toString('base64'), datos: cifrado.toString('base64'),
  }));
}
async function avisarFalloCopia(mensaje) {
  avisarAlerta('⚠️ La copia de la base de datos ha fallado', 'Mira el registro de Railway. Se reintenta cada hora.', { prioridad: 4, etiqueta: 'floppy_disk' });
  if (!brevoActivo()) return;
  const conn = await pool.getConnection();
  try {
    const [admins] = await conn.execute('SELECT correo FROM asesores WHERE es_admin = 1 AND activo = 1');
    for (const a of admins) {
      try {
        await enviarCorreo(a.correo, '⚠️ La copia de seguridad de Acros ha fallado',
          '<p>La copia nocturna de la base de datos de Acros no se ha podido hacer.</p>' +
          '<p>Motivo técnico: <code>' + String(mensaje).replace(/[<>&]/g, '') .slice(0, 300) + '</code></p>' +
          '<p>El sistema lo reintenta cada hora. Si mañana sigue fallando, revisa el registro de Railway o las variables de Cloudflare R2.</p><p>— Acros</p>');
      } catch (e) { console.error('Correo de fallo de copia no enviado:', e.message); }
    }
  } finally { conn.release(); }
}
async function hacerCopiaBaseDeDatos({ manual = false } = {}) {
  if (copiaEnMarcha) throw new Error('Ya hay una copia en marcha');
  copiaEnMarcha = true;
  const { fecha } = fechaMadrid();
  const conn = await pool.getConnection();
  try {
    const exp = await exportarBaseDeDatos(conn);
    const comprimido = zlib.gzipSync(Buffer.from(JSON.stringify(exp.datos)));
    const cifrado = cifrarCopia(comprimido);
    const clave = 'copias-bd/' + new Date().toISOString().replace(/[:.]/g, '-') + '.acros-bd.json';
    await subirAR2(clave, cifrado, 'application/json');
    const [r] = await conn.execute(
      "INSERT INTO copias_bd (`fecha`, `clave_r2`, `bytes`, `tablas`, `filas`, `estado`, `es_manual`) VALUES (?, ?, ?, ?, ?, 'ok', ?)",
      [fecha, clave, cifrado.length, exp.tablas, exp.filas, manual ? 1 : 0]);
    // Conservar solo las últimas
    const [viejas] = await conn.query("SELECT `id`, `clave_r2` FROM copias_bd WHERE `estado` = 'ok' ORDER BY `creado_en` DESC, `id` DESC LIMIT 1000 OFFSET ?", [COPIAS_A_CONSERVAR]);
    for (const v of viejas) {
      try { await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: v.clave_r2 })); } catch (e) { console.error('No se pudo borrar la copia antigua', v.clave_r2, e.message); continue; }
      await conn.execute('DELETE FROM copias_bd WHERE `id` = ?', [v.id]);
    }
    await conn.execute("DELETE FROM copias_bd WHERE `estado` = 'error' AND `creado_en` < NOW() - INTERVAL 60 DAY");
    console.log(`Copia de la base de datos hecha: ${clave} (${exp.tablas} tablas, ${exp.filas} filas, ${cifrado.length} bytes)`);
    anotarRegistro({ actor_tipo: 'sistema', actor_nombre: 'Sistema', tipo: 'sistema', accion: manual ? 'Copia de seguridad (a mano)' : 'Copia de seguridad nocturna', detalle: { tablas: exp.tablas, filas: exp.filas, bytes: cifrado.length } });   // 30/10
    return { id: r.insertId, clave, bytes: cifrado.length, tablas: exp.tablas, filas: exp.filas };
  } catch (err) {
    console.error('COPIA BD: ha fallado:', err.message);
    try { await conn.execute("INSERT INTO copias_bd (`fecha`, `estado`, `error`, `es_manual`) VALUES (?, 'error', ?, ?)", [fecha, String(err.message).slice(0, 2000), manual ? 1 : 0]); } catch (e) { /* sin base no hay registro */ }
    throw err;
  } finally {
    conn.release();
    copiaEnMarcha = false;
  }
}
// Revisión periódica: ¿toca la copia de hoy? (03:30 o más tarde, sin copia
// correcta hoy, y como mucho un intento por hora si ha fallado)
async function revisarCopiaNocturna() {
  if (copiaEnMarcha || !R2_BUCKET) return;
  const ahoraM = fechaMadrid();
  if (ahoraM.hora < 3 || (ahoraM.hora === 3 && ahoraM.minuto < 30)) return;
  let conn;
  try {
    conn = await pool.getConnection();
    const [hoy] = await conn.execute("SELECT `estado`, `creado_en` FROM copias_bd WHERE `fecha` = ? AND `es_manual` = 0 ORDER BY `id` DESC", [ahoraM.fecha]);
    if (hoy.some(f => f.estado === 'ok')) return;
    const [recientes] = await conn.execute("SELECT COUNT(*) AS n FROM copias_bd WHERE `fecha` = ? AND `es_manual` = 0 AND `estado` = 'error' AND `creado_en` > NOW() - INTERVAL 55 MINUTE", [ahoraM.fecha]);
    if (recientes[0].n > 0) return;
    const fallosPrevios = hoy.filter(f => f.estado === 'error').length;
    conn.release(); conn = null;
    try { await hacerCopiaBaseDeDatos(); }
    catch (err) { if (fallosPrevios === 0) await avisarFalloCopia(err.message); } // un aviso por noche, no uno por reintento
  } catch (err) {
    console.error('Revisión de la copia nocturna:', err.message);
  } finally { if (conn) conn.release(); }
}
setInterval(revisarCopiaNocturna, Math.max(5000, Number(process.env.COPIA_REVISION_MS) || 10 * 60 * 1000));
setTimeout(revisarCopiaNocturna, 60 * 1000);

app.get('/api/admin/copias-bd', requiereSesionAsesor, requiereRol('informatico'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.query('SELECT `id`, `fecha`, `bytes`, `tablas`, `filas`, `estado`, `error`, `es_manual` AS `manual`, `creado_en` FROM copias_bd ORDER BY `creado_en` DESC, `id` DESC LIMIT 60');
    res.json({ copias: filas, conservadas: COPIAS_A_CONSERVAR, r2_configurado: !!R2_BUCKET });
  } finally { conn.release(); }
});
app.post('/api/admin/copias-bd/ahora', requiereSesionAsesor, requiereRol('informatico'), async (req, res) => {
  try {
    const r = await hacerCopiaBaseDeDatos({ manual: true });
    res.json({ ok: true, ...r });
  } catch (err) {
    res.status(500).json({ error: 'La copia ha fallado: ' + err.message });
  }
});
app.get('/api/admin/copias-bd/:id/descargar', requiereSesionAsesor, requiereRol('informatico'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [filas] = await conn.execute("SELECT `clave_r2`, `fecha` FROM copias_bd WHERE `id` = ? AND `estado` = 'ok'", [Number(req.params.id)]);
    if (!filas.length) return res.status(404).json({ error: 'Esa copia no existe' });
    const { buffer } = await bajarDeR2(filas[0].clave_r2);
    const nombre = 'acros-bd-' + String(filas[0].fecha).slice(0, 10) + '-' + req.params.id + '.acros-bd.json';
    res.set('Content-Type', 'application/json');
    res.set('Content-Disposition', 'attachment; filename="' + nombre + '"');
    res.send(buffer);
  } catch (err) {
    console.error('Descarga de copia:', err.message);
    res.status(500).json({ error: 'No se pudo descargar la copia' });
  } finally { conn.release(); }
});

app.post('/api/admin/avisos/prueba', requiereSesionAsesor, async (req, res) => {
  if (!NTFY_TOPIC) return res.status(400).json({ error: 'Falta la variable NTFY_TOPIC en Railway: sin ella no se envía ningún aviso.' });
  const ok = await avisar('🔔 Aviso de prueba · canal de clientes', 'Si ves esto, los avisos de clientes funcionan.', { etiqueta: 'tada' });
  if (!ok) return res.status(502).json({ error: 'ntfy no ha aceptado el aviso. Revisa el nombre del canal en NTFY_TOPIC.' });
  // 15/10: también al canal de administración y al propio del asesor, si los hay
  if (NTFY_TOPIC_ADMIN) await avisarEn(NTFY_TOPIC_ADMIN, '🔔 Aviso de prueba · canal de administración', 'Si ves esto, los avisos de administración funcionan.', { etiqueta: 'tada' });
  const [q] = await pool.execute('SELECT ntfy_topic FROM personas WHERE asesor_id = ? AND ntfy_topic IS NOT NULL LIMIT 1', [req.asesor.id]);
  if (q.length && q[0].ntfy_topic !== NTFY_TOPIC) await avisarEn(q[0].ntfy_topic, '🔔 Aviso de prueba · tu canal', 'Si ves esto, te llegan los avisos de tus clientes.', { etiqueta: 'tada' });
  res.json({ ok: true, canal_admin: !!NTFY_TOPIC_ADMIN, canal_propio: !!q.length });
});

// ================================================================
// SERVICIOS: EJERCICIO, PLAZOS Y CIERRE A DOS BANDAS (20/10, ACROS 7 · fase 1)
// Cada servicio contratado es ahora una fila propia (servicios_cliente) con
// su tipo, su ejercicio fiscal (o rango) y su estado. La clave interna es
// «tipo-ejercicio» (renta-2025), única por cliente; el nombre visible se
// genera a partir de ella. El plazo y la ventana de urgencia NO se guardan
// salvo que se editen a mano: se calculan al leer (por servicio → ajuste
// anual del panel → valor por defecto del tipo), así un cambio del ajuste
// anual alcanza a lo que sigue abierto.
//   Estados: abierto → (asesor «Dar por terminado») por_confirmar →
//   terminado (cliente «Sí, terminado», o su conformidad al informe) |
//   cerrado_sin_respuesta (el asesor, a los 15 días). «Tengo algo
//   pendiente» (o pedir cambios en el informe) lo devuelve a abierto.
//   Un servicio NUNCA se cierra por plazo: vencer solo lo marca.
// El enlace con documentos, mensajes y entregas sigue siendo
// propuesta_id + servicio (el id de la propuesta, p. ej. 'pg2025').
// ================================================================
const DIAS_CIERRE_SIN_RESPUESTA = 15;
const ANIO_MINIMO_EJERCICIO = 2009;
const AVISO_PLAZO_VENTANA_GENERAL = 10;   // días de urgencia si el tipo no dice otra cosa
const TIPOS_SERVICIO = {
  pyg:            { legacy: 'pg2025',     rango: false, nombre: { es: a => `Informe de pérdidas y ganancias ${a}`, en: a => `Gains and losses report ${a}` } },
  pyg_anteriores: { legacy: 'pganterior', rango: true,  nombre: { es: a => `Informe P&G de ejercicios anteriores (${a})`, en: a => `Gains and losses report, previous years (${a})` } },   // 21/10: que no se confunda con el P&G del año
  origen:         { legacy: 'origen',     rango: true,  sinAnio: true, nombre: { es: () => 'Origen de fondos', en: () => 'Source of funds' } },
  certificado:    { legacy: 'certificado', rango: true, sinAnio: true, nombre: { es: () => 'Certificado de valoración', en: () => 'Valuation certificate' } },
  nft:            { legacy: 'nft',        rango: true,  sinAnio: true, nombre: { es: () => 'Operaciones con NFT', en: () => 'NFT transactions' } },
  renta:          { legacy: 'renta',      rango: false, plazo: { mes: 6, dia: 30, sig: 1 }, ventana: 10, nombre: { es: a => `Declaración de la Renta ${a}`, en: a => `${a} income tax return` } },
  m714:           { legacy: 'm714',       rango: false, plazo: { mes: 6, dia: 30, sig: 1 }, ventana: 10, nombre: { es: a => `Modelo 714 (${a})`, en: a => `Form 714 (${a})` } },
  m720:           { legacy: 'm720',       rango: false, plazo: { mes: 3, dia: 31, sig: 1 }, ventana: 10, nombre: { es: a => `Modelo 720 (${a})`, en: a => `Form 720 (${a})` } },
  m721:           { legacy: 'm721',       rango: false, plazo: { mes: 3, dia: 31, sig: 1 }, ventana: 10, nombre: { es: a => `Modelo 721 (${a})`, en: a => `Form 721 (${a})` } },
  requerimiento:  { legacy: 'requerimiento', rango: true, ventana: 5, nombre: { es: a => `Requerimiento de Hacienda (${a})`, en: a => `Tax office request (${a})` } },   // el plazo es el de la carta: se pone a mano
  acompanamiento: { legacy: 'acompanamiento', rango: true, sinAnio: true, nombre: { es: () => 'Acompañamiento fiscal', en: () => 'Tax support' } },
  optimizacion:   { legacy: 'optimizacion', rango: false, plazo: { mes: 12, dia: 31, sig: 0 }, ventana: 16, nombre: { es: a => `Optimización fin de año ${a}`, en: a => `Year-end optimisation ${a}` } },   // urgente desde el 15/12
};
// 21/10: nombre sin año (servicios con el ejercicio aún sin confirmar, avisos de propuestas repetidas)
TIPOS_SERVICIO.pyg.generico = { es: 'Informe de pérdidas y ganancias', en: 'Gains and losses report' };
TIPOS_SERVICIO.pyg_anteriores.generico = { es: 'Informe P&G de ejercicios anteriores', en: 'Gains and losses report, previous years' };
TIPOS_SERVICIO.origen.generico = { es: 'Origen de fondos', en: 'Source of funds' };
TIPOS_SERVICIO.certificado.generico = { es: 'Certificado de valoración', en: 'Valuation certificate' };
TIPOS_SERVICIO.nft.generico = { es: 'Operaciones con NFT', en: 'NFT transactions' };
TIPOS_SERVICIO.renta.generico = { es: 'Declaración de la Renta', en: 'Income tax return' };
TIPOS_SERVICIO.m714.generico = { es: 'Modelo 714', en: 'Form 714' };
TIPOS_SERVICIO.m720.generico = { es: 'Modelo 720', en: 'Form 720' };
TIPOS_SERVICIO.m721.generico = { es: 'Modelo 721', en: 'Form 721' };
TIPOS_SERVICIO.requerimiento.generico = { es: 'Requerimiento de Hacienda', en: 'Tax office request' };
TIPOS_SERVICIO.acompanamiento.generico = { es: 'Acompañamiento fiscal', en: 'Tax support' };
TIPOS_SERVICIO.optimizacion.generico = { es: 'Optimización fin de año', en: 'Year-end optimisation' };

const TIPOS_ANIO_AMBIGUO = new Set(['renta', 'm714', 'm720', 'm721', 'pyg', 'pyg_anteriores', 'requerimiento']);   // su ejercicio, deducido, se enseña a revisar

// --- Fechas (todo en texto AAAA-MM-DD; sin zonas horarias de por medio) ---
const FECHA_ISO_SERV = /^\d{4}-\d{2}-\d{2}$/;
function fechaISOValida(s) {
  if (typeof s !== 'string' || !FECHA_ISO_SERV.test(s)) return false;
  const d = new Date(s + 'T12:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}
const diasEntreISO = (aISO, bISO) => Math.round((Date.parse(aISO + 'T12:00:00Z') - Date.parse(bISO + 'T12:00:00Z')) / 864e5);
const sumaDiasISO = (iso, n) => new Date(Date.parse(iso + 'T12:00:00Z') + n * 864e5).toISOString().slice(0, 10);
const fechaES = iso => iso ? iso.slice(8, 10) + '/' + iso.slice(5, 7) + '/' + iso.slice(0, 4) : '';
const hoyMadridISO = () => fechaMadrid().fecha;
function anioValido(n) { return Number.isInteger(n) && n >= ANIO_MINIMO_EJERCICIO && n <= Number(hoyMadridISO().slice(0, 4)) + 1; }

// --- Tipo, ejercicio y plazo por defecto ---
function tipoDeServicio(id) {
  const s = String(id);
  for (const [t, d] of Object.entries(TIPOS_SERVICIO)) if (d.legacy === s || t === s) return t;
  return s.toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 40) || 'otro';
}
// Ejercicio que se asume si el asesor no lo ha indicado: el de la próxima
// presentación por vencer (si la fecha está dentro del plazo de la campaña,
// el ejercicio anterior; si ya pasó, el actual). Siempre se enseña a revisar.
function ejercicioPorDefecto(tipo, fechaISO) {
  const anio = Number(fechaISO.slice(0, 4)), md = fechaISO.slice(5);
  switch (tipo) {
    case 'renta': case 'm714': case 'pyg': return md <= '06-30' ? anio - 1 : anio;
    case 'm720': case 'm721': return md <= '03-31' ? anio - 1 : anio;
    case 'pyg_anteriores': case 'requerimiento': return anio - 1;
    default: return anio;
  }
}
function textoDeduccion(tipo, fechaISO, ejercicio) {
  const anio = Number(fechaISO.slice(0, 4)), base = 'Encargo del ' + fechaES(fechaISO) + ': ';
  if (['renta', 'm714', 'm720', 'm721', 'pyg'].includes(tipo)) {
    return base + (ejercicio === anio - 1 ? 'dentro de la campaña, se asume el ejercicio anterior (' + ejercicio + ')' : 'pasado el plazo de la campaña, se asume el ejercicio en curso (' + ejercicio + ')');
  }
  if (tipo === 'pyg_anteriores' || tipo === 'requerimiento') return base + 'se asume el ejercicio anterior (' + ejercicio + '); indica el rango o el año real';
  return 'Año de referencia: el del encargo (' + ejercicio + ')';
}
function plazoPorDefectoDeTipo(tipo, ejercicioHasta) {
  const d = TIPOS_SERVICIO[tipo];
  if (!d || !d.plazo) return null;
  return `${ejercicioHasta + d.plazo.sig}-${String(d.plazo.mes).padStart(2, '0')}-${String(d.plazo.dia).padStart(2, '0')}`;
}
function validarEjercicio(tipo, desdeIn, hastaIn) {
  const def = TIPOS_SERVICIO[tipo];
  const desde = Number(desdeIn), hasta = (hastaIn === undefined || hastaIn === null || hastaIn === '') ? desde : Number(hastaIn);
  if (!anioValido(desde) || !anioValido(hasta)) return { error: 'El ejercicio debe ser un año entre ' + ANIO_MINIMO_EJERCICIO + ' y ' + (Number(hoyMadridISO().slice(0, 4)) + 1) };
  if (hasta < desde) return { error: 'El ejercicio final no puede ser anterior al inicial' };
  if (hasta !== desde && !(def && def.rango)) return { error: 'Este servicio es de un único ejercicio' };
  return { desde, hasta };
}
const etiquetaEjercicio = (desde, hasta) => desde === hasta ? String(hasta) : `${desde}–${hasta}`;
function nombreServicio(f, idioma, duplicado) {
  const def = TIPOS_SERVICIO[f.tipo];
  if (!def) return f.servicio;
  const a = etiquetaEjercicio(f.ejercicio_desde, f.ejercicio_hasta);
  let n = def.nombre[idioma](a);
  if (def.sinAnio && duplicado) n += ` (${a})`;   // dos del mismo tipo: se distinguen por el año
  return n;
}

// --- Claves internas, únicas por cliente ---
async function claveUnica(conn, clienteId, tipo, desde, hasta, excluirId) {
  const base = `${tipo}-${desde}` + (hasta !== desde ? `-${hasta}` : '');
  for (let n = 1; n < 200; n++) {
    const clave = n === 1 ? base : `${base}-${n}`;
    const [f] = await conn.execute('SELECT id FROM servicios_cliente WHERE cliente_id = ? AND clave = ? AND id <> ?', [clienteId, clave, excluirId || 0]);
    if (!f.length) return clave;
  }
  throw new Error('No se pudo generar una clave de servicio única');
}
async function apuntarServicio(conn, servicioId, evento, autor, asesorId, detalle) {
  await conn.execute('INSERT INTO servicios_historial (servicio_id, evento, autor, asesor_id, detalle) VALUES (?, ?, ?, ?, ?)',
    [servicioId, evento, autor, asesorId || null, detalle ? String(detalle).slice(0, 300) : null]).catch(err => console.error('Historial de servicio:', err.message));
}

// --- Alta de las filas de servicio de un encargo (idempotente) ---
// Nativo (al aceptar la propuesta): ejercicio del asesor o, si no lo indicó,
// el que corresponde por la fecha de hoy. Migración (encargos anteriores a
// esta función): ejercicio deducido de la fecha del encargo, SIN confirmar:
// no se usa hasta que un administrador lo confirma.
async function crearServiciosDePropuesta(conn, p, { migracion = false } = {}) {
  const ids = [...new Set(serviciosDePropuesta(p))];
  if (!ids.length) return 0;
  const [ya] = await conn.execute('SELECT servicio FROM servicios_cliente WHERE propuesta_id = ?', [p.id]);
  const existentes = new Set(ya.map(x => x.servicio));
  let detalle = {}; try { detalle = JSON.parse(p.servicios_detalle || '{}') || {}; } catch (e) { detalle = {}; }
  const refISO = migracion ? fechaMadrid(new Date(p.creado_en)).fecha : hoyMadridISO();
  let creados = 0;
  for (const id of ids) {
    if (existentes.has(id)) continue;
    const tipo = tipoDeServicio(id);
    const d = detalle[id];
    let desde, hasta, origen, deduccion = null, confianza = null, plazoPropio = null;
    if (d && anioValido(d.desde) && anioValido(d.hasta)) {
      desde = d.desde; hasta = d.hasta; origen = 'asesor'; plazoPropio = fechaISOValida(d.plazo) ? d.plazo : null;
    } else {
      desde = hasta = ejercicioPorDefecto(tipo, refISO);
      origen = migracion ? 'migracion' : 'defecto';
      deduccion = textoDeduccion(tipo, refISO, hasta);
      confianza = TIPOS_ANIO_AMBIGUO.has(tipo) ? 'revisar' : 'alta';
    }
    // En una migración, lo que ya tenga un informe aceptado por el cliente está terminado
    let estado = 'abierto', cierreVia = null, cerradoEn = null;
    if (migracion) {
      const [ult] = await conn.execute('SELECT estado, respondido_en FROM entregas WHERE propuesta_id = ? AND servicio = ? ORDER BY id DESC LIMIT 1', [p.id, id]);
      if (ult.length && ult[0].estado === 'conforme') { estado = 'terminado'; cierreVia = 'informe'; cerradoEn = ult[0].respondido_en || null; }
    }
    let insertado = false;
    for (let intento = 0; intento < 5 && !insertado; intento++) {
      const clave = await claveUnica(conn, p.cliente_id, tipo, desde, hasta, 0);
      try {
        const [r] = await conn.execute(
          'INSERT INTO servicios_cliente (cliente_id, propuesta_id, servicio, tipo, ejercicio_desde, ejercicio_hasta, clave, plazo_propio, estado, cierre_via, cerrado_en, ejercicio_origen, confirmado, deduccion, confianza, aviso_urgencia) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          [p.cliente_id, p.id, id, tipo, desde, hasta, clave, plazoPropio, estado, cierreVia, cerradoEn, origen, migracion ? 0 : 1, deduccion, confianza, migracion ? 'base' : null]);   // migrado: su urgencia ya se sabía
        insertado = true; creados++;
        await apuntarServicio(conn, r.insertId, migracion ? 'migrado' : 'creado', 'sistema', null, clave);
      } catch (err) { if (err.code !== 'ER_DUP_ENTRY') throw err; }   // otro proceso tomó la clave: se recalcula
    }
  }
  return creados;
}
async function migrarServiciosExistentes() {
  const [ps] = await pool.query("SELECT p.* FROM propuestas p JOIN clientes c ON c.id = p.cliente_id WHERE p.estado = 'aceptada' AND c.estado = 'activo' AND NOT EXISTS (SELECT 1 FROM servicios_cliente s WHERE s.propuesta_id = p.id) ORDER BY p.id");
  let n = 0;
  for (const p of ps) {
    const conn = await pool.getConnection();
    try { n += await crearServiciosDePropuesta(conn, p, { migracion: true }); }
    catch (err) { console.error('Migración de servicios del encargo ' + p.id + ':', err.message); }
    finally { conn.release(); }
  }
  if (n) console.log('Servicios migrados a ejercicio/plazo/estado: ' + n + ' (pendientes de confirmar por un administrador).');
}
// Los ejercicios que indica el asesor al enviar la propuesta: { "renta": 2025 } o
// { "pganterior": { desde: 2021, hasta: 2024 }, "requerimiento": { desde: 2024, plazo: "2026-12-15" } }
function normalizarEjerciciosPropuesta(ejercicios, ids) {
  if (ejercicios === undefined || ejercicios === null) return { detalle: null };
  if (typeof ejercicios !== 'object' || Array.isArray(ejercicios)) return { error: 'Los ejercicios deben indicarse por servicio' };
  const detalle = {};
  for (const [id, v] of Object.entries(ejercicios)) {
    if (!ids.includes(id)) return { error: `Has indicado un ejercicio para «${id}», que no está en la propuesta` };
    const o = (v && typeof v === 'object') ? v : { desde: v };
    const e = validarEjercicio(tipoDeServicio(id), o.desde !== undefined ? o.desde : o.ejercicio_desde, o.hasta !== undefined ? o.hasta : o.ejercicio_hasta);
    if (e.error) return { error: `${id}: ${e.error}` };
    let plazo = null;
    if (o.plazo !== undefined && o.plazo !== null && o.plazo !== '') { if (!fechaISOValida(o.plazo)) return { error: `${id}: el plazo debe ser una fecha AAAA-MM-DD` }; plazo = o.plazo; }
    detalle[id] = { desde: e.desde, hasta: e.hasta, plazo };
  }
  return { detalle: Object.keys(detalle).length ? detalle : null };
}

// --- Lectura: plazo efectivo, estado del plazo y vista de un servicio ---
async function plazosConfigurados(conn) {
  const [f] = await conn.query("SELECT tipo, ejercicio, DATE_FORMAT(plazo, '%Y-%m-%d') AS plazo, ventana_dias FROM plazos_defecto");
  return new Map(f.map(x => [`${x.tipo}|${x.ejercicio}`, { plazo: x.plazo, ventana_dias: x.ventana_dias }]));
}
const SQL_SERVICIOS = `SELECT s.id, s.cliente_id, s.propuesta_id, s.servicio, s.tipo, s.ejercicio_desde, s.ejercicio_hasta, s.clave,
    DATE_FORMAT(s.plazo_propio, '%Y-%m-%d') AS plazo_propio, s.ventana_propia, DATE_FORMAT(s.presentado_en, '%Y-%m-%d') AS presentado_en,
    s.estado, s.propuesto_en, s.propuesto_por, s.cerrado_en, s.cerrado_por, s.cierre_via, s.ejercicio_origen, s.confirmado, s.deduccion, s.confianza, s.creado_en,
    (SELECT a.nombre FROM asesores a WHERE a.id = s.propuesto_por) AS propuesto_por_nombre,
    (SELECT COUNT(*) FROM documentos_fiscales d WHERE d.propuesta_id = s.propuesta_id AND d.servicio = s.servicio AND d.estado IN ('pendiente','rechazado')) AS docs_pendientes,
    (SELECT COUNT(*) FROM documentos_fiscales d WHERE d.propuesta_id = s.propuesta_id AND d.servicio = s.servicio AND d.estado = 'enviado') AS docs_por_revisar,
    (SELECT e.estado FROM entregas e WHERE e.propuesta_id = s.propuesta_id AND e.servicio = s.servicio ORDER BY e.id DESC LIMIT 1) AS entrega_estado
  FROM servicios_cliente s`;
function vistaServicio(f, cfg, hoyISO, duplicado) {
  const def = TIPOS_SERVICIO[f.tipo];
  const c = cfg.get(`${f.tipo}|${f.ejercicio_hasta}`) || {};
  let plazo = null, plazoOrigen = null;
  if (f.plazo_propio) { plazo = f.plazo_propio; plazoOrigen = 'servicio'; }
  else if (c.plazo) { plazo = c.plazo; plazoOrigen = 'config'; }
  else { const d = plazoPorDefectoDeTipo(f.tipo, f.ejercicio_hasta); if (d) { plazo = d; plazoOrigen = 'defecto'; } }
  const ventana = f.ventana_propia != null ? f.ventana_propia : (c.ventana_dias != null ? c.ventana_dias : (def && def.ventana != null ? def.ventana : AVISO_PLAZO_VENTANA_GENERAL));
  const enCurso = f.estado === 'abierto' || f.estado === 'por_confirmar';
  let plazoEstado = null, dias = null;
  // Un servicio sin confirmar (migración) o ya presentado no avisa: su plazo no cuenta
  if (plazo && enCurso && !f.presentado_en && f.confirmado) {
    dias = diasEntreISO(plazo, hoyISO);
    plazoEstado = dias < 0 ? 'vencido' : dias <= ventana ? 'urgente' : 'normal';
  }
  let puedeCerrar = false, cerrarDesde = null;
  if (f.estado === 'por_confirmar' && f.propuesto_en) {
    cerrarDesde = sumaDiasISO(fechaMadrid(new Date(f.propuesto_en)).fecha, DIAS_CIERRE_SIN_RESPUESTA);
    puedeCerrar = hoyISO >= cerrarDesde;
  }
  const motivos = [];
  if (enCurso && f.confirmado) {
    if (f.estado === 'por_confirmar') motivos.push('confirmar');
    if (f.docs_pendientes > 0) motivos.push('documentos');
    if (plazoEstado === 'vencido') motivos.push('plazo_vencido');
    else if (plazoEstado === 'urgente') motivos.push('plazo_urgente');
  }
  return {
    id: f.id, cliente_id: f.cliente_id, propuesta_id: f.propuesta_id, servicio: f.servicio, tipo: f.tipo, clave: f.clave,
    ejercicio_desde: f.ejercicio_desde, ejercicio_hasta: f.ejercicio_hasta, ejercicio: f.ejercicio_hasta,   // «ejercicio» = el de la burbuja (el último del rango)
    es_rango: f.ejercicio_desde !== f.ejercicio_hasta,
    admite_rango: !!(def && def.rango),
    nombre_es: nombreServicio(f, 'es', duplicado), nombre_en: nombreServicio(f, 'en', duplicado),
    estado: f.estado, en_curso: enCurso,
    plazo, plazo_origen: plazoOrigen, ventana_dias: ventana, plazo_estado: plazoEstado, dias_restantes: dias,
    presentado_en: f.presentado_en,
    propuesto_en: f.propuesto_en, propuesto_por_nombre: f.propuesto_por_nombre || null,
    puede_cerrar_sin_respuesta: puedeCerrar, cerrar_sin_respuesta_desde: cerrarDesde,
    cerrado_en: f.cerrado_en, cierre_via: f.cierre_via,
    docs_pendientes: f.docs_pendientes, docs_por_revisar: f.docs_por_revisar, entrega_estado: f.entrega_estado || null,
    necesita_atencion: motivos.length > 0, motivos_atencion: motivos,
    ejercicio_origen: f.ejercicio_origen, confirmado: !!f.confirmado, deduccion: f.deduccion, confianza: f.confianza, creado_en: f.creado_en,
  };
}
const CAMPOS_CLIENTE_SERVICIO = ['sin_confirmar', 'id', 'propuesta_id', 'servicio', 'tipo', 'clave', 'ejercicio_desde', 'ejercicio_hasta', 'ejercicio', 'es_rango', 'nombre_es', 'nombre_en', 'estado', 'en_curso',
  'plazo', 'ventana_dias', 'plazo_estado', 'dias_restantes', 'presentado_en', 'propuesto_en', 'cerrado_en', 'cierre_via', 'docs_pendientes', 'entrega_estado', 'necesita_atencion', 'motivos_atencion', 'progreso'];
const paraCliente = v => Object.fromEntries(CAMPOS_CLIENTE_SERVICIO.map(k => [k, v[k]]));
// Dos servicios del mismo tipo en un cliente se distinguen por el año en el nombre; se mira en TODA su
// lista (no solo en las filas devueltas), para que el nombre no cambie según el filtro
async function vistasDeFilas(conn, filas) {
  const [dup] = await conn.query('SELECT cliente_id, tipo FROM servicios_cliente GROUP BY cliente_id, tipo HAVING COUNT(*) > 1');
  const dups = new Set(dup.map(x => x.cliente_id + '|' + x.tipo));
  const cfg = await plazosConfigurados(conn), hoy = hoyMadridISO();
  const vistas = filas.map(f => vistaServicio(f, cfg, hoy, dups.has(f.cliente_id + '|' + f.tipo)));
  await ponerProgreso(conn, vistas);   // 30/10: un solo cálculo del progreso para el panel, la ficha y el Área
  return vistas;
}
// ---- 30/10 (Vikn): progreso de un servicio, el mismo en todas partes ----
// Encargo: propuesta enviada 10 · aceptada sin pagar 20 · pago por confirmar 30 · alta pendiente 45 (con «pagar después», el pago no frena).
// Servicio: pagado o en marcha 50 · faltan documentos 60 (manda lo que falta) · documentos por revisar 70 · documentación completa 80 ·
// el cliente pide cambios 85 · informe entregado 90 · terminado, falta que confirme 95 · terminado 100.
function progresoServicio(v, e, validos) {
  if (e) {
    if (e.estado === 'rechazada' || e.estado === 'caducada') return 0;
    if (e.estado === 'enviada') return 10;
    if (e.cobro !== 'despues') { if (!e.pago) return 20; if (e.pago !== 'confirmado') return 30; }
    if (e.alta === 'rechazado') return 0;
    if (e.alta !== 'aprobado') return 45;
  }
  if (!v.en_curso) return 100;
  if (v.estado === 'por_confirmar') return 95;
  if (v.entrega_estado === 'entregado') return 90;
  if (v.entrega_estado === 'cambios') return 85;
  if (Number(v.docs_pendientes) > 0) return 60;
  if (Number(v.docs_por_revisar) > 0) return 70;
  return validos > 0 ? 80 : 50;
}
async function estadoEncargos(conn, ids) {
  const enc = {}; if (!ids.length) return enc;
  const [ps] = await conn.query('SELECT id, estado, cobro FROM propuestas WHERE id IN (?)', [ids]);
  const [pg] = await conn.query('SELECT propuesta_id, estado FROM pagos WHERE propuesta_id IN (?) ORDER BY id', [ids]);
  const [dl] = await conn.query('SELECT propuesta_id, estado FROM diligencias WHERE propuesta_id IN (?) ORDER BY id', [ids]);
  ps.forEach(p => { enc[p.id] = { estado: p.estado, cobro: p.cobro || 'antes', pago: null, alta: null }; });
  pg.forEach(g => { const e = enc[g.propuesta_id]; if (e && e.pago !== 'confirmado') e.pago = g.estado; });
  dl.forEach(d => { const e = enc[d.propuesta_id]; if (e) e.alta = d.estado; });
  return enc;
}
async function ponerProgreso(conn, vistas) {
  const ids = [...new Set(vistas.map(v => v.propuesta_id).filter(Boolean))];
  if (!ids.length) return vistas;
  const enc = await estadoEncargos(conn, ids);
  const [dv] = await conn.query("SELECT propuesta_id, servicio, SUM(estado = 'valido') AS v FROM documentos_fiscales WHERE propuesta_id IN (?) GROUP BY propuesta_id, servicio", [ids]);
  const val = {}; dv.forEach(x => { val[x.propuesta_id + '|' + x.servicio] = Number(x.v) || 0; });
  vistas.forEach(v => { v.progreso = progresoServicio(v, enc[v.propuesta_id], val[v.propuesta_id + '|' + v.servicio] || 0); });
  return vistas;
}
async function listarServiciosCliente(conn, clienteId, { soloConfirmados = false } = {}) {
  const [filas] = await conn.query(SQL_SERVICIOS + ' WHERE s.cliente_id = ?' + (soloConfirmados ? ' AND s.confirmado = 1' : ' AND s.confirmado IN (0, 1)') + ' ORDER BY s.ejercicio_hasta DESC, s.id', [clienteId]);   // 20/10: sin los fusionados (duplicados)
  return vistasDeFilas(conn, filas);
}
async function servicioPorId(conn, id) {
  const [f] = await conn.query(SQL_SERVICIOS + ' WHERE s.id = ?', [id]);
  return f[0] || null;
}
async function vistaPorId(conn, id) {
  const f = await servicioPorId(conn, id);
  if (!f) return null;
  return (await vistasDeFilas(conn, [f]))[0];
}
async function reclaveServicio(conn, f, desde, hasta) {
  const clave = await claveUnica(conn, f.cliente_id, f.tipo, desde, hasta, f.id);
  await conn.execute('UPDATE servicios_cliente SET ejercicio_desde = ?, ejercicio_hasta = ?, clave = ? WHERE id = ?', [desde, hasta, clave, f.id]);
  return clave;
}
// Fusión de fichas: los servicios del duplicado pasan a la principal con clave nueva si chocan
async function moverServiciosDeCliente(conn, desde, hacia) {
  const [fs] = await conn.execute('SELECT id, tipo, ejercicio_desde, ejercicio_hasta FROM servicios_cliente WHERE cliente_id = ? ORDER BY id', [desde]);
  for (const f of fs) {
    const clave = await claveUnica(conn, hacia, f.tipo, f.ejercicio_desde, f.ejercicio_hasta, f.id);
    await conn.execute('UPDATE servicios_cliente SET cliente_id = ?, clave = ? WHERE id = ?', [hacia, clave, f.id]);
  }
}
// La conformidad del cliente a un informe da el servicio por terminado; pedir cambios lo reabre
async function cerrarServicioPorInforme(conn, propuesta, servicio) {
  const [r] = await conn.execute("UPDATE servicios_cliente SET estado = 'terminado', cierre_via = 'informe', cerrado_en = NOW() WHERE propuesta_id = ? AND servicio = ? AND estado IN ('abierto','por_confirmar')", [propuesta.id, servicio]);
  if (r.affectedRows) { const [f] = await conn.execute('SELECT id FROM servicios_cliente WHERE propuesta_id = ? AND servicio = ?', [propuesta.id, servicio]); if (f.length) await apuntarServicio(conn, f[0].id, 'terminado_informe', 'cliente', null, 'conformidad al informe'); }
}
async function reabrirServicioPorCambios(conn, propuesta, servicio) {
  const [f] = await conn.execute("SELECT id FROM servicios_cliente WHERE propuesta_id = ? AND servicio = ? AND estado <> 'abierto'", [propuesta.id, servicio]);
  if (!f.length) return;
  await conn.execute("UPDATE servicios_cliente SET estado = 'abierto', propuesto_en = NULL, propuesto_por = NULL, cerrado_en = NULL, cerrado_por = NULL, cierre_via = NULL WHERE id = ?", [f[0].id]);
  await apuntarServicio(conn, f[0].id, 'reabierto', 'cliente', null, 'pide cambios en el informe');
}

// --- Rutas del panel ---
const soloAdministrador = (req, res, next) => (req.asesor && req.asesor.esAdmin) ? next() : res.status(403).json({ error: 'Solo un administrador puede hacer esto' });
const TEXTO_CIERRE_PROPUESTO = 'He dado por terminado este servicio. Si estás conforme, confírmalo desde tu área; si te falta algo, cuéntamelo por aquí y lo seguimos.';

// Tipos de servicio con su plazo de ese ejercicio (para el formulario de propuesta y el ajuste anual)
app.get('/api/admin/servicios/tipos', requiereSesionAsesor, async (req, res) => {
  const ejercicio = Number(req.query.ejercicio) || Number(hoyMadridISO().slice(0, 4));
  const cfg = await plazosConfigurados(pool);
  res.json({
    ejercicio, cierre_sin_respuesta_dias: DIAS_CIERRE_SIN_RESPUESTA,
    tipos: Object.entries(TIPOS_SERVICIO).map(([tipo, d]) => {
      const c = cfg.get(`${tipo}|${ejercicio}`) || {};
      const defecto = plazoPorDefectoDeTipo(tipo, ejercicio);
      return {
        tipo, servicio: d.legacy, nombre_es: d.nombre.es(ejercicio), nombre_en: d.nombre.en(ejercicio), admite_rango: !!d.rango,
        tiene_plazo: !!d.plazo, plazo: c.plazo || defecto, plazo_origen: c.plazo ? 'config' : defecto ? 'defecto' : null, plazo_defecto: defecto,
        ventana_dias: c.ventana_dias != null ? c.ventana_dias : (d.ventana != null ? d.ventana : AVISO_PLAZO_VENTANA_GENERAL), ventana_defecto: d.ventana != null ? d.ventana : AVISO_PLAZO_VENTANA_GENERAL,
        ejercicio_sugerido: ejercicioPorDefecto(tipo, hoyMadridISO()),
      };
    }),
  });
});
// Ajuste anual de plazos (solo administradores): { ejercicio, plazos: { renta: { plazo: 'AAAA-MM-DD'|null, ventana_dias: n|null } } }
app.put('/api/admin/plazos', requiereSesionAsesor, soloAdministrador, async (req, res) => {
  const b = req.body || {};
  const ejercicio = Number(b.ejercicio);
  if (!anioValido(ejercicio)) return res.status(400).json({ error: 'Indica el ejercicio (un año válido)' });
  if (!b.plazos || typeof b.plazos !== 'object' || Array.isArray(b.plazos)) return res.status(400).json({ error: 'Faltan los plazos' });
  const cambios = [];
  for (const [tipo, v] of Object.entries(b.plazos)) {
    if (!TIPOS_SERVICIO[tipo]) return res.status(400).json({ error: `Tipo de servicio desconocido: ${tipo}` });
    const o = v || {};
    const plazo = (o.plazo === undefined || o.plazo === null || o.plazo === '') ? null : o.plazo;
    if (plazo !== null && !fechaISOValida(plazo)) return res.status(400).json({ error: `${tipo}: el plazo debe ser una fecha AAAA-MM-DD` });
    let ventana = null;
    if (o.ventana_dias !== undefined && o.ventana_dias !== null && o.ventana_dias !== '') {
      ventana = Number(o.ventana_dias);
      if (!Number.isInteger(ventana) || ventana < 0 || ventana > 120) return res.status(400).json({ error: `${tipo}: la ventana de urgencia son entre 0 y 120 días` });
    }
    cambios.push([tipo, plazo, ventana]);
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const [tipo, plazo, ventana] of cambios) {
      if (plazo === null && ventana === null) await conn.execute('DELETE FROM plazos_defecto WHERE tipo = ? AND ejercicio = ?', [tipo, ejercicio]);   // vuelve al valor por defecto
      else await conn.execute('INSERT INTO plazos_defecto (tipo, ejercicio, plazo, ventana_dias, actualizado_por) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE plazo = VALUES(plazo), ventana_dias = VALUES(ventana_dias), actualizado_por = VALUES(actualizado_por)', [tipo, ejercicio, plazo, ventana, req.asesor.id]);
    }
    await conn.commit();
    res.json({ ok: true, ejercicio, actualizados: cambios.length });
  } catch (err) { await conn.rollback(); throw err; } finally { conn.release(); }
});

// Migración: los servicios de encargos anteriores, con el ejercicio deducido, para que un administrador los confirme
app.get('/api/admin/servicios/migracion', requiereSesionAsesor, soloAdministrador, async (req, res) => {
  const [filas] = await pool.query(SQL_SERVICIOS.replace('FROM servicios_cliente s', ', c.nombre AS cliente_nombre, c.apellidos AS cliente_apellidos, c.correo AS cliente_correo, c.codigo AS cliente_codigo, p.creado_en AS encargo_creado_en FROM servicios_cliente s JOIN clientes c ON c.id = s.cliente_id JOIN propuestas p ON p.id = s.propuesta_id') + ' WHERE s.confirmado = 0 ORDER BY s.cliente_id, s.propuesta_id, s.id');
  const vistas = await vistasDeFilas(pool, filas);
  const cands = await candidatosDuplicado(pool, [...new Set(filas.map(f => f.cliente_id))]);   // 20/10: posibles duplicados
  res.json({
    pendientes: vistas.length,
    items: vistas.map((v, i) => Object.assign(v, {
      cliente: { id: filas[i].cliente_id, nombre: [filas[i].cliente_nombre, filas[i].cliente_apellidos].filter(Boolean).join(' '), correo: filas[i].cliente_correo, codigo: filas[i].cliente_codigo },
      encargo_creado_en: filas[i].encargo_creado_en, admite_rango: !!(TIPOS_SERVICIO[v.tipo] && TIPOS_SERVICIO[v.tipo].rango),
      yo: cands.find(c => c.id === v.id) || null,
      candidatos_duplicado: cands.filter(c => c.id !== v.id && c.cliente_id === filas[i].cliente_id && c.tipo === v.tipo),
      posible_duplicado: cands.some(c => c.id !== v.id && c.cliente_id === filas[i].cliente_id && c.tipo === v.tipo && c.ejercicio_desde === v.ejercicio_desde && c.ejercicio_hasta === v.ejercicio_hasta),
    })),
  });
});
// { ids: [..] | todos: true, cambios: { "<id>": { ejercicio_desde, ejercicio_hasta, plazo } } }
app.post('/api/admin/servicios/migracion/confirmar', requiereSesionAsesor, soloAdministrador, async (req, res) => {
  const b = req.body || {};
  const conn = await pool.getConnection();
  try {
    const [pend] = await conn.query('SELECT id, tipo, cliente_id, ejercicio_desde, ejercicio_hasta FROM servicios_cliente WHERE confirmado = 0');
    const porId = new Map(pend.map(x => [x.id, x]));
    const objetivo = b.todos === true ? pend.map(x => x.id) : (Array.isArray(b.ids) ? b.ids.map(Number) : []);
    const cambios = (b.cambios && typeof b.cambios === 'object') ? b.cambios : {};
    const duplicados = (b.duplicados && typeof b.duplicados === 'object') ? Object.fromEntries(Object.entries(b.duplicados).map(([k, v]) => [Number(k), Number(v)])) : {};   // 20/10
    for (const [dId, tId] of Object.entries(duplicados)) if (duplicados[tId]) return res.status(400).json({ error: `El servicio ${tId} no puede quedarse y ser a la vez duplicado de otro` });
    for (const id of [...objetivo, ...Object.keys(cambios).map(Number)]) if (!porId.has(id)) return res.status(409).json({ error: `El servicio ${id} no está pendiente de confirmar` });
    if (!objetivo.length && !Object.keys(cambios).length && !Object.keys(duplicados).length) return res.status(400).json({ error: 'No hay nada que confirmar' });
    const aplicar = [];   // se valida todo antes de tocar nada
    for (const [idTxt, c] of Object.entries(cambios)) {
      const f = porId.get(Number(idTxt)); const o = c || {};
      const e = validarEjercicio(f.tipo, o.ejercicio_desde !== undefined ? o.ejercicio_desde : f.ejercicio_desde, o.ejercicio_hasta !== undefined ? o.ejercicio_hasta : (o.ejercicio_desde !== undefined && f.ejercicio_desde === f.ejercicio_hasta ? o.ejercicio_desde : f.ejercicio_hasta));
      if (e.error) return res.status(400).json({ error: `Servicio ${idTxt}: ${e.error}` });
      let plazo;   // undefined = no tocar
      if (o.plazo !== undefined) { if (o.plazo !== null && o.plazo !== '' && !fechaISOValida(o.plazo)) return res.status(400).json({ error: `Servicio ${idTxt}: el plazo debe ser una fecha AAAA-MM-DD` }); plazo = o.plazo || null; }
      aplicar.push({ f, e, plazo });
    }
    await conn.beginTransaction();
    for (const { f, e, plazo } of aplicar) {
      if (e.desde !== f.ejercicio_desde || e.hasta !== f.ejercicio_hasta) { await reclaveServicio(conn, f, e.desde, e.hasta); await apuntarServicio(conn, f.id, 'ejercicio_cambiado', 'asesor', req.asesor.id, `${etiquetaEjercicio(f.ejercicio_desde, f.ejercicio_hasta)} → ${etiquetaEjercicio(e.desde, e.hasta)}`); }
      if (plazo !== undefined) { await conn.execute('UPDATE servicios_cliente SET plazo_propio = ? WHERE id = ?', [plazo, f.id]); await apuntarServicio(conn, f.id, 'plazo_cambiado', 'asesor', req.asesor.id, plazo || 'sin plazo propio'); }
    }
    const confirmar = [...new Set([...objetivo, ...Object.keys(cambios).map(Number)])].filter(id => !duplicados[id]);
    if (confirmar.length) {
      await conn.query('UPDATE servicios_cliente SET confirmado = 1 WHERE id IN (?)', [confirmar]);
      for (const id of confirmar) await apuntarServicio(conn, id, 'confirmado', 'asesor', req.asesor.id, 'ejercicio confirmado');
    }
    let fusionados = 0;
    for (const [dId, tId] of Object.entries(duplicados)) {
      const r = await fusionarDuplicado(conn, Number(dId), tId, req.asesor.id);
      if (r.error) { await conn.rollback(); return res.status(r.error[0]).json({ error: `Servicio ${dId}: ${r.error[1]}` }); }
      fusionados++;
    }
    await conn.commit();
    res.json({ ok: true, confirmados: confirmar.length, fusionados, pendientes: pend.length - confirmar.length - fusionados });
  } catch (err) { await conn.rollback(); throw err; } finally { conn.release(); }
});

// Lista (p. ej. «Plazos que vencen»): ?estado=abierto,por_confirmar  ?plazo_estado=vencido,urgente  ?cliente_id=  ?ejercicio=
app.get('/api/admin/servicios', requiereSesionAsesor, async (req, res) => {
  const where = ['s.confirmado = 1', "c.estado = 'activo'"], params = [];   // un cliente inerte (alta rechazada, reembolsado) no genera avisos de plazo
  if (req.query.cliente_id) { where.push('s.cliente_id = ?'); params.push(Number(req.query.cliente_id)); }
  if (req.query.ejercicio) { where.push('s.ejercicio_hasta = ?'); params.push(Number(req.query.ejercicio)); }
  const estados = String(req.query.estado || '').split(',').filter(x => ['abierto', 'por_confirmar', 'terminado', 'cerrado_sin_respuesta'].includes(x));
  if (estados.length) { where.push('s.estado IN (?)'); params.push(estados); }
  const [filas] = await pool.query(SQL_SERVICIOS.replace('FROM servicios_cliente s', ', c.nombre AS cliente_nombre, c.apellidos AS cliente_apellidos, c.codigo AS cliente_codigo, (SELECT q.nombre FROM personas q WHERE q.id = c.asesor_persona_id) AS asesor_nombre FROM servicios_cliente s JOIN clientes c ON c.id = s.cliente_id') + ' WHERE ' + where.join(' AND ') + ' LIMIT 3000', params);
  let vistas = await vistasDeFilas(pool, filas);
  vistas.forEach((v, i) => { v.cliente_nombre = [filas[i].cliente_nombre, filas[i].cliente_apellidos].filter(Boolean).join(' '); v.cliente_codigo = filas[i].cliente_codigo; v.asesor_nombre = filas[i].asesor_nombre; });
  const pe = String(req.query.plazo_estado || '').split(',').filter(Boolean);
  if (pe.length) vistas = vistas.filter(v => pe.includes(v.plazo_estado));
  const rango = v => !v.en_curso ? 5 : v.plazo_estado === 'vencido' ? 0 : v.plazo_estado === 'urgente' ? 1 : v.plazo ? 2 : 3;
  vistas.sort((a, b) => rango(a) - rango(b) || (a.dias_restantes == null ? 1e9 : a.dias_restantes) - (b.dias_restantes == null ? 1e9 : b.dias_restantes) || a.id - b.id);
  res.json(vistas);
});
app.get('/api/admin/clientes/:id(\\d+)/servicios', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try { res.json(await listarServiciosCliente(conn, Number(req.params.id))); } finally { conn.release(); }
});
app.get('/api/admin/servicios/:id(\\d+)/historial', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT h.evento, h.autor, h.detalle, h.creado_en, a.nombre AS asesor FROM servicios_historial h LEFT JOIN asesores a ON a.id = h.asesor_id WHERE h.servicio_id = ? ORDER BY h.id DESC', [Number(req.params.id)]);
  res.json(f);
});
// Editar un servicio: ejercicio (o rango), plazo propio (null = vuelve al del ajuste anual), ventana de urgencia y fecha de presentación
app.put('/api/admin/servicios/:id(\\d+)', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), b = req.body || {};
  const conn = await pool.getConnection();
  try {
    const f = await servicioPorId(conn, id);
    if (!f) return res.status(404).json({ error: 'Servicio no encontrado' });
    const sets = [], vals = [], notas = [];
    let nuevoDesde = f.ejercicio_desde, nuevoHasta = f.ejercicio_hasta;
    if (b.ejercicio_desde !== undefined || b.ejercicio_hasta !== undefined) {
      const desdeIn = b.ejercicio_desde !== undefined ? b.ejercicio_desde : f.ejercicio_desde;
      const hastaIn = b.ejercicio_hasta !== undefined ? b.ejercicio_hasta : (b.ejercicio_desde !== undefined && f.ejercicio_desde === f.ejercicio_hasta ? b.ejercicio_desde : f.ejercicio_hasta);
      const e = validarEjercicio(f.tipo, desdeIn, hastaIn);
      if (e.error) return res.status(400).json({ error: e.error });
      nuevoDesde = e.desde; nuevoHasta = e.hasta;
    }
    if (b.plazo !== undefined) {
      if (b.plazo !== null && b.plazo !== '' && !fechaISOValida(b.plazo)) return res.status(400).json({ error: 'El plazo debe ser una fecha AAAA-MM-DD' });
      sets.push('plazo_propio = ?'); vals.push(b.plazo || null); notas.push(['plazo_cambiado', b.plazo ? 'plazo ' + b.plazo : 'plazo propio quitado']);
    }
    if (b.ventana_dias !== undefined) {
      const v = (b.ventana_dias === null || b.ventana_dias === '') ? null : Number(b.ventana_dias);
      if (v !== null && (!Number.isInteger(v) || v < 0 || v > 120)) return res.status(400).json({ error: 'La ventana de urgencia son entre 0 y 120 días' });
      sets.push('ventana_propia = ?'); vals.push(v); notas.push(['plazo_cambiado', v === null ? 'ventana por defecto' : 'ventana ' + v + ' días']);
    }
    if (b.presentado_en !== undefined) {
      if (b.presentado_en !== null && b.presentado_en !== '' && !fechaISOValida(b.presentado_en)) return res.status(400).json({ error: 'La fecha de presentación debe ser AAAA-MM-DD' });
      sets.push('presentado_en = ?'); vals.push(b.presentado_en || null); notas.push(['presentado', b.presentado_en ? 'presentado el ' + b.presentado_en : 'presentación quitada']);
    }
    const cambiaEjercicio = nuevoDesde !== f.ejercicio_desde || nuevoHasta !== f.ejercicio_hasta;
    if (!sets.length && !cambiaEjercicio) return res.status(400).json({ error: 'No hay nada que cambiar' });
    await conn.beginTransaction();
    if (sets.length) await conn.execute('UPDATE servicios_cliente SET ' + sets.join(', ') + ' WHERE id = ?', [...vals, id]);
    if (cambiaEjercicio) { await reclaveServicio(conn, f, nuevoDesde, nuevoHasta); await apuntarServicio(conn, id, 'ejercicio_cambiado', 'asesor', req.asesor.id, `${etiquetaEjercicio(f.ejercicio_desde, f.ejercicio_hasta)} → ${etiquetaEjercicio(nuevoDesde, nuevoHasta)}`); }
    for (const [ev, det] of notas) await apuntarServicio(conn, id, ev, 'asesor', req.asesor.id, det);
    await conn.commit();
    res.json({ ok: true, servicio: await vistaPorId(conn, id) });
  } catch (err) { await conn.rollback(); throw err; } finally { conn.release(); }
});
// El asesor da el servicio por terminado: pasa a «por confirmar» y el cliente lo ve en su aviso y en el chat
app.post('/api/admin/servicios/:id(\\d+)/dar-por-terminado', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), b = req.body || {};
  if (b.presentado_en !== undefined && b.presentado_en !== null && b.presentado_en !== '' && !fechaISOValida(b.presentado_en)) return res.status(400).json({ error: 'La fecha de presentación debe ser AAAA-MM-DD' });
  const conn = await pool.getConnection();
  try {
    const f = await servicioPorId(conn, id);
    if (!f) return res.status(404).json({ error: 'Servicio no encontrado' });
    if (!f.confirmado) return res.status(409).json({ error: 'Antes de cerrarlo hay que confirmar su ejercicio (migración pendiente)' });
    const [r] = await conn.execute("UPDATE servicios_cliente SET estado = 'por_confirmar', propuesto_en = NOW(), propuesto_por = ?, presentado_en = COALESCE(?, presentado_en) WHERE id = ? AND estado = 'abierto'", [req.asesor.id, b.presentado_en || null, id]);
    if (!r.affectedRows) return res.status(409).json({ error: 'Este servicio ya no está abierto (' + f.estado + ')' });
    const texto = textoMensaje(b.mensaje) || TEXTO_CIERRE_PROPUESTO;
    await conn.execute("INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, asesor_id, texto) VALUES (?, ?, ?, 'asesor', ?, ?)", [f.propuesta_id, f.cliente_id, f.servicio, req.asesor.id, texto]);
    await apuntarServicio(conn, id, 'propuesto_cierre', 'asesor', req.asesor.id, b.presentado_en ? 'presentado el ' + b.presentado_en : null);
    res.json({ ok: true, servicio: await vistaPorId(conn, id) });
  } finally { conn.release(); }
});
// A los 15 días sin respuesta del cliente, el asesor lo cierra
app.post('/api/admin/servicios/:id(\\d+)/cerrar-sin-respuesta', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    const f = await servicioPorId(conn, id);
    if (!f) return res.status(404).json({ error: 'Servicio no encontrado' });
    if (f.estado !== 'por_confirmar') return res.status(409).json({ error: 'Solo se puede cerrar sin respuesta un servicio que espera la confirmación del cliente (ahora: ' + f.estado + ')' });
    const v = (await vistasDeFilas(conn, [f]))[0];
    if (!v.puede_cerrar_sin_respuesta) return res.status(409).json({ error: 'Podrás cerrarlo sin respuesta a partir del ' + fechaES(v.cerrar_sin_respuesta_desde) + ' (' + DIAS_CIERRE_SIN_RESPUESTA + ' días después de pedir la confirmación)', desde: v.cerrar_sin_respuesta_desde });
    const [r] = await conn.execute("UPDATE servicios_cliente SET estado = 'cerrado_sin_respuesta', cierre_via = 'asesor', cerrado_en = NOW(), cerrado_por = ? WHERE id = ? AND estado = 'por_confirmar'", [req.asesor.id, id]);
    if (!r.affectedRows) return res.status(409).json({ error: 'El cliente acaba de responder' });
    await apuntarServicio(conn, id, 'cerrado_sin_respuesta', 'asesor', req.asesor.id, null);
    res.json({ ok: true, servicio: await vistaPorId(conn, id) });
  } finally { conn.release(); }
});
// Volver a abrir (retirar la petición de confirmación, o reabrir uno terminado o cerrado sin respuesta)
app.post('/api/admin/servicios/:id(\\d+)/reabrir', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    const f = await servicioPorId(conn, id);
    if (!f) return res.status(404).json({ error: 'Servicio no encontrado' });
    const [r] = await conn.execute("UPDATE servicios_cliente SET estado = 'abierto', propuesto_en = NULL, propuesto_por = NULL, cerrado_en = NULL, cerrado_por = NULL, cierre_via = NULL WHERE id = ? AND estado <> 'abierto'", [id]);
    if (!r.affectedRows) return res.status(409).json({ error: 'Este servicio ya está abierto' });
    await apuntarServicio(conn, id, 'reabierto', 'asesor', req.asesor.id, 'estaba ' + f.estado + (req.body && req.body.motivo ? ': ' + textoMensaje(req.body.motivo).slice(0, 200) : ''));
    res.json({ ok: true, servicio: await vistaPorId(conn, id) });
  } finally { conn.release(); }
});

// --- Rutas del Área del cliente (por el token de su propuesta, como el resto) ---
app.get('/api/propuestas/:token/servicios', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const lista = (await listarServiciosCliente(conn, p.cliente_id)).map(v => {
      if (v.confirmado) return v;
      // 21/10: aún sin confirmar su año: el cliente lo ve (cada servicio por separado), pero sin año deducido ni plazo
      const g = (TIPOS_SERVICIO[v.tipo] && TIPOS_SERVICIO[v.tipo].generico) || { es: v.nombre_es, en: v.nombre_en };
      return Object.assign({}, v, { sin_confirmar: true, ejercicio: null, ejercicio_desde: null, ejercicio_hasta: null, es_rango: false, nombre_es: g.es, nombre_en: g.en,
        plazo: null, plazo_estado: null, dias_restantes: null, ventana_dias: null, necesita_atencion: v.docs_pendientes > 0 || v.entrega_estado === 'entregado' });
    });
    const porEj = new Map();
    lista.filter(v => !v.sin_confirmar).forEach(v => {
      const e = porEj.get(v.ejercicio) || { ejercicio: v.ejercicio, en_curso: 0, terminados: 0, necesita_atencion: false };
      if (v.en_curso) e.en_curso++; else e.terminados++;
      if (v.necesita_atencion) e.necesita_atencion = true;
      porEj.set(v.ejercicio, e);
    });
    res.json({
      hoy: hoyMadridISO(),
      en_curso: lista.filter(v => v.en_curso).length, necesita_atencion: lista.filter(v => v.necesita_atencion).length,
      ejercicios: [...porEj.values()].sort((a, b) => b.ejercicio - a.ejercicio),
      servicios: lista.map(paraCliente),
    });
  } finally { conn.release(); }
});
async function servicioDelCliente(conn, token, id) {
  const p = await propuestaVigente(conn, token);
  if (!p) return { error: [404, 'Propuesta no encontrada'] };
  const f = await servicioPorId(conn, Number(id));
  if (!f || f.cliente_id !== p.cliente_id || (f.confirmado !== 0 && f.confirmado !== 1)) return { error: [404, 'Servicio no encontrado'] };   // 21/10: también los de año sin confirmar (no los fusionados)
  return { p, f };
}
app.post('/api/propuestas/:token/servicios/:id(\\d+)/terminado', exigirPagoConfirmado, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await servicioDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    const [u] = await conn.execute("UPDATE servicios_cliente SET estado = 'terminado', cierre_via = 'cliente', cerrado_en = NOW() WHERE id = ? AND estado = 'por_confirmar'", [r.f.id]);
    if (!u.affectedRows) return res.status(409).json({ error: r.f.estado === 'abierto' ? 'Tu asesor aún no ha dado este servicio por terminado' : 'Este servicio ya no espera tu confirmación' });
    await apuntarServicio(conn, r.f.id, 'terminado_cliente', 'cliente', null, null);
    avisarCliente(r.f.cliente_id, '✅', 'un cliente ha confirmado que su servicio está terminado', 'Queda cerrado.', { etiqueta: 'white_check_mark' });
    res.json({ ok: true, estado: 'terminado' });
  } finally { conn.release(); }
});
app.post('/api/propuestas/:token/servicios/:id(\\d+)/pendiente', exigirPagoConfirmado, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await servicioDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    const [u] = await conn.execute("UPDATE servicios_cliente SET estado = 'abierto', propuesto_en = NULL, propuesto_por = NULL WHERE id = ? AND estado = 'por_confirmar'", [r.f.id]);
    if (!u.affectedRows) return res.status(409).json({ error: 'Este servicio ya no espera tu confirmación' });
    const detalle = textoMensaje(req.body && req.body.texto);
    await conn.execute("INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, texto) VALUES (?, ?, ?, 'cliente', ?)", [r.f.propuesta_id, r.f.cliente_id, r.f.servicio, 'Tengo algo pendiente en este servicio.' + (detalle ? ' ' + detalle : '')]);
    await apuntarServicio(conn, r.f.id, 'pendiente_cliente', 'cliente', null, detalle ? detalle.slice(0, 200) : null);
    avisarCliente(r.f.cliente_id, '✏️', 'un cliente dice que tiene algo pendiente en un servicio', 'Lo tienes en «Mensajes sin leer» y en su ficha.', { prioridad: 4, etiqueta: 'pencil2' });
    res.json({ ok: true, estado: 'abierto' });
  } finally { conn.release(); }
});


// ================================================================
// «RECORDÁRSELO» DESDE LA FICHA (20/10, ACROS 7 · fase 2)
// En «Le toca al cliente» cada cosa que espera al cliente (un documento
// pedido o rechazado, la confirmación de un servicio dado por terminado) tiene
// su «Recordárselo»: un correo corto con el enlace a su área, respetando sus
// preferencias de avisos. Tope: uno al día por cosa, para no agobiar. Todo
// queda en la actividad del equipo (y, si es un servicio, en su historial).
// ================================================================
const HORAS_ENTRE_RECORDATORIOS = 24;
async function enviarRecordatorioCliente(conn, req, o) {
  const [ult] = await conn.execute('SELECT MAX(creado_en) AS ultimo FROM recordatorios_cliente WHERE tipo = ? AND objeto_id = ? AND creado_en > NOW() - INTERVAL ? HOUR', [o.tipo, o.objetoId, HORAS_ENTRE_RECORDATORIOS]);
  if (ult[0].ultimo) return { limite: true, ultimo: ult[0].ultimo };
  await conn.execute('INSERT INTO recordatorios_cliente (tipo, objeto_id, cliente_id, asesor_id) VALUES (?, ?, ?, ?)', [o.tipo, o.objetoId, o.clienteId, req.asesor.id]);
  const [cl] = await conn.execute('SELECT correo, nombre FROM clientes WHERE id = ?', [o.clienteId]);
  const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
  let correo = 'sin_correo';
  if (cl.length && cl[0].correo) {
    if (!brevoActivo()) correo = 'sin_servicio';
    else {
      const c = plantillaCorreo({
        titulo: o.titulo,
        parrafos: [cl[0].nombre ? `Hola, ${ESC_HTML(cl[0].nombre)}:` : 'Hola:', ...o.parrafos],
        boton: enlace ? { texto: 'Entrar en mi área', url: enlace } : null,
        nota: 'Por tu privacidad, no envíes documentos por correo: súbelos siempre desde tu área.',
      });
      try {
        const salio = await notificarCliente(conn, o.clienteId, 'recordatorios', () => enviarCorreo(cl[0].correo, o.asunto, c.html, c.texto), o.textoWA + (enlace ? ' ' + enlace : ''));
        correo = salio ? 'enviado' : 'desactivado_por_cliente';
      } catch (err) { console.error('Recordatorio al cliente no enviado:', err.message); correo = 'fallo'; }
    }
  }
  return { ok: true, correo };
}
const respuestaRecordatorio = (res, r) => r.limite
  ? res.status(429).json({ error: 'Ya se lo recordaste hoy. Podrás volver a hacerlo pasadas ' + HORAS_ENTRE_RECORDATORIOS + ' horas.', ultimo: r.ultimo })
  : res.json({ ok: true, correo: r.correo });

app.post('/api/admin/documentos/:id(\\d+)/recordar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT id, cliente_id, nombre, estado, razon_rechazo FROM documentos_fiscales WHERE id = ?', [Number(req.params.id)]);
    if (!f.length) return res.status(404).json({ error: 'Documento no encontrado' });
    const d = f[0];
    if (!['pendiente', 'rechazado'].includes(d.estado)) return res.status(409).json({ error: 'Ese documento ya no está pendiente del cliente' });
    const asesor = await personaDeCliente(d.cliente_id, conn).catch(() => null);
    const quien = asesor ? ESC_HTML(asesor.nombre) : 'tu asesor';
    const r = await enviarRecordatorioCliente(conn, req, {
      clienteId: d.cliente_id, tipo: 'documento', objetoId: d.id,
      asunto: (asesor ? asesor.nombre + ', tu asesor de Acros' : 'Tu asesor de Acros') + ', te recuerda un documento',
      titulo: d.estado === 'rechazado' ? 'Hay que volver a subir un documento' : 'Te falta un documento',
      parrafos: d.estado === 'rechazado'
        ? [`${quien} no ha podido dar por bueno este documento: <strong>${ESC_HTML(d.nombre)}</strong>.`, d.razon_rechazo ? 'Motivo: ' + ESC_HTML(d.razon_rechazo) : '', 'Cuando puedas, súbelo de nuevo desde tu área.'].filter(Boolean)
        : [`${quien} sigue esperando este documento para avanzar con tu encargo:`, `<strong>${ESC_HTML(d.nombre)}</strong>`, 'Súbelo desde tu área de cliente; viaja y se guarda cifrado.'],
      textoWA: 'Acros: ' + (asesor ? asesor.nombre : 'tu asesor') + ' te recuerda un documento pendiente en tu área.',
    });
    respuestaRecordatorio(res, r);
  } finally { conn.release(); }
});
app.post('/api/admin/servicios/:id(\\d+)/recordar', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const v = await vistaPorId(conn, Number(req.params.id));
    if (!v) return res.status(404).json({ error: 'Servicio no encontrado' });
    if (v.estado !== 'por_confirmar') return res.status(409).json({ error: 'Solo se puede recordar un servicio que espera la confirmación del cliente' });
    const asesor = await personaDeCliente(v.cliente_id, conn).catch(() => null);
    const quien = asesor ? ESC_HTML(asesor.nombre) : 'Tu asesor';
    const r = await enviarRecordatorioCliente(conn, req, {
      clienteId: v.cliente_id, tipo: 'servicio', objetoId: v.id,
      asunto: (asesor ? asesor.nombre + ', tu asesor de Acros' : 'Tu asesor de Acros') + ', espera tu confirmación',
      titulo: 'Falta tu confirmación',
      parrafos: [`${quien} ha dado por terminado este servicio: <strong>${ESC_HTML(v.nombre_es)}</strong>.`, 'Entra en tu área y dinos si está todo bien o si te falta algo.'],
      textoWA: 'Acros: ' + (asesor ? asesor.nombre : 'tu asesor') + ' espera tu confirmación de un servicio terminado.',
    });
    if (r.ok) await apuntarServicio(conn, v.id, 'recordado', 'asesor', req.asesor.id, 'correo: ' + r.correo);
    respuestaRecordatorio(res, r);
  } finally { conn.release(); }
});
// Todo lo que ha pasado con los servicios de un cliente (para el historial de su ficha)
app.get('/api/admin/clientes/:id(\\d+)/servicios/historial', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute(
    `SELECT h.servicio_id, s.clave, h.evento, h.autor, h.detalle, h.creado_en, a.nombre AS asesor
     FROM servicios_historial h JOIN servicios_cliente s ON s.id = h.servicio_id LEFT JOIN asesores a ON a.id = h.asesor_id
     WHERE s.cliente_id = ? ORDER BY h.id DESC LIMIT 400`, [Number(req.params.id)]);
  res.json(f);
});

// 26/10 (Vikn): «Recordar el pago». Un correo al cliente con el enlace a su área; desde entonces, en
// «Te toca a ti» su botón «Pagar» sale en teja (lo urgente o pedido por el asesor), no en verde.
app.post('/api/admin/propuestas/:id(\\d+)/recordar-pago', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT id, cliente_id, estado, servicios, creado_en FROM propuestas WHERE id = ?', [Number(req.params.id)]);
    if (!f.length) return res.status(404).json({ error: 'Encargo no encontrado' });
    const p = f[0];
    if (p.estado !== 'aceptada') return res.status(409).json({ error: 'Ese encargo no está aceptado' });
    const [pg] = await conn.execute('SELECT COUNT(*) AS n FROM pagos WHERE propuesta_id = ?', [p.id]);
    if (pg[0].n) return res.status(409).json({ error: 'El cliente ya ha hecho el pago de ese encargo' });
    const asesor = await personaDeCliente(p.cliente_id, conn).catch(() => null);
    const quien = asesor ? ESC_HTML(asesor.nombre) : 'Tu asesor';
    const nombres = serviciosDePropuesta(p).map(id => { const t = TIPOS_SERVICIO[tipoDeServicio(id)]; return t && t.generico ? t.generico.es : id; });
    const r = await enviarRecordatorioCliente(conn, req, {
      clienteId: p.cliente_id, tipo: 'pago', objetoId: p.id,
      asunto: (asesor ? asesor.nombre + ', tu asesor de Acros' : 'Tu asesor de Acros') + ', te recuerda el pago de tu encargo',
      titulo: 'Falta el pago de tu encargo',
      parrafos: [`${quien} te recuerda que, para empezar a trabajar en tu encargo, falta el pago:`, nombres.length ? '<strong>' + nombres.map(ESC_HTML).join(', ') + '</strong>' : '', 'Puedes hacerlo desde tu área de cliente, con el método que prefieras.'].filter(Boolean),
      textoWA: 'Acros: ' + (asesor ? asesor.nombre : 'tu asesor') + ' te recuerda el pago de tu encargo. Puedes hacerlo desde tu área.',
    });
    respuestaRecordatorio(res, r);
  } finally { conn.release(); }
});

// ================================================================
// ÁREA DEL CLIENTE NUEVA (20/10, ACROS 7 · fase 3): datos de TODOS sus encargos
// La pantalla nueva se organiza por servicios y ejercicios, no por encargo, así
// que necesita en una llamada lo que antes salía encargo a encargo: documentos,
// informes, mensajes e historial. Todo viene por el token de cualquiera de sus
// propuestas (identifica al cliente) y solo trae lo suyo. También: escribir en
// el hilo de un servicio sin conocer el token de su encargo, marcarlo leído, y
// «cerrar sesión en todos los dispositivos».
// ================================================================
const EVENTOS_SERVICIO_CLIENTE = ['propuesto_cierre', 'terminado_cliente', 'terminado_informe', 'cerrado_sin_respuesta', 'reabierto', 'pendiente_cliente'];
app.get('/api/propuestas/:token/area', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [props] = await conn.execute("SELECT id, token, estado, servicios, creado_en, inicio_inmediato_en, token_expira_en, cobro FROM propuestas WHERE cliente_id = ? AND (estado = 'aceptada' OR (estado = 'enviada' AND token_expira_en > NOW())) ORDER BY creado_en DESC, id DESC", [p.cliente_id]);
    const ids = props.map(x => x.id);
    const vacio = { encargos: [], documentos: [], entregas: [], mensajes: [], historial: [], subidas_hoy: 0, limite_subidas: LIMITE_SUBIDAS_DIA };
    if (!ids.length) return res.json(vacio);
    const [dils] = await conn.query('SELECT propuesta_id, estado, creado_en, resuelto_en FROM diligencias WHERE propuesta_id IN (?) ORDER BY id', [ids]);
    const aprobadas = new Set(dils.filter(d => d.estado === 'aprobado').map(d => d.propuesta_id));
    const [svs] = await conn.execute('SELECT id, propuesta_id, servicio FROM servicios_cliente WHERE cliente_id = ? AND confirmado IN (0, 1)', [p.cliente_id]);   // 21/10: también los de año sin confirmar
    const sidDe = (pid, serv) => { const s = svs.find(x => x.propuesta_id === pid && x.servicio === serv); return s ? s.id : null; };
    // La documentación solo se ve cuando el alta de ESE encargo está aprobada (como siempre)
    const [docs] = aprobadas.size ? await conn.query('SELECT id, propuesta_id, servicio, nombre, urgente, estado, razon_rechazo, subido_en, creado_en, revisado_en FROM documentos_fiscales WHERE propuesta_id IN (?) ORDER BY creado_en, id', [[...aprobadas]]) : [[]];
    const [ents] = await conn.execute('SELECT id, propuesta_id, servicio, version, nombre_archivo, bytes, subido_en, estado, comentario, respondido_en, conformidad_pedida_en FROM entregas WHERE cliente_id = ? ORDER BY id', [p.cliente_id]);
    const [msgs] = await conn.query(
      `SELECT m.id, m.propuesta_id, m.servicio, m.autor, m.texto, m.creado_en, m.leido_en, a.nombre AS asesor, m.archivo_nombre, m.archivo_tipo, m.archivo_bytes
       FROM mensajes m LEFT JOIN asesores a ON a.id = m.asesor_id
       WHERE m.propuesta_id IN (?) AND m.oculto_cliente_en IS NULL AND m.retirado_en IS NULL ORDER BY m.creado_en, m.id`, [ids]);
    const [pagos] = await conn.query('SELECT propuesta_id, metodo, estado, creado_en, confirmado_en FROM pagos WHERE propuesta_id IN (?)', [ids]);
    const [evS] = await conn.query("SELECT h.servicio_id, h.evento, h.creado_en FROM servicios_historial h JOIN servicios_cliente s ON s.id = h.servicio_id WHERE s.cliente_id = ? AND s.confirmado IN (0, 1) AND h.evento IN (?)", [p.cliente_id, EVENTOS_SERVICIO_CLIENTE]);
    // Historial, ya apto para enseñárselo al cliente: nada interno del equipo
    const h = [], add = (cuando, tipo, datos) => { if (cuando) h.push(Object.assign({ cuando, tipo }, datos || {})); };
    props.forEach(e => { add(e.creado_en, 'propuesta'); if (e.inicio_inmediato_en) add(e.inicio_inmediato_en, 'aceptada'); });
    pagos.forEach(x => { add(x.creado_en, 'pago_declarado', { propuesta_id: x.propuesta_id }); if (x.estado === 'confirmado') add(x.confirmado_en, 'pago_confirmado', { propuesta_id: x.propuesta_id }); });
    dils.forEach(x => { add(x.creado_en, 'alta_enviada'); if (x.resuelto_en) add(x.resuelto_en, x.estado === 'aprobado' ? 'alta_aprobada' : 'alta_rechazada'); });
    docs.forEach(x => { const sid = sidDe(x.propuesta_id, x.servicio); add(x.creado_en, 'doc_pedido', { servicio_id: sid, nombre: x.nombre }); if (x.subido_en) add(x.subido_en, 'doc_subido', { servicio_id: sid, nombre: x.nombre }); if (x.revisado_en) add(x.revisado_en, x.estado === 'rechazado' ? 'doc_rechazado' : 'doc_validado', { servicio_id: sid, nombre: x.nombre, motivo: x.estado === 'rechazado' ? x.razon_rechazo : undefined }); });
    ents.forEach(x => { const sid = sidDe(x.propuesta_id, x.servicio); add(x.subido_en, 'informe', { servicio_id: sid, nombre: x.nombre_archivo, version: x.version }); if (x.respondido_en) add(x.respondido_en, x.estado === 'conforme' ? 'conforme' : 'cambios', { servicio_id: sid, motivo: x.estado === 'cambios' ? x.comentario : undefined }); });
    evS.forEach(x => add(x.creado_en, 'servicio', { servicio_id: x.servicio_id, evento: x.evento }));
    h.sort((a, b) => new Date(b.cuando) - new Date(a.cuando));
    const [recPago] = await conn.execute("SELECT objeto_id, MAX(creado_en) AS ultimo FROM recordatorios_cliente WHERE tipo = 'pago' AND cliente_id = ? GROUP BY objeto_id", [p.cliente_id]);   // 26/10
    res.json({
      encargos: props.map(x => ({ id: x.id, token: x.token, estado: x.estado, creado_en: x.creado_en, alta_aprobada: aprobadas.has(x.id),
        pago_recordado_en: ((recPago.find(r => r.objeto_id === x.id)) || {}).ultimo || null,
        pago: pagos.some(g => g.propuesta_id === x.id), pago_confirmado: pagos.some(g => g.propuesta_id === x.id && g.estado === 'confirmado'), cobro: x.cobro || 'antes', plazo_pago: plazoPagoDe(x), informes_bloqueados: pagos.some(g => g.propuesta_id === x.id && g.estado === 'confirmado') ? 0 : ents.filter(e => e.propuesta_id === x.id && e.estado === 'entregado').length, alta: ((dils.filter(g => g.propuesta_id === x.id).slice(-1)[0]) || {}).estado || null, servicios_nombres: x.estado === 'aceptada' ? serviciosDePropuesta(x).map(id => { const t = TIPOS_SERVICIO[tipoDeServicio(id)]; return t && t.generico ? t.generico : { es: id, en: id }; }) : undefined, expira_en: x.estado === 'enviada' ? x.token_expira_en : null, servicios: x.estado === 'enviada' ? serviciosDePropuesta(x) : undefined })),
      documentos: docs, entregas: ents.filter(e => pagos.some(g => g.propuesta_id === e.propuesta_id && g.estado === 'confirmado')),   // 29/10: los informes solo con el pago confirmado
      mensajes: msgs.map(m => Object.assign(m, { servicio_id: sidDe(m.propuesta_id, m.servicio) })),
      historial: h, subidas_hoy: await subidasDeHoy(conn, p.cliente_id), limite_subidas: LIMITE_SUBIDAS_DIA,
    });
  } finally { conn.release(); }
});
// Escribir en el hilo de un servicio (el servidor sabe a qué encargo pertenece)
app.post('/api/propuestas/:token/servicios/:id(\\d+)/mensajes', async (req, res) => {
  const texto = textoMensaje(req.body && req.body.texto);
  if (!texto) return res.status(400).json({ error: 'El mensaje está vacío' });
  const conn = await pool.getConnection();
  try {
    const r = await servicioDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    const [ins] = await conn.execute("INSERT INTO mensajes (propuesta_id, cliente_id, servicio, autor, texto) VALUES (?, ?, ?, 'cliente', ?)", [r.f.propuesta_id, r.f.cliente_id, r.f.servicio, texto]);
    const ahoraMs = Date.now();
    if (ahoraMs - (ultimoAvisoMensaje.get(r.f.propuesta_id) || 0) > 5 * 60 * 1000) {
      ultimoAvisoMensaje.set(r.f.propuesta_id, ahoraMs);
      avisarCliente(r.f.cliente_id, '💬', 'un cliente te ha escrito', 'Contéstale desde «Mensajes sin leer» en el panel.', { prioridad: 4, etiqueta: 'speech_balloon' });
    }
    res.status(201).json({ ok: true, id: ins.insertId });
  } finally { conn.release(); }
});
// Al abrir el hilo de un servicio, lo que escribió el asesor queda leído
app.post('/api/propuestas/:token/servicios/:id(\\d+)/leidos', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const r = await servicioDelCliente(conn, req.params.token, req.params.id);
    if (r.error) return res.status(r.error[0]).json({ error: r.error[1] });
    const [u] = await conn.execute("UPDATE mensajes SET leido_en = NOW() WHERE propuesta_id = ? AND servicio = ? AND autor = 'asesor' AND leido_en IS NULL", [r.f.propuesta_id, r.f.servicio]);
    res.json({ ok: true, marcados: u.affectedRows });
  } finally { conn.release(); }
});


// ================================================================
// AVISOS DE URGENCIA (20/10, ACROS 7 · fase 2)
// Cuando un servicio en curso ENTRA en urgencia (faltan menos días que su
// ventana) o VENCE: un ntfy al asesor del cliente (sin ningún dato personal:
// la regla de Acros) y, solo al entrar en urgencia y si el cliente tiene algo
// pendiente en ese servicio (documentos pedidos o rechazados, o un informe por
// revisar), un correo al cliente que respeta sus preferencias («recordatorios»).
// Una vez por estado y plazo (servicios_cliente.aviso_urgencia = «urgente|AAAA-MM-DD»):
// si el plazo cambia, vuelve a avisar. De noche no se avisa (espera a las 8:00).
// Lo que ya estaba así al desplegar o al migrar queda marcado «base» y se da por
// sabido en silencio: así el primer día no hay avalancha de avisos ni correos.
// El resumen de las 8:00 de los administradores lleva «Plazos que vencen».
// ================================================================
const MS_TAREA_URGENCIA = Math.max(5000, Number(process.env.URGENCIA_TAREA_MS) || 10 * 60 * 1000);
const HORA_AVISOS_DESDE = 8, HORA_AVISOS_HASTA = 21;
// Servicios confirmados en curso de clientes activos con el plazo urgente o vencido
async function serviciosEnUrgencia(conn) {
  const [filas] = await conn.query(SQL_SERVICIOS + " JOIN clientes c ON c.id = s.cliente_id WHERE s.confirmado = 1 AND s.estado IN ('abierto','por_confirmar') AND c.estado = 'activo'");
  return (await vistasDeFilas(conn, filas)).filter(v => v.plazo_estado === 'urgente' || v.plazo_estado === 'vencido');
}
const fechaISOaES = iso => iso ? iso.slice(8, 10) + '/' + iso.slice(5, 7) + '/' + iso.slice(0, 4) : '';
let urgenciaEnMarcha = false;
async function revisarUrgencias({ forzar = false } = {}) {
  if (urgenciaEnMarcha) return null;
  const h = fechaMadrid();
  if (!forzar && (h.hora < HORA_AVISOS_DESDE || h.hora >= HORA_AVISOS_HASTA)) return null;
  urgenciaEnMarcha = true;
  const conn = await pool.getConnection();
  const hechos = { avisos: 0, correos: 0, silenciosos: 0 };
  try {
    const [estado] = await conn.query("SELECT s.id, s.aviso_urgencia FROM servicios_cliente s JOIN clientes c ON c.id = s.cliente_id WHERE s.confirmado = 1 AND s.estado IN ('abierto','por_confirmar') AND c.estado = 'activo'");
    if (!estado.length) return hechos;
    const antes = new Map(estado.map(x => [x.id, x.aviso_urgencia]));
    const urg = new Map((await serviciosEnUrgencia(conn)).map(v => [v.id, v]));
    for (const [id, previo] of antes) {
      const v = urg.get(id);
      const clave = v ? v.plazo_estado + '|' + v.plazo : 'normal';
      if (previo === clave) continue;
      // Marcar primero: si algo falla después, no se repite el aviso en bucle
      const [u] = await conn.execute('UPDATE servicios_cliente SET aviso_urgencia = ? WHERE id = ? AND (aviso_urgencia <=> ?)', [clave, id, previo]);
      if (!u.affectedRows) continue;   // otro proceso se adelantó
      if (previo === 'base' || !v) { if (previo === 'base') hechos.silenciosos++; continue; }   // ya se sabía / salió de urgencia
      const vencido = v.plazo_estado === 'vencido';
      await apuntarServicio(conn, id, vencido ? 'aviso_vencido' : 'aviso_urgencia', 'sistema', null, v.plazo);
      avisarCliente(v.cliente_id, '⏰', vencido ? 'a un cliente se le ha pasado un plazo' : 'un plazo de un cliente entra en urgencia',
        'Míralo en «Plazos que vencen» del panel.', { prioridad: vencido ? 4 : 3, etiqueta: 'alarm_clock' });
      hechos.avisos++;
      if (!vencido && (v.docs_pendientes > 0 || v.entrega_estado === 'entregado')) {
        if (await correoUrgenciaCliente(conn, v)) hechos.correos++;
      }
    }
    return hechos;
  } catch (err) {
    console.error('Avisos de urgencia:', err.message);
    return null;
  } finally { conn.release(); urgenciaEnMarcha = false; }
}
async function correoUrgenciaCliente(conn, v) {
  const [cl] = await conn.execute('SELECT correo, nombre FROM clientes WHERE id = ?', [v.cliente_id]);
  if (!cl.length || !cl[0].correo || !brevoActivo()) return false;
  const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
  const queFalta = v.docs_pendientes > 0
    ? (v.docs_pendientes === 1 ? 'Nos falta un documento tuyo' : `Nos faltan ${v.docs_pendientes} documentos tuyos`) + ' para poder terminarlo a tiempo.'
    : 'Tienes un informe esperando tu revisión.';
  const c = plantillaCorreo({
    titulo: 'Se acerca un plazo',
    parrafos: [cl[0].nombre ? `Hola, ${ESC_HTML(cl[0].nombre)}:` : 'Hola:',
      `El plazo de <strong>${ESC_HTML(v.nombre_es)}</strong> vence el ${fechaISOaES(v.plazo)}${v.dias_restantes === 0 ? ' (hoy)' : v.dias_restantes === 1 ? ' (mañana)' : ' (en ' + v.dias_restantes + ' días)'}.`,
      queFalta, 'Lo tienes todo en «Te toca a ti», en tu área.'],
    boton: enlace ? { texto: 'Entrar en mi área', url: enlace } : null,
    nota: 'Por tu privacidad, no envíes documentos por correo: súbelos siempre desde tu área.',
  });
  try {
    const salio = await notificarCliente(conn, v.cliente_id, 'recordatorios', () => enviarCorreo(cl[0].correo, 'Se acerca un plazo · Acros', c.html, c.texto),
      `Acros: el plazo de ${v.nombre_es} vence el ${fechaISOaES(v.plazo)}. ${queFalta}` + (enlace ? ' ' + enlace : ''));
    if (salio) await conn.execute('INSERT INTO recordatorios_cliente (tipo, objeto_id, cliente_id, asesor_id) VALUES (?, ?, ?, NULL)', ['urgencia', v.id, v.cliente_id]).catch(() => {});
    return salio;
  } catch (err) { console.error('Correo de urgencia no enviado:', err.message); return false; }
}
// Para el resumen de las 8:00 (correo a los administradores: aquí sí van nombres)
async function plazosParaResumen(conn) {
  const lista = await serviciosEnUrgencia(conn);
  if (!lista.length) return [];
  const [cs] = await conn.query('SELECT c.id, c.nombre, c.apellidos, c.correo, p.nombre AS asesor FROM clientes c LEFT JOIN personas p ON p.id = c.asesor_persona_id WHERE c.id IN (?)', [[...new Set(lista.map(v => v.cliente_id))]]);
  const cli = new Map(cs.map(c => [c.id, c]));
  return lista.sort((a, b) => a.dias_restantes - b.dias_restantes).map(v => {
    const c = cli.get(v.cliente_id) || {};
    return ESC_HTML([c.nombre, c.apellidos].filter(Boolean).join(' ') || c.correo || '') + ' · ' + ESC_HTML(v.nombre_es) + ' · ' + ESC_HTML(c.asesor || 'sin asesor') + ' · ' +
      (v.plazo_estado === 'vencido' ? '<strong>venció el ' + fechaISOaES(v.plazo) + '</strong>' : 'vence el ' + fechaISOaES(v.plazo) + (v.dias_restantes === 0 ? ' (hoy)' : ' (en ' + v.dias_restantes + (v.dias_restantes === 1 ? ' día)' : ' días)')));
  });
}
setInterval(revisarUrgencias, MS_TAREA_URGENCIA);
setTimeout(revisarUrgencias, 75 * 1000);
// Para el administrador (y las pruebas): revisar ahora, a cualquier hora
app.post('/api/admin/urgencias/revisar', requiereSesionAsesor, soloAdministrador, async (req, res) => {
  const r = await revisarUrgencias({ forzar: true });
  res.json(r || { error: 'Ya había una revisión en marcha; inténtalo en un momento' });
});


// ================================================================
// LLAVES DE JEFES Y ENCARGADOS (20/10, ACROS 7 · fase 4)
// El derecho a abrir los documentos de un cliente (SQL_DERECHO) incluye ya,
// además del asesor titular y quienes colaboran, al JEFE del equipo del
// titular y al ENCARGADO de ese equipo: los mismos que ya veían al cliente en
// el panel pero no podían abrir sus documentos. Solo si tienen ese rol y el
// equipo está activo; si dejan de serlo, su llave se retira sola (como siempre,
// al pedir las pendientes). Aquí: cuántas faltan por conceder, para «Hoy».
// ================================================================
app.get('/api/admin/llaves/por-conceder', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const [p] = await pool.query(`SELECT COUNT(*) AS n FROM (${SQL_DOCS}) x
    JOIN (${SQL_DERECHO}) t ON t.cliente_id = x.cliente_id
    JOIN asesores a ON a.id = t.asesor_id AND a.activo = 1 AND a.es_admin = 0 AND a.llave_publica IS NOT NULL
    LEFT JOIN llaves_documento l ON l.tipo = x.tipo AND l.objeto_id = x.objeto_id AND l.asesor_id = a.id
    WHERE l.id IS NULL`);
  // quien tiene derecho pero aún no ha creado su llave (la crea al entrar por primera vez en el panel)
  const [s] = await pool.query(`SELECT COUNT(DISTINCT a.id) AS n FROM (${SQL_DOCS}) x
    JOIN (${SQL_DERECHO}) t ON t.cliente_id = x.cliente_id
    JOIN asesores a ON a.id = t.asesor_id AND a.activo = 1 AND a.es_admin = 0 AND a.llave_publica IS NULL`);
  res.json({ pendientes: p[0].n, asesores_sin_llave: s[0].n });
});


// ================================================================
// PROPUESTAS SIN RESPUESTA E INICIALES EN LOS AVISOS (20/10)
// - Una propuesta enviada pasaba a «caducada» solo cuando alguien la abría:
//   hasta entonces el panel la daba por pendiente («Aceptar la propuesta…»)
//   aunque hubiera caducado. Ahora caducan solas (cada 10 minutos y antes de
//   listarlas o de que entre un cliente).
// - Al entrar con su sesión, el cliente iba a su propuesta MÁS RECIENTE aunque
//   estuviera caducada o rechazada: se quedaba en «propuesta caducada» sin poder
//   llegar a sus encargos. Ahora va a su encargo aceptado más reciente; si no
//   tiene, a la propuesta vigente; y si no, a la última.
// - «Hoy» del panel: propuestas sin respuesta (vigentes) y las que caducaron en
//   los últimos 30 días, de los clientes que cada uno puede ver.
// - Iniciales en los avisos de ntfy (decidido con Vikn): en los canales generales
//   va quién (iniciales, nunca el nombre); en el canal propio de cada persona, no.
// ================================================================
async function caducarPropuestas(clienteId) {
  try {
    const [r] = await pool.execute("UPDATE propuestas SET estado = 'caducada' WHERE estado = 'enviada' AND token_expira_en < NOW()" + (clienteId ? ' AND cliente_id = ?' : ''), clienteId ? [clienteId] : []);
    return r.affectedRows;
  } catch (err) { console.error('Caducar propuestas:', err.message); return 0; }
}
setInterval(() => caducarPropuestas(), 10 * 60 * 1000);
setTimeout(() => caducarPropuestas(), 20 * 1000);
const SQL_PROPUESTA_DE_ENTRADA = "SELECT token, estado FROM propuestas WHERE cliente_id = ? ORDER BY (estado = 'aceptada') DESC, (estado = 'enviada') DESC, creado_en DESC, id DESC LIMIT 1";
app.get('/api/admin/propuestas/sin-respuesta', requiereSesionAsesor, async (req, res) => {
  await caducarPropuestas();
  const permitidos = await clientesPermitidos(req);
  if (permitidos && !permitidos.size) return res.json({ vigentes: [], caducadas: [] });
  const filtro = permitidos ? ' AND p.cliente_id IN (?)' : '';
  const params = permitidos ? [[...permitidos]] : [];
  const sql = estado => `SELECT p.id, p.cliente_id, p.servicios, p.importe_centimos, p.creado_en, p.token_expira_en AS expira_en, c.nombre, c.apellidos, c.correo, q.nombre AS asesor
    FROM propuestas p JOIN clientes c ON c.id = p.cliente_id LEFT JOIN personas q ON q.id = c.asesor_persona_id
    WHERE ${estado}${filtro} ORDER BY p.token_expira_en`;
  const [vig] = await pool.query(sql("p.estado = 'enviada'"), params);
  const [cad] = await pool.query(sql("p.estado = 'caducada' AND p.token_expira_en > NOW() - INTERVAL 30 DAY"), params);
  const lim = l => l.map(x => Object.assign(x, { servicios: serviciosDePropuesta(x) }));
  res.json({ vigentes: lim(vig), caducadas: lim(cad).reverse() });
});

// --- Iniciales ---
const PARTICULAS_NOMBRE = new Set(['de', 'del', 'la', 'las', 'los', 'y', 'e', 'i', 'da', 'das', 'do', 'dos', 'van', 'von', 'der', 'di', 'du', 'le', 'el', 'san', 'santa']);
const sinAcentosIni = t => String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
// Primera letra de las dos primeras palabras (sin «de», «del», «la»…); un apellido con guion es una palabra; con una sola palabra, sus dos primeras letras
function inicialesSugeridas(nombre) {
  const p = sinAcentosIni(nombre).replace(/[^A-Za-z\s-]/g, '').split(/\s+/).filter(w => w && !PARTICULAS_NOMBRE.has(w.toLowerCase()));
  if (!p.length) return '';
  return (p.length === 1 ? p[0].slice(0, 2) : p[0][0] + p[1][0]).toUpperCase();
}
const normalizarIniciales = t => sinAcentosIni(t).toUpperCase().replace(/[^A-Z]/g, '').slice(0, 4);
let CACHE_INICIALES = { hasta: 0 };
async function mapaIniciales() {
  if (Date.now() < CACHE_INICIALES.hasta) return CACHE_INICIALES;
  const [ps] = await pool.query('SELECT id, nombre, iniciales, asesor_id FROM personas ORDER BY activa DESC, id');
  const porPersona = new Map(), usadas = new Set();
  ps.filter(p => p.iniciales).forEach(p => { porPersona.set(p.id, p.iniciales); usadas.add(p.iniciales); });   // las escritas a mano mandan
  ps.filter(p => !p.iniciales).forEach(p => { const base = inicialesSugeridas(p.nombre) || 'X'; let ini = base, n = 1; while (usadas.has(ini)) ini = base + (++n); usadas.add(ini); porPersona.set(p.id, ini); });
  const porAsesor = new Map(ps.filter(p => p.asesor_id).map(p => [p.asesor_id, porPersona.get(p.id)]));
  CACHE_INICIALES = { hasta: Date.now() + 60 * 1000, porPersona, porAsesor };
  return CACHE_INICIALES;
}
async function inicialesDePersona(id) { try { return (await mapaIniciales()).porPersona.get(id) || ''; } catch (e) { return ''; } }
async function inicialesDeAsesor(asesorId) {
  try {
    const m = await mapaIniciales(); if (m.porAsesor.has(asesorId)) return m.porAsesor.get(asesorId);
    const [a] = await pool.execute('SELECT nombre FROM asesores WHERE id = ?', [asesorId]); return a.length ? inicialesSugeridas(a[0].nombre) : '';
  } catch (e) { return ''; }
}
const quienIni = ini => ini || 'Alguien del equipo';


// ================================================================
// SERVICIOS DUPLICADOS (20/10)
// Si un cliente tiene el mismo servicio en dos encargos (p. ej. el Informe de
// P&G 2026 contratado dos veces), un administrador marca uno como «duplicado
// de» el otro: sus documentos, mensajes e informes pasan al que se queda (los
// informes, con versión siguiente) y el sobrante queda «fusionado»
// (confirmado = 2): no cuenta en ningún sitio ni lo ve el cliente, pero no se
// borra (si se borrara, la migración lo volvería a crear al arrancar). El pago
// sigue en su encargo, sin tocarlo. El cliente no recibe ningún aviso.
// Queda en el historial de los dos servicios.
// ================================================================
const FUSIONADO = 2;
async function fusionarDuplicado(conn, id, destinoId, asesorId) {
  if (Number(id) === Number(destinoId)) return { error: [400, 'Un servicio no puede ser duplicado de sí mismo'] };
  const [[d]] = await conn.query('SELECT * FROM servicios_cliente WHERE id = ?', [id]);
  const [[t]] = await conn.query('SELECT * FROM servicios_cliente WHERE id = ?', [destinoId]);
  if (!d || !t) return { error: [404, 'Servicio no encontrado'] };
  if (d.confirmado === FUSIONADO || t.confirmado === FUSIONADO) return { error: [409, 'Uno de los dos ya está fusionado con otro'] };
  if (d.cliente_id !== t.cliente_id) return { error: [400, 'Los dos servicios tienen que ser del mismo cliente'] };
  if (d.tipo !== t.tipo) return { error: [400, 'Solo se puede marcar como duplicado un servicio del mismo tipo'] };
  const mover = [t.propuesta_id, t.servicio, d.propuesta_id, d.servicio];
  const [rd] = await conn.execute('UPDATE documentos_fiscales SET propuesta_id = ?, servicio = ? WHERE propuesta_id = ? AND servicio = ?', mover);
  const [rm] = await conn.execute('UPDATE mensajes SET propuesta_id = ?, servicio = ? WHERE propuesta_id = ? AND servicio = ?', mover);
  const [[mx]] = await conn.execute('SELECT COALESCE(MAX(version), 0) AS v FROM entregas WHERE propuesta_id = ? AND servicio = ?', [t.propuesta_id, t.servicio]);
  const [ents] = await conn.execute('SELECT id FROM entregas WHERE propuesta_id = ? AND servicio = ? ORDER BY version, id', [d.propuesta_id, d.servicio]);
  let v = mx.v;
  for (const e of ents) await conn.execute('UPDATE entregas SET propuesta_id = ?, servicio = ?, version = ? WHERE id = ?', [t.propuesta_id, t.servicio, ++v, e.id]);
  await conn.execute('UPDATE servicios_cliente SET confirmado = ? WHERE id = ?', [FUSIONADO, d.id]);
  const resumen = `${rd.affectedRows} documentos, ${rm.affectedRows} mensajes y ${ents.length} informes`;
  await apuntarServicio(conn, d.id, 'fusionado', 'asesor', asesorId, `duplicado del servicio ${t.id}: ${resumen} pasan a él`);
  await apuntarServicio(conn, t.id, 'fusion', 'asesor', asesorId, `recibe ${resumen} del servicio ${d.id} (duplicado)`);
  return { ok: true, documentos: rd.affectedRows, mensajes: rm.affectedRows, informes: ents.length };
}
app.post('/api/admin/servicios/:id(\\d+)/duplicado', requiereSesionAsesor, soloAdministrador, async (req, res) => {
  const destino = Number((req.body || {}).de);
  if (!Number.isInteger(destino) || destino <= 0) return res.status(400).json({ error: 'Indica de qué servicio es duplicado' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const r = await fusionarDuplicado(conn, Number(req.params.id), destino, req.asesor.id);
    if (r.error) { await conn.rollback(); return res.status(r.error[0]).json({ error: r.error[1] }); }
    await conn.commit();
    res.json(r);
  } catch (err) { await conn.rollback().catch(() => {}); throw err; }
  finally { conn.release(); }
});
// Para elegir bien cuál se queda: del mismo cliente y tipo, con sus documentos, mensajes y si su alta está aprobada
async function candidatosDuplicado(conn, clienteIds) {
  if (!clienteIds.length) return [];
  const [f] = await conn.query(`SELECT s.id, s.cliente_id, s.tipo, s.ejercicio_desde, s.ejercicio_hasta, s.confirmado, p.creado_en AS encargo_creado_en,
      (SELECT COUNT(*) FROM documentos_fiscales x WHERE x.propuesta_id = s.propuesta_id AND x.servicio = s.servicio) AS docs,
      (SELECT COUNT(*) FROM mensajes m WHERE m.propuesta_id = s.propuesta_id AND m.servicio = s.servicio) AS mensajes,
      (SELECT COUNT(*) FROM diligencias g WHERE g.propuesta_id = s.propuesta_id AND g.estado = 'aprobado') > 0 AS alta_aprobada
    FROM servicios_cliente s JOIN propuestas p ON p.id = s.propuesta_id WHERE s.cliente_id IN (?) AND s.confirmado IN (0, 1)`, [clienteIds]);
  const vistas = new Map();
  for (const c of clienteIds) (await listarServiciosCliente(conn, c)).forEach(v => vistas.set(v.id, v));
  return f.map(x => Object.assign(x, { nombre_es: (vistas.get(x.id) || {}).nombre_es || x.tipo, alta_aprobada: !!x.alta_aprobada }));
}


// ================================================================
// CORRECCIONES DEL 21/10 (lista de Vikn)
// - Versión visible: el panel enseña la suya y la del servidor, para saber
//   sin adivinar qué está en marcha (antes se deducía por señales indirectas).
// - Alta (diligencia debida) una sola vez por cliente: un encargo nuevo
//   hereda la aprobada más reciente si tiene menos de 12 meses (sin repetir el
//   cuestionario ni el documento). Si es más antigua, se vuelve a pedir.
// - Al enviar una propuesta: aviso si el cliente ya tiene alguno de esos
//   servicios y años en curso, o en otra propuesta pendiente (que el asesor
//   puede retirar en el mismo paso).
// ================================================================
const VERSION_ACROS = '2026-10-30.1';
app.get('/api/version', (req, res) => res.json({ servidor: VERSION_ACROS }));

// --- Alta heredada ---
const ALTA_VALIDEZ_MESES = 12;
async function heredarAlta(conn, p) {
  if (!p || p.estado !== 'aceptada') return false;
  const [ya] = await conn.execute('SELECT id FROM diligencias WHERE propuesta_id = ?', [p.id]);
  if (ya.length) return false;
  const [ap] = await conn.execute("SELECT id, DATE_FORMAT(resuelto_en, '%d/%m/%Y') AS fecha FROM diligencias WHERE cliente_id = ? AND estado = 'aprobado' AND heredada_de IS NULL AND resuelto_en > NOW() - INTERVAL ? MONTH ORDER BY resuelto_en DESC LIMIT 1", [p.cliente_id, ALTA_VALIDEZ_MESES]);
  if (!ap.length) return false;
  await conn.execute("INSERT INTO diligencias (cliente_id, propuesta_id, estado, resuelto_en, heredada_de, nota_asesor) VALUES (?, ?, 'aprobado', NOW(), ?, ?)",
    [p.cliente_id, p.id, ap[0].id, 'Alta heredada de la aprobada el ' + ap[0].fecha + ' (válida ' + ALTA_VALIDEZ_MESES + ' meses): no se repite el cuestionario']);
  return true;
}
async function heredarAltasDeCliente(conn, clienteId) {
  const [ps] = await conn.execute("SELECT * FROM propuestas WHERE cliente_id = ? AND estado = 'aceptada'", [clienteId]);
  let n = 0; for (const p of ps) if (await heredarAlta(conn, p)) n++;
  return n;
}
async function heredarAltasPendientes() {
  const conn = await pool.getConnection();
  try {
    const [cs] = await conn.query("SELECT DISTINCT p.cliente_id FROM propuestas p WHERE p.estado = 'aceptada' AND NOT EXISTS (SELECT 1 FROM diligencias d WHERE d.propuesta_id = p.id) AND EXISTS (SELECT 1 FROM diligencias a WHERE a.cliente_id = p.cliente_id AND a.estado = 'aprobado')");
    let n = 0; for (const c of cs) n += await heredarAltasDeCliente(conn, c.cliente_id);
    if (n) console.log('Altas heredadas por encargos que no la tenían: ' + n);
  } catch (err) { console.error('Altas heredadas:', err.message); }
  finally { conn.release(); }
}
setTimeout(heredarAltasPendientes, 15 * 1000);

// --- Aviso de servicios repetidos al enviar una propuesta ---
app.post('/api/admin/propuestas/comprobar', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, vacio = { repetidos: [], pendientes: [] };
  const correo = String(b.correo || '').trim().toLowerCase();
  const norm = correo ? normalizarServiciosPropuesta(b.servicios, b.importe_centimos) : null;
  if (!correo || !norm) return res.json(vacio);
  const ids = serviciosDePropuesta({ servicios: JSON.stringify(norm.servicios) });
  const ej = normalizarEjerciciosPropuesta(b.ejercicios, ids);
  if (ej.error) return res.json(vacio);
  const conn = await pool.getConnection();
  try {
    const [cl] = await conn.execute('SELECT id FROM clientes WHERE correo = ?', [correo]);
    if (!cl.length) return res.json(vacio);
    await caducarPropuestas(cl[0].id);
    const hoy = hoyMadridISO();
    const propuestos = ids.map(id => { const tipo = tipoDeServicio(id), d = ej.detalle && ej.detalle[id]; const desde = d ? d.desde : ejercicioPorDefecto(tipo, hoy); return { id, tipo, desde, hasta: d ? d.hasta : desde }; });
    const serv = await listarServiciosCliente(conn, cl[0].id);
    const [encs] = await conn.execute('SELECT id, creado_en FROM propuestas WHERE cliente_id = ?', [cl[0].id]);
    const fechaEnc = new Map(encs.map(e => [e.id, e.creado_en]));
    const repetidos = [];
    propuestos.forEach(x => serv.filter(s => s.en_curso && s.tipo === x.tipo && x.desde <= s.ejercicio_hasta && s.ejercicio_desde <= x.hasta)
      .forEach(s => repetidos.push({ servicio: x.id, nombre: s.nombre_es, encargo_creado_en: fechaEnc.get(s.propuesta_id) || null, sin_confirmar: !s.confirmado })));
    const tipos = new Set(propuestos.map(x => x.tipo));
    const [pend] = await conn.execute("SELECT id, servicios, creado_en, token_expira_en FROM propuestas WHERE cliente_id = ? AND estado = 'enviada' ORDER BY creado_en", [cl[0].id]);
    const nombre = id => { const t = TIPOS_SERVICIO[tipoDeServicio(id)]; return t && t.generico ? t.generico.es : id; };
    const pendientes = pend.map(p => { const sv = serviciosDePropuesta(p), rep = sv.filter(id => tipos.has(tipoDeServicio(id)));
      return rep.length ? { id: p.id, creado_en: p.creado_en, expira_en: p.token_expira_en, servicios: sv.map(nombre), repetidos: rep.map(nombre) } : null; }).filter(Boolean);
    res.json({ repetidos, pendientes });
  } finally { conn.release(); }
});

// --- Renovación rápida del alta (21/10): si su última alta aprobada tiene más de 12 meses ---
// El cuestionario se abre con sus respuestas anteriores (las revisa y cambia lo que haga falta),
// puede usar el mismo documento de identidad y vuelve a firmar la declaración. El asesor la revisa como cualquier alta.
async function altaAnteriorDeCliente(conn, clienteId) {
  const [f] = await conn.execute("SELECT * FROM diligencias WHERE cliente_id = ? AND estado = 'aprobado' AND heredada_de IS NULL AND documento_ref IS NOT NULL ORDER BY resuelto_en DESC LIMIT 1", [clienteId]);
  return f[0] || null;
}
app.get('/api/propuestas/:token/diligencia/anterior', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const a = await altaAnteriorDeCliente(conn, p.cliente_id);
    if (!a) return res.json({ hay: false });
    res.json({ hay: true, aprobada_en: a.resuelto_en, documento_subido_en: a.firma_en || a.creado_en,
      respuestas: { relacion: a.relacion, opera_desde: a.opera_desde, origen_fondos: a.origen_fondos, origen_fondos_otro: a.origen_fondos_otro, custodia: a.custodia, patrimonio_rango: a.patrimonio_rango, terceros: !!a.terceros, terceros_detalle: a.terceros_detalle, actividad: a.actividad, prp: !!a.prp } });
  } finally { conn.release(); }
});
// Con «documento_anterior», el alta nueva usa el documento (cifrado) de la anterior aprobada
async function rellenarDocumentoAnterior(req) {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token); if (!p) return;
    const a = await altaAnteriorDeCliente(conn, p.cliente_id); if (!a) return;
    Object.assign(req.body, { documento_ref: a.documento_ref, documento_iv: a.documento_iv, documento_clave_cifrada: a.documento_clave_cifrada, documento_tipo_mime: a.documento_tipo_mime });
    req.renovacionDe = a.id;
  } finally { conn.release(); }
}
// --- Llamadas pendientes con contexto y notas (21/10) ---
// Antes de llamar: si ese teléfono ya es cliente (con servicios en curso y su
// último mensaje), si pidió presupuesto o si es una empresa; el motivo que
// escribió en la web (opcional) y las notas del equipo («no contesta»,
// «volver a llamar el lunes»), con quién y cuándo.
const nueveDigitos = t => String(t || '').replace(/\D/g, '').slice(-9);
async function enriquecerLlamadas(conn, filas) {
  if (!filas.length) return filas;
  const ids = filas.map(f => f.id);
  const [notas] = await conn.query('SELECT n.llamada_id, n.texto, n.creado_en, a.nombre AS asesor FROM llamadas_notas n LEFT JOIN asesores a ON a.id = n.asesor_id WHERE n.llamada_id IN (?) ORDER BY n.creado_en', [ids]);
  const [cls] = await conn.query("SELECT c.id, c.nombre, c.apellidos, c.correo, c.codigo, c.telefono, c.telefono2, q.nombre AS asesor FROM clientes c LEFT JOIN personas q ON q.id = c.asesor_persona_id WHERE c.telefono IS NOT NULL OR c.telefono2 IS NOT NULL");
  const [sols] = await conn.query('SELECT telefono, servicios, creado_en FROM solicitudes_presupuesto ORDER BY creado_en DESC LIMIT 2000');
  const [emps] = await conn.query('SELECT razon_social, estado, telefono FROM empresas');
  const permitidos = filas.__permitidos;
  for (const f of filas) {
    const t = nueveDigitos(f.telefono);
    const c = t.length === 9 ? cls.find(x => nueveDigitos(x.telefono) === t || nueveDigitos(x.telefono2) === t) : null;
    let cliente = null;
    if (c && (!permitidos || permitidos.has(c.id))) {
      const sv = await listarServiciosCliente(conn, c.id);
      const [ult] = await conn.execute('SELECT MAX(creado_en) AS u FROM mensajes WHERE cliente_id = ?', [c.id]);
      cliente = { id: c.id, nombre: [c.nombre, c.apellidos].filter(Boolean).join(' ') || c.correo, asesor: c.asesor || null, servicios_en_curso: sv.filter(s => s.en_curso).map(s => s.nombre_es), ultimo_mensaje: ult[0].u };
    }
    const sol = t.length === 9 ? sols.filter(x => nueveDigitos(x.telefono) === t).slice(0, 3).map(x => ({ creado_en: x.creado_en, servicios: (() => { try { return JSON.parse(x.servicios); } catch (e) { return []; } })() })) : [];
    const emp = t.length === 9 ? emps.find(x => nueveDigitos(x.telefono) === t) : null;
    f.contexto = { cliente, es_cliente_de_otro: !!(c && !cliente), solicitudes: sol, empresa: emp ? { nombre: emp.razon_social, estado: emp.estado } : null };
    f.notas = notas.filter(n => n.llamada_id === f.id).map(n => ({ texto: n.texto, asesor: n.asesor, creado_en: n.creado_en, origen: 'llamada' }));
    if (cliente) { const todas = await notasDeCliente(conn, cliente.id); if (todas) f.notas = todas.slice().reverse(); }   // 26/10: todas las del cliente
  }
  return filas;
}
app.post('/api/admin/llamadas/:id(\\d+)/notas', requiereSesionAsesor, async (req, res) => {
  const texto = String((req.body || {}).texto || '').trim().slice(0, 1000);
  if (!texto) return res.status(400).json({ error: 'La nota está vacía' });
  const [l] = await pool.execute('SELECT id FROM solicitudes_llamada WHERE id = ?', [Number(req.params.id)]);
  if (!l.length) return res.status(404).json({ error: 'Llamada no encontrada' });
  await pool.execute('INSERT INTO llamadas_notas (llamada_id, asesor_id, texto) VALUES (?, ?, ?)', [Number(req.params.id), req.asesor.id, texto]);
  const [n] = await pool.execute('SELECT n.texto, n.creado_en, a.nombre AS asesor FROM llamadas_notas n LEFT JOIN asesores a ON a.id = n.asesor_id WHERE n.llamada_id = ? ORDER BY n.creado_en', [Number(req.params.id)]);
  // 26/10: si es de un cliente que ve quien escribe, se devuelven todas las del cliente
  const [ll] = await pool.execute('SELECT telefono FROM solicitudes_llamada WHERE id = ?', [Number(req.params.id)]);
  const t = nueveDigitos(ll[0].telefono), permitidos = await clientesPermitidos(req).catch(() => null);
  if (t.length === 9) {
    const [cs] = await pool.query('SELECT id, telefono, telefono2 FROM clientes WHERE telefono IS NOT NULL OR telefono2 IS NOT NULL');
    const c = cs.find(x => (nueveDigitos(x.telefono) === t || nueveDigitos(x.telefono2) === t) && (!permitidos || permitidos.has(x.id)));
    if (c) { const conn = await pool.getConnection(); try { return res.status(201).json({ notas: (await notasDeCliente(conn, c.id)).slice().reverse() }); } finally { conn.release(); } }
  }
  res.status(201).json({ notas: n });
});

// ================================================================
// ASISTENTE: MÁS HERRAMIENTAS Y SOLO TEMAS DEL DESPACHO (21/10, Vikn)
// Además de chats y equipo, ve servicios (con sus plazos y si el año está sin
// confirmar), propuestas sin respuesta, pagos por confirmar, documentos por
// revisar y altas pendientes. Mismas reglas que las otras herramientas: solo
// los clientes que ve quien pregunta (un administrador, todos) y a la IA solo
// le llega el código de cada cliente, nunca su nombre (el panel lo cambia).
// ================================================================
IA_HERRAMIENTAS_PANEL.push(
  { name: 'servicios', description: 'Servicios contratados por los clientes (uno por fila): código del cliente, asesor, servicio, ejercicio, estado (en curso, el despacho lo dio por terminado y falta que el cliente lo confirme, terminado), si su año está aún sin confirmar por un administrador, plazo y si está urgente o vencido, y documentos que faltan del cliente.',
    input_schema: { type: 'object', properties: { filtro: { type: 'string', enum: ['en_curso', 'terminados', 'por_confirmar_cliente', 'anio_sin_confirmar', 'plazo_urgente_o_vencido', 'todos'], description: 'Qué servicios (por defecto, en curso)' }, asesor: { type: 'string', description: 'Opcional: nombre (o parte) del asesor' }, limite: { type: 'integer', description: 'Máximo (por defecto 50)' } } } },
  { name: 'propuestas_sin_respuesta', description: 'Propuestas enviadas que el cliente aún no ha aceptado (vigentes) y las que caducaron sin respuesta en los últimos 30 días: código del cliente, asesor, servicios, cuándo se envió y cuándo caduca o caducó.',
    input_schema: { type: 'object', properties: {} } },
  { name: 'pagos_por_confirmar', description: 'Pagos que el cliente dice haber hecho y el despacho aún no ha confirmado: código del cliente, método, importe en euros y desde cuándo.',
    input_schema: { type: 'object', properties: {} } },
  { name: 'documentos', description: 'Documentos fiscales: los subidos por el cliente que el despacho tiene que revisar, y los pedidos o rechazados que el cliente aún no ha subido. Código del cliente, asesor, servicio, nombre del documento y fecha.',
    input_schema: { type: 'object', properties: { filtro: { type: 'string', enum: ['por_revisar', 'pendientes_del_cliente'], description: 'Por defecto, por revisar' } } } },
  { name: 'altas', description: 'Altas de clientes (diligencia debida) en revisión o en examen especial, y encargos pagados que aún no tienen el alta hecha: código del cliente, asesor, estado y desde cuándo.',
    input_schema: { type: 'object', properties: {} } }
);
async function iaClientes(permitidos) {
  const [cs] = await pool.query('SELECT c.id, c.codigo, c.nombre, c.apellidos, c.correo, c.numero_documento, q.nombre AS asesor FROM clientes c LEFT JOIN personas q ON q.id = c.asesor_persona_id');
  return new Map(cs.filter(c => !permitidos || permitidos.has(c.id)).map(c => [c.id, Object.assign(c, { cod: c.codigo || ('C' + c.id) })]));
}
const iaFiltroAsesor = (c, f) => !f || sinAcentos(c.asesor || '').includes(sinAcentos(f));
const iaHerramientasExtra = {
  async servicios(e, permitidos, usados) {
    const cli = await iaClientes(permitidos);
    const [filas] = await pool.query(SQL_SERVICIOS + ' WHERE s.confirmado IN (0, 1)');
    const vistas = (await vistasDeFilas(pool, filas)).filter(v => cli.has(v.cliente_id) && iaFiltroAsesor(cli.get(v.cliente_id), e.asesor));
    const f = e.filtro || 'en_curso';
    const sel = vistas.filter(v => f === 'todos' || (f === 'en_curso' && v.en_curso) || (f === 'terminados' && !v.en_curso) || (f === 'por_confirmar_cliente' && v.estado === 'por_confirmar') || (f === 'anio_sin_confirmar' && !v.confirmado) || (f === 'plazo_urgente_o_vencido' && v.en_curso && v.confirmado && (v.plazo_estado === 'urgente' || v.plazo_estado === 'vencido')));
    const lim = Math.min(200, Math.max(1, Number(e.limite) || 50));
    const res = sel.slice(0, lim).map(v => { const c = cli.get(v.cliente_id); usados.set(c.cod, c.id);
      return { codigo: c.cod, asesor: c.asesor || 'sin asignar', servicio: v.nombre_es, ejercicio: v.confirmado ? (v.es_rango ? v.ejercicio_desde + '–' + v.ejercicio_hasta : v.ejercicio) : 'sin confirmar', estado: v.estado, anio_confirmado: !!v.confirmado, plazo: v.confirmado ? v.plazo : null, plazo_estado: v.confirmado ? v.plazo_estado : null, dias_restantes: v.confirmado ? v.dias_restantes : null, documentos_que_faltan: v.docs_pendientes }; });
    return { total: sel.length, mostrados: res.length, hoy: hoyMadridISO(), servicios: res };
  },
  async propuestas_sin_respuesta(e, permitidos, usados) {
    await caducarPropuestas();
    const cli = await iaClientes(permitidos);
    const [ps] = await pool.query("SELECT id, cliente_id, servicios, estado, creado_en, token_expira_en FROM propuestas WHERE estado = 'enviada' OR (estado = 'caducada' AND token_expira_en > NOW() - INTERVAL 30 DAY) ORDER BY token_expira_en");
    const nombre = id => { const t = TIPOS_SERVICIO[tipoDeServicio(id)]; return t && t.generico ? t.generico.es : id; };
    const res = ps.filter(p => cli.has(p.cliente_id)).map(p => { const c = cli.get(p.cliente_id); usados.set(c.cod, c.id);
      return { codigo: c.cod, asesor: c.asesor || 'sin asignar', estado: p.estado === 'enviada' ? 'vigente, sin respuesta' : 'caducó sin respuesta', servicios: serviciosDePropuesta(p).map(nombre), enviada: p.creado_en, caduca: p.token_expira_en }; });
    return { total: res.length, propuestas: res };
  },
  async pagos_por_confirmar(e, permitidos, usados) {
    const cli = await iaClientes(permitidos);
    const [pg] = await pool.query("SELECT g.metodo, g.creado_en, p.cliente_id, p.importe_centimos FROM pagos g JOIN propuestas p ON p.id = g.propuesta_id WHERE g.estado = 'autodeclarado' ORDER BY g.creado_en");
    const res = pg.filter(x => cli.has(x.cliente_id)).map(x => { const c = cli.get(x.cliente_id); usados.set(c.cod, c.id); return { codigo: c.cod, asesor: c.asesor || 'sin asignar', metodo: x.metodo, importe_euros: x.importe_centimos / 100, desde: x.creado_en }; });
    return { total: res.length, pagos: res };
  },
  async documentos(e, permitidos, usados) {
    const cli = await iaClientes(permitidos), por = e.filtro === 'pendientes_del_cliente';
    const [ds] = await pool.query(`SELECT cliente_id, servicio, nombre, estado, subido_en, creado_en FROM documentos_fiscales WHERE estado IN (${por ? "'pendiente','rechazado'" : "'enviado'"}) ORDER BY COALESCE(subido_en, creado_en)`);
    const res = ds.filter(d => cli.has(d.cliente_id)).slice(0, 200).map(d => { const c = cli.get(d.cliente_id); usados.set(c.cod, c.id);
      return { codigo: c.cod, asesor: c.asesor || 'sin asignar', servicio: d.servicio, documento: recorte(seudonimizarTexto(d.nombre, c), 120), estado: d.estado, fecha: d.subido_en || d.creado_en }; });
    return { total: res.length, documentos: res };
  },
  async altas(e, permitidos, usados) {
    const cli = await iaClientes(permitidos);
    const [ds] = await pool.query("SELECT cliente_id, estado, creado_en FROM diligencias WHERE estado IN ('revision', 'examen') ORDER BY creado_en");
    const [sin] = await pool.query("SELECT p.cliente_id, MIN(g.creado_en) AS pagado FROM propuestas p JOIN pagos g ON g.propuesta_id = p.id WHERE p.estado = 'aceptada' AND NOT EXISTS (SELECT 1 FROM diligencias d WHERE d.propuesta_id = p.id) GROUP BY p.cliente_id");
    const fila = (x, estado, desde) => { const c = cli.get(x.cliente_id); usados.set(c.cod, c.id); return { codigo: c.cod, asesor: c.asesor || 'sin asignar', estado, desde }; };
    return { altas: ds.filter(x => cli.has(x.cliente_id)).map(x => fila(x, x.estado === 'examen' ? 'en examen especial' : 'en revisión', x.creado_en))
      .concat(sin.filter(x => cli.has(x.cliente_id)).map(x => fila(x, 'pagado y sin hacer el alta', x.pagado))) };
  },
};
const iaEjecutarHerramientaBase = iaEjecutarHerramienta;
iaEjecutarHerramienta = async function (nombre, entrada, req, usados) {
  if (iaHerramientasExtra[nombre]) return iaHerramientasExtra[nombre](entrada || {}, await iaAlcance(req), usados);
  if (nombre === 'registro') return iaRegistro(entrada || {}, req, usados);   // 30/10: solo administradores
  return iaEjecutarHerramientaBase(nombre, entrada, req, usados);
};
IA_HERRAMIENTAS_PANEL.push({ name: 'registro', description: 'Registro maestro de actividad (solo para administradores): quién hizo qué y cuándo en el panel y en el Área (entradas, PIN, cambios de roles y permisos con el antes y el después, fichas y documentos abiertos, acciones de los clientes, correos y avisos enviados). Úsalo para preguntas como «¿alguien ha cambiado roles?» o «¿quién abrió la ficha de C12?». Responde con fecha, quién y qué.',
  input_schema: { type: 'object', properties: { desde: { type: 'string', description: 'AAAA-MM-DD' }, hasta: { type: 'string', description: 'AAAA-MM-DD' }, tipo: { type: 'string', enum: ['acceso', 'lectura', 'cambio', 'cliente', 'sistema'] }, persona: { type: 'string', description: 'Nombre (o parte) de quien lo hizo' }, texto: { type: 'string', description: 'Palabra a buscar en la acción o el detalle, p. ej. «roles», «PIN», «fusiona»' } } } });

// Solo en las baterías de pruebas (ACROS_PRUEBAS=1; en Railway no existe): ejecutar una herramienta como lo haría el asistente
if (process.env.ACROS_PRUEBAS === '1') app.post('/api/admin/ia/herramienta-prueba', requiereSesionAsesor, async (req, res) => {
  const usados = new Map();
  res.json({ resultado: await iaEjecutarHerramienta(String((req.body || {}).nombre), (req.body || {}).entrada || {}, req, usados), codigos: [...usados.keys()] });
});

// ================================================================
// «RECORDAR AL CLIENTE» (26/10, Vikn)
// Un solo botón en la ficha: se ven todas las cosas que se le pueden recordar
// a ese cliente (documentos, pagos, servicios por confirmar, el visto bueno de
// sus informes, completar el alta), cada una con cuándo se le recordó por
// última vez; se marcan las que se quieran y sale UN correo con todas.
// El visto bueno de un informe («Todo correcto») ya no lo puede dar el cliente
// por su cuenta: el asesor se lo pide desde aquí (la primera vez es «Pedir el
// visto bueno»), y entonces en su área le aparece el botón, en teja.
// ================================================================
const nombreGenerico = id => { const t = TIPOS_SERVICIO[tipoDeServicio(id)]; return t && t.generico ? t.generico.es : (id || ''); };
async function recordablesDeCliente(conn, clienteId) {
  const [recs] = await conn.execute('SELECT tipo, objeto_id, MAX(creado_en) AS ultimo FROM recordatorios_cliente WHERE cliente_id = ? GROUP BY tipo, objeto_id', [clienteId]);
  const ult = (t, id) => { const r = recs.find(x => x.tipo === t && x.objeto_id === id); return r ? r.ultimo : null; };
  const hoy = f => !!f && (Date.now() - new Date(f).getTime()) < HORAS_ENTRE_RECORDATORIOS * 3600e3;
  const it = [];
  const [docs] = await conn.execute("SELECT id, nombre, servicio, estado, creado_en, revisado_en FROM documentos_fiscales WHERE cliente_id = ? AND estado IN ('pendiente','rechazado') ORDER BY id", [clienteId]);
  docs.forEach(d => it.push({ tipo: 'documento', id: d.id, titulo: (d.estado === 'rechazado' ? 'Volver a subir «' : 'Subir «') + d.nombre + '»', sub: nombreGenerico(d.servicio) || 'Documento' }));
  const [props] = await conn.execute("SELECT p.id, p.servicios, p.creado_en, (SELECT COUNT(*) FROM pagos g WHERE g.propuesta_id = p.id) AS n_pagos, (SELECT COUNT(*) FROM diligencias d WHERE d.propuesta_id = p.id) AS n_altas FROM propuestas p WHERE p.cliente_id = ? AND p.estado = 'aceptada' ORDER BY p.id", [clienteId]);
  const dma = f => { const d = new Date(f); return String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0') + '/' + d.getFullYear(); };
  props.forEach(p => {
    const sv = serviciosDePropuesta(p).map(nombreGenerico).join(', ');
    if (!p.n_pagos) it.push({ tipo: 'pago', id: p.id, titulo: 'Pagar el encargo del ' + dma(p.creado_en), sub: sv });
    else if (!p.n_altas) it.push({ tipo: 'alta', id: p.id, titulo: 'Completar el alta (cuestionario y documento de identidad)', sub: 'Encargo del ' + dma(p.creado_en) });
  });
  const sv = await listarServiciosCliente(conn, clienteId);
  sv.filter(s => s.estado === 'por_confirmar').forEach(s => it.push({ tipo: 'servicio', id: s.id, titulo: 'Confirmar que está terminado', sub: s.nombre_es }));
  const [ents] = await conn.execute("SELECT e.id, e.nombre_archivo, e.servicio, e.conformidad_pedida_en FROM entregas e WHERE e.cliente_id = ? AND e.estado = 'entregado' AND e.id = (SELECT MAX(e2.id) FROM entregas e2 WHERE e2.propuesta_id = e.propuesta_id AND e2.servicio = e.servicio) ORDER BY e.id", [clienteId]);
  ents.forEach(e => it.push({ tipo: 'informe', id: e.id, titulo: e.conformidad_pedida_en ? 'Dar el visto bueno al informe «' + e.nombre_archivo + '»' : 'Pedirle el visto bueno del informe «' + e.nombre_archivo + '»', sub: nombreGenerico(e.servicio), pedida: e.conformidad_pedida_en }));
  return it.map(x => { const u = ult(x.tipo, x.id); return Object.assign(x, { ultimo: u, recordado_hoy: hoy(u) }); });
}
app.get('/api/admin/clientes/:id(\\d+)/recordables', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try { res.json({ items: await recordablesDeCliente(conn, Number(req.params.id)) }); } finally { conn.release(); }
});
app.post('/api/admin/clientes/:id(\\d+)/recordar', requiereSesionAsesor, async (req, res) => {
  const clienteId = Number(req.params.id);
  const pedidos = Array.isArray((req.body || {}).items) ? req.body.items : [];
  if (!pedidos.length) return res.status(400).json({ error: 'Marca al menos una cosa que recordarle' });
  const conn = await pool.getConnection();
  try {
    const todos = await recordablesDeCliente(conn, clienteId);
    const elegidos = [], omitidos = [];
    for (const p of pedidos) {
      const x = todos.find(t => t.tipo === p.tipo && t.id === Number(p.id));
      if (!x) { omitidos.push({ tipo: p.tipo, id: p.id, motivo: 'ya no está pendiente' }); continue; }
      if (x.recordado_hoy) { omitidos.push({ tipo: x.tipo, id: x.id, motivo: 'ya se le recordó hoy' }); continue; }
      elegidos.push(x);
    }
    if (!elegidos.length) return res.status(409).json({ error: 'Nada que enviar: ' + omitidos.map(o => o.motivo).filter((v, i, a) => a.indexOf(v) === i).join('; '), omitidos });
    for (const x of elegidos) {
      await conn.execute('INSERT INTO recordatorios_cliente (tipo, objeto_id, cliente_id, asesor_id) VALUES (?, ?, ?, ?)', [x.tipo, x.id, clienteId, req.asesor.id]);
      if (x.tipo === 'informe') await conn.execute('UPDATE entregas SET conformidad_pedida_en = COALESCE(conformidad_pedida_en, NOW()) WHERE id = ?', [x.id]);
    }
    const [cl] = await conn.execute('SELECT correo, nombre FROM clientes WHERE id = ?', [clienteId]);
    const asesor = await personaDeCliente(clienteId, conn).catch(() => null);
    const quien = asesor ? ESC_HTML(asesor.nombre) : 'Tu asesor';
    const enlace = SITE_URL ? `${SITE_URL}/area?login=1` : null;
    const linea = x => x.tipo === 'informe' ? 'Dar el visto bueno a tu informe «' + ESC_HTML(x.titulo.replace(/^.*«|»$/g, '')) + '» (' + ESC_HTML(x.sub) + ')' : ESC_HTML(x.titulo) + (x.sub ? ' (' + ESC_HTML(x.sub) + ')' : '');
    let correo = 'sin_correo';
    if (cl.length && cl[0].correo) {
      if (!brevoActivo()) correo = 'sin_servicio';
      else {
        const c = plantillaCorreo({
          titulo: elegidos.length === 1 ? 'Tienes algo pendiente en tu área' : 'Tienes ' + elegidos.length + ' cosas pendientes en tu área',
          parrafos: [cl[0].nombre ? `Hola, ${ESC_HTML(cl[0].nombre)}:` : 'Hola:', `${quien} te recuerda lo que tienes pendiente para avanzar con tu encargo:`, '<ul>' + elegidos.map(x => '<li>' + linea(x) + '</li>').join('') + '</ul>', 'Lo tienes todo en «Te toca a ti», dentro de tu área.'],
          boton: enlace ? { texto: 'Entrar en mi área', url: enlace } : null,
          nota: 'Por tu privacidad, no envíes documentos por correo: súbelos siempre desde tu área.',
        });
        try {
          const salio = await notificarCliente(conn, clienteId, 'recordatorios', () => enviarCorreo(cl[0].correo, (asesor ? asesor.nombre + ', tu asesor de Acros' : 'Tu asesor de Acros') + ', te recuerda lo que tienes pendiente', c.html, c.texto), 'Acros: ' + (asesor ? asesor.nombre : 'tu asesor') + ' te recuerda lo que tienes pendiente en tu área.' + (enlace ? ' ' + enlace : ''));
          correo = salio ? 'enviado' : 'desactivado_por_cliente';
        } catch (err) { console.error('Recordatorio conjunto no enviado:', err.message); correo = 'fallo'; }
      }
    }
    res.json({ ok: true, correo, enviados: elegidos.length, omitidos });
  } finally { conn.release(); }
});

// ================================================================
// NOTAS DEL CLIENTE (26/10, Vikn)
// Un solo historial por cliente, como un blog: no se borra ni se edita nada y
// cada nota lleva quién, cuándo y desde dónde se escribió. Junta las notas
// escritas en su ficha y las de sus llamadas (por su teléfono), se escribieran
// donde se escribieran.
// ================================================================
async function notasDeCliente(conn, clienteId) {
  const [cl] = await conn.execute('SELECT telefono, telefono2 FROM clientes WHERE id = ?', [clienteId]);
  if (!cl.length) return null;
  const [propias] = await conn.execute("SELECT n.id, n.texto, n.creado_en, n.origen, a.nombre AS asesor FROM notas_cliente n LEFT JOIN asesores a ON a.id = n.asesor_id WHERE n.cliente_id = ?", [clienteId]);
  const tels = [cl[0].telefono, cl[0].telefono2].map(nueveDigitos).filter(t => t.length === 9);
  let deLlamadas = [];
  if (tels.length) {
    const [ll] = await conn.query('SELECT id, telefono, creado_en FROM solicitudes_llamada');
    const ids = ll.filter(l => tels.includes(nueveDigitos(l.telefono))).map(l => l.id);
    if (ids.length) [deLlamadas] = await conn.query("SELECT n.id, n.texto, n.creado_en, 'llamada' AS origen, n.llamada_id, a.nombre AS asesor FROM llamadas_notas n LEFT JOIN asesores a ON a.id = n.asesor_id WHERE n.llamada_id IN (?)", [ids]);
  }
  return propias.map(n => Object.assign(n, { clave: 'c' + n.id })).concat(deLlamadas.map(n => Object.assign(n, { clave: 'l' + n.id })))
    .sort((a, b) => new Date(b.creado_en) - new Date(a.creado_en) || (b.clave > a.clave ? 1 : -1));
}
app.get('/api/admin/clientes/:id(\\d+)/notas', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try { const n = await notasDeCliente(conn, Number(req.params.id)); if (!n) return res.status(404).json({ error: 'Cliente no encontrado' }); res.json({ notas: n }); } finally { conn.release(); }
});
app.post('/api/admin/clientes/:id(\\d+)/notas', requiereSesionAsesor, async (req, res) => {
  const texto = String((req.body || {}).texto || '').trim().slice(0, 4000);
  if (!texto) return res.status(400).json({ error: 'Escribe la nota' });
  const conn = await pool.getConnection();
  try {
    const [c] = await conn.execute('SELECT id FROM clientes WHERE id = ?', [Number(req.params.id)]);
    if (!c.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    await conn.execute("INSERT INTO notas_cliente (cliente_id, asesor_id, origen, texto) VALUES (?, ?, 'ficha', ?)", [Number(req.params.id), req.asesor.id, texto]);
    res.status(201).json({ notas: await notasDeCliente(conn, Number(req.params.id)) });
  } finally { conn.release(); }
});

// ================================================================
// RELACIÓN CON ACROS (26/10, Vikn)
// Una vista propia por cliente con lo «comercial»: la cobertura por ejercicio
// (qué servicios tiene con nosotros cada año, con «Sí» automático por sus
// servicios y marcas a mano «No» o «Sí, fuera del sistema» con su nota, que
// guardan historial: nada se borra), resumen de encargos y pagos y valoraciones.
// ================================================================
const FILAS_COBERTURA = ['renta', 'pyg', 'm720', 'm721', 'm714', 'optimizacion', 'requerimiento', 'origen', 'certificado', 'nft', 'acompanamiento'];
const ESTADOS_MARCA = ['no', 'fuera', 'quitar'];
app.get('/api/admin/clientes/:id(\\d+)/relacion', requiereSesionAsesor, async (req, res) => {
  const clienteId = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    const [cl] = await conn.execute('SELECT id, creado_en FROM clientes WHERE id = ?', [clienteId]);
    if (!cl.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const [sv] = await conn.execute('SELECT id, tipo, ejercicio_desde, ejercicio_hasta, estado, confirmado FROM servicios_cliente WHERE cliente_id = ? AND confirmado IN (0, 1)', [clienteId]);
    const [mar] = await conn.execute('SELECT m.id, m.tipo, m.ejercicio, m.estado, m.nota, m.creado_en, a.nombre AS asesor FROM cobertura_marcas m LEFT JOIN asesores a ON a.id = m.asesor_id WHERE m.cliente_id = ? ORDER BY m.creado_en, m.id', [clienteId]);
    const [vals] = await conn.execute("SELECT v.propuesta_id, v.atencion, v.calidad, v.rapidez, COALESCE(v.comentario_revisado, v.comentario) AS comentario, v.estado, v.creado_en FROM valoraciones v WHERE v.cliente_id = ? AND v.estado <> 'omitida' ORDER BY v.creado_en DESC", [clienteId]);
    const anioActual = Number(hoyMadridISO().slice(0, 4));
    const anios = new Set();
    for (let a = anioActual - 4; a <= anioActual; a++) anios.add(a);
    const celdas = [];
    sv.forEach(s => {
      const fila = s.tipo === 'pyg_anteriores' ? 'pyg' : s.tipo;
      if (!FILAS_COBERTURA.includes(fila)) return;
      const d = s.ejercicio_desde || s.ejercicio_hasta, h = s.ejercicio_hasta || s.ejercicio_desde;
      if (!d) return;
      for (let a = d; a <= h && a <= anioActual + 1; a++) { anios.add(a); celdas.push({ fila, anio: a, servicio_id: s.id, estado: s.estado, sin_confirmar: !s.confirmado, via: s.tipo === 'pyg_anteriores' ? 'P&G de ejercicios anteriores' : null }); }
    });
    const ultima = {};
    mar.forEach(m => { ultima[m.tipo + ':' + m.ejercicio] = m; anios.add(m.ejercicio); });
    const marcas = Object.values(ultima).filter(m => m.estado !== 'quitar');
    const medias = vals.filter(v => v.atencion || v.calidad || v.rapidez);
    const media = medias.length ? Math.round(medias.reduce((t, v) => t + ((v.atencion || 0) + (v.calidad || 0) + (v.rapidez || 0)) / [v.atencion, v.calidad, v.rapidez].filter(Boolean).length, 0) / medias.length * 10) / 10 : null;
    res.json({
      filas: FILAS_COBERTURA.map(t => ({ tipo: t, nombre: (TIPOS_SERVICIO[t].generico || {}).es || t })),
      anios: [...anios].filter(a => a >= 2010 && a <= anioActual + 1).sort((a, b) => a - b), anio_actual: anioActual,
      celdas, marcas, historial_marcas: mar, valoraciones: vals, valoracion_media: media, cliente_desde: cl[0].creado_en,
    });
  } finally { conn.release(); }
});
app.post('/api/admin/clientes/:id(\\d+)/cobertura', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {};
  const tipo = String(b.tipo || ''), anio = Number(b.ejercicio), estado = String(b.estado || ''), nota = String(b.nota || '').trim().slice(0, 1000);
  if (!FILAS_COBERTURA.includes(tipo)) return res.status(400).json({ error: 'Servicio no válido' });
  if (!Number.isInteger(anio) || anio < 2010 || anio > 2100) return res.status(400).json({ error: 'Ejercicio no válido' });
  if (!ESTADOS_MARCA.includes(estado)) return res.status(400).json({ error: 'Marca no válida' });
  if (estado !== 'quitar' && !nota) return res.status(400).json({ error: 'Escribe el motivo: es lo que explica por qué tiene o no tiene ese servicio con nosotros' });
  const [c] = await pool.execute('SELECT id FROM clientes WHERE id = ?', [Number(req.params.id)]);
  if (!c.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  await pool.execute('INSERT INTO cobertura_marcas (cliente_id, tipo, ejercicio, estado, nota, asesor_id) VALUES (?, ?, ?, ?, ?, ?)', [Number(req.params.id), tipo, anio, estado, nota || null, req.asesor.id]);
  res.status(201).json({ ok: true });
});

// ================================================================
// COBRO «ANTES» O «DESPUÉS» (29/10, Vikn)
// Cada propuesta lleva `cobro`: 'antes' (como siempre: aceptar → pagar → alta)
// o 'despues' (aceptar → alta → trabajo → pagar, con 30 días de plazo para el
// pago). En los dos casos, hasta que un administrador CONFIRMA el pago, el
// cliente no puede: ver ni descargar informes, dar el visto bueno ni pedir
// cambios, ver la cartera publicada ni el simulador, cerrar un servicio por
// su parte ni valorar. El asesor sí puede subir informes: quedan preparados.
// ================================================================
const DIAS_PLAZO_PAGO = 30;
async function pagoConfirmadoDe(conn, propuestaId) {
  const [r] = await conn.execute("SELECT 1 FROM pagos WHERE propuesta_id = ? AND estado = 'confirmado' LIMIT 1", [propuestaId]);
  return r.length > 0;
}
async function clienteConPagoConfirmado(conn, clienteId) {
  const [r] = await conn.execute("SELECT 1 FROM pagos g JOIN propuestas p ON p.id = g.propuesta_id WHERE p.cliente_id = ? AND g.estado = 'confirmado' LIMIT 1", [clienteId]);
  return r.length > 0;
}
function plazoPagoDe(p) {
  if (p.cobro !== 'despues' || p.estado !== 'aceptada') return null;
  const d = new Date(p.inicio_inmediato_en || p.creado_en); d.setDate(d.getDate() + DIAS_PLAZO_PAGO);
  return d;
}
const SIN_PAGO = { error: 'Esta parte se desbloquea cuando Acros confirme tu pago.', codigo: 'pago_pendiente' };
// Un «portero» para las rutas del cliente que exigen pago confirmado (por encargo)
async function exigirPagoConfirmado(req, res, next) {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (!(await pagoConfirmadoDe(conn, p.id))) return res.status(402).json(SIN_PAGO);
    next();
  } finally { conn.release(); }
}
// Y otro por cliente (cartera y simulador): basta con que tenga algún encargo pagado
async function exigirAlgunPagoConfirmado(req, res, next) {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    if (!(await clienteConPagoConfirmado(conn, p.cliente_id))) return res.status(402).json(SIN_PAGO);
    next();
  } finally { conn.release(); }
}

// ================================================================
// CAMBIO DE ASESOR (29/10, Vikn): solo se ofrecen los del mismo equipo, con una
// opción «al azar» dentro del equipo; y el aviso llega también por correo a los
// administradores (antes solo salía por ntfy).
// ================================================================
async function candidatasCambioAsesor(conn, actual) {
  const [todas] = await conn.query('SELECT * FROM personas WHERE `activa` = 1 AND `atiende_clientes` = 1 ORDER BY `orden`, `id`');
  const eq = actual && actual.equipo_id;
  return todas.filter(x => (!actual || x.id !== actual.id) && (!eq || x.equipo_id === eq));
}
async function correoCambioAsesor(_conn, clienteId, actual, destino, motivo, azar) {
  if (!brevoActivo()) return;
  const [cl] = await pool.execute('SELECT nombre, apellidos, correo FROM clientes WHERE id = ?', [clienteId]);
  if (!cl.length) return;
  const nombre = [cl[0].nombre, cl[0].apellidos].filter(Boolean).join(' ') || cl[0].correo;
  const c = plantillaCorreo({ titulo: 'Un cliente pide cambiar de asesor', parrafos: [
    ESC_HTML(nombre) + ' (' + ESC_HTML(cl[0].correo) + ') pide pasar ' + (actual ? 'de <strong>' + ESC_HTML(actual.nombre) + '</strong> ' : '') + 'a <strong>' + ESC_HTML(destino.nombre) + '</strong>' + (azar ? ' (ha dejado que se elija al azar dentro de su equipo)' : '') + '.',
    motivo ? 'Motivo: «' + ESC_HTML(motivo) + '»' : 'No ha dado motivo.',
    'Confírmalo en «Cambios de asesor pendientes»: panel.acrosfi.es' ] });
  const [admins] = await pool.execute('SELECT correo FROM asesores WHERE es_admin = 1 AND activo = 1');
  for (const a of admins) {
    try { await enviarCorreo(a.correo, 'Cambio de asesor pedido · ' + nombre, c.html, c.texto); }
    catch (err) { console.error('Aviso de cambio de asesor no enviado a ' + a.correo + ':', err.message); }
  }
}
// El correo de respuesta al cliente como un hilo: lo que pidió y lo que se le contesta
function hiloCambioAsesor(cambio, destino, respuesta) {
  const fmt = f => { const d = new Date(f); return String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0') + '/' + d.getFullYear(); };
  const azar = /^Ha pedido que se elija al azar/.test(cambio.motivo || '');
  let texto = String(cambio.texto_cliente || '').trim();
  if (!texto && cambio.motivo) texto = String(cambio.motivo).replace(/^Ha pedido que se elija al azar dentro de su equipo\.\s*/, '').trim();
  if (!texto) texto = azar ? 'Cambio de asesor, sin preferencias.' : 'Cambio de asesor a ' + (destino ? destino.nombre : 'otra persona') + '.';
  const h = [{ quien: 'Tu solicitud', fecha: fmt(cambio.creado_en), texto }];
  if (respuesta) h.push({ quien: 'Respuesta de Acros', propio: true, texto: respuesta });
  return h;
}

// ---- Género del asesor en los correos (29/10, Vikn): «Marta, tu asesora de Acros» / «Felipe, tu asesor de Acros» ----
const NOMBRES_FEM_EXC = new Set(['borja', 'luca', 'joshua', 'jose maria', 'josé maría', 'costa', 'garcia']);   // acaban en -a y son de hombre
const NOMBRES_MASC_EXC = new Set(['carmen', 'pilar', 'beatriz', 'mar', 'inés', 'ines', 'raquel', 'isabel', 'consuelo', 'rocío', 'rocio', 'dolores', 'mercedes', 'esther', 'ester', 'noelia', 'lourdes', 'montserrat']);   // no acaban en -a y son de mujer
function generoPorNombre(nombre) {
  const n = String(nombre || '').trim().toLowerCase().split(/\s+/)[0] || '';
  if (NOMBRES_MASC_EXC.has(n)) return 'f';
  if (NOMBRES_FEM_EXC.has(n)) return 'm';
  return /a$/.test(n) ? 'f' : 'm';
}
let CACHE_GENERO = { hasta: 0, mujeres: [] };
async function mujeresDelEquipo() {
  if (Date.now() < CACHE_GENERO.hasta) return CACHE_GENERO.mujeres;
  try { const [f] = await pool.query("SELECT nombre FROM personas WHERE genero = 'f'"); CACHE_GENERO = { hasta: Date.now() + 60000, mujeres: f.map(x => x.nombre) }; } catch (e) { /* aún sin columna */ }
  return CACHE_GENERO.mujeres;
}
// Ajusta «tu asesor» al género de la persona nombrada justo delante; sin nombre, no se presupone género: «Tu equipo de Acros»
async function ajustarGeneroCorreo(...textos) {
  const mujeres = await mujeresDelEquipo();
  return textos.map(t => {
    if (!t) return t;
    let r = String(t);
    for (const n of mujeres) {
      const variantes = [n, ESC_HTML(n)].filter((v, i, a) => a.indexOf(v) === i);
      for (const v of variantes) r = r.split(v + ', tu asesor').join(v + ', tu asesora');
    }
    return r.replace(/(^|[>.!?]\s*|\n)Tu asesor de Acros/g, '$1Tu equipo de Acros');
  });
}

// ================================================================
// PANTALLAS DE ERROR BONITAS (29/10, Vikn) — generado por generar_errores.py
// A quien llega con un navegador a una dirección que no existe o que falla se le enseña una página de Acros; a los programas, el JSON de siempre.
// ================================================================
const PAGINAS_ERROR = {"es": {"404": "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>No encontramos esa página · Acros</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\"><style>\n:root { --fondo:#FBF8F2; --panel:#FFFFFF; --linea:#E6DCCD; --tinta:#335C47; --titular:#23402F; --suave:#6B655C; --acento:#A84C18; --boton:#B9541B; --boton-t:#FFFFFF; --sombra:0 10px 30px rgba(66,52,36,.10); }\n@media (prefers-color-scheme: dark) { :root { --fondo:#16301F; --panel:#1F3428; --linea:#3A5245; --tinta:#E8E1D4; --titular:#F2ECE1; --suave:#C9C2B6; --acento:#D9A066; --boton:#D9A066; --boton-t:#1C2A22; --sombra:none; } }\n* { box-sizing:border-box; } html,body { height:100%; margin:0; }\nbody { background:var(--fondo); color:var(--tinta); font-family:'IBM Plex Sans', Helvetica, Arial, sans-serif; line-height:1.55; display:flex; align-items:center; justify-content:center; padding:24px; }\n.caja { width:100%; max-width:560px; background:var(--panel); border:1px solid var(--linea); border-top:4px solid #D2601F; border-radius:18px; box-shadow:var(--sombra); padding:36px 34px 28px; text-align:center; }\n.logo { width:58px; height:58px; display:block; margin:0 auto 6px; }\n.marca { font-family:'IBM Plex Serif', Georgia, serif; letter-spacing:.3em; font-size:18px; color:var(--titular); margin:0 0 18px; }\n.codigo { font-family:'IBM Plex Serif', Georgia, serif; font-size:72px; line-height:1; color:var(--acento); margin:6px 0 4px; font-weight:600; }\nh1 { font-family:'IBM Plex Serif', Georgia, serif; font-size:26px; line-height:1.25; color:var(--titular); margin:6px 0 10px; font-weight:600; }\np { margin:0 auto 22px; max-width:440px; color:var(--suave); font-size:15.5px; }\n.botones { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; margin-bottom:6px; }\n.boton { display:inline-block; padding:13px 24px; border-radius:11px; font:inherit; font-weight:600; font-size:15.5px; text-decoration:none; cursor:pointer; border:1px solid transparent; }\n.boton.prim { background:var(--boton); color:var(--boton-t); } .boton.sec { background:transparent; color:var(--tinta); border-color:var(--linea); }\n.pie { border-top:1px solid var(--linea); margin-top:24px; padding-top:14px; font-size:12.5px; color:var(--suave); }\n.pie a { color:var(--suave); }\n@media (max-width:480px) { .caja { padding:28px 20px 22px; } .codigo { font-size:58px; } h1 { font-size:22px; } .boton { width:100%; text-align:center; } }\n</style></head>\n<body><main class=\"caja\"><img class=\"logo\" src=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\" alt=\"\"><p class=\"marca\" style=\"max-width:none\">ACROS</p>\n<div class=\"codigo\">404</div><h1>No encontramos esa página</h1><p>Puede que la dirección esté mal escrita o que la página ya no exista. Desde aquí puedes volver al inicio o entrar en tu área.</p>\n<div class=\"botones\"><a class=\"boton prim\" href=\"https://acrosfi.es\">Ir al inicio</a><a class=\"boton sec\" href=\"https://acrosfi.es/area\">Entrar en mi área</a></div>\n<div class=\"pie\">Acros, tu asesoría fiscal de criptoactivos.<br>Contacta en: <a href=\"https://acrosfi.es\">acrosfi.es</a> / 668 170 020</div></main></body></html>", "500": "<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>Algo no ha ido bien · Acros</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\"><style>\n:root { --fondo:#FBF8F2; --panel:#FFFFFF; --linea:#E6DCCD; --tinta:#335C47; --titular:#23402F; --suave:#6B655C; --acento:#A84C18; --boton:#B9541B; --boton-t:#FFFFFF; --sombra:0 10px 30px rgba(66,52,36,.10); }\n@media (prefers-color-scheme: dark) { :root { --fondo:#16301F; --panel:#1F3428; --linea:#3A5245; --tinta:#E8E1D4; --titular:#F2ECE1; --suave:#C9C2B6; --acento:#D9A066; --boton:#D9A066; --boton-t:#1C2A22; --sombra:none; } }\n* { box-sizing:border-box; } html,body { height:100%; margin:0; }\nbody { background:var(--fondo); color:var(--tinta); font-family:'IBM Plex Sans', Helvetica, Arial, sans-serif; line-height:1.55; display:flex; align-items:center; justify-content:center; padding:24px; }\n.caja { width:100%; max-width:560px; background:var(--panel); border:1px solid var(--linea); border-top:4px solid #D2601F; border-radius:18px; box-shadow:var(--sombra); padding:36px 34px 28px; text-align:center; }\n.logo { width:58px; height:58px; display:block; margin:0 auto 6px; }\n.marca { font-family:'IBM Plex Serif', Georgia, serif; letter-spacing:.3em; font-size:18px; color:var(--titular); margin:0 0 18px; }\n.codigo { font-family:'IBM Plex Serif', Georgia, serif; font-size:72px; line-height:1; color:var(--acento); margin:6px 0 4px; font-weight:600; }\nh1 { font-family:'IBM Plex Serif', Georgia, serif; font-size:26px; line-height:1.25; color:var(--titular); margin:6px 0 10px; font-weight:600; }\np { margin:0 auto 22px; max-width:440px; color:var(--suave); font-size:15.5px; }\n.botones { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; margin-bottom:6px; }\n.boton { display:inline-block; padding:13px 24px; border-radius:11px; font:inherit; font-weight:600; font-size:15.5px; text-decoration:none; cursor:pointer; border:1px solid transparent; }\n.boton.prim { background:var(--boton); color:var(--boton-t); } .boton.sec { background:transparent; color:var(--tinta); border-color:var(--linea); }\n.pie { border-top:1px solid var(--linea); margin-top:24px; padding-top:14px; font-size:12.5px; color:var(--suave); }\n.pie a { color:var(--suave); }\n@media (max-width:480px) { .caja { padding:28px 20px 22px; } .codigo { font-size:58px; } h1 { font-size:22px; } .boton { width:100%; text-align:center; } }\n</style></head>\n<body><main class=\"caja\"><img class=\"logo\" src=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\" alt=\"\"><p class=\"marca\" style=\"max-width:none\">ACROS</p>\n<div class=\"codigo\">500</div><h1>Algo no ha ido bien</h1><p>Hemos tenido un problema de nuestro lado. No se ha perdido nada: inténtalo de nuevo en un momento. Si sigue pasando, escríbenos o llámanos.</p>\n<div class=\"botones\"><a class=\"boton prim\" href=\"javascript:location.reload()\">Reintentar</a><a class=\"boton sec\" href=\"https://acrosfi.es\">Ir al inicio</a></div>\n<div class=\"pie\">Acros, tu asesoría fiscal de criptoactivos.<br>Contacta en: <a href=\"https://acrosfi.es\">acrosfi.es</a> / 668 170 020</div></main></body></html>"}, "en": {"404": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>We can't find that page · Acros</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\"><style>\n:root { --fondo:#FBF8F2; --panel:#FFFFFF; --linea:#E6DCCD; --tinta:#335C47; --titular:#23402F; --suave:#6B655C; --acento:#A84C18; --boton:#B9541B; --boton-t:#FFFFFF; --sombra:0 10px 30px rgba(66,52,36,.10); }\n@media (prefers-color-scheme: dark) { :root { --fondo:#16301F; --panel:#1F3428; --linea:#3A5245; --tinta:#E8E1D4; --titular:#F2ECE1; --suave:#C9C2B6; --acento:#D9A066; --boton:#D9A066; --boton-t:#1C2A22; --sombra:none; } }\n* { box-sizing:border-box; } html,body { height:100%; margin:0; }\nbody { background:var(--fondo); color:var(--tinta); font-family:'IBM Plex Sans', Helvetica, Arial, sans-serif; line-height:1.55; display:flex; align-items:center; justify-content:center; padding:24px; }\n.caja { width:100%; max-width:560px; background:var(--panel); border:1px solid var(--linea); border-top:4px solid #D2601F; border-radius:18px; box-shadow:var(--sombra); padding:36px 34px 28px; text-align:center; }\n.logo { width:58px; height:58px; display:block; margin:0 auto 6px; }\n.marca { font-family:'IBM Plex Serif', Georgia, serif; letter-spacing:.3em; font-size:18px; color:var(--titular); margin:0 0 18px; }\n.codigo { font-family:'IBM Plex Serif', Georgia, serif; font-size:72px; line-height:1; color:var(--acento); margin:6px 0 4px; font-weight:600; }\nh1 { font-family:'IBM Plex Serif', Georgia, serif; font-size:26px; line-height:1.25; color:var(--titular); margin:6px 0 10px; font-weight:600; }\np { margin:0 auto 22px; max-width:440px; color:var(--suave); font-size:15.5px; }\n.botones { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; margin-bottom:6px; }\n.boton { display:inline-block; padding:13px 24px; border-radius:11px; font:inherit; font-weight:600; font-size:15.5px; text-decoration:none; cursor:pointer; border:1px solid transparent; }\n.boton.prim { background:var(--boton); color:var(--boton-t); } .boton.sec { background:transparent; color:var(--tinta); border-color:var(--linea); }\n.pie { border-top:1px solid var(--linea); margin-top:24px; padding-top:14px; font-size:12.5px; color:var(--suave); }\n.pie a { color:var(--suave); }\n@media (max-width:480px) { .caja { padding:28px 20px 22px; } .codigo { font-size:58px; } h1 { font-size:22px; } .boton { width:100%; text-align:center; } }\n</style></head>\n<body><main class=\"caja\"><img class=\"logo\" src=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\" alt=\"\"><p class=\"marca\" style=\"max-width:none\">ACROS</p>\n<div class=\"codigo\">404</div><h1>We can't find that page</h1><p>The address may be misspelled or the page may no longer exist. From here you can go back home or enter your area.</p>\n<div class=\"botones\"><a class=\"boton prim\" href=\"https://acrosfi.es\">Go to the homepage</a><a class=\"boton sec\" href=\"https://acrosfi.es/area\">Enter my area</a></div>\n<div class=\"pie\">Acros, your crypto-asset tax advisory.<br>Contact: <a href=\"https://acrosfi.es\">acrosfi.es</a> / +34 668 170 020</div></main></body></html>", "500": "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><title>Something went wrong · Acros</title>\n<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\"><style>\n:root { --fondo:#FBF8F2; --panel:#FFFFFF; --linea:#E6DCCD; --tinta:#335C47; --titular:#23402F; --suave:#6B655C; --acento:#A84C18; --boton:#B9541B; --boton-t:#FFFFFF; --sombra:0 10px 30px rgba(66,52,36,.10); }\n@media (prefers-color-scheme: dark) { :root { --fondo:#16301F; --panel:#1F3428; --linea:#3A5245; --tinta:#E8E1D4; --titular:#F2ECE1; --suave:#C9C2B6; --acento:#D9A066; --boton:#D9A066; --boton-t:#1C2A22; --sombra:none; } }\n* { box-sizing:border-box; } html,body { height:100%; margin:0; }\nbody { background:var(--fondo); color:var(--tinta); font-family:'IBM Plex Sans', Helvetica, Arial, sans-serif; line-height:1.55; display:flex; align-items:center; justify-content:center; padding:24px; }\n.caja { width:100%; max-width:560px; background:var(--panel); border:1px solid var(--linea); border-top:4px solid #D2601F; border-radius:18px; box-shadow:var(--sombra); padding:36px 34px 28px; text-align:center; }\n.logo { width:58px; height:58px; display:block; margin:0 auto 6px; }\n.marca { font-family:'IBM Plex Serif', Georgia, serif; letter-spacing:.3em; font-size:18px; color:var(--titular); margin:0 0 18px; }\n.codigo { font-family:'IBM Plex Serif', Georgia, serif; font-size:72px; line-height:1; color:var(--acento); margin:6px 0 4px; font-weight:600; }\nh1 { font-family:'IBM Plex Serif', Georgia, serif; font-size:26px; line-height:1.25; color:var(--titular); margin:6px 0 10px; font-weight:600; }\np { margin:0 auto 22px; max-width:440px; color:var(--suave); font-size:15.5px; }\n.botones { display:flex; gap:10px; justify-content:center; flex-wrap:wrap; margin-bottom:6px; }\n.boton { display:inline-block; padding:13px 24px; border-radius:11px; font:inherit; font-weight:600; font-size:15.5px; text-decoration:none; cursor:pointer; border:1px solid transparent; }\n.boton.prim { background:var(--boton); color:var(--boton-t); } .boton.sec { background:transparent; color:var(--tinta); border-color:var(--linea); }\n.pie { border-top:1px solid var(--linea); margin-top:24px; padding-top:14px; font-size:12.5px; color:var(--suave); }\n.pie a { color:var(--suave); }\n@media (max-width:480px) { .caja { padding:28px 20px 22px; } .codigo { font-size:58px; } h1 { font-size:22px; } .boton { width:100%; text-align:center; } }\n</style></head>\n<body><main class=\"caja\"><img class=\"logo\" src=\"data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2212 -80 996 996%22%3E%3Cg transform=%22translate%280 827%29 scale%28.1 -.1%29%22 fill=%22%23D2601F%22%3E%3Cpath d=%22M4945 8083 c-136 -13 -249 -51 -358 -122 -136 -89 -225 -199 -414 -506 -44 -71 -135 -218 -202 -325 -132 -209 -165 -262 -346 -555 -202 -325 -235 -378 -505 -815 -145 -234 -302 -488 -350 -565 -48 -77 -124 -201 -170 -275 -46 -74 -111 -180 -145 -235 -118 -191 -380 -612 -605 -970 -124 -198 -285 -454 -357 -570 -188 -302 -299 -482 -369 -593 -58 -94 -180 -289 -309 -497 -583 -940 -595 -961 -620 -1068 -21 -87 -20 -362 0 -442 52 -197 205 -328 413 -356 51 -6 1605 -9 4552 -7 l4475 3 65 23 c134 48 217 123 279 252 l36 75 4 183 c4 199 -5 270 -44 358 -20 46 -119 211 -395 664 -42 69 -135 222 -207 340 -72 118 -166 272 -209 342 -44 70 -116 187 -160 260 -170 278 -543 883 -804 1303 -48 77 -154 248 -235 380 -179 290 -420 677 -620 995 -129 205 -447 719 -525 850 -15 25 -62 101 -105 170 -43 69 -175 285 -293 480 -118 195 -277 456 -352 580 -199 329 -205 337 -299 430 -129 128 -267 192 -450 210 -92 9 -293 11 -376 3z m227 -629 c115 -58 118 -62 570 -804 69 -113 161 -261 203 -330 140 -226 230 -372 383 -620 l151 -245 -147 -5 c-114 -4 -154 -9 -179 -22 -19 -11 -69 -70 -125 -145 -157 -215 -193 -262 -200 -263 -4 0 -37 39 -75 87 -292 371 -270 355 -498 351 -191 -4 -187 -2 -299 -141 -41 -51 -123 -154 -184 -229 l-110 -138 -78 103 c-43 56 -118 155 -166 219 -92 122 -130 157 -187 177 -44 14 -303 14 -356 0 -44 -12 -122 -87 -245 -233 -37 -45 -86 -101 -109 -126 l-42 -45 49 80 c27 44 71 116 97 160 27 44 60 98 75 120 15 22 65 103 112 180 47 77 133 217 193 310 59 94 186 296 283 450 96 154 185 296 197 315 12 19 54 85 92 145 348 552 371 583 483 644 30 17 56 31 58 31 1 0 26 -12 54 -26z m-972 -3012 c196 -249 243 -299 289 -312 20 -5 96 -10 170 -10 115 0 141 3 177 21 32 15 90 75 239 249 l197 230 168 -204 c202 -244 190 -236 383 -236 72 0 149 5 169 10 43 12 84 57 266 286 l119 152 34 -43 c80 -101 230 -274 259 -299 31 -26 32 -26 202 -26 188 0 213 7 259 71 11 16 24 29 28 29 3 0 15 -15 26 -32 10 -18 124 -204 254 -413 129 -209 269 -436 311 -505 43 -69 195 -316 340 -550 144 -234 287 -465 318 -515 180 -296 549 -902 840 -1383 83 -138 102 -176 91 -183 -20 -12 -8460 -12 -8479 1 -13 8 -12 15 9 52 44 79 476 784 706 1153 34 55 137 219 227 365 234 376 395 633 729 1165 80 127 234 373 344 549 189 304 199 317 214 298 83 -104 147 -172 170 -182 19 -7 87 -10 206 -8 l177 3 46 50 c25 28 112 132 195 233 83 100 153 182 156 181 3 0 76 -89 161 -197z%22/%3E%3C/g%3E%3C/svg%3E\" alt=\"\"><p class=\"marca\" style=\"max-width:none\">ACROS</p>\n<div class=\"codigo\">500</div><h1>Something went wrong</h1><p>We had a problem on our side. Nothing has been lost: please try again in a moment. If it keeps happening, write or call us.</p>\n<div class=\"botones\"><a class=\"boton prim\" href=\"javascript:location.reload()\">Try again</a><a class=\"boton sec\" href=\"https://acrosfi.es\">Go to the homepage</a></div>\n<div class=\"pie\">Acros, your crypto-asset tax advisory.<br>Contact: <a href=\"https://acrosfi.es\">acrosfi.es</a> / +34 668 170 020</div></main></body></html>"}};
function pideHTML(req) { const a = String(req.headers.accept || ''); return a.includes('text/html') && !a.includes('application/json'); }
function paginaError(req, codigo) { const i = /^en\b/i.test(String(req.headers['accept-language'] || '')) ? 'en' : 'es'; return PAGINAS_ERROR[i][codigo]; }

// ================================================================
// ARCHIVOS EN EL CHAT (29/10, Vikn)
// El asesor puede adjuntar un archivo (PDF, imagen, Excel, Word, CSV o ZIP, hasta 10 MB) a un mensaje; el cliente lo descarga desde su
// burbuja. No exige pago confirmado (pedir una copia de sus propios datos es un derecho del cliente) ni pide visto bueno. Se guarda en R2
// bajo entregas/chat/, así que el kit del SSD lo recoge sin cambios. Como los informes, no va cifrado por Acros.
// ================================================================
const R2_MEMORIA = new Map();   // solo para las pruebas (ACROS_PRUEBAS=1 y sin R2)
const almacenamientoListo = () => !!R2_BUCKET || process.env.ACROS_PRUEBAS === '1';
function tiposChat() { return Object.assign({ 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' }, TIPOS_ENTREGA); }
function validarAdjuntoChat(a) {
  const tipo = String((a && a.tipo) || ''), ext = tiposChat()[tipo];
  if (!ext) return { error: [400, 'Formato no admitido (PDF, imagen, Excel, Word, CSV o ZIP)'] };
  const buffer = Buffer.from(String((a && a.datos_base64) || ''), 'base64');
  if (!buffer.length) return { error: [400, 'El archivo está vacío'] };
  if (buffer.length > MAX_BYTES_ENTREGA) return { error: [413, 'El archivo supera los 10 MB'] };
  if (!almacenamientoListo()) return { error: [500, 'El almacenamiento (R2) no está configurado'] };
  return { buffer, tipo, ext, nombre: nombreSeguro((a && a.nombre) || ('archivo.' + ext)) };
}
async function enviarArchivoMensaje(res, m) {
  const { buffer, tipoMime } = await bajarDeR2(m.archivo_clave);
  res.set('Content-Type', tipoMime || m.archivo_tipo || 'application/octet-stream');
  res.set('Content-Disposition', 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(m.archivo_nombre || 'archivo'));
  res.send(buffer);
}
app.get('/api/propuestas/:token/mensajes/:id(\\d+)/archivo', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const p = await propuestaVigente(conn, req.params.token);
    if (!p) return res.status(404).json({ error: 'Propuesta no encontrada' });
    const [f] = await conn.execute('SELECT * FROM mensajes WHERE id = ? AND cliente_id = ? AND archivo_clave IS NOT NULL AND oculto_cliente_en IS NULL AND retirado_en IS NULL', [Number(req.params.id), p.cliente_id]);
    if (!f.length) return res.status(404).json({ error: 'No encontrado' });
    await enviarArchivoMensaje(res, f[0]);
  } finally { conn.release(); }
});
app.get('/api/admin/mensajes/:id(\\d+)/archivo', requiereSesionAsesor, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [f] = await conn.execute('SELECT * FROM mensajes WHERE id = ? AND archivo_clave IS NOT NULL', [Number(req.params.id)]);
    if (!f.length) return res.status(404).json({ error: 'No encontrado' });
    const permitidos = await clientesPermitidos(req).catch(() => null);
    if (permitidos && !permitidos.has(f[0].cliente_id)) return res.status(403).json({ error: 'No tienes acceso a este cliente' });
    await enviarArchivoMensaje(res, f[0]);
  } finally { conn.release(); }
});

// ================================================================
// PIN DEL PANEL (29/10, Vikn)
// Cada persona tiene un PIN de 6 cifras. El panel se bloquea tras 10 minutos sin actividad y el SERVIDOR deja de dar datos de clientes
// a esa sesión hasta que se escriba el PIN (no basta con tapar la pantalla). Si se olvida, se restablece con la contraseña (y el código
// de dos pasos si lo tiene). Al cambiarlo o restablecerlo se avisa a la persona y a los administradores. Un administrador puede
// reiniciar el de cualquiera (la persona elige otro; el administrador no lo ve).
// ================================================================
const PIN_MINUTOS = 10;
const pinObligatorio = () => !(process.env.ACROS_PRUEBAS === '1' && process.env.ACROS_PIN !== '1');   // en las pruebas generales va apagado
const RUTAS_SIN_PIN = [/^\/api\/admin\/pin\//, /^\/api\/admin\/sesion$/, /^\/api\/admin\/logout$/, /^\/api\/admin\/version/];
function pinNuevoNoValido(pin) {
  pin = String(pin || '');
  if (!/^\d{6}$/.test(pin)) return 'El PIN son 6 cifras';
  if (/^(\d)\1{5}$/.test(pin) || '01234567890'.includes(pin) || '09876543210'.includes(pin)) return 'Ese PIN es demasiado fácil de adivinar: elige otro';
  return null;
}
const hastaPin = () => aSQLDatetime(new Date(Date.now() + PIN_MINUTOS * 60000));
async function avisarCambioPin(asesorId, tipo, actor) {
  try {
    const [f] = await pool.execute('SELECT a.nombre, a.correo, p.id AS persona_id FROM asesores a LEFT JOIN personas p ON p.asesor_id = a.id WHERE a.id = ?', [asesorId]);
    if (!f.length) return;
    const quien = f[0], cuando = new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' });
    const QUE = { cambio: 'ha cambiado su PIN del panel', restablecido: 'ha restablecido su PIN del panel con su contraseña', reiniciado: 'tiene el PIN del panel reiniciado por ' + (actor ? actor.nombre : 'un administrador') };
    if (brevoActivo()) {
      const c = plantillaCorreo({ titulo: 'Tu PIN del panel ha cambiado', parrafos: ['Hola, ' + ESC_HTML(quien.nombre) + ':', tipo === 'reiniciado' ? 'Un administrador (' + ESC_HTML(actor ? actor.nombre : '') + ') ha reiniciado tu PIN del panel. La próxima vez que entres te pedirá que elijas uno nuevo.' : 'Tu PIN del panel se ha ' + (tipo === 'cambio' ? 'cambiado' : 'restablecido con tu contraseña') + ' el ' + ESC_HTML(cuando) + '.', 'Si no has sido tú, avisa cuanto antes a un administrador.'] });
      try { await enviarCorreo(quien.correo, 'Tu PIN del panel de Acros ha cambiado', c.html, c.texto); } catch (e) { console.error('Aviso de PIN no enviado:', e.message); }
      const [admins] = await pool.execute('SELECT correo FROM asesores WHERE es_admin = 1 AND activo = 1 AND id <> ? AND id <> ?', [asesorId, actor ? actor.id : 0]);
      const ca = plantillaCorreo({ titulo: 'Cambio de PIN en el panel', parrafos: [ESC_HTML(quien.nombre) + ' ' + ESC_HTML(QUE[tipo]) + ' (' + ESC_HTML(cuando) + ').', 'Queda en el registro de actividad. Si no te cuadra, revísalo en Equipo.'] });
      for (const a of admins) { try { await enviarCorreo(a.correo, 'Cambio de PIN en el panel · ' + quien.nombre, ca.html, ca.texto); } catch (e) { console.error('Aviso de PIN a administrador no enviado:', e.message); } }
    }
    const ini = quien.persona_id ? quienIni(await inicialesDePersona(quien.persona_id)) : '';
    avisarEn(canalDe('equipo'), 'PIN del panel cambiado' + (ini ? ': ' + ini : ''), 'Detalle en el correo de los administradores y en el registro de actividad.');
  } catch (e) { console.error('Aviso de PIN:', e.message); }
}
app.get('/api/admin/pin/estado', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT a.pin_hash, a.pin_pausa_hasta, a.totp_activo, a.auth_v2, s.desbloqueada_hasta FROM asesores a JOIN sesiones_asesor s ON s.asesor_id = a.id WHERE a.id = ? AND s.id = ?', [req.asesor.id, req.asesor.sesionId]);
  const x = f[0] || {};
  res.json({ obligatorio: pinObligatorio(), tiene_pin: !!x.pin_hash, desbloqueado: !!x.pin_hash && !!x.desbloqueada_hasta && new Date(x.desbloqueada_hasta) > ahora(), minutos: PIN_MINUTOS, pausa_hasta: x.pin_pausa_hasta && new Date(x.pin_pausa_hasta) > ahora() ? x.pin_pausa_hasta : null, tiene_2fa: !!x.totp_activo, auth_v2: !!x.auth_v2 });
});
app.post('/api/admin/pin/crear', requiereSesionAsesor, async (req, res) => {
  const pin = String((req.body || {}).pin || ''), mal = pinNuevoNoValido(pin);
  if (mal) return res.status(400).json({ error: mal });
  const [f] = await pool.execute('SELECT pin_hash FROM asesores WHERE id = ?', [req.asesor.id]);
  if (f[0].pin_hash) return res.status(409).json({ error: 'Ya tienes un PIN: cámbialo desde tus ajustes' });
  await pool.execute('UPDATE asesores SET pin_hash = ?, pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [await bcrypt.hash(pin, 10), req.asesor.id]);
  await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = ? WHERE id = ?', [hastaPin(), req.asesor.sesionId]);
  res.status(201).json({ ok: true });
});
app.post('/api/admin/pin/desbloquear', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT pin_hash, pin_intentos, pin_pausa_hasta FROM asesores WHERE id = ?', [req.asesor.id]);
  const a = f[0];
  if (!a.pin_hash) return res.status(409).json({ error: 'Todavía no tienes PIN: créalo', codigo: 'pin_crear' });
  if (a.pin_pausa_hasta && new Date(a.pin_pausa_hasta) > ahora()) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos y vuelve a probar.' });
  if (await bcrypt.compare(String((req.body || {}).pin || ''), a.pin_hash)) {
    await pool.execute('UPDATE asesores SET pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [req.asesor.id]);
    await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = ? WHERE id = ?', [hastaPin(), req.asesor.sesionId]);
    return res.json({ ok: true });
  }
  const n = (a.pin_intentos || 0) + 1;
  if (n >= 5) {   // al quinto fallo, fuera: hay que volver a entrar con contraseña (y dos pasos)
    await pool.execute('UPDATE asesores SET pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [req.asesor.id]);
    await pool.execute('DELETE FROM sesiones_asesor WHERE id = ?', [req.asesor.sesionId]);
    return res.status(401).json({ error: 'Demasiados intentos: vuelve a iniciar sesión con tu contraseña.' });
  }
  await pool.execute('UPDATE asesores SET pin_intentos = ?, pin_pausa_hasta = ? WHERE id = ?', [n, n === 3 ? aSQLDatetime(new Date(Date.now() + 5 * 60000)) : null, req.asesor.id]);
  if (n === 3) return res.status(429).json({ error: 'PIN incorrecto. Tres fallos seguidos: espera 5 minutos.' });
  res.status(403).json({ error: 'PIN incorrecto. Te quedan ' + (5 - n) + ' intentos antes de cerrar la sesión.' });
});
app.post('/api/admin/pin/latido', requiereSesionAsesor, async (req, res) => {   // el panel lo manda solo si ha habido actividad de verdad
  const [r] = await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = ? WHERE id = ? AND desbloqueada_hasta > NOW()', [hastaPin(), req.asesor.sesionId]);
  res.json({ ok: true, desbloqueado: r.affectedRows > 0 });
});
app.post('/api/admin/pin/bloquear', requiereSesionAsesor, async (req, res) => {
  await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = NULL WHERE id = ?', [req.asesor.sesionId]);
  res.json({ ok: true });
});
app.post('/api/admin/pin/cambiar', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, mal = pinNuevoNoValido(b.nuevo);
  if (mal) return res.status(400).json({ error: mal });
  const [f] = await pool.execute('SELECT a.pin_hash, s.desbloqueada_hasta FROM asesores a JOIN sesiones_asesor s ON s.asesor_id = a.id WHERE a.id = ? AND s.id = ?', [req.asesor.id, req.asesor.sesionId]);
  if (!f[0].desbloqueada_hasta || new Date(f[0].desbloqueada_hasta) <= ahora()) return res.status(423).json({ error: 'El panel está bloqueado: escribe tu PIN', codigo: 'pin' });
  if (!f[0].pin_hash || !(await bcrypt.compare(String(b.actual || ''), f[0].pin_hash))) return res.status(403).json({ error: 'Tu PIN actual no es correcto' });
  await pool.execute('UPDATE asesores SET pin_hash = ?, pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [await bcrypt.hash(String(b.nuevo), 10), req.asesor.id]);
  avisarCambioPin(req.asesor.id, 'cambio', req.asesor);
  res.json({ ok: true });
});
app.post('/api/admin/pin/olvidado', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, mal = pinNuevoNoValido(b.nuevo);
  if (mal) return res.status(400).json({ error: mal });
  const [f] = await pool.execute('SELECT contrasena_hash, totp_secreto, totp_activo, auth_v2 FROM asesores WHERE id = ?', [req.asesor.id]);
  const prueba = f[0].auth_v2 ? String(b.clave_auth || '') : String(b.contrasena || '');
  if (!prueba || !(await bcrypt.compare(prueba, f[0].contrasena_hash))) return res.status(403).json({ error: 'Tu contraseña no es correcta' });
  if (f[0].totp_activo && !totpValido(f[0].totp_secreto, b.codigo)) return res.status(403).json({ error: 'El código de tu app no es correcto' });
  await pool.execute('UPDATE asesores SET pin_hash = ?, pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [await bcrypt.hash(String(b.nuevo), 10), req.asesor.id]);
  await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = ? WHERE id = ?', [hastaPin(), req.asesor.sesionId]);
  avisarCambioPin(req.asesor.id, 'restablecido', req.asesor);
  res.json({ ok: true });
});
app.post('/api/admin/asesores/:id(\\d+)/pin/reiniciar', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {   // el PIN del propio admin tiene que estar desbloqueado (lo exige requiereSesionAsesor)
  const id = Number(req.params.id);
  const [r] = await pool.execute('UPDATE asesores SET pin_hash = NULL, pin_intentos = 0, pin_pausa_hasta = NULL WHERE id = ?', [id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Asesor no encontrado' });
  await pool.execute('UPDATE sesiones_asesor SET desbloqueada_hasta = NULL WHERE asesor_id = ?', [id]);
  avisarCambioPin(id, 'reiniciado', req.asesor);
  res.json({ ok: true });
});

// ================================================================
// MÉTRICAS DEL EQUIPO (29/10, Vikn)
// Amplían «Rendimiento»: tiempos del chat (mediana, percentil 90, en horario, hasta leer, porcentaje en objetivo, sin contestar),
// el proceso por etapas separando el tiempo «nuestro» del «del cliente» (la pasividad del cliente, comparada con el equipo),
// el perfil de los mensajes de cada asesor (sin IA: medidas objetivas y una puntuación de cercanía; y cuánto usa los borradores de IA),
// y, con los horarios de cada persona (o «No tiene horario»), festivos y ausencias: horas laborables, carga, capacidad y cobertura.
// Se trabaja por objetivos: lo de fuera de horario es solo un dato de carga, nunca un reproche.
// ================================================================
const FMT_MADRID = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
function msMadrid(d) { const p = Object.fromEntries(FMT_MADRID.formatToParts(new Date(d)).map(x => [x.type, x.value])); return Date.UTC(+p.year, +p.month - 1, +p.day, (+p.hour) % 24, +p.minute, +p.second); }   // hora de Madrid como si fuera UTC
const aMin = t => { const [h, m] = String(t).split(':').map(Number); return h * 60 + m; };
function horarioDe(texto) { try { const h = texto ? JSON.parse(texto) : null; return h && !h.sin_horario && h.dias && Object.values(h.dias).some(f => f && f.length) ? h : null; } catch (e) { return null; } }
function franjasDelDia(h, dia0) {   // dia0: ms de la medianoche (Madrid «como UTC»)
  const dow = ((new Date(dia0).getUTCDay() + 6) % 7) + 1;
  return (h.dias[dow] || h.dias[String(dow)] || []).map(([i, f]) => [dia0 + aMin(i) * 60000, dia0 + aMin(f) * 60000]);
}
const fechaDe = ms => new Date(ms).toISOString().slice(0, 10);
const diaLibre = (ms, festivos, ausencias) => { const f = fechaDe(ms); return festivos.has(f) || ausencias.some(([d, h]) => f >= d && f <= h); };
function horasEntre(h, a, b, festivos, ausencias) {   // horas laborables entre dos instantes; sin horario, horas corridas
  if (!(b > a)) return 0;
  if (!h) return (new Date(b) - new Date(a)) / 3600000;
  const A = msMadrid(a), B = msMadrid(b); let tot = 0;
  for (let d = Date.UTC(new Date(A).getUTCFullYear(), new Date(A).getUTCMonth(), new Date(A).getUTCDate()), n = 0; d < B && n < 200; d += 86400000, n++) {
    if (diaLibre(d, festivos, ausencias)) continue;
    for (const [i, f] of franjasDelDia(h, d)) tot += Math.max(0, Math.min(f, B) - Math.max(i, A));
  }
  return tot / 3600000;
}
function enHorario(h, t, festivos, ausencias) {
  if (!h) return true;
  const T = msMadrid(t), d = T - (T % 86400000);
  if (diaLibre(d, festivos, ausencias)) return false;
  return franjasDelDia(h, d).some(([i, f]) => T >= i && T < f);
}
const mediana = v => { const x = v.filter(n => n != null && isFinite(n)).sort((p, q) => p - q); if (!x.length) return null; const m = Math.floor(x.length / 2); return x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2; };
const percentil = (v, p) => { const x = v.filter(n => n != null && isFinite(n)).sort((a, b) => a - b); return x.length ? x[Math.min(x.length - 1, Math.ceil(p / 100 * x.length) - 1)] : null; };
const r1 = n => n == null ? null : Math.round(n * 10) / 10;
const pct = (a, b) => b ? Math.round(a / b * 100) : null;
const SALUDO = /^\s*(hola|buen[oa]s|buenos d[ií]as|buenas tardes|buenas noches|hey|qu[eé] tal)\b/i;
const DESPEDIDA = /(un saludo|saludos|un abrazo|gracias|quedo a tu disposici[oó]n|cualquier cosa me dices|hablamos|feliz d[ií]a|que vaya bien)/i;
const CERCANO = /(!|gracias|genial|perfecto|encantad|tranquil|un abrazo|[\u{1F300}-\u{1FAFF}\u2600-\u27BF])/iu;
async function ampliarRendimiento(conn, filas, porAsesor, ini, fin) {
  const [pers] = await conn.query('SELECT id, horario, activa, atiende_clientes FROM personas');
  const H = {}; pers.forEach(p => { H[p.id] = horarioDe(p.horario); });
  const [aj] = await conn.query("SELECT clave, valor FROM ajustes WHERE clave IN ('festivos', 'objetivo_respuesta_h')");
  const ajuste = k => (aj.find(x => x.clave === k) || {}).valor;
  const festivos = new Set(String(ajuste('festivos') || '').split(/[\s,;]+/).filter(x => /^\d{4}-\d{2}-\d{2}$/.test(x)));
  const objetivo = Number(ajuste('objetivo_respuesta_h')) || 24;
  const [aus] = await conn.query("SELECT persona_id, DATE_FORMAT(desde, '%Y-%m-%d') AS d, DATE_FORMAT(hasta, '%Y-%m-%d') AS h FROM ausencias");
  const AUS = {}; aus.forEach(x => { (AUS[x.persona_id] = AUS[x.persona_id] || []).push([x.d, x.h]); });
  const hor = (pid, a, b) => horasEntre(H[pid] || null, a, b, festivos, AUS[pid] || []);
  const [cl] = await conn.query('SELECT id, asesor_persona_id, nombre FROM clientes');
  const deCli = {}, nombreCli = {}; cl.forEach(c => { deCli[c.id] = c.asesor_persona_id; nombreCli[c.id] = String(c.nombre || '').trim().split(/\s+/)[0]; });
  const T = k => Object.values(filas).forEach(f => { f[k] = []; });
  ['_r', '_rl', '_j', '_leer', '_aln', '_dabrir', '_drev', '_inf', '_vbp', '_cacep', '_cdoc', '_crec', '_cvb', '_msgs'].forEach(T);
  Object.values(filas).forEach(f => { f._obj = [0, 0]; f._fuera = [0, 0]; f._cli_msgs = 0; });
  const fila = pid => pid ? filas[pid] : null;
  const enMes = t => t && new Date(t) >= ini && new Date(t) < fin;
  // ---- Chat: tiempos de respuesta (quien responde) y de lectura (asesor del cliente) ----
  const [msgs] = await conn.execute('SELECT id, propuesta_id, servicio, autor, asesor_id, cliente_id, texto, creado_en, leido_en, ia_borrador, ia_cambio_pct, retirado_en FROM mensajes WHERE creado_en >= ? - INTERVAL 1 DAY AND creado_en < ? + INTERVAL 7 DAY ORDER BY propuesta_id, servicio, creado_en, id', [sqlFecha(ini), sqlFecha(fin)]);
  let pend = null;
  msgs.forEach(x => {
    const hilo = x.propuesta_id + '|' + x.servicio;
    if (pend && pend.hilo !== hilo) pend = null;
    if (x.autor === 'cliente') {
      if (enMes(x.creado_en)) { const fc = fila(deCli[x.cliente_id]); if (fc) { fc._cli_msgs++; if (x.leido_en) fc._leer.push((new Date(x.leido_en) - new Date(x.creado_en)) / 3600000); } }
      if (!pend && enMes(x.creado_en)) pend = { hilo, t: x.creado_en };
    } else {
      const pid = porAsesor[x.asesor_id], f = fila(pid);
      if (f && enMes(x.creado_en) && !x.retirado_en) { f._msgs.push(x); if (H[pid]) { f._fuera[1]++; if (!enHorario(H[pid], x.creado_en, festivos, AUS[pid] || [])) f._fuera[0]++; } }
      if (pend && f) {
        const corr = (new Date(x.creado_en) - new Date(pend.t)) / 3600000, lab = hor(pid, pend.t, x.creado_en);
        f._r.push(corr); f._rl.push(lab); f._obj[1]++; if (lab <= objetivo) f._obj[0]++;
        if (H[pid] && !enHorario(H[pid], pend.t, festivos, AUS[pid] || [])) f._j.push(lab);
      }
      pend = null;
    }
  });
  // ---- Sin contestar ahora (estado actual): el último mensaje del hilo es del cliente ----
  const [ult] = await conn.query("SELECT m.cliente_id, m.creado_en FROM mensajes m JOIN (SELECT propuesta_id, servicio, MAX(id) AS mid FROM mensajes WHERE retirado_en IS NULL GROUP BY propuesta_id, servicio) u ON u.mid = m.id WHERE m.autor = 'cliente'");
  Object.values(filas).forEach(f => { f.sin_contestar = 0; f.sin_contestar_max_h = null; });
  ult.forEach(u => { const f = fila(deCli[u.cliente_id]); if (!f) return; f.sin_contestar++; const h = (Date.now() - new Date(u.creado_en)) / 3600000; f.sin_contestar_max_h = r1(Math.max(f.sin_contestar_max_h || 0, h)); });
  // ---- Proceso: tiempo nuestro ----
  const dias = (a, b) => (new Date(b) - new Date(a)) / 86400000;
  const [dils] = await conn.execute('SELECT cliente_id, creado_en, resuelto_en FROM diligencias WHERE resuelto_en >= ? AND resuelto_en < ?', [sqlFecha(ini), sqlFecha(fin)]);
  dils.forEach(d => { const f = fila(deCli[d.cliente_id]); if (f) f._aln.push(dias(d.creado_en, d.resuelto_en)); });
  const [docs] = await conn.execute('SELECT id, cliente_id, propuesta_id, servicio, estado, creado_en, subido_en, revisado_en FROM documentos_fiscales WHERE (subido_en >= ? AND subido_en < ?) OR (revisado_en >= ? AND revisado_en < ?)', [sqlFecha(ini), sqlFecha(fin), sqlFecha(ini), sqlFecha(fin)]);
  const idsDocs = docs.map(d => d.id);
  let aperturas = [];
  if (idsDocs.length) [aperturas] = await conn.query("SELECT objeto_id, MIN(creado_en) AS t FROM actividad WHERE ruta LIKE '%/documentos/%/descargar' AND objeto_id IN (?) GROUP BY objeto_id", [idsDocs]);
  const abierto = {}; aperturas.forEach(a => { abierto[a.objeto_id] = a.t; });
  const [recs] = await conn.query("SELECT objeto_id, creado_en FROM recordatorios_cliente WHERE tipo IN ('documento', 'doc')");
  docs.forEach(d => {
    const f = fila(deCli[d.cliente_id]); if (!f) return;
    if (enMes(d.subido_en)) {
      if (abierto[d.id] && new Date(abierto[d.id]) >= new Date(d.subido_en)) f._dabrir.push((new Date(abierto[d.id]) - new Date(d.subido_en)) / 3600000);
      f._cdoc.push(dias(d.creado_en, d.subido_en));
      f._crec.push(recs.filter(r => r.objeto_id === d.id && new Date(r.creado_en) <= new Date(d.subido_en)).length);
    }
    if (enMes(d.revisado_en) && d.subido_en) f._drev.push(dias(d.subido_en, d.revisado_en));
  });
  const [ents] = await conn.execute("SELECT e.cliente_id, e.propuesta_id, e.servicio, e.version, e.subido_en, e.conformidad_pedida_en, e.estado, e.respondido_en, (SELECT MAX(d.revisado_en) FROM documentos_fiscales d WHERE d.propuesta_id = e.propuesta_id AND d.servicio = e.servicio AND d.estado = 'valido' AND d.revisado_en <= e.subido_en) AS ult_doc FROM entregas e WHERE (e.subido_en >= ? AND e.subido_en < ?) OR (e.conformidad_pedida_en >= ? AND e.conformidad_pedida_en < ?) OR (e.respondido_en >= ? AND e.respondido_en < ?)", [sqlFecha(ini), sqlFecha(fin), sqlFecha(ini), sqlFecha(fin), sqlFecha(ini), sqlFecha(fin)]);
  ents.forEach(e => {
    const f = fila(deCli[e.cliente_id]); if (!f) return;
    if (enMes(e.subido_en) && e.version === 1 && e.ult_doc) f._inf.push(dias(e.ult_doc, e.subido_en));
    if (enMes(e.conformidad_pedida_en)) f._vbp.push(dias(e.subido_en, e.conformidad_pedida_en));
    if (enMes(e.respondido_en) && e.estado === 'conforme' && e.conformidad_pedida_en) f._cvb.push(dias(e.conformidad_pedida_en, e.respondido_en));
  });
  // ---- Tiempo del cliente: aceptar la propuesta ----
  const [props] = await conn.execute("SELECT cliente_id, creado_en, inicio_inmediato_en FROM propuestas WHERE inicio_inmediato_en >= ? AND inicio_inmediato_en < ?", [sqlFecha(ini), sqlFecha(fin)]);
  props.forEach(p => { const f = fila(deCli[p.cliente_id]); if (f) f._cacep.push(dias(p.creado_en, p.inicio_inmediato_en)); });
  // ---- IA: borradores pedidos ----
  const [ia] = await conn.execute("SELECT persona_id AS asesor_id, COUNT(*) AS n FROM ia_uso WHERE funcion LIKE '%borrador%' AND ok = 1 AND creado_en >= ? AND creado_en < ? GROUP BY persona_id", [sqlFecha(ini), sqlFecha(fin)]);
  Object.values(filas).forEach(f => { f.ia_borradores = 0; });
  ia.forEach(x => { const f = fila(porAsesor[x.asesor_id]); if (f) f.ia_borradores = Number(x.n); });
  // ---- Capacidad (próximos 60 días) ----
  // el plazo de cada servicio se calcula (vistasDeFilas), no es una columna
  const [svF] = await conn.query(SQL_SERVICIOS + " WHERE s.estado IN ('abierto', 'por_confirmar') AND s.confirmado = 1");
  const svs = await vistasDeFilas(conn, svF), hoyD = hoyMadridISO(), limite60 = new Date(Date.now() + 60 * 86400000).toISOString().slice(0, 10);
  Object.values(filas).forEach(f => { f.cap_servicios_60d = 0; });
  svs.filter(v => v.plazo && v.plazo >= hoyD && v.plazo < limite60).forEach(v => { const f = fila(deCli[v.cliente_id]); if (f) f.cap_servicios_60d++; });
  // ---- Cierre por persona ----
  const ahora60 = new Date(Date.now() + 60 * 86400000);
  Object.values(filas).forEach(f => {
    const pid = f.persona_id;
    f.resp_mediana_h = r1(mediana(f._r)); f.resp_p90_h = r1(percentil(f._r, 90)); f.resp_lab_mediana_h = r1(mediana(f._rl));
    f.resp_objetivo_pct = pct(f._obj[0], f._obj[1]); f.jornada_mediana_h = r1(mediana(f._j)); f.leer_mediana_h = r1(mediana(f._leer));
    f.et_alta_dias = r1(mediana(f._aln)); f.et_doc_abrir_h = r1(mediana(f._dabrir)); f.et_doc_revisar_dias = r1(mediana(f._drev)); f.et_informe_dias = r1(mediana(f._inf)); f.et_vb_pedir_dias = r1(mediana(f._vbp));
    f.cli_acepta_dias = r1(mediana(f._cacep)); f.cli_doc_dias = r1(mediana(f._cdoc)); f.cli_doc_7d_pct = pct(f._cdoc.filter(x => x <= 7).length, f._cdoc.length);
    f.cli_recordatorios = f._crec.length ? r1(f._crec.reduce((a, b) => a + b, 0) / f._crec.length) : null; f.cli_vb_dias = r1(mediana(f._cvb));
    // perfil de los mensajes (sin IA)
    const ms = f._msgs.filter(m => String(m.texto || '').trim()), n = ms.length;
    const conNombre = ms.filter(m => nombreCli[m.cliente_id] && nombreCli[m.cliente_id].length > 1 && new RegExp('\\b' + nombreCli[m.cliente_id].replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(m.texto)).length;
    const norm = t => String(t).toLowerCase().replace(/\s+/g, ' ').trim(), vistos = new Set(); let repes = 0;
    ms.forEach(m => { const k = norm(m.texto); if (k.length > 20 && vistos.has(k)) repes++; vistos.add(k); });
    f.msg_n = n; f.msg_longitud = n ? Math.round(ms.reduce((a, m) => a + String(m.texto).length, 0) / n) : null;
    f.msg_saludo_pct = pct(ms.filter(m => SALUDO.test(m.texto)).length, n); f.msg_despedida_pct = pct(ms.filter(m => DESPEDIDA.test(m.texto)).length, n);
    f.msg_nombre_pct = pct(conNombre, n); f.msg_preguntas_pct = pct(ms.filter(m => /\?/.test(m.texto)).length, n);
    f.msg_usted_pct = pct(ms.filter(m => /\busted(es)?\b/i.test(m.texto)).length, n); f.msg_plantilla_pct = pct(repes, n);
    f.tono_cercania = n ? Math.round(ms.reduce((a, m) => a + (SALUDO.test(m.texto) ? 25 : 0) + (DESPEDIDA.test(m.texto) ? 20 : 0) + (nombreCli[m.cliente_id] && new RegExp('\\b' + nombreCli[m.cliente_id].replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(m.texto) ? 25 : 0) + (CERCANO.test(m.texto) ? 15 : 0) + (String(m.texto).length >= 80 ? 15 : 0), 0) / n) : null;
    f.tono = f.tono_cercania == null ? null : f.tono_cercania >= 60 ? 'cercano' : f.tono_cercania >= 35 ? 'neutro' : 'seco';
    f.ia_enviado_pct = pct(f._msgs.filter(m => m.ia_borrador).length, f._msgs.length); f.ia_cambio_mediana = r1(mediana(f._msgs.filter(m => m.ia_borrador && m.ia_cambio_pct != null).map(m => m.ia_cambio_pct)));
    // horario: carga y capacidad (sin horario, no aplica)
    f.tiene_horario = !!H[pid];
    f.horas_disponibles = H[pid] ? r1(hor(pid, ini, fin)) : null;
    f.carga_mensajes_hora = H[pid] && f.horas_disponibles ? Math.round(f._cli_msgs / f.horas_disponibles * 100) / 100 : null;
    f.fuera_horario_pct = H[pid] ? pct(f._fuera[0], f._fuera[1]) : null;
    f.cap_horas_60d = H[pid] ? r1(hor(pid, new Date(), ahora60)) : null;
    f.cap_horas_por_servicio = H[pid] && f.cap_servicios_60d ? r1(f.cap_horas_60d / f.cap_servicios_60d) : null;
    ['_r', '_rl', '_j', '_leer', '_aln', '_dabrir', '_drev', '_inf', '_vbp', '_cacep', '_cdoc', '_crec', '_cvb', '_msgs', '_obj', '_fuera', '_cli_msgs'].forEach(k => delete f[k]);
  });
  // ---- Equipo: etapas (mediana del equipo) y pasividad del cliente comparada ----
  const vals = k => Object.values(filas).map(f => f[k]).filter(v => v != null);
  const ETAPAS = [
    ['et_alta_dias', 'Alta enviada → alta revisada', 'nuestro', 'días'], ['et_doc_abrir_h', 'Documento subido → lo abre el asesor', 'nuestro', 'h'],
    ['et_doc_revisar_dias', 'Documento subido → revisado', 'nuestro', 'días'], ['et_informe_dias', 'Último documento válido → informe entregado', 'nuestro', 'días'],
    ['et_vb_pedir_dias', 'Informe entregado → se pide el visto bueno', 'nuestro', 'días'],
    ['cli_acepta_dias', 'Propuesta enviada → aceptada', 'cliente', 'días'], ['cli_doc_dias', 'Documento pedido → subido', 'cliente', 'días'],
    ['cli_vb_dias', 'Visto bueno pedido → lo da', 'cliente', 'días'],
  ];
  const etapas = ETAPAS.map(([k, nombre, de, unidad]) => ({ clave: k, nombre, de, unidad, equipo: r1(mediana(vals(k))) }));
  const medCliDoc = mediana(vals('cli_doc_dias'));
  Object.values(filas).forEach(f => { f.cli_doc_vs_equipo = f.cli_doc_dias != null && medCliDoc ? Math.round(f.cli_doc_dias / medCliDoc * 100) / 100 : null; });
  // ---- Cobertura: mensajes de clientes por día y hora frente a personas disponibles (solo quien tiene horario) ----
  const conHorario = pers.filter(p => H[p.id] && p.activa && p.atiende_clientes);
  let cobertura = null;
  if (conHorario.length) {
    const men = Array.from({ length: 7 }, () => Array(24).fill(0)), disp = Array.from({ length: 7 }, () => Array(24).fill(0));
    for (let dw = 1; dw <= 7; dw++) for (let h = 0; h < 24; h++) conHorario.forEach(p => { if ((H[p.id].dias[dw] || H[p.id].dias[String(dw)] || []).some(([i, f]) => aMin(i) <= h * 60 && aMin(f) > h * 60)) disp[dw - 1][h]++; });
    let sinCubrir = 0;
    msgs.filter(x => x.autor === 'cliente' && enMes(x.creado_en)).forEach(x => { const T0 = msMadrid(x.creado_en), dw = ((new Date(T0).getUTCDay() + 6) % 7), h = new Date(T0).getUTCHours(); men[dw][h]++; if (!disp[dw][h] || festivos.has(fechaDe(T0))) sinCubrir++; });
    cobertura = { mensajes: men, disponibles: disp, sin_cubrir: sinCubrir, personas_con_horario: conHorario.length };
  }
  const [eqs] = await conn.query('SELECT id, nombre FROM equipos WHERE activo = 1 ORDER BY nombre');
  return { etapas, cobertura, objetivo_h: objetivo, festivos: [...festivos].sort(), equipos: eqs };
}
// ---- Horarios, ausencias, festivos y objetivo ----
async function puedeTocarHorario(req, personaId) {
  if (req.asesor.esAdmin) return true;
  if (!req.asesor.roles.has('jefe')) return false;
  const [f] = await pool.execute('SELECT e.jefe_persona_id, (SELECT id FROM personas WHERE asesor_id = ?) AS yo FROM personas p JOIN equipos e ON e.id = p.equipo_id WHERE p.id = ?', [req.asesor.id, personaId]);
  return !!(f.length && f[0].yo && f[0].jefe_persona_id === f[0].yo);
}
function horarioValido(b) {
  if (b && b.sin_horario) return { sin_horario: true };
  const dias = {};
  for (let d = 1; d <= 7; d++) {
    const fr = ((b && b.dias && (b.dias[d] || b.dias[String(d)])) || []).filter(x => Array.isArray(x) && x[0] && x[1]);
    if (fr.length > 3) return null;
    for (const [i, f] of fr) { if (!/^\d{2}:\d{2}$/.test(i) || !/^\d{2}:\d{2}$/.test(f) || aMin(i) >= aMin(f) || aMin(f) > 1440) return null; }
    dias[d] = fr.map(([i, f]) => [i, f]);
  }
  return { dias };
}
app.get('/api/admin/horarios', requiereSesionAsesor, requiereRol('encargado'), async (req, res) => {
  const [p] = await pool.query('SELECT id, nombre, equipo_id, horario, activa, atiende_clientes FROM personas ORDER BY orden, id');
  const [a] = await pool.query("SELECT id, persona_id, DATE_FORMAT(desde, '%Y-%m-%d') AS desde, DATE_FORMAT(hasta, '%Y-%m-%d') AS hasta, motivo FROM ausencias ORDER BY desde DESC");
  const [aj] = await pool.query("SELECT clave, valor FROM ajustes WHERE clave IN ('festivos', 'objetivo_respuesta_h')");
  const v = k => (aj.find(x => x.clave === k) || {}).valor;
  res.json({ personas: p.map(x => ({ ...x, horario: x.horario ? JSON.parse(x.horario) : null })), ausencias: a, festivos: String(v('festivos') || '').split(/[\s,;]+/).filter(Boolean), objetivo_h: Number(v('objetivo_respuesta_h')) || 24 });
});
app.put('/api/admin/personas/:id(\\d+)/horario', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id);
  if (!(await puedeTocarHorario(req, id))) return res.status(403).json({ error: 'Solo un administrador o el jefe de su equipo pueden cambiar su horario' });
  const h = horarioValido(req.body || {});
  if (!h) return res.status(400).json({ error: 'Horario no válido: cada franja con hora de inicio y de fin (la de fin, después), y como mucho 3 por día' });
  const [r] = await pool.execute('UPDATE personas SET horario = ? WHERE id = ?', [JSON.stringify(h), id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Persona no encontrada' });
  res.json({ ok: true, horario: h });
});
app.post('/api/admin/ausencias', requiereSesionAsesor, async (req, res) => {
  const b = req.body || {}, pid = Number(b.persona_id), re = /^\d{4}-\d{2}-\d{2}$/;
  if (!(await puedeTocarHorario(req, pid))) return res.status(403).json({ error: 'Solo un administrador o el jefe de su equipo' });
  if (!re.test(b.desde) || !re.test(b.hasta) || b.hasta < b.desde) return res.status(400).json({ error: 'Fechas no válidas' });
  const [r] = await pool.execute('INSERT INTO ausencias (persona_id, desde, hasta, motivo) VALUES (?, ?, ?, ?)', [pid, b.desde, b.hasta, String(b.motivo || '').slice(0, 120) || null]);
  res.status(201).json({ ok: true, id: r.insertId });
});
app.delete('/api/admin/ausencias/:id(\\d+)', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT persona_id FROM ausencias WHERE id = ?', [Number(req.params.id)]);
  if (!f.length) return res.status(404).json({ error: 'No encontrada' });
  if (!(await puedeTocarHorario(req, f[0].persona_id))) return res.status(403).json({ error: 'Solo un administrador o el jefe de su equipo' });
  await pool.execute('DELETE FROM ausencias WHERE id = ?', [Number(req.params.id)]);
  res.json({ ok: true });
});
app.put('/api/admin/ajustes-rendimiento', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const b = req.body || {};
  const fest = (Array.isArray(b.festivos) ? b.festivos : String(b.festivos || '').split(/[\s,;]+/)).map(String).filter(x => /^\d{4}-\d{2}-\d{2}$/.test(x));
  const obj = Number(b.objetivo_respuesta_h);
  if (b.objetivo_respuesta_h != null && !(obj >= 1 && obj <= 720)) return res.status(400).json({ error: 'El objetivo de respuesta va de 1 a 720 horas' });
  for (const [k, v] of [['festivos', fest.join(',')], ['objetivo_respuesta_h', b.objetivo_respuesta_h != null ? String(obj) : null]]) if (v != null) await pool.execute('INSERT INTO ajustes (clave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)', [k, v]);
  res.json({ ok: true, festivos: fest, objetivo_h: obj || undefined });
});

// ================================================================
// RESPUESTAS POR CORREO DENTRO DEL PANEL (30/10, Vikn)
// Cada correo del panel lleva su propia dirección de respuesta (r-<id>-<código>@CORREO_RESPUESTAS_DOMINIO). Cuando el cliente
// contesta, Brevo (recepción de correos, «Inbound Parsing») lo manda a /api/correo-entrante/<secreto>; el servidor lo une al hilo
// de su ficha, y los adjuntos van solos a la documentación del cliente, cifrados con la llave de Acros como los que sube él
// («Recibido por correo: …», en revisión). Sin CORREO_RESPUESTAS_DOMINIO, todo sigue como antes (respuestas al buzón del asesor).
// ================================================================
const CORREO_RESPUESTAS_DOMINIO = String(process.env.CORREO_RESPUESTAS_DOMINIO || '').trim().toLowerCase();
const CORREO_ENTRANTE_SECRETO = String(process.env.CORREO_ENTRANTE_SECRETO || '').trim();
const MAX_ADJ_CORREO = 15 * 1024 * 1024, MAX_ADJ_POR_CORREO = 10;
const TIPOS_ADJ_OK = /^(application\/pdf|image\/(png|jpe?g|webp|heic|heif)|text\/(csv|plain)|application\/(zip|x-zip-compressed|vnd\.ms-excel|msword|vnd\.openxmlformats-officedocument\.(spreadsheetml\.sheet|wordprocessingml\.document)))$/i;
const EXT_ADJ_OK = /\.(pdf|png|jpe?g|webp|heic|heif|csv|txt|zip|xlsx?|docx?)$/i;
const EXT_PELIGROSA = /\.(exe|bat|cmd|com|scr|js|vbs|msi|ps1|jar|sh|apk|dll)$/i;
function direccionRespuesta(id, token) { return CORREO_RESPUESTAS_DOMINIO ? 'r-' + id + '-' + token + '@' + CORREO_RESPUESTAS_DOMINIO : null; }
function cifrarParaDocumentos(buffer) {   // igual que el navegador del cliente: AES-256-GCM (etiqueta al final) y la clave con RSA-OAEP/SHA-256
  const claveAES = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
  const cifrado = Buffer.concat([c.update(buffer), c.final(), c.getAuthTag()]);
  const clave = crypto.publicEncrypt({ key: CLAVE_PUBLICA_COPIAS, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, claveAES);
  return { cifrado, iv: iv.toString('base64'), clave: clave.toString('base64') };
}
async function bajarAdjuntoBrevo(a) {
  if (a.Content || a.content) return Buffer.from(String(a.Content || a.content), 'base64');
  const tok = a.DownloadToken || a.downloadToken; if (!tok) throw new Error('sin contenido');
  const base = new URL(process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email').origin;
  const r = await axios.get(base + '/v3/inbound/attachments/' + encodeURIComponent(tok), { headers: { 'api-key': BREVO_API_KEY }, responseType: 'arraybuffer', timeout: 30000, maxContentLength: MAX_ADJ_CORREO + 4096 });
  return Buffer.from(r.data);
}
function textoEntrante(it) {
  let t = it.ExtractedMarkdownMessage || it.RawTextBody || it.text || '';
  if (!t && it.RawHtmlBody) t = String(it.RawHtmlBody).replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n\n').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
  return String(t || '').replace(/\r/g, '').trim().slice(0, 20000);
}
async function guardarCorreoEntrante(it) {
  const destinos = [].concat(it.To || it.to || [], it.Cc || [], it.Recipients || []).map(x => String((x && typeof x === 'object' ? (x.Address || x.address || x.email) : x) || '').trim().toLowerCase());
  let m = null; for (const d of destinos) { m = d.match(/^r-(\d+)-([a-f0-9]{8,32})@/); if (m) break; }
  if (!m) { anotarRegistro({ actor_tipo: 'sistema', actor_nombre: 'Sistema', tipo: 'sistema', accion: 'Correo recibido que no responde a ninguno nuestro (descartado)', detalle: { para: destinos.slice(0, 3) } }); return false; }
  const [orig] = await pool.execute('SELECT * FROM correos_panel WHERE id = ? AND respuesta_token = ?', [Number(m[1]), m[2]]);
  if (!orig.length) { anotarRegistro({ actor_tipo: 'sistema', actor_nombre: 'Sistema', tipo: 'sistema', accion: 'Correo recibido con una dirección de respuesta no válida (descartado)', detalle: { para: destinos.slice(0, 3) } }); return false; }
  const o = orig[0];
  const mid = String(it.MessageId || it.messageId || '').slice(0, 250) || null;
  if (mid) { const [d] = await pool.execute('SELECT id FROM correos_panel WHERE mensaje_id = ?', [mid]); if (d.length) return false; }   // reintento de Brevo: ya guardado
  const de = String((it.From && typeof it.From === 'object' ? (it.From.Address || it.From.address) : it.From || it.from) || '').trim().toLowerCase().slice(0, 190);
  const asunto = String(it.Subject || it.subject || ('Re: ' + o.asunto)).slice(0, 150);
  const [ins] = await pool.execute("INSERT INTO correos_panel (cliente_id, asesor_id, persona_id, para, asunto, cuerpo, direccion, de, en_respuesta_a, mensaje_id, hilo_id, ok) VALUES (?, ?, ?, ?, ?, ?, 'entrante', ?, ?, ?, ?, 1)",
    [o.cliente_id, o.asesor_id, o.persona_id, o.responder_a || '', asunto, textoEntrante(it) || '(sin texto)', de, o.id, mid, o.hilo_id || o.id]);
  const adj = [].concat(it.Attachments || it.attachments || []), notas = [];
  if (adj.length) {
    const [ps] = await pool.execute("SELECT id FROM propuestas WHERE cliente_id = ? AND estado = 'aceptada' ORDER BY id DESC LIMIT 1", [o.cliente_id]);
    for (const [i, a] of adj.entries()) {
      const nombre = String(a.Name || a.name || 'adjunto').replace(/[\\/:*?"<>|]+/g, '_').trim().slice(0, 200) || 'adjunto', tipo = String(a.ContentType || a.contentType || 'application/octet-stream').toLowerCase().split(';')[0];
      if (i >= MAX_ADJ_POR_CORREO) { notas.push({ nombre, guardado: false, motivo: 'más de ' + MAX_ADJ_POR_CORREO + ' adjuntos en un correo' }); continue; }
      if (!ps.length) { notas.push({ nombre, guardado: false, motivo: 'el cliente no tiene ningún encargo aceptado' }); continue; }
      if (EXT_PELIGROSA.test(nombre) || (!TIPOS_ADJ_OK.test(tipo) && !EXT_ADJ_OK.test(nombre))) { notas.push({ nombre, guardado: false, motivo: 'formato no admitido' }); continue; }
      if (Number(a.ContentLength || a.contentLength || 0) > MAX_ADJ_CORREO) { notas.push({ nombre, guardado: false, motivo: 'supera los 15 MB' }); continue; }
      let datos; try { datos = await bajarAdjuntoBrevo(a); } catch (e) { notas.push({ nombre, guardado: false, motivo: 'no se pudo descargar' }); continue; }
      if (!datos.length || datos.length > MAX_ADJ_CORREO) { notas.push({ nombre, guardado: false, motivo: datos.length ? 'supera los 15 MB' : 'está vacío' }); continue; }
      const c = cifrarParaDocumentos(datos), clave = `docs/${o.cliente_id}/${generarToken()}.enc`;
      await subirAR2(clave, c.cifrado, 'application/octet-stream');
      const [d] = await pool.execute("INSERT INTO documentos_fiscales (cliente_id, propuesta_id, servicio, nombre, estado, documento_ref, documento_iv, documento_clave_cifrada, documento_tipo_mime, subido_en, nombre_original) VALUES (?, ?, 'general', ?, 'enviado', ?, ?, ?, ?, ?, ?)",
        [o.cliente_id, ps[0].id, ('Recibido por correo: ' + nombre).slice(0, 200), clave, c.iv, c.clave, TIPOS_ADJ_OK.test(tipo) ? tipo : 'application/octet-stream', aSQLDatetime(ahora()), nombre]);
      notas.push({ nombre, guardado: true, documento_id: d.insertId });
    }
    await pool.execute('UPDATE correos_panel SET adjuntos = ? WHERE id = ?', [JSON.stringify(notas).slice(0, 8000), ins.insertId]);
  }
  avisarCliente(o.cliente_id, '✉️', 'un cliente ha respondido a un correo', 'Lo tienes en su ficha, en «Correos».' + (notas.some(n => n.guardado) ? ' Trae adjuntos: ya están en su documentación, por revisar.' : ''), { etiqueta: 'envelope' });
  anotarRegistro({ actor_tipo: 'cliente', actor_nombre: 'Cliente', tipo: 'cliente', accion: 'El cliente responde a un correo', cliente_id: o.cliente_id, objeto_id: ins.insertId, detalle: { adjuntos: adj.length, guardados: notas.filter(n => n.guardado).length } });
  return true;
}
app.post('/api/correo-entrante/:secreto', async (req, res) => {
  if (!CORREO_ENTRANTE_SECRETO || req.params.secreto !== CORREO_ENTRANTE_SECRETO) return res.status(404).json({ error: 'No encontrado' });
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [req.body || {}];
  let guardados = 0;
  for (const it of items.slice(0, 50)) { try { if (await guardarCorreoEntrante(it)) guardados++; } catch (e) { console.error('Correo entrante:', e.message); } }
  res.json({ ok: true, guardados });   // siempre 200: si no, Brevo reintenta sin fin
});
app.post('/api/admin/clientes/:id(\\d+)/correos/leidos', requiereSesionAsesor, async (req, res) => {
  await pool.execute("UPDATE correos_panel SET leido_en = NOW() WHERE cliente_id = ? AND direccion = 'entrante' AND leido_en IS NULL", [Number(req.params.id)]);
  res.json({ ok: true });
});

// ================================================================
// CORREOS DESDE EL PANEL (30/10, Vikn)
// Un asesor escribe a su cliente desde la ficha. Sale de la dirección única de Acros (BREVO_REMITENTE: hola@acrosfi.es) con su
// nombre («Jorge, tu asesor de Acros»); las respuestas le llegan a su «Correo para clientes» (o, si no lo tiene, al de entrada) y
// una copia oculta va a la bandeja común (Sistema; por defecto hola@acrosfi.es). Sin adjuntos: los archivos van por el Área.
// Queda guardado en la ficha del cliente.
// ================================================================
// (correoValido ya existe en el servidor)
async function bandejaComun() {
  try { const [f] = await pool.query("SELECT valor FROM ajustes WHERE clave = 'bandeja_comun'"); if (f.length && correoValido(f[0].valor)) return f[0].valor; } catch (e) {}
  return 'hola@acrosfi.es';
}
async function remitenteDeAsesor(asesorId) {
  const [f] = await pool.execute('SELECT a.nombre AS a_nombre, a.correo AS a_correo, p.id AS persona_id, p.nombre, p.genero, p.correo_clientes FROM asesores a LEFT JOIN personas p ON p.asesor_id = a.id WHERE a.id = ?', [asesorId]);
  const x = f[0] || {}, nombre = x.nombre || x.a_nombre || 'Acros', genero = x.genero || generoPorNombre(nombre);
  return { persona_id: x.persona_id || null, nombre, presentacion: nombre + ', tu ' + (genero === 'f' ? 'asesora' : 'asesor') + ' de Acros', responder_a: correoValido(x.correo_clientes) ? x.correo_clientes : x.a_correo };
}
app.get('/api/admin/correo-ajustes', requiereSesionAsesor, requiereAdminWeb, async (req, res) => { res.json({ bandeja_comun: await bandejaComun(), remitente: BREVO_REMITENTE || null }); });
app.put('/api/admin/correo-ajustes', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const c = String((req.body || {}).bandeja_comun || '').trim().toLowerCase();
  if (!correoValido(c)) return res.status(400).json({ error: 'Escribe una dirección de correo válida' });
  await pool.execute("INSERT INTO ajustes (clave, valor) VALUES ('bandeja_comun', ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)", [c]);
  res.json({ ok: true, bandeja_comun: c });
});
app.get('/api/admin/clientes/:id(\\d+)/correos', requiereSesionAsesor, async (req, res) => {
  const [f] = await pool.execute('SELECT c.id, c.asunto, c.cuerpo, c.enviado_en, c.ok, c.error, c.responder_a, c.presentacion, c.direccion, c.de, c.en_respuesta_a, c.leido_en, c.adjuntos FROM correos_panel c WHERE c.cliente_id = ? ORDER BY c.id DESC LIMIT 80', [Number(req.params.id)]);
  const r = await remitenteDeAsesor(req.asesor.id);
  res.json({ correos: f.map(x => Object.assign(x, { direccion: x.direccion || 'saliente', adjuntos: (() => { try { return x.adjuntos ? JSON.parse(x.adjuntos) : []; } catch (e) { return []; } })() })),
    sin_leer: f.filter(x => x.direccion === 'entrante' && !x.leido_en).length,
    remitente: { presentacion: r.presentacion, responder_a: CORREO_RESPUESTAS_DOMINIO ? 'el panel (en esta ficha)' : r.responder_a, al_panel: !!CORREO_RESPUESTAS_DOMINIO, desde: BREVO_REMITENTE || null, copia: await bandejaComun() } });
});
app.post('/api/admin/clientes/:id(\\d+)/correo', requiereSesionAsesor, async (req, res) => {
  const id = Number(req.params.id), b = req.body || {};
  const asunto = String(b.asunto || '').trim().slice(0, 150), cuerpo = String(b.cuerpo || '').replace(/\r/g, '').trim().slice(0, 5000);
  if (!asunto) return res.status(400).json({ error: 'Escribe el asunto' });
  if (!cuerpo) return res.status(400).json({ error: 'Escribe el mensaje' });
  if (!brevoActivo()) return res.status(503).json({ error: 'El correo no está configurado (Brevo)' });
  const [cl] = await pool.execute('SELECT correo, nombre FROM clientes WHERE id = ?', [id]);
  if (!cl.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  if (!correoValido(cl[0].correo)) return res.status(400).json({ error: 'Este cliente no tiene un correo válido' });
  const r = await remitenteDeAsesor(req.asesor.id), copia = await bandejaComun();
  // ¿responde a un correo del cliente? Se queda en el mismo hilo (también en el programa de correo del cliente)
  let previo = null;
  if (b.en_respuesta_a) { const [pv] = await pool.execute("SELECT * FROM correos_panel WHERE id = ? AND cliente_id = ? AND direccion = 'entrante'", [Number(b.en_respuesta_a), id]); previo = pv[0] || null; }
  const token = crypto.randomBytes(6).toString('hex');
  const [ins] = await pool.execute("INSERT INTO correos_panel (cliente_id, asesor_id, persona_id, para, asunto, cuerpo, presentacion, responder_a, copia, ok, direccion, respuesta_token, en_respuesta_a, hilo_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'saliente', ?, ?, ?)",
    [id, req.asesor.id, r.persona_id, cl[0].correo, asunto, cuerpo, r.presentacion, r.responder_a, copia, token, previo ? previo.id : null, previo ? (previo.hilo_id || previo.id) : null]);
  const responderA = direccionRespuesta(ins.insertId, token) || r.responder_a;
  if (!previo) await pool.execute('UPDATE correos_panel SET hilo_id = id WHERE id = ?', [ins.insertId]);
  const c = plantillaCorreo({
    titulo: asunto,
    parrafos: cuerpo.split(/\n{2,}/).map(p => ESC_HTML(p).replace(/\n/g, '<br>')),
    boton: SITE_URL ? { texto: 'Ir a mi área', url: SITE_URL + '/area?login=1' } : null,
    nota: 'Puedes responder a este correo: le llega directamente a ' + ESC_HTML(r.nombre) + (CORREO_RESPUESTAS_DOMINIO ? '. Si nos mandas documentos como adjuntos, se guardan solos en tu área.' : '.'),
  });
  let ok = 1, error = null;
  const cab = previo && previo.mensaje_id ? { 'In-Reply-To': previo.mensaje_id, References: previo.mensaje_id } : null;
  try { await enviarCorreo(cl[0].correo, asunto, c.html, c.texto, { nombre: r.presentacion, responderA: responderA, copiaOculta: copia, cabeceras: cab }); }
  catch (e) { ok = 0; error = String((e.response && e.response.data && e.response.data.message) || e.message).slice(0, 300); }
  await pool.execute('UPDATE correos_panel SET ok = ?, error = ?, responder_a = ? WHERE id = ?', [ok, error, responderA, ins.insertId]);
  if (previo) await pool.execute("UPDATE correos_panel SET leido_en = COALESCE(leido_en, NOW()) WHERE id = ?", [previo.id]);
  if (!ok) return res.status(502).json({ error: 'No se ha podido enviar: ' + error, id: ins.insertId });
  res.status(201).json({ ok: true, id: ins.insertId });
});

// Middleware de error genérico (10/09): un payload que supera el límite de
// express.json() (15mb) llegaba antes como una página HTML cruda de
// Express, no como el JSON que espera el resto de la web. No es un fallo
// nuevo de la subida de documentos — afectaba a cualquier ruta — pero se
// nota más ahí porque es la única que mueve archivos grandes de verdad.
// 29/10: una dirección que no existe: página de Acros para el navegador, JSON para los programas
// ---- Consultar el registro (solo administradores) ----
function filtrosRegistro(q) {
  const w = [], p = [];
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.desde || '')) { w.push('r.creado_en >= ?'); p.push(q.desde + ' 00:00:00'); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.hasta || '')) { w.push('r.creado_en < ? + INTERVAL 1 DAY'); p.push(q.hasta + ' 00:00:00'); }
  if (['acceso', 'lectura', 'cambio', 'cliente', 'sistema'].includes(q.tipo)) { w.push('r.tipo = ?'); p.push(q.tipo); }
  if (q.persona) { w.push('r.actor_nombre LIKE ?'); p.push('%' + String(q.persona).slice(0, 60) + '%'); }
  if (/^\d+$/.test(q.cliente || '')) { w.push('r.cliente_id = ?'); p.push(Number(q.cliente)); }
  else if (q.cliente) { w.push('(c.correo LIKE ? OR c.nombre LIKE ? OR c.apellidos LIKE ? OR c.codigo = ?)'); const t = '%' + String(q.cliente).slice(0, 60) + '%'; p.push(t, t, t, String(q.cliente)); }
  if (q.q) { w.push('(r.accion LIKE ? OR r.ruta LIKE ? OR r.detalle LIKE ?)'); const t = '%' + String(q.q).slice(0, 80) + '%'; p.push(t, t, t); }
  if (/^\d+$/.test(q.antes_de || '')) { w.push('r.id < ?'); p.push(Number(q.antes_de)); }
  return { where: w.length ? ' WHERE ' + w.join(' AND ') : '', params: p };
}
const SQL_REG = "SELECT r.id, r.creado_en, r.actor_tipo, r.actor_id, r.actor_nombre, r.tipo, r.accion, r.metodo, r.ruta, r.estado_http, r.objeto_id, r.cliente_id, r.detalle, r.ip, TRIM(CONCAT(COALESCE(c.nombre, ''), ' ', COALESCE(c.apellidos, ''))) AS cliente_nombre, c.correo AS cliente_correo, c.codigo AS cliente_codigo FROM registro r LEFT JOIN clientes c ON c.id = r.cliente_id";
app.get('/api/admin/registro', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const { where, params } = filtrosRegistro(req.query || {}), lim = Math.min(500, Number(req.query.limite) || 200);
  const [f] = await pool.query(SQL_REG + where + ' ORDER BY r.id DESC LIMIT ' + lim, params);
  res.json({ filas: f.map(x => Object.assign(x, { detalle: detalleSeguro(x.detalle) })), hay_mas: f.length === lim });
});
app.get('/api/admin/registro.csv', requiereSesionAsesor, requiereAdminWeb, async (req, res) => {
  const { where, params } = filtrosRegistro(req.query || {});
  const [f] = await pool.query(SQL_REG + where + ' ORDER BY r.id DESC LIMIT 20000', params);
  const c = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const filas = [['Fecha', 'Quién', 'Tipo', 'Qué', 'Cliente', 'Resultado', 'Detalle', 'IP']].concat(f.map(x => [new Date(x.creado_en).toLocaleString('es-ES', { timeZone: 'Europe/Madrid' }), x.actor_nombre, x.tipo, x.accion, x.cliente_nombre || x.cliente_correo || (x.cliente_id ? 'Cliente ' + x.cliente_id : ''), x.estado_http, x.detalle, x.ip]));
  res.set('Content-Type', 'text/csv; charset=utf-8'); res.set('Content-Disposition', 'attachment; filename="registro-acros.csv"');
  res.send('\ufeff' + filas.map(l => l.map(c).join(';')).join('\r\n'));
});
// ---- Herramienta del asistente (solo si pregunta un administrador). Los clientes salen por código y sin sus datos personales ----
const DATOS_PERSONALES_CLI = /^(nombre|apellidos|correo|telefono|telefono2|numero_documento|tipo_documento|direccion|codigo_postal|fecha_nacimiento|iban)$/i;
async function iaRegistro(e, req, usados) {
  if (!req.asesor || !req.asesor.esAdmin) return { error: 'El registro maestro solo lo pueden consultar los administradores.' };
  const { where, params } = filtrosRegistro({ desde: e.desde, hasta: e.hasta, tipo: e.tipo, persona: e.persona, q: e.texto });
  const [f] = await pool.query(SQL_REG + where + ' ORDER BY r.id DESC LIMIT 80', params);
  const cli = await iaClientes(null);
  const limpia = d => { if (!d || !d.cambios) return d; const c = d.cambios; if (c.tabla === 'clientes') ['antes', 'despues'].forEach(k => { Object.keys(c[k] || {}).forEach(x => { if (DATOS_PERSONALES_CLI.test(x)) c[k][x] = '(dato personal)'; }); }); return d; };
  return { anotaciones: f.map(x => { const k = x.cliente_id && cli.get(x.cliente_id); if (k) usados.set(k.cod, x.cliente_id); const d = limpia(detalleSeguro(x.detalle)); if (d && d.datos) delete d.datos.correo;
    return { fecha: new Date(x.creado_en).toLocaleString('es-ES', { timeZone: 'Europe/Madrid' }), quien: x.actor_tipo === 'cliente' ? (k ? 'cliente ' + k.cod : 'cliente') : x.actor_nombre, tipo: x.tipo, que: x.accion, cliente: k ? k.cod : null, resultado: x.estado_http, detalle: d }; }), nota: f.length === 80 ? 'Hay más: acota por fechas, persona o tipo.' : undefined };
}

app.use((req, res, next) => {
  if (pideHTML(req) && !String(req.path).startsWith('/api/')) return res.status(404).type('html').send(paginaError(req, '404'));
  res.status(404).json({ error: 'No encontrado' });
});
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'El archivo es demasiado grande (máximo 15 MB por subida).' });
  }
  // 08/10: cualquier otro error de una ruta (ver el envoltorio junto a «const app»)
  console.error('Error en ' + req.method + ' ' + req.path + ':', err.message || err);
  if (res.headersSent) return next(err);
  if (pideHTML(req) && !String(req.path).startsWith('/api/')) return res.status(500).type('html').send(paginaError(req, '500'));
  res.status(500).json({ error: 'Error interno del servidor. Inténtalo de nuevo en un momento.' });
});

const PUERTO = process.env.PORT || 3000;
asegurarEsquema().finally(() => {
  app.listen(PUERTO, () => console.log(`Backend de Acros escuchando en el puerto ${PUERTO}`));
});
