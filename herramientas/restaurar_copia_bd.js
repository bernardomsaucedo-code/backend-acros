#!/usr/bin/env node
/* =====================================================================
   ACROS — RESTAURAR UNA COPIA DE LA BASE DE DATOS (07/10)
   Solo para emergencias (p. ej. Railway pierde la base). Se ejecuta en un
   ordenador, desde la carpeta del backend (usa sus dependencias).

   1) Comprobar que una copia se abre (no toca ninguna base):
        node herramientas/restaurar_copia_bd.js --copia ARCHIVO.acros-bd.json --clave privada.pem --solo-comprobar

   2) Restaurar en una base de datos (normalmente una NUEVA y vacía):
        a. Arranca el backend una vez contra esa base: crea todas las tablas.
        b. node herramientas/restaurar_copia_bd.js --copia ARCHIVO.acros-bd.json --clave privada.pem \
             --destino "mysql://usuario:contraseña@servidor:puerto/basededatos" --confirmo-borrar
      Borra lo que haya en las tablas de la copia y mete los datos de la copia.
      Sin --confirmo-borrar no toca nada.

   La clave privada es la misma de los documentos (la que se pega en el panel).
   Nunca la subas a ningún sitio ni la pegues en un chat.
   ===================================================================== */
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');

function arg(nombre) { const i = process.argv.indexOf('--' + nombre); return i > -1 ? process.argv[i + 1] : null; }
function bandera(nombre) { return process.argv.includes('--' + nombre); }

function abrirCopia(rutaCopia, rutaClave) {
  const env = JSON.parse(fs.readFileSync(rutaCopia, 'utf8'));
  if (env.formato !== 'acros-copia-bd-cifrada-v1') throw new Error('Este archivo no es una copia de Acros');
  const clavePrivada = fs.readFileSync(rutaClave, 'utf8');
  const claveAES = crypto.privateDecrypt({ key: clavePrivada, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(env.clave_cifrada, 'base64'));
  const todo = Buffer.from(env.datos, 'base64');
  const etiqueta = todo.subarray(todo.length - 16), cifrado = todo.subarray(0, todo.length - 16);
  const descifrador = crypto.createDecipheriv('aes-256-gcm', claveAES, Buffer.from(env.iv, 'base64'));
  descifrador.setAuthTag(etiqueta);
  const comprimido = Buffer.concat([descifrador.update(cifrado), descifrador.final()]);
  const datos = JSON.parse(zlib.gunzipSync(comprimido).toString('utf8'));
  if (datos.formato !== 'acros-bd-v1') throw new Error('Formato de datos desconocido');
  return datos;
}
const valorSQL = v => (v && typeof v === 'object' && v.__b64 !== undefined) ? Buffer.from(v.__b64, 'base64') : v;

async function restaurar(datos, destino) {
  const mysql = require('mysql2/promise');
  const conn = await mysql.createConnection({ uri: destino, dateStrings: true, multipleStatements: false });
  try {
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    const [existentes] = await conn.query('SHOW TABLES');
    const nombres = new Set(existentes.map(t => Object.values(t)[0]));
    for (const [tabla, filas] of Object.entries(datos.tablas)) {
      if (!nombres.has(tabla)) { console.log(`  · ${tabla}: no existe en el destino (¿arrancaste antes el backend?), se salta`); continue; }
      const [cols] = await conn.query('SHOW COLUMNS FROM `' + tabla + '`');
      const columnas = new Set(cols.map(c => c.Field));
      await conn.query('DELETE FROM `' + tabla + '`');
      for (let i = 0; i < filas.length; i += 200) {
        const lote = filas.slice(i, i + 200);
        const usadas = Object.keys(lote[0]).filter(k => columnas.has(k));
        const sql = 'INSERT INTO `' + tabla + '` (' + usadas.map(c => '`' + c + '`').join(',') + ') VALUES ' + lote.map(() => '(' + usadas.map(() => '?').join(',') + ')').join(',');
        await conn.query(sql, lote.flatMap(f => usadas.map(c => valorSQL(f[c]))));
      }
      console.log(`  · ${tabla}: ${filas.length} filas`);
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
  } finally { await conn.end(); }
}

(async () => {
  const copia = arg('copia'), clave = arg('clave'), destino = arg('destino');
  if (!copia || !clave) { console.log('Uso: ver la cabecera de este archivo.'); process.exit(1); }
  const datos = abrirCopia(copia, clave);
  console.log(`Copia del ${datos.creado_en} abierta correctamente:`);
  for (const [t, f] of Object.entries(datos.tablas)) console.log(`  · ${t}: ${f.length} filas`);
  if (bandera('solo-comprobar')) return;
  if (!destino) { console.log('\nFalta --destino para restaurar.'); process.exit(1); }
  if (!bandera('confirmo-borrar')) { console.log('\nPara restaurar hay que añadir --confirmo-borrar (se borran las tablas de destino que estén en la copia).'); process.exit(1); }
  console.log('\nRestaurando…');
  await restaurar(datos, destino);
  console.log('Hecho.');
})().catch(err => { console.error('ERROR:', err.message); process.exit(1); });
