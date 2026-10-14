# Backend de Acros

Servidor de Acros (acrosfi.es): formularios de la web, propuestas y pagos,
área de clientes, documentos cifrados, panel de asesores, avisos y copias
de seguridad. Node.js + Express sobre MySQL, desplegado en **Railway**.

Todo el código está en un único archivo: `server.js`.

## Cómo se despliega

1. Se sube `server.js` (y, si cambia, `package.json`) a este repositorio.
2. Railway lo detecta y lo publica solo.
3. **No hay que tocar la base de datos a mano, nunca.** Al arrancar, el
   servidor crea las tablas y columnas que falten y deja intactos los datos
   que ya existan.

## Variables de entorno (en Railway)

Aquí solo van los **nombres**. Los valores viven únicamente en Railway.

| Variable | Para qué sirve |
| --- | --- |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | Conexión a MySQL |
| `PORT` | Puerto del servidor (lo pone Railway) |
| `ADMIN_KEY` | Clave maestra: dar de alta asesores y cambiar quién es administrador |
| `SITE_URL` | Dirección de la web (`https://acrosfi.es`) para los enlaces de los correos |
| `ORIGENES_PERMITIDOS` | Páginas que pueden llamar al backend, separadas por comas. Con el panel publicado: `https://acrosfi.es,https://www.acrosfi.es,https://panel.acrosfi.es` |
| `BREVO_API_KEY`, `BREVO_REMITENTE`, `BREVO_API_URL` | Envío de correos (Brevo) |
| `NTFY_SERVER`, `NTFY_TOPIC` | Avisos al móvil del equipo (canal general) |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM`, `TWILIO_API_URL` | WhatsApp (en pruebas) |
| `R2_ENDPOINT`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | Almacén de documentos, informes y copias (Cloudflare R2) |
| `CLAVE_PUBLICA_DOCUMENTOS` | Clave pública con la que se cifran documentos y copias |
| `CRIPTO_DIRECCION_BTC`, `CRIPTO_DIRECCION_ETH`, `CRIPTO_DIRECCION_SOL` | Direcciones de cobro en cripto |
| `EXPLORER_BTC_URL`, `EXPLORER_ETH_RPC_URL`, `EXPLORER_SOL_RPC_URL` | Comprobación de pagos cripto |
| `MODO_ACCESO_CLIENTE` | Cómo entran los clientes: con contraseña, con enlace o ambos (por defecto, ambos) |
| `MODO_DEMO` | Solo para pruebas |
| `CHAT_AVISO_SEGUNDOS`, `CHAT_TAREA_MS`, `COPIA_REVISION_MS`, `VALORACION_RECORDATORIO_SEGUNDOS` | Tiempos internos (normalmente no se tocan) |

Si falta alguna de un servicio (Brevo, Twilio, R2…), esa parte se desactiva
sin romper el resto.

## Seguridad

- **Asesores:** contraseña + **verificación en dos pasos obligatoria** (app
  tipo Google Authenticator) con códigos de recuperación. Máximo 5
  contraseñas fallidas por correo en 15 minutos.
- **Permisos:** un asesor solo ve y toca a sus clientes y los encargos donde
  colabora; los administradores lo ven todo. Todo lo que se cambia en el
  panel queda en el **registro de actividad**.
- **Clientes:** entran con enlace por correo o con contraseña;
  verificación en dos pasos opcional.
- **Documentos:** se cifran en el navegador del cliente antes de subirse;
  solo el equipo puede descifrarlos, con la clave privada que se guarda en
  cada navegador del panel (nunca en el servidor).
- **Mensajes:** nunca se borran; el cliente los oculta de su vista y el
  asesor los retira, pero quedan como registro.

## Copias de seguridad

- Cada noche se hace una copia **completa y cifrada** de la base de datos en
  R2. Se conservan las de los últimos 30 días. También se puede hacer una a
  mano desde el panel («Copias de seguridad»), y se hace sola antes de
  fusionar dos fichas de cliente.
- **Restaurar:** con la herramienta `herramientas/restaurar_copia_bd.js` y la
  clave privada (las instrucciones están dentro del propio archivo). Primero
  se restaura en una base de datos aparte para comprobarla.

## Pruebas

La carpeta `prueba/` tiene lo necesario para levantar una copia local
(MariaDB + un R2 de imitación) y probar el servidor sin tocar producción.

## Dónde está el detalle

El historial de cambios, las decisiones y lo pendiente viven en los
documentos de estado del proyecto (`ACROS_ESTADO_GENERAL.md` y
`ACROS_WEB_ESTADO.md`), no aquí.
