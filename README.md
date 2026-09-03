# Backend de Acros — "Llamadme gratis" → MySQL

Esto ya está **probado de verdad**, no es teoría: se montó MySQL y este mismo
servidor en un entorno de pruebas, se le mandaron dos peticiones idénticas a
las que hace el formulario real, y las dos quedaron guardadas en la tabla
con sus datos correctos. Lo único que falta es desplegarlo en algún sitio
con una URL pública, y apuntar el formulario ahí.

## Qué hay en esta carpeta

- `server.js` — el servidor (Node.js + Express). Un único endpoint,
  `POST /api/llamada`, que valida los datos y los guarda en MySQL.
- `esquema.sql` — la tabla `solicitudes_llamada`. Se ejecuta una sola vez.
- `package.json` — las dependencias (`express`, `mysql2`, `cors`, `dotenv`).
- `.env.example` — plantilla de las variables de entorno. Cópiala como
  `.env` y rellena con los datos reales de tu base de datos.

## Cómo ponerlo en marcha (recomendado: Railway)

Railway te da Node.js y MySQL en el mismo sitio, con capa gratuita
suficiente para empezar.

1. Crea una cuenta en [railway.app](https://railway.app) (puedes entrar
   con tu cuenta de GitHub).
2. "New Project" → "Provision MySQL" — esto te crea una base de datos y te
   da directamente las credenciales (host, usuario, contraseña, puerto).
3. Ejecuta `esquema.sql` contra esa base de datos: Railway trae un cliente
   MySQL integrado en su panel (pestaña "Data"), o puedes conectarte con
   cualquier cliente MySQL de escritorio (TablePlus, DBeaver...) usando
   esas mismas credenciales.
4. En el mismo proyecto de Railway: "New" → "GitHub Repo" (sube esta
   carpeta a un repositorio de GitHub primero) o "Empty Service" y sube
   los archivos directamente.
5. En la configuración del servicio (pestaña "Variables"), añade las
   mismas variables que ves en `.env.example`, con los datos reales que
   te dio Railway en el paso 2.
6. Railway despliega solo y te da una URL pública, algo como
   `https://backend-acros-production.up.railway.app`.
7. Prueba que está vivo entrando a esa URL + `/salud` en el navegador —
   debe responder `{"estado":"ok"}`.

## Conectar el formulario de verdad

En `acros_inicio.html` y `acros_empieza_aqui.html`, busca esta línea:

```js
const ENDPOINT_LLAMADA = '';
```

y cámbiala por tu URL real más `/api/llamada`:

```js
const ENDPOINT_LLAMADA = 'https://backend-acros-production.up.railway.app/api/llamada';
```

En cuanto hagas ese cambio, "Llamadme gratis" deja de ser una maqueta:
cada envío llega de verdad a la base de datos.

## Qué falta todavía (para no llevarte una sorpresa)

- **CORS**: en `.env`, `ORIGENES_PERMITIDOS` está en `*` (acepta cualquier
  origen) para que puedas probarlo fácil. Antes de hacerlo público de
  verdad, cámbialo a vuestro dominio real, o cualquiera podría usar
  vuestro backend desde otra web.
- **Ver las solicitudes guardadas**: hoy solo se pueden ver entrando
  directamente a la base de datos. El siguiente paso natural es un
  endpoint (o una vista en el panel de admin de clientes) que las liste.
- **Aviso automático** (que a Vikn/Bernardo les llegue un WhatsApp o
  correo en cuanto entra una solicitud nueva): no está montado — hoy solo
  se guarda, no avisa a nadie. Se puede añadir con Twilio (WhatsApp/SMS) o
  Resend (correo) más adelante, sin tocar lo que ya funciona.
- Esto cubre **solo** "Llamadme gratis". "Pide presupuesto" y el acceso de
  clientes necesitarían sus propias tablas y endpoints, con la misma
  idea.
