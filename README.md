# Backend de Acros — "Llamadme gratis" y "Pide presupuesto" → MySQL

Esto ya está **probado de verdad**, no es teoría: se montó MySQL y este mismo
servidor en un entorno de pruebas, se le mandaron peticiones idénticas a las
que hacen los formularios reales (llamada y presupuesto, con array de
servicios y con texto libre), y todas quedaron guardadas correctamente. Lo
único que falta es desplegarlo con una URL pública y apuntar los formularios
ahí.

## Qué hay en esta carpeta

- `server.js` — el servidor (Node.js + Express). Dos endpoints:
  `POST /api/llamada` (Llamadme gratis) y `POST /api/presupuesto` (Pide
  presupuesto). Ambos validan los datos y los guardan en MySQL, creando
  ellos mismos las tablas que necesitan la primera vez que arrancan.
- `esquema.sql` — cómo son las tablas `solicitudes_llamada` y
  `solicitudes_presupuesto`, solo de referencia: el propio `server.js` las
  crea solas al arrancar si todavía no existen, así que no hace falta
  ejecutar este archivo a mano en ningún sitio.
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
3. En el mismo proyecto de Railway: "New" → "GitHub Repo" (sube esta
   carpeta a un repositorio de GitHub primero) o "Empty Service" y sube
   los archivos directamente.
4. En la configuración del servicio (pestaña "Variables"), añade las
   mismas variables que ves en `.env.example`, con los datos reales que
   te dio Railway en el paso 2.
5. Railway despliega solo. La primera vez que arranca, `server.js` crea
   él mismo la tabla que necesita — no hace falta tocar la base de datos
   a mano.
6. En la configuración del servicio, genera la URL pública (Settings →
   Networking → Public Networking → "Generate Domain") — algo como
   `https://backend-acros-production.up.railway.app`.
7. Prueba que está vivo entrando a esa URL + `/salud` en el navegador —
   debe responder `{"estado":"ok"}`.

## Conectar los formularios de verdad

En `acros_inicio.html` y `acros_empieza_aqui.html`, busca estas líneas:

```js
const ENDPOINT_LLAMADA = '';
const ENDPOINT_SOLICITUD = '';
```

y cámbialas por tu URL real:

```js
const ENDPOINT_LLAMADA = 'https://backend-acros-production.up.railway.app/api/llamada';
const ENDPOINT_SOLICITUD = 'https://backend-acros-production.up.railway.app/api/presupuesto';
```

En cuanto hagas esos cambios, "Llamadme gratis" y "Pide presupuesto" dejan
de ser una maqueta: cada envío llega de verdad a la base de datos.

Nota sobre `/api/presupuesto`: espera `servicios` (una lista, o el texto de
"necesito algo más"), `telefono` (obligatorio), y opcionalmente `detalle`,
`correo`, `utm` y `origen`. Si el formulario real envía los campos con
otros nombres, dímelo y ajusto el endpoint — es un cambio pequeño.

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
- Esto cubre "Llamadme gratis" y "Pide presupuesto". El acceso de clientes
  (código de un solo uso) necesitaría su propia tabla y endpoints — está
  pendiente de aclarar cómo tiene que funcionar exactamente antes de
  montarlo.
