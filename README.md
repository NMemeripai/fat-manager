# FAT Manager — backend real (Firebase + Cloudinary, listo para hosting gratis)

Backend real para FAT Manager: **Express + Firestore** (base de datos de Firebase) +
**Cloudinary** (archivos adjuntos reales, no solo el nombre). Autenticación con
**bcrypt** + **JWT**, permisos por rol verificados en el servidor. El frontend
(`public/index.html`) ya está conectado a esta API.

## Importante antes de arrancar

Este código está escrito con cuidado y revisado a fondo, pero **no pude probarlo en
vivo contra Firebase ni Cloudinary reales** desde donde lo generé (sin acceso a esos
servicios). Sí probé toda la lógica del servidor contra un Firestore simulado en
memoria (19 pruebas automáticas, incluyendo permisos por rol y navegador real haciendo
clics) — eso confirma que la lógica de negocio está bien, pero **no reemplaza probarlo
con tus credenciales reales**. Por eso incluí `npm run check`: corré eso apenas tengas
tus credenciales, ANTES de usarlo con datos reales del colegio.

## Paso 1 — Crear el proyecto de Firebase (gratis)

1. Andá a **https://console.firebase.google.com** y creá una cuenta / proyecto nuevo
2. En el menú lateral, andá a **"Firestore Database"** → "Crear base de datos" → modo
   producción → elegí una región cercana
3. Andá a **⚙️ Configuración del proyecto → Cuentas de servicio**
4. Hacé clic en **"Generar nueva clave privada"** — se descarga un archivo `.json`
5. Renombrá ese archivo a `serviceAccountKey.json` y ponelo dentro de esta carpeta
   (`fat-backend`), junto a `server.js`. **No lo subas a GitHub** (ya está en
   `.gitignore`).

Para desplegar en Render (Paso 4) no podés subir un archivo directamente, así que en
vez de eso vas a pegar el CONTENIDO de ese JSON como variable de entorno
`FIREBASE_SERVICE_ACCOUNT_JSON` (una sola línea).

## Paso 2 — Crear la cuenta de Cloudinary (gratis)

1. Andá a **https://cloudinary.com** y creá una cuenta gratis
2. En el Dashboard principal vas a ver 3 datos: **Cloud Name**, **API Key**, **API
   Secret** — los vas a necesitar

## Paso 3 — Probar que todo conecta bien

```bash
npm install
cp .env.example .env
```

Editá `.env` y completá:
- `FIREBASE_SERVICE_ACCOUNT_JSON` con el contenido de tu `serviceAccountKey.json` (todo en una línea), **o** dejá el archivo `serviceAccountKey.json` en la carpeta y borrá esa línea del `.env`
- `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`

Después corré:
```bash
npm run check
```

Esto prueba de verdad —escribiendo y leyendo datos reales— que Firebase y Cloudinary
están bien conectados, y te dice exactamente qué está mal si algo falla. No sigas al
paso siguiente hasta que esto te dé todo en ✓.

Una vez que dé bien, arrancalo local con:
```bash
npm start
```
y abrí `http://localhost:3001`.

## Paso 4 — Desplegar gratis en Render, accesible para todo el colegio

1. Subí el código a GitHub (sin el `serviceAccountKey.json` ni el `.env`, ya están en
   `.gitignore`)
2. Andá a **https://render.com**, creá cuenta gratis → "New +" → "Web Service" → elegí
   tu repositorio
3. Build command: `npm install` — Start command: `npm start` — Plan: Free
4. En "Environment Variables" agregá:
   - `FIREBASE_SERVICE_ACCOUNT_JSON` = el contenido completo de tu JSON de Firebase (una línea)
   - `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`
   - `JWT_SECRET` = un texto largo y random que inventes
5. Create Web Service. Te va a dar una URL pública para compartir con el colegio.

## Usuarios de ejemplo (se crean solos la primera vez que arranca)

| Rol | Usuario | Contraseña |
|---|---|---|
| Administrador | `admin` | `admin2026` |
| Coordinador FAT | `coordinador` | `coord2026` |
| Profesor de sección | `prof.administracion` | `prof2026` |

**Cambiá estas contraseñas** antes de usarlo con datos reales.

## Sobre los planes gratuitos

- **Firestore (Spark, gratis)**: 1 GB de almacenamiento y una cuota diaria de
  lecturas/escrituras de sobra para una escuela. No vence, no pide tarjeta.
- **Cloudinary (gratis)**: 25 créditos mensuales (~25 GB entre almacenamiento y ancho
  de banda), de sobra para documentos de alumnos. No vence.
- **Render (gratis)**: se "duerme" tras 15 min sin uso; el primer ingreso del día tarda
  unos 30-50 segundos en despertar. No afecta los datos.

## Notas honestas

- Repito lo de arriba porque es importante: corré `npm run check` con tus credenciales
  reales antes de confiar en esto para datos reales del colegio. Yo revisé el código a
  fondo y probé toda la lógica contra un Firestore simulado, pero un simulador nunca
  reemplaza 100% al servicio real (reglas de seguridad de Firestore, límites de cuota
  reales, comportamiento exacto de índices, etc.)
- Los adjuntos ahora sí son archivos reales (suben a Cloudinary y quedan con un enlace
  para ver/descargar), no solo el nombre como en la versión anterior.
- Si en algún momento preferís volver a una base SQL tradicional (Postgres/Neon), avisame:
  ya tengo esa versión armada y probada en vivo, es la alternativa más "tradicional".
