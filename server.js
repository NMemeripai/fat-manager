require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType, WidthType, BorderStyle, ShadingType } = require('docx');
const { db, uid, todayISO, logActivity, getActivityLog, getSectionsOrdered, recomputeTotalWeeks, generateRotationsFor, ensureSeed } = require('./db');

// JWT_SECRET es obligatorio: NUNCA usar un valor por defecto acá. Si faltara y el servidor
// arrancara igual con un secreto "de muestra", cualquiera que conociera ese valor (por ejemplo,
// por estar en un repo público o en un historial de chat) podría fabricar tokens válidos de
// cualquier rol, incluido admin, sin loguearse. Preferimos que el server directamente no arranque.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 20) {
  console.error('[server] Falta configurar la variable de entorno JWT_SECRET (o es demasiado corta/insegura).');
  console.error('[server] En Render: Environment → agregá JWT_SECRET con un valor largo y random (32+ caracteres).');
  console.error('[server] Podés generar uno con: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  process.exit(1);
}
const PORT = process.env.PORT || 3001;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const CLOUDINARY_READY = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

const app = express();
app.use(helmet({
  // El frontend es una sola página HTML con estilos/scripts inline (no un sitio de terceros
  // embebiendo cosas), así que dejamos crossOriginResourcePolicy abierto para no romper la
  // carga de imágenes/archivos subidos a Cloudinary. El resto de los headers de helmet
  // (X-Frame-Options, X-Content-Type-Options, HSTS, etc.) quedan con sus valores seguros por defecto.
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false // la app usa estilos/scripts inline; una CSP estricta la rompería sin un trabajo aparte de reescritura
}));

// CORS: el frontend se sirve desde el mismo origen que la API (Express sirve el HTML), así que
// no hace falta permitir orígenes cruzados por defecto. Si en algún momento necesitás pegarle a
// esta API desde otro dominio (por ejemplo una app aparte), agregá ALLOWED_ORIGINS en Render
// con los dominios separados por coma.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors(allowedOrigins.length ? { origin: allowedOrigins } : { origin: false }));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Límite general: protege contra abuso/scraping automatizado sin molestar el uso normal
// (generoso a propósito, porque el propio frontend ya optimiza sus lecturas).
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000, max: 600,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Probá de nuevo en unos minutos.' }
}));
// Límite específico y más estricto para login, para frenar fuerza bruta de contraseñas.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiados intentos de inicio de sesión. Probá de nuevo en unos minutos.' }
});


function h(fn) {
  return (req, res) => fn(req, res).catch(err => {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  });
}

/* ---------------------------- auth middleware ---------------------------- */
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: 'Token inválido o expirado' }); }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'No tenés permiso para esta acción' });
    next();
  };
}

/* ---------------------------- pequeños helpers de Firestore ---------------------------- */
async function docData(collection, id) {
  const snap = await db.collection(collection).doc(id).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}
async function whereEquals(collection, field, value) {
  const snap = await db.collection(collection).where(field, '==', value).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}
async function allDocs(collection) {
  const snap = await db.collection(collection).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

/* ---------------------------- auth routes ---------------------------- */
app.post('/api/auth/login', loginLimiter, h(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  const matches = await whereEquals('users', 'username', username.trim());
  // Firestore no hace comparaciones case-insensitive nativas; buscamos también en minúsculas por si acaso.
  const u = matches[0] || (await whereEquals('users', 'username', username.trim().toLowerCase()))[0];
  if (!u || !bcrypt.compareSync(password, u.passwordHash)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  if (u.active === false) {
    return res.status(403).json({ error: 'Esta cuenta está desactivada. Contactá al administrador.' });
  }
  const payload = { sub: u.id, username: u.username, role: u.role, nombre: u.nombre, teacherId: u.teacherId || null, sectionId: u.sectionId || null, studentId: u.studentId || null };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: payload });
}));

app.get('/api/me', auth, (req, res) => res.json(req.user));

/* ---------------------------- upload de archivos reales (Cloudinary) ---------------------------- */
app.post('/api/upload', auth, upload.single('file'), h(async (req, res) => {
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor (faltan variables de entorno).' });
  if (!req.file) return res.status(400).json({ error: 'No se envió ningún archivo' });
  const ext = extOf(req.file.originalname);
  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager', resource_type: 'raw', public_id: uid('doc') + ext },
      (err, r) => err ? reject(err) : resolve(r)
    );
    stream.end(req.file.buffer);
  });
  res.status(201).json({ url: result.secure_url, name: req.file.originalname });
}));

/* ---------------------------- Centro de Documentos ---------------------------- */
const ALLOWED_DOC_EXT = ['.pdf', '.doc', '.docx', '.xls', '.xlsx'];
const DOC_MIME_TYPES = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};
function extOf(filename) {
  const i = filename.lastIndexOf('.');
  return i >= 0 ? filename.slice(i).toLowerCase() : '';
}
function formatoOf(ext) {
  if (ext === '.pdf') return 'pdf';
  if (ext === '.doc' || ext === '.docx') return 'word';
  if (ext === '.xls' || ext === '.xlsx') return 'excel';
  return 'otro';
}

app.post('/api/documentos', auth, upload.single('file'), h(async (req, res) => {
  if (!['admin', 'seccion', 'alumno'].includes(req.user.role)) return res.status(403).json({ error: 'No tenés permiso para subir documentos' });
  if (!req.file) return res.status(400).json({ error: 'No se envió ningún archivo' });
  const ext = extOf(req.file.originalname);
  if (!ALLOWED_DOC_EXT.includes(ext)) return res.status(400).json({ error: 'Formato no permitido. Solo se aceptan .pdf, .doc, .docx, .xls y .xlsx' });
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });

  let tipo, studentId = null, curso = null, groupId = null;
  if (req.user.role === 'alumno') {
    tipo = 'alumno';
    studentId = req.user.studentId;
    const st = await docData('students', studentId);
    curso = st ? (st.curso + ' "' + st.division + '"') : null;
    groupId = st ? (st.groupId || null) : null;
  } else if (req.user.role === 'seccion') {
    tipo = 'mep';
    studentId = req.body.studentId || null;
  } else {
    tipo = req.body.tipo === 'alumno' ? 'alumno' : 'mep';
    studentId = req.body.studentId || null;
  }

  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager/documentos', resource_type: 'raw', public_id: uid('file') + ext },
      (err, r) => err ? reject(err) : resolve(r)
    );
    stream.end(req.file.buffer);
  });

  const now = new Date();
  const id = uid('doc');
  const docRecord = {
    tipo, nombre: req.file.originalname, url: result.secure_url,
    uploadedBy: req.user.sub, uploadedByNombre: req.user.nombre, uploadedByRole: req.user.role,
    studentId, curso, groupId, observaciones: req.body.observaciones || '',
    fecha: now.toISOString().slice(0, 10), hora: now.toTimeString().slice(0, 5),
    createdAt: now.toISOString(),
    tamano: req.file.size, formato: formatoOf(ext),
    semana: null, rotationId: null, sectionId: null,
    estado: req.user.role === 'alumno' ? 'en_progreso' : 'entregado'
  };
  await db.collection('documentos').doc(id).set(docRecord);
  await logActivity(`${req.user.nombre} subió el documento "${req.file.originalname}".`);
  res.status(201).json({ id, ...docRecord });
}));

function canDownloadDocumento(user, d) {
  if (user.role === 'admin' || user.role === 'viewadmin') return true;
  return d.uploadedBy === user.sub;
}
app.get('/api/documentos/:id/download', auth, h(async (req, res) => {
  const d = await docData('documentos', req.params.id);
  if (!d) return res.status(404).json({ error: 'Documento no encontrado' });
  if (!canDownloadDocumento(req.user, d)) return res.status(403).json({ error: 'No tenés permiso para descargar este documento' });
  const upstream = await fetch(d.url);
  if (!upstream.ok) return res.status(502).json({ error: 'No se pudo obtener el archivo desde el almacenamiento' });
  const ext = extOf(d.nombre);
  const buffer = Buffer.from(await upstream.arrayBuffer());
  res.setHeader('Content-Type', DOC_MIME_TYPES[ext] || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${d.nombre}"; filename*=UTF-8''${encodeURIComponent(d.nombre)}`);
  res.send(buffer);
}));

app.get('/api/documentos', auth, requireRole('admin', 'viewadmin'), h(async (req, res) => {
  const docs = await allDocs('documentos');
  docs.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  res.json({ documentos: docs });
}));

app.delete('/api/documentos/:id', auth, requireRole('admin'), h(async (req, res) => {
  const d = await docData('documentos', req.params.id);
  if (!d) return res.status(404).json({ error: 'Documento no encontrado' });
  await db.collection('documentos').doc(req.params.id).delete();
  await logActivity(`Se eliminó el documento "${d.nombre}".`);
  res.json({ ok: true });
}));

app.get('/api/mis-documentos', auth, h(async (req, res) => {
  if (!['seccion', 'alumno'].includes(req.user.role)) return res.status(403).json({ error: 'No tenés documentos propios en este sistema' });
  const all = await allDocs('documentos');
  const mine = all.filter(d => d.uploadedBy === req.user.sub).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  res.json({ documentos: mine });
}));


app.get('/api/state', auth, h(async (req, res) => {
  if (req.user.role === 'alumno') return res.status(403).json({ error: 'Los alumnos no tienen acceso a este recurso' });
  // Soporte de recarga parcial: ?only=rotations,students trae solo esas colecciones
  // (ahorra lecturas de Firestore evitando releer las 11 colecciones en cada acción).
  // Sin el parámetro "only", el comportamiento es idéntico al de antes (trae todo).
  const only = req.query.only ? String(req.query.only).split(',').map(s => s.trim()).filter(Boolean) : null;
  const wants = key => !only || only.includes(key);

  const result = {};
  if (wants('config')) {
    const cfgSnap = await db.collection('config').doc('main').get();
    result.config = cfgSnap.data();
  }
  if (wants('teachers')) result.teachers = await allDocs('teachers');
  if (wants('sections')) result.sections = (await allDocs('sections')).sort((a, b) => a.orden - b.orden);
  if (wants('students')) result.students = await allDocs('students');
  if (wants('rotations')) result.rotations = await allDocs('rotations');
  if (wants('consignas')) result.consignas = await allDocs('consignas');
  if (wants('objetivos')) result.objetivos = await allDocs('objetivos');
  if (wants('groups')) result.groups = await allDocs('groups');
  if (wants('pendientes')) result.pendientes = await allDocs('pendientes');
  if (wants('activityLog')) result.activityLog = await getActivityLog(40);
  if (wants('users')) {
    result.users = (await allDocs('users')).map(u => ({ id: u.id, username: u.username, role: u.role, nombre: u.nombre, teacherId: u.teacherId, sectionId: u.sectionId, studentId: u.studentId || null }));
  }
  if (wants('comunicados')) {
    let comunicados = await allDocs('comunicados');
    comunicados.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    if (req.user.role === 'seccion') {
      comunicados = comunicados.filter(c => comunicadoVisibleParaProfesor(c, req.user.teacherId)).map(c => comunicadoParaProfesor(c, req.user.teacherId));
    }
    result.comunicados = comunicados;
  }
  if (wants('cronogramaActividades')) {
    result.cronogramaActividades = ['admin', 'coordinador', 'viewadmin'].includes(req.user.role) ? await allDocs('cronogramaActividades') : [];
  }
  if (wants('objetivosSemanales')) {
    result.objetivosSemanales = await listarObjetivosSemanales(req.user);
  }
  res.json(result);
}));

/* ---------------------------- students ---------------------------- */
app.post('/api/students', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre, apellido, dni, curso, division, legajo, fechaInicio, estado, groupId, username, password } = req.body || {};
  if (!nombre || !apellido || !dni || !legajo) return res.status(400).json({ error: 'Faltan campos obligatorios' });
  const dupe = await whereEquals('students', 'legajo', legajo);
  if (dupe.length) return res.status(409).json({ error: 'Ya existe un alumno con ese legajo' });
  const sections = await getSectionsOrdered();
  if (!sections.length) return res.status(400).json({ error: 'No hay secciones creadas todavía. Creá al menos una sección antes de dar de alta alumnos.' });
  if (username) {
    const dupeUser = await whereEquals('users', 'username', username);
    if (dupeUser.length) return res.status(409).json({ error: 'Ese usuario ya existe' });
  }
  const id = uid('al');
  const data = { nombre, apellido, dni, curso, division, legajo, fechaInicio: fechaInicio || todayISO(), estado: estado || 'activo', groupId: groupId || null };
  await db.collection('students').doc(id).set(data);
  await generateRotationsFor({ id, fechaInicio: data.fechaInicio });
  if (username && password) {
    await db.collection('users').doc(uid('u')).set({
      username, passwordHash: bcrypt.hashSync(password, 10), role: 'alumno', nombre: nombre + ' ' + apellido,
      teacherId: null, sectionId: null, studentId: id
    });
  }
  await logActivity(`Se creó el alumno ${nombre} ${apellido} con sus ${sections.length} rotaciones.`);
  res.status(201).json({ id });
}));

app.put('/api/students/:id', auth, requireRole('admin'), h(async (req, res) => {
  const exists = await docData('students', req.params.id);
  if (!exists) return res.status(404).json({ error: 'Alumno no encontrado' });
  const { nombre, apellido, dni, curso, division, legajo, fechaInicio, estado, groupId, username, password } = req.body || {};
  await db.collection('students').doc(req.params.id).update({ nombre, apellido, dni, curso, division, legajo, fechaInicio, estado, groupId: groupId || null });
  if (username) {
    const linked = await whereEquals('users', 'studentId', req.params.id);
    const existingUser = linked[0];
    if (existingUser) {
      const update = { username, nombre: nombre + ' ' + apellido };
      if (password) update.passwordHash = bcrypt.hashSync(password, 10);
      await db.collection('users').doc(existingUser.id).update(update);
    } else if (password) {
      const dupeUser = await whereEquals('users', 'username', username);
      if (dupeUser.length) return res.status(409).json({ error: 'Ese usuario ya existe' });
      await db.collection('users').doc(uid('u')).set({
        username, passwordHash: bcrypt.hashSync(password, 10), role: 'alumno', nombre: nombre + ' ' + apellido,
        teacherId: null, sectionId: null, studentId: req.params.id
      });
    }
  }
  await logActivity(`Se actualizaron los datos de ${nombre} ${apellido}.`);
  res.json({ ok: true });
}));

app.delete('/api/students/:id', auth, requireRole('admin'), h(async (req, res) => {
  const st = await docData('students', req.params.id);
  if (!st) return res.status(404).json({ error: 'Alumno no encontrado' });
  const rots = await whereEquals('rotations', 'studentId', req.params.id);
  const linkedUsers = await whereEquals('users', 'studentId', req.params.id);
  const batch = db.batch();
  rots.forEach(r => batch.delete(db.collection('rotations').doc(r.id)));
  linkedUsers.forEach(u => batch.delete(db.collection('users').doc(u.id)));
  batch.delete(db.collection('students').doc(req.params.id));
  await batch.commit();
  await logActivity(`Se eliminó al alumno ${st.nombre} ${st.apellido}.`);
  res.json({ ok: true });
}));

/* ---------------------------- sections (dinámicas: crear, editar, eliminar, reordenar) ---------------------------- */
app.post('/api/sections', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre, teacherId, weeks, color } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre de la sección es obligatorio' });
  const existing = await getSectionsOrdered();
  const id = uid('s');
  await db.collection('sections').doc(id).set({
    nombre, teacherId: teacherId || null, orden: existing.length + 1, weeks: Number(weeks) || 5, color: color || null
  });
  await recomputeTotalWeeks();
  await logActivity(`Se creó la sección ${nombre}.`);
  res.status(201).json({ id });
}));

app.put('/api/sections/:id', auth, requireRole('admin'), h(async (req, res) => {
  const sec = await docData('sections', req.params.id);
  if (!sec) return res.status(404).json({ error: 'Sección no encontrada' });
  const { nombre, teacherId, weeks, color } = req.body || {};
  await db.collection('sections').doc(req.params.id).update({
    nombre, teacherId: teacherId || null, weeks: weeks != null ? (Number(weeks) || 5) : (sec.weeks || 5),
    color: color !== undefined ? (color || null) : (sec.color || null)
  });
  const rots = await whereEquals('rotations', 'sectionId', req.params.id);
  const batch = db.batch();
  rots.filter(r => r.status !== 'finalizada').forEach(r => batch.update(db.collection('rotations').doc(r.id), { teacherId: teacherId || null }));
  await batch.commit();
  if (weeks != null && Number(weeks) !== sec.weeks) await recomputeTotalWeeks();
  await logActivity(`Se actualizó la sección ${nombre}.`);
  res.json({ ok: true });
}));

app.delete('/api/sections/:id', auth, requireRole('admin'), h(async (req, res) => {
  const sec = await docData('sections', req.params.id);
  if (!sec) return res.status(404).json({ error: 'Sección no encontrada' });
  const rots = await whereEquals('rotations', 'sectionId', req.params.id);
  const force = req.query.force === 'true' || (req.body && req.body.force === true);
  if (rots.length && !force) {
    return res.status(409).json({ error: `Esta sección tiene ${rots.length} rotación(es) asociadas.`, rotationsCount: rots.length });
  }
  const batch = db.batch();
  rots.forEach(r => batch.delete(db.collection('rotations').doc(r.id)));
  batch.delete(db.collection('sections').doc(req.params.id));
  await batch.commit();
  // reordenamos las restantes para que el "orden" quede contiguo (1,2,3...)
  const remaining = await getSectionsOrdered();
  const reorderBatch = db.batch();
  remaining.forEach((s, idx) => reorderBatch.update(db.collection('sections').doc(s.id), { orden: idx + 1 }));
  await reorderBatch.commit();
  await recomputeTotalWeeks();
  await logActivity(`Se eliminó la sección ${sec.nombre}${rots.length ? ` (junto con ${rots.length} rotación/es asociadas)` : ''}.`);
  res.json({ ok: true });
}));

app.put('/api/sections-order', auth, requireRole('admin'), h(async (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order) || !order.length) return res.status(400).json({ error: 'Falta la lista de orden' });
  const batch = db.batch();
  order.forEach((id, idx) => batch.update(db.collection('sections').doc(id), { orden: idx + 1 }));
  await batch.commit();
  await logActivity('Se reordenaron las secciones.');
  res.json({ ok: true });
}));

/* ---------------------------- grupos ---------------------------- */
app.post('/api/groups', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre del grupo es obligatorio' });
  const id = uid('g');
  await db.collection('groups').doc(id).set({ nombre });
  await logActivity(`Se creó el grupo ${nombre}.`);
  res.status(201).json({ id });
}));

app.put('/api/groups/:id', auth, requireRole('admin'), h(async (req, res) => {
  const g = await docData('groups', req.params.id);
  if (!g) return res.status(404).json({ error: 'Grupo no encontrado' });
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre del grupo es obligatorio' });
  await db.collection('groups').doc(req.params.id).update({ nombre });
  await logActivity(`Se renombró el grupo a ${nombre}.`);
  res.json({ ok: true });
}));

app.delete('/api/groups/:id', auth, requireRole('admin'), h(async (req, res) => {
  const g = await docData('groups', req.params.id);
  if (!g) return res.status(404).json({ error: 'Grupo no encontrado' });
  const students = await whereEquals('students', 'groupId', req.params.id);
  const batch = db.batch();
  students.forEach(s => batch.update(db.collection('students').doc(s.id), { groupId: null }));
  batch.delete(db.collection('groups').doc(req.params.id));
  await batch.commit();
  await logActivity(`Se eliminó el grupo ${g.nombre}${students.length ? ` (${students.length} alumno/s quedaron sin grupo)` : ''}.`);
  res.json({ ok: true });
}));

/* ---------------------------- teachers (+ usuario vinculado) ---------------------------- */
app.post('/api/teachers', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre, rol, sectionId, username, password } = req.body || {};
  if (!nombre || !username || !password) return res.status(400).json({ error: 'Faltan campos obligatorios' });
  const dupe = await whereEquals('users', 'username', username);
  if (dupe.length) return res.status(409).json({ error: 'Ese usuario ya existe' });
  const id = uid('t');
  await db.collection('teachers').doc(id).set({ nombre, rol });
  if (sectionId) await db.collection('sections').doc(sectionId).update({ teacherId: id });
  await db.collection('users').doc(uid('u')).set({
    username, passwordHash: bcrypt.hashSync(password, 10), role: rol, nombre, teacherId: id, sectionId: sectionId || null
  });
  await logActivity(`Se creó el profesor ${nombre}.`);
  res.status(201).json({ id });
}));

app.put('/api/teachers/:id', auth, requireRole('admin'), h(async (req, res) => {
  const t = await docData('teachers', req.params.id);
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  const { nombre, rol, sectionId, username, password } = req.body || {};
  await db.collection('teachers').doc(req.params.id).update({ nombre, rol });
  if (sectionId) await db.collection('sections').doc(sectionId).update({ teacherId: t.id });
  const userMatches = await whereEquals('users', 'teacherId', t.id);
  const user = userMatches[0];
  if (user) {
    const update = { username: username || user.username, nombre, role: rol, sectionId: sectionId || null };
    if (password) update.passwordHash = bcrypt.hashSync(password, 10);
    await db.collection('users').doc(user.id).update(update);
  }
  await logActivity(`Se actualizó el perfil del profesor ${nombre}.`);
  res.json({ ok: true });
}));

app.delete('/api/teachers/:id', auth, requireRole('admin'), h(async (req, res) => {
  const t = await docData('teachers', req.params.id);
  if (!t) return res.status(404).json({ error: 'Profesor no encontrado' });
  const userMatches = await whereEquals('users', 'teacherId', req.params.id);
  const batch = db.batch();
  userMatches.forEach(u => batch.delete(db.collection('users').doc(u.id)));
  batch.delete(db.collection('teachers').doc(req.params.id));
  await batch.commit();
  await logActivity(`Se eliminó al profesor ${t.nombre}.`);
  res.json({ ok: true });
}));

/* ---------------------------- rotations (permiso verificado en el servidor) ---------------------------- */
function canEditRotation(user, rotation) {
  if (user.role === 'admin') return true;
  if (user.role === 'seccion') return rotation.teacherId === user.teacherId;
  return false;
}
function canViewRotationAttachment(user, rotation) {
  if (canEditRotation(user, rotation)) return true;
  if (user.role === 'viewadmin') return true;
  if (user.role === 'alumno') return rotation.studentId === user.studentId;
  return false;
}
app.get('/api/rotations/:id/attachment', auth, h(async (req, res) => {
  const r = await docData('rotations', req.params.id);
  if (!r) return res.status(404).json({ error: 'Rotación no encontrada' });
  if (!r.attachmentUrl) return res.status(404).json({ error: 'Esta rotación no tiene ningún adjunto' });
  if (!canViewRotationAttachment(req.user, r)) return res.status(403).json({ error: 'No tenés permiso para descargar este archivo' });
  const upstream = await fetch(r.attachmentUrl);
  if (!upstream.ok) return res.status(502).json({ error: 'No se pudo obtener el archivo desde el almacenamiento' });
  const name = r.attachmentName || 'adjunto';
  const ext = extOf(name);
  const buffer = Buffer.from(await upstream.arrayBuffer());
  res.setHeader('Content-Type', DOC_MIME_TYPES[ext] || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${name}"; filename*=UTF-8''${encodeURIComponent(name)}`);
  res.send(buffer);
}));
app.put('/api/rotations/:id', auth, h(async (req, res) => {
  const r = await docData('rotations', req.params.id);
  if (!r) return res.status(404).json({ error: 'Rotación no encontrada' });
  if (!canEditRotation(req.user, r)) return res.status(403).json({ error: 'No tenés permiso para editar esta rotación' });
  const { plan, actividades, observaciones, informeFinal, comentarios, status, attachmentName, attachmentUrl } = req.body || {};
  const update = {
    plan: plan || '', actividades: actividades || '', observaciones: observaciones || '',
    informeFinal: informeFinal || '', comentarios: comentarios || '', status
  };
  if (attachmentName) update.attachmentName = attachmentName;
  if (attachmentUrl) update.attachmentUrl = attachmentUrl;
  await db.collection('rotations').doc(req.params.id).update(update);
  const student = await docData('students', r.studentId);
  const section = await docData('sections', r.sectionId);
  await logActivity(`Se actualizó la rotación de ${student.nombre} ${student.apellido} en ${section.nombre}.`);
  if (r.status !== 'finalizada' && status === 'finalizada') {
    await logActivity(`${student.nombre} ${student.apellido} finalizó la rotación en ${section.nombre}.`);
    const notas = (r.informesSemanales || []).filter(e => e.nota != null);
    if (!notas.length) {
      const lastSemana = (r.informesSemanales || []).reduce((max, e) => Math.max(max, e.semana || 0), 0);
      await db.collection('pendientes').doc(uid('p')).set({
        studentId: r.studentId, sectionId: r.sectionId, teacherId: r.teacherId,
        semana: lastSemana || r.orden, motivo: 'Sección finalizada sin calificaciones cargadas',
        contenido: 'Revisar el contenido completo de la sección con el alumno', estado: 'pendiente',
        createdAt: new Date().toISOString()
      });
      await logActivity(`Se generó un registro en Contenidos Pendientes para ${student.nombre} ${student.apellido} (${section.nombre}, sin notas).`);
    }
  }
  res.json({ ok: true });
}));

/* ---------------------------- Cronograma de Rotaciones (admin): ediciones acotadas, sin tocar el resto ---------------------------- */
app.put('/api/rotations/:id/schedule', auth, requireRole('admin'), h(async (req, res) => {
  const r = await docData('rotations', req.params.id);
  if (!r) return res.status(404).json({ error: 'Rotación no encontrada' });
  const { sectionId, teacherId, startDate, endDate, empresa, observaciones } = req.body || {};
  const update = {};
  if (sectionId !== undefined) {
    const newSection = await docData('sections', sectionId);
    if (!newSection) return res.status(400).json({ error: 'La sección elegida no existe' });
    update.sectionId = sectionId;
    update.teacherId = teacherId !== undefined ? teacherId : (newSection.teacherId || null);
  } else if (teacherId !== undefined) {
    update.teacherId = teacherId;
  }
  if (startDate !== undefined) update.startDate = startDate;
  if (endDate !== undefined) update.endDate = endDate;
  if (empresa !== undefined) update.empresa = empresa;
  if (observaciones !== undefined) update.observaciones = observaciones;
  if (startDate && endDate && startDate > endDate) return res.status(400).json({ error: 'La fecha de inicio no puede ser posterior a la de fin' });
  if (!Object.keys(update).length) return res.status(400).json({ error: 'No se envió ningún cambio' });
  await db.collection('rotations').doc(req.params.id).update(update);
  const student = await docData('students', r.studentId);
  await logActivity(`Se ajustó el cronograma de la rotación de ${student.nombre} ${student.apellido}.`);
  res.json({ ok: true });
}));

app.post('/api/rotations', auth, requireRole('admin'), h(async (req, res) => {
  const { studentId, sectionId, startDate, endDate, teacherId, empresa, observaciones } = req.body || {};
  if (!studentId || !sectionId || !startDate || !endDate) return res.status(400).json({ error: 'Faltan alumno, sección o fechas' });
  if (startDate > endDate) return res.status(400).json({ error: 'La fecha de inicio no puede ser posterior a la de fin' });
  const student = await docData('students', studentId);
  if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });
  const section = await docData('sections', sectionId);
  if (!section) return res.status(400).json({ error: 'La sección elegida no existe' });
  const existing = await whereEquals('rotations', 'studentId', studentId);
  const maxOrden = existing.reduce((m, r) => Math.max(m, r.orden || 0), 0);
  const id = uid('rot');
  const record = {
    studentId, sectionId, orden: maxOrden + 1, startDate, endDate,
    teacherId: teacherId !== undefined ? teacherId : (section.teacherId || null),
    status: 'pendiente', plan: '', actividades: '', observaciones: observaciones || '',
    empresa: empresa || '', informesSemanales: [], informeFinal: '', calificacion: null,
    comentarios: '', attachmentName: null, attachmentUrl: null, respuestasAlumno: []
  };
  await db.collection('rotations').doc(id).set(record);
  await logActivity(`Se agregó una rotación manual para ${student.nombre} ${student.apellido} en ${section.nombre}.`);
  res.status(201).json({ id, ...record });
}));

app.delete('/api/rotations/:id', auth, requireRole('admin'), h(async (req, res) => {
  const r = await docData('rotations', req.params.id);
  if (!r) return res.status(404).json({ error: 'Rotación no encontrada' });
  const student = await docData('students', r.studentId);
  await db.collection('rotations').doc(req.params.id).delete();
  await logActivity(`Se eliminó una rotación de ${student ? student.nombre + ' ' + student.apellido : 'un alumno'} del cronograma.`);
  res.json({ ok: true });
}));

app.put('/api/students/:id/group', auth, requireRole('admin'), h(async (req, res) => {
  const st = await docData('students', req.params.id);
  if (!st) return res.status(404).json({ error: 'Alumno no encontrado' });
  const { groupId } = req.body || {};
  await db.collection('students').doc(req.params.id).update({ groupId: groupId || null });
  res.json({ ok: true });
}));

app.post('/api/rotations/:id/weekly-report', auth, h(async (req, res) => {
  const r = await docData('rotations', req.params.id);
  if (!r) return res.status(404).json({ error: 'Rotación no encontrada' });
  if (!canEditRotation(req.user, r)) return res.status(403).json({ error: 'No tenés permiso para editar esta rotación' });
  const { semana, texto, fecha, nota, observaciones, ausente, motivo } = req.body || {};
  if (!texto && nota == null && !ausente) return res.status(400).json({ error: 'Cargá al menos el texto del informe, una nota o marcá ausencia' });
  if (nota != null && (nota < 1 || nota > 10)) return res.status(400).json({ error: 'La nota debe estar entre 1 y 10' });
  const nuevo = {
    semana, texto: texto || '', fecha: fecha || todayISO(),
    nota: nota ?? null, observaciones: observaciones || '',
    ausente: !!ausente, profesorId: req.user.teacherId || null, profesorNombre: req.user.nombre
  };
  const existingList = r.informesSemanales || [];
  const existingIdx = existingList.findIndex(e => e.semana === semana);
  const informesSemanales = existingIdx >= 0
    ? existingList.map((e, i) => i === existingIdx ? nuevo : e)
    : [...existingList, nuevo];
  await db.collection('rotations').doc(req.params.id).update({ informesSemanales });
  const student = await docData('students', r.studentId);
  await logActivity(`Se cargó el registro semanal ${semana} de ${student.nombre} ${student.apellido}.`);

  const wasAlreadyAusente = existingIdx >= 0 && existingList[existingIdx].ausente;
  if (ausente && !wasAlreadyAusente) {
    const section = await docData('sections', r.sectionId);
    await db.collection('pendientes').doc(uid('p')).set({
      studentId: r.studentId, sectionId: r.sectionId, teacherId: r.teacherId, semana,
      motivo: motivo || 'Ausente en la semana ' + semana,
      contenido: 'Contenido de la semana ' + semana + (section ? ` (${section.nombre})` : ''),
      estado: 'pendiente', createdAt: new Date().toISOString()
    });
  }
  res.status(201).json({ ok: true });
}));

/* ---------------------------- contenidos pendientes ---------------------------- */
function canTouchPendiente(user, p) {
  if (user.role === 'admin') return true;
  if (user.role === 'seccion') return p.teacherId === user.teacherId;
  return false;
}
app.post('/api/pendientes', auth, h(async (req, res) => {
  const { studentId, sectionId, semana, motivo, contenido } = req.body || {};
  if (!studentId || !sectionId || !motivo) return res.status(400).json({ error: 'Faltan campos obligatorios' });
  const section = await docData('sections', sectionId);
  if (req.user.role === 'seccion' && section && section.teacherId !== req.user.teacherId) {
    return res.status(403).json({ error: 'Solo podés registrar pendientes de tu propia sección' });
  }
  if (req.user.role !== 'admin' && req.user.role !== 'seccion') return res.status(403).json({ error: 'No tenés permiso para esta acción' });
  const id = uid('p');
  await db.collection('pendientes').doc(id).set({
    studentId, sectionId, teacherId: section ? section.teacherId : null, semana: semana || null,
    motivo, contenido: contenido || '', estado: 'pendiente', createdAt: new Date().toISOString()
  });
  const student = await docData('students', studentId);
  await logActivity(`Se registró un contenido pendiente para ${student ? student.nombre + ' ' + student.apellido : 'un alumno'}.`);
  res.status(201).json({ id });
}));

app.put('/api/pendientes/:id', auth, h(async (req, res) => {
  const p = await docData('pendientes', req.params.id);
  if (!p) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!canTouchPendiente(req.user, p)) return res.status(403).json({ error: 'No tenés permiso para editar este registro' });
  const { estado } = req.body || {};
  if (!['pendiente', 'en_recuperacion', 'completado', 'no_recuperado'].includes(estado)) return res.status(400).json({ error: 'Estado inválido' });
  await db.collection('pendientes').doc(req.params.id).update({ estado });
  res.json({ ok: true });
}));

// Registro completo de un recuperatorio (fecha, contenido recuperado, resultado, observaciones).
// Reutiliza el mismo registro de "pendientes" en vez de crear una colección aparte — el pendiente
// y su recuperatorio son la misma entidad en dos momentos distintos.
app.put('/api/pendientes/:id/recuperatorio', auth, requireRole('admin'), h(async (req, res) => {
  const p = await docData('pendientes', req.params.id);
  if (!p) return res.status(404).json({ error: 'Registro no encontrado' });
  const { estadoRecuperacion, fechaRecuperatorio, contenidoRecuperado, actividadRealizada, resultado, observacionesRecuperatorio } = req.body || {};
  if (!['programado', 'recuperado', 'no_recuperado'].includes(estadoRecuperacion)) return res.status(400).json({ error: 'Estado de recuperación inválido' });
  const estadoMap = { programado: 'en_recuperacion', recuperado: 'completado', no_recuperado: 'no_recuperado' };
  await db.collection('pendientes').doc(req.params.id).update({
    estado: estadoMap[estadoRecuperacion],
    recuperatorio: {
      estadoRecuperacion, fechaRecuperatorio: fechaRecuperatorio || null, contenidoRecuperado: contenidoRecuperado || '',
      actividadRealizada: actividadRealizada || '', resultado: resultado || '', observaciones: observacionesRecuperatorio || '',
      registradoPor: req.user.nombre, registradoAt: new Date().toISOString()
    }
  });
  const student = await docData('students', p.studentId);
  await logActivity(`${req.user.nombre} registró un recuperatorio de ${student ? student.nombre + ' ' + student.apellido : 'un alumno'}.`);
  res.json({ ok: true });
}));

app.delete('/api/pendientes/:id', auth, requireRole('admin'), h(async (req, res) => {
  await db.collection('pendientes').doc(req.params.id).delete();
  res.json({ ok: true });
}));

// Nota Final: no existe una fórmula automática ya definida para combinar las calificaciones
// E/MB/B/R/M en un solo valor final, así que (tal como se pidió) no se inventa una — queda
// como un campo que carga manualmente el administrador.
app.put('/api/students/:id/nota-final', auth, requireRole('admin'), h(async (req, res) => {
  const s = await docData('students', req.params.id);
  if (!s) return res.status(404).json({ error: 'Alumno no encontrado' });
  await db.collection('students').doc(req.params.id).update({ notaFinal: req.body.notaFinal || null });
  await logActivity(`Se cargó la nota final de ${s.nombre} ${s.apellido}.`);
  res.json({ ok: true });
}));

/* ---------------------------- Seguimiento de Alumnos (Dashboard ampliado) ----------------------------
   Junta datos que YA existen en otros módulos (rotaciones/cronograma, respuestas semanales del
   alumno, pendientes/recuperatorios, planillas/calificaciones) en una sola vista de seguimiento,
   sin duplicar ni volver a cargar nada de eso a mano. */
function addDaysISO(iso, n) {
  const d = new Date(iso + 'T00:00:00');
  d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}
async function buildSeguimiento(studentId) {
  const student = await docData('students', studentId);
  if (!student) return null;
  const cfgSnap = await db.collection('config').doc('main').get();
  const config = cfgSnap.data();
  const today = todayISO();
  const totalWeeks = config.totalWeeks || 20;

  const rotations = (await whereEquals('rotations', 'studentId', studentId)).sort((a, b) => (a.startDate || '').localeCompare(b.startDate || ''));
  const sections = await allDocs('sections');
  const teachers = await allDocs('teachers');
  const sById = Object.fromEntries(sections.map(s => [s.id, s]));
  const tById = Object.fromEntries(teachers.map(t => [t.id, t]));
  const group = student.groupId ? await docData('groups', student.groupId) : null;

  const current = rotations.find(r => today >= r.startDate && today <= r.endDate)
    || rotations.filter(r => r.startDate <= today).sort((a, b) => b.startDate.localeCompare(a.startDate))[0]
    || rotations.find(r => r.startDate > today) || rotations[rotations.length - 1] || null;

  const pendientes = (await whereEquals('pendientes', 'studentId', studentId)).map(p => ({
    ...p, sectionNombre: p.sectionId && sById[p.sectionId] ? sById[p.sectionId].nombre : null,
    teacherNombre: p.teacherId && tById[p.teacherId] ? tById[p.teacherId].nombre : null
  })).sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  const pendientesPorSemana = {};
  pendientes.forEach(p => { if (p.semana != null) pendientesPorSemana[p.semana] = p; });

  // Semana a semana: la fuente de verdad es fecha de inicio del alumno + duración configurada,
  // igual que currentWeekOf(); acá reconstruimos el rango de cada semana con el mismo criterio.
  const semanas = [];
  for (let wk = 1; wk <= totalWeeks; wk++) {
    const desde = addDaysISO(student.fechaInicio, (wk - 1) * 7);
    const hasta = addDaysISO(student.fechaInicio, wk * 7 - 1);
    const rot = rotations.find(r => desde <= r.endDate && hasta >= r.startDate);
    const pend = pendientesPorSemana[wk];
    let estado;
    if (pend) estado = pend.estado === 'completado' ? 'recuperada' : 'con_pendiente';
    else if (today > hasta) estado = 'completada';
    else if (today >= desde && today <= hasta) estado = 'en_curso';
    else estado = 'futura';
    semanas.push({ numero: wk, desde, hasta, sectionNombre: rot && sById[rot.sectionId] ? sById[rot.sectionId].nombre : null, estado });
  }

  const contenidosPorSemana = [];
  rotations.forEach(r => {
    (r.respuestasAlumno || []).forEach(resp => {
      // Compatibilidad: respuestas viejas guardaban un solo documentoId; las nuevas guardan
      // un array "documentos" (uno por cada archivo que el alumno haya subido esa semana).
      const documentos = resp.documentos || (resp.documentoId ? [{ documentoId: resp.documentoId, documentoNombre: resp.documentoNombre }] : []);
      contenidosPorSemana.push({
        semana: resp.semana, sectionNombre: sById[r.sectionId] ? sById[r.sectionId].nombre : null,
        leido: !!resp.leido, actividadRealizada: !!resp.actividadRealizada,
        documentos, observacion: resp.observacion || '',
        estado: resp.actividadRealizada ? 'completado' : (resp.leido ? 'en_proceso' : 'pendiente')
      });
    });
  });
  contenidosPorSemana.sort((a, b) => (a.semana || 0) - (b.semana || 0));

  const planillas = (await allDocs('planillas')).filter(p => p.studentId === studentId).map(p => ({
    id: p.id, fecha: p.fecha, sectionNombre: p.sectionId && sById[p.sectionId] ? sById[p.sectionId].nombre : (p.entorno || null),
    teacherNombre: p.teacherId && tById[p.teacherId] ? tById[p.teacherId].nombre : null,
    calificacion: p.calificacion || null, observaciones: p.observaciones || ''
  })).sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));

  const semanasCompletadas = semanas.filter(s => s.estado === 'completada' || s.estado === 'recuperada').length;
  const semanasConPendiente = semanas.filter(s => s.estado === 'con_pendiente').length;
  const semanasCursadas = semanas.filter(s => s.estado !== 'futura').length;

  return {
    student: { id: student.id, nombre: student.nombre, apellido: student.apellido, legajo: student.legajo, curso: student.curso, division: student.division, estado: student.estado, notaFinal: student.notaFinal || null },
    curso: student.curso, division: student.division, grupo: group ? group.nombre : null,
    seccionActual: current && sById[current.sectionId] ? sById[current.sectionId].nombre : null,
    profesorMEP: current && current.teacherId && tById[current.teacherId] ? tById[current.teacherId].nombre : null,
    totalWeeks, semanas,
    resumen: {
      semanasCursadas, semanasCompletadas, semanasPendientes: semanasConPendiente,
      porcentajeAvance: totalWeeks ? Math.round(semanasCompletadas / totalWeeks * 100) : 0,
      contenidosRealizados: contenidosPorSemana.filter(c => c.actividadRealizada).length,
      contenidosPendientes: pendientes.filter(p => p.estado !== 'completado').length,
      cantidadRecuperatorios: pendientes.filter(p => p.recuperatorio).length,
      recuperatoriosRecuperados: pendientes.filter(p => p.recuperatorio && p.recuperatorio.estadoRecuperacion === 'recuperado').length
    },
    contenidosPorSemana, pendientes, calificaciones: planillas
  };
}

app.get('/api/seguimiento', auth, requireRole('admin', 'viewadmin', 'coordinador'), h(async (req, res) => {
  const { q, curso, groupId, sectionId } = req.query;
  let students = await allDocs('students');
  if (curso) students = students.filter(s => s.curso === curso);
  if (groupId) students = students.filter(s => s.groupId === groupId);
  if (q) {
    const qq = String(q).toLowerCase();
    students = students.filter(s => (s.nombre + ' ' + s.apellido).toLowerCase().includes(qq) || String(s.legajo || '').toLowerCase().includes(qq));
  }
  if (sectionId) {
    const today = todayISO();
    const allRot = await allDocs('rotations');
    const idsEnSeccion = new Set(allRot.filter(r => r.sectionId === sectionId && today >= r.startDate && today <= r.endDate).map(r => r.studentId));
    students = students.filter(s => idsEnSeccion.has(s.id));
  }
  students.sort((a, b) => {
    const da = String(a.legajo || '').match(/\d+/g), db_ = String(b.legajo || '').match(/\d+/g);
    const na = da ? da.map(d => d.padStart(10, '0')).join('-') : String(a.legajo || '');
    const nb = db_ ? db_.map(d => d.padStart(10, '0')).join('-') : String(b.legajo || '');
    return na.localeCompare(nb);
  });
  const groups = await allDocs('groups');
  const gById = Object.fromEntries(groups.map(g => [g.id, g.nombre]));
  const rotations = await allDocs('rotations');
  const sections = await allDocs('sections');
  const sById = Object.fromEntries(sections.map(s => [s.id, s.nombre]));
  const today = todayISO();
  const resumen = students.map(s => {
    const rots = rotations.filter(r => r.studentId === s.id);
    const current = rots.find(r => today >= r.startDate && today <= r.endDate) || null;
    return {
      id: s.id, nombre: s.nombre, apellido: s.apellido, legajo: s.legajo, curso: s.curso, division: s.division,
      grupo: s.groupId ? gById[s.groupId] : null, seccionActual: current ? sById[current.sectionId] : null, estado: s.estado
    };
  });
  res.json({ alumnos: resumen });
}));

app.get('/api/seguimiento/:studentId', auth, requireRole('admin', 'viewadmin', 'coordinador'), h(async (req, res) => {
  const data = await buildSeguimiento(req.params.studentId);
  if (!data) return res.status(404).json({ error: 'Alumno no encontrado' });
  res.json(data);
}));

/* ---------------------------- config y lineamientos ---------------------------- */

app.put('/api/config', auth, requireRole('admin'), h(async (req, res) => {
  const { notaAprobacion } = req.body || {};
  const n = Number(notaAprobacion);
  if (!n || n < 1 || n > 10) return res.status(400).json({ error: 'La nota de aprobación debe estar entre 1 y 10' });
  await db.collection('config').doc('main').update({ notaAprobacion: n });
  await logActivity('Se actualizó la nota mínima de aprobación.');
  res.json({ ok: true });
}));

app.put('/api/guidelines', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  await db.collection('config').doc('main').update({ lineamientos: req.body.lineamientos || '' });
  await logActivity('Se publicaron nuevos lineamientos generales.');
  res.json({ ok: true });
}));

// Objetivo General POR SECCIÓN: cada entorno productivo (Pasturas, Agricultura, etc.) tiene su
// propio objetivo general independiente, con sus propios materiales (PDF/Word/enlaces). Reemplaza
// el modelo anterior (un solo objetivo general para todo el establecimiento, que no permitía tener
// más de un material a la vez). Reutiliza el mismo patrón de descarga ya probado en /api/documentos.
const OBJETIVOS_GENERALES_COL = 'objetivosGenerales';
async function getOrCreateObjetivoGeneral(sectionId) {
  const existentes = await whereEquals(OBJETIVOS_GENERALES_COL, 'sectionId', sectionId);
  if (existentes.length) return existentes[0];
  const section = await docData('sections', sectionId);
  if (!section) return null;
  const id = uid('objgen');
  const record = { sectionId, sectionName: section.nombre, generalObjective: '', materials: [], updatedAt: new Date().toISOString(), updatedBy: null };
  await db.collection(OBJETIVOS_GENERALES_COL).doc(id).set(record);
  return { id, ...record };
}

app.get('/api/objetivos-generales', auth, blockAlumno, h(async (req, res) => {
  const sections = await allDocs('sections');
  const existentes = await allDocs(OBJETIVOS_GENERALES_COL);
  const bySection = Object.fromEntries(existentes.map(o => [o.sectionId, o]));
  let list = sections.map(s => bySection[s.id] || { id: null, sectionId: s.id, sectionName: s.nombre, generalObjective: '', materials: [] });
  if (req.user.role === 'seccion') list = list.filter(o => o.sectionId === req.user.sectionId);
  res.json({ objetivosGenerales: list });
}));

app.get('/api/objetivos-generales/:sectionId', auth, blockAlumno, h(async (req, res) => {
  const o = await getOrCreateObjetivoGeneral(req.params.sectionId);
  if (!o) return res.status(404).json({ error: 'Sección no encontrada' });
  res.json(o);
}));

app.put('/api/objetivos-generales/:sectionId', auth, requireRole('admin'), h(async (req, res) => {
  const o = await getOrCreateObjetivoGeneral(req.params.sectionId);
  if (!o) return res.status(404).json({ error: 'Sección no encontrada' });
  await db.collection(OBJETIVOS_GENERALES_COL).doc(o.id).update({
    generalObjective: req.body.generalObjective || '', updatedAt: new Date().toISOString(), updatedBy: req.user.nombre
  });
  await logActivity(`Se actualizó el Objetivo General de ${o.sectionName}.`);
  res.json({ ok: true });
}));

// Agrega UN material (no reemplaza los anteriores). Archivo (PDF/Word) o enlace externo (ej. Drive),
// nunca los dos a la vez, y un enlace nunca se sube como si fuera un archivo.
app.post('/api/objetivos-generales/:sectionId/material', auth, requireRole('admin'), upload.single('file'), h(async (req, res) => {
  const o = await getOrCreateObjetivoGeneral(req.params.sectionId);
  if (!o) return res.status(404).json({ error: 'Sección no encontrada' });

  let material;
  if (req.file) {
    if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });
    const ext = extOf(req.file.originalname);
    if (!['.pdf', '.doc', '.docx'].includes(ext)) return res.status(400).json({ error: 'Formato no permitido. Usá PDF, DOC o DOCX.' });
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'fat-manager/objetivos-generales', resource_type: 'raw', public_id: uid('mat') + ext },
        (err, rr) => err ? reject(err) : resolve(rr)
      );
      stream.end(req.file.buffer);
    });
    material = { id: uid('mat'), tipo: ext === '.pdf' ? 'pdf' : 'word', nombre: req.file.originalname, url: result.secure_url, fecha: new Date().toISOString() };
  } else if (req.body.url && req.body.url.trim()) {
    material = { id: uid('mat'), tipo: 'link', nombre: req.body.nombre || 'Enlace', url: req.body.url.trim(), fecha: new Date().toISOString() };
  } else {
    return res.status(400).json({ error: 'Subí un archivo o pegá un enlace' });
  }

  const materials = [...(o.materials || []), material];
  await db.collection(OBJETIVOS_GENERALES_COL).doc(o.id).update({ materials, updatedAt: new Date().toISOString(), updatedBy: req.user.nombre });
  await logActivity(`Se agregó material al Objetivo General de ${o.sectionName}.`);
  res.status(201).json({ material });
}));

app.delete('/api/objetivos-generales/:sectionId/material/:materialId', auth, requireRole('admin'), h(async (req, res) => {
  const o = await getOrCreateObjetivoGeneral(req.params.sectionId);
  if (!o) return res.status(404).json({ error: 'Sección no encontrada' });
  const materials = (o.materials || []).filter(m => m.id !== req.params.materialId);
  await db.collection(OBJETIVOS_GENERALES_COL).doc(o.id).update({ materials, updatedAt: new Date().toISOString(), updatedBy: req.user.nombre });
  res.json({ ok: true });
}));

// Ver/descargar un material — mismo patrón ya probado en /api/documentos/:id/download, así el
// archivo se abre/descarga con el Content-Type y el nombre correctos (en vez de depender
// directamente de la URL cruda de Cloudinary, que es donde fallaba antes).
app.get('/api/objetivos-generales/:sectionId/material/:materialId/download', auth, h(async (req, res) => {
  const o = await getOrCreateObjetivoGeneral(req.params.sectionId);
  if (!o) return res.status(404).json({ error: 'Sección no encontrada' });
  const m = (o.materials || []).find(x => x.id === req.params.materialId);
  if (!m) return res.status(404).json({ error: 'Material no encontrado' });
  if (m.tipo === 'link') return res.redirect(m.url);
  const upstream = await fetch(m.url);
  if (!upstream.ok) return res.status(502).json({ error: 'No se pudo obtener el archivo desde el almacenamiento' });
  const ext = extOf(m.nombre);
  const buffer = Buffer.from(await upstream.arrayBuffer());
  // El navegador no tiene forma de "mostrar" un Word adentro de una pestaña (no hay visor nativo
  // como con el PDF), así que para Word siempre forzamos la descarga — si no, el link de "ver"
  // no hacía nada útil y parecía que estaba roto.
  const disposition = (m.tipo === 'word' || req.query.download === '1') ? 'attachment' : 'inline';
  res.setHeader('Content-Type', DOC_MIME_TYPES[ext] || 'application/octet-stream');
  res.setHeader('Content-Disposition', `${disposition}; filename="${m.nombre}"; filename*=UTF-8''${encodeURIComponent(m.nombre)}`);
  res.send(buffer);
}));


app.post('/api/consignas', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  const id = uid('c');
  await db.collection('consignas').doc(id).set({ texto: req.body.texto });
  await logActivity('Se agregó una nueva consigna.');
  res.status(201).json({ id });
}));
app.delete('/api/consignas/:id', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  await db.collection('consignas').doc(req.params.id).delete();
  res.json({ ok: true });
}));

app.post('/api/objetivos', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  const id = uid('o');
  await db.collection('objetivos').doc(id).set({ semana: req.body.semana, texto: req.body.texto });
  await logActivity(`Se agregó un objetivo para la semana ${req.body.semana}.`);
  res.status(201).json({ id });
}));
app.delete('/api/objetivos/:id', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  await db.collection('objetivos').doc(req.params.id).delete();
  res.json({ ok: true });
}));

/* ---------------------------- Objetivos Semanales (asignación masiva: alumno / grupo(s) / entorno productivo) ---------------------------- */
const OBJETIVOS_SEM_COL = 'objetivosSemanales';
function objetivoAplicaA(o, student, sectionId) {
  if (o.destinoStudentId) return o.destinoStudentId === student.id;
  if (o.destinoGroupIds && o.destinoGroupIds.length && !o.destinoGroupIds.includes(student.groupId)) return false;
  if (o.destinoSectionId && sectionId && o.destinoSectionId !== sectionId) return false;
  if (o.destinoSectionId && !sectionId) return false;
  return true;
}
async function objetivosSemanalesParaAlumno(student, sectionId) {
  const todos = await allDocs(OBJETIVOS_SEM_COL);
  return todos.filter(o => objetivoAplicaA(o, student, sectionId))
    .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
}

async function listarObjetivosSemanales(user) {
  let list = await allDocs(OBJETIVOS_SEM_COL);
  if (user.role === 'seccion') {
    const misSecciones = (await allDocs('sections')).filter(s => s.teacherId === user.teacherId).map(s => s.id);
    list = list.filter(o => !o.destinoSectionId || misSecciones.includes(o.destinoSectionId));
  }
  list.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  const groups = await allDocs('groups');
  const sections = await allDocs('sections');
  const students = await allDocs('students');
  const gById = Object.fromEntries(groups.map(g => [g.id, g.nombre]));
  const sById = Object.fromEntries(sections.map(s => [s.id, s.nombre]));
  const stById = Object.fromEntries(students.map(s => [s.id, s.nombre + ' ' + s.apellido]));
  return list.map(o => ({
    ...o,
    destinoGrupoNombres: (o.destinoGroupIds || []).map(id => gById[id]).filter(Boolean),
    destinoSectionNombre: o.destinoSectionId ? sById[o.destinoSectionId] : null,
    destinoStudentNombre: o.destinoStudentId ? stById[o.destinoStudentId] : null
  }));
}
app.get('/api/objetivos-semanales', auth, blockAlumno, h(async (req, res) => {
  const enriched = await listarObjetivosSemanales(req.user);
  res.json({ objetivosSemanales: enriched });
}));

app.post('/api/objetivos-semanales', auth, requireRole('admin', 'seccion', 'coordinador'), upload.single('file'), h(async (req, res) => {
  const { texto, destinoTipo, destinoStudentId, destinoSectionId } = req.body || {};
  let destinoGroupIds = req.body.destinoGroupIds;
  if (typeof destinoGroupIds === 'string') destinoGroupIds = destinoGroupIds.split(',').map(s => s.trim()).filter(Boolean);
  if (!texto || !texto.trim()) return res.status(400).json({ error: 'El objetivo no puede estar vacío' });
  if (destinoTipo === 'alumno' && !destinoStudentId) return res.status(400).json({ error: 'Elegí un alumno' });
  if ((destinoTipo === 'grupo' || destinoTipo === 'grupos') && (!destinoGroupIds || !destinoGroupIds.length)) return res.status(400).json({ error: 'Elegí al menos un grupo' });
  if (destinoTipo === 'seccion' && !destinoSectionId) return res.status(400).json({ error: 'Elegí un entorno productivo' });
  // Un profesor de sección solo puede asignar objetivos dentro de su propia sección.
  if (req.user.role === 'seccion') {
    const misSecciones = (await allDocs('sections')).filter(s => s.teacherId === req.user.teacherId).map(s => s.id);
    if (destinoSectionId && !misSecciones.includes(destinoSectionId)) return res.status(403).json({ error: 'Solo podés asignar objetivos en tu propia sección' });
  }
  let archivo = null;
  if (req.file) {
    if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });
    const ext = extOf(req.file.originalname);
    if (!['.pdf', '.doc', '.docx'].includes(ext)) return res.status(400).json({ error: 'Formato no permitido. Usá PDF, DOC o DOCX.' });
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'fat-manager/objetivos-semanales', resource_type: 'raw', public_id: uid('objsem') + ext },
        (err, rr) => err ? reject(err) : resolve(rr)
      );
      stream.end(req.file.buffer);
    });
    archivo = { url: result.secure_url, nombre: req.file.originalname };
  }
  const id = uid('osem');
  await db.collection(OBJETIVOS_SEM_COL).doc(id).set({
    texto: texto.trim(),
    destinoStudentId: destinoTipo === 'alumno' ? destinoStudentId : null,
    destinoGroupIds: (destinoTipo === 'grupo' || destinoTipo === 'grupos') ? destinoGroupIds : [],
    destinoSectionId: destinoTipo === 'seccion' ? destinoSectionId : null,
    archivo, createdBy: req.user.sub, createdByNombre: req.user.nombre, createdAt: new Date().toISOString()
  });
  await logActivity(`${req.user.nombre} asignó un objetivo semanal.`);
  res.status(201).json({ id });
}));

app.delete('/api/objetivos-semanales/:id', auth, requireRole('admin', 'seccion', 'coordinador'), h(async (req, res) => {
  const o = await docData(OBJETIVOS_SEM_COL, req.params.id);
  if (!o) return res.status(404).json({ error: 'Objetivo no encontrado' });
  if (req.user.role === 'seccion' && o.createdBy !== req.user.sub) return res.status(403).json({ error: 'Solo podés eliminar los objetivos que vos asignaste' });
  await db.collection(OBJETIVOS_SEM_COL).doc(req.params.id).delete();
  res.json({ ok: true });
}));

/* ---------------------------- Comunicados (lineamientos individuales con destinatarios) ---------------------------- */
function comunicadoVisibleParaProfesor(c, teacherId) {
  return c.destinatarioTipo === 'todos' || (c.destinatarios || []).includes(teacherId);
}
// Recorta el registro para un profesor: solo su propia lectura, nunca la de otros colegas.
function comunicadoParaProfesor(c, teacherId) {
  const { lecturas, ...rest } = c;
  return { ...rest, miLectura: (lecturas || {})[teacherId] || null };
}

app.post('/api/comunicados', auth, requireRole('admin'), upload.array('adjuntos', 5), h(async (req, res) => {
  const { titulo, descripcion, prioridad, destinatarioTipo, vencimiento } = req.body || {};
  if (!titulo) return res.status(400).json({ error: 'El título es obligatorio' });
  if (!['urgente', 'importante', 'informativo'].includes(prioridad)) return res.status(400).json({ error: 'Prioridad inválida' });
  if (!['todos', 'especifico', 'varios'].includes(destinatarioTipo)) return res.status(400).json({ error: 'Destinatario inválido' });
  let destinatarios = [];
  try { destinatarios = req.body.destinatarios ? JSON.parse(req.body.destinatarios) : []; } catch (e) { destinatarios = []; }
  if (destinatarioTipo !== 'todos' && !destinatarios.length) return res.status(400).json({ error: 'Elegí al menos un destinatario' });

  let adjuntos = [];
  if (req.files && req.files.length) {
    if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });
    adjuntos = await Promise.all(req.files.map(f => new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'fat-manager/comunicados', resource_type: 'raw', public_id: uid('adj') + extOf(f.originalname) },
        (err, r) => err ? reject(err) : resolve({ nombre: f.originalname, url: r.secure_url })
      );
      stream.end(f.buffer);
    })));
  }

  const id = uid('com');
  const now = new Date();
  const record = {
    titulo, descripcion: descripcion || '', prioridad, destinatarioTipo,
    destinatarios: destinatarioTipo === 'todos' ? [] : destinatarios,
    vencimiento: vencimiento || null, adjuntos, lecturas: {},
    createdBy: req.user.sub, createdByNombre: req.user.nombre, createdAt: now.toISOString()
  };
  await db.collection('comunicados').doc(id).set(record);
  await logActivity(`${req.user.nombre} envió el lineamiento "${titulo}".`);
  res.status(201).json({ id, ...record });
}));

app.post('/api/comunicados/:id/leido', auth, requireRole('seccion'), h(async (req, res) => {
  const c = await docData('comunicados', req.params.id);
  if (!c) return res.status(404).json({ error: 'Lineamiento no encontrado' });
  if (!comunicadoVisibleParaProfesor(c, req.user.teacherId)) return res.status(403).json({ error: 'Este lineamiento no es para vos' });
  if (!(c.lecturas || {})[req.user.teacherId]) {
    const now = new Date();
    await db.collection('comunicados').doc(req.params.id).update({
      [`lecturas.${req.user.teacherId}`]: { fecha: now.toISOString().slice(0, 10), hora: now.toTimeString().slice(0, 5) }
    });
  }
  res.json({ ok: true });
}));

app.delete('/api/comunicados/:id', auth, requireRole('admin'), h(async (req, res) => {
  await db.collection('comunicados').doc(req.params.id).delete();
  res.json({ ok: true });
}));

/* ---------------------------- Cronograma de Actividades ----------------------------
   Módulo NUEVO e independiente del Cronograma de Rotaciones: registra actividades
   puntuales por día (sección, horario, observaciones), sin tocar la colección
   "rotations" ni sus datos ya cargados. */
app.post('/api/cronograma-actividades', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  const { fecha, sectionId, studentId, tipo, motivo, horaInicio, horaFin, observaciones } = req.body || {};
  if (!fecha || !sectionId) return res.status(400).json({ error: 'Fecha y sección son obligatorias' });
  if (studentId) {
    const student = await docData('students', studentId);
    if (!student) return res.status(400).json({ error: 'El alumno indicado no existe' });
  }
  const id = uid('act');
  const record = {
    fecha, sectionId, studentId: studentId || null, tipo: tipo || null, motivo: motivo || '',
    horaInicio: horaInicio || null, horaFin: horaFin || null, observaciones: observaciones || '',
    createdBy: req.user.sub, createdByNombre: req.user.nombre, createdAt: new Date().toISOString()
  };
  await db.collection('cronogramaActividades').doc(id).set(record);
  if (studentId) {
    const student = await docData('students', studentId);
    await logActivity(`Se registró una excepción para ${student.nombre} ${student.apellido} el ${fecha}.`);
  }
  res.status(201).json({ id, ...record });
}));

app.put('/api/cronograma-actividades/:id', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  const a = await docData('cronogramaActividades', req.params.id);
  if (!a) return res.status(404).json({ error: 'Actividad no encontrada' });
  const { fecha, sectionId, studentId, tipo, motivo, horaInicio, horaFin, observaciones } = req.body || {};
  await db.collection('cronogramaActividades').doc(req.params.id).update({
    fecha: fecha || a.fecha, sectionId: sectionId || a.sectionId,
    studentId: studentId !== undefined ? (studentId || null) : a.studentId,
    tipo: tipo !== undefined ? (tipo || null) : (a.tipo || null),
    motivo: motivo !== undefined ? motivo : (a.motivo || ''),
    horaInicio: horaInicio !== undefined ? (horaInicio || null) : a.horaInicio,
    horaFin: horaFin !== undefined ? (horaFin || null) : a.horaFin,
    observaciones: observaciones !== undefined ? observaciones : a.observaciones
  });
  res.json({ ok: true });
}));

app.delete('/api/cronograma-actividades/:id', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  await db.collection('cronogramaActividades').doc(req.params.id).delete();
  res.json({ ok: true });
}));

// Genera actividades a partir de las rotaciones YA CARGADAS (no crea duplicados si se corre
// más de una vez: por cada día usa una sola actividad por sección, sin importar cuántos
// alumnos estén rotando ahí ese día).
app.post('/api/cronograma-actividades/generar', auth, requireRole('admin', 'coordinador'), h(async (req, res) => {
  const { desde, hasta } = req.body || {};
  if (!desde || !hasta) return res.status(400).json({ error: 'Rango de fechas requerido' });
  const rotations = await allDocs('rotations');
  const existentes = await allDocs('cronogramaActividades');
  const existentesSet = new Set(existentes.map(a => a.fecha + '|' + a.sectionId));

  const nuevas = [];
  let cursor = desde;
  while (cursor <= hasta) {
    const sectionsActivas = new Set(rotations.filter(r => cursor >= r.startDate && cursor <= r.endDate).map(r => r.sectionId));
    sectionsActivas.forEach(sectionId => {
      const key = cursor + '|' + sectionId;
      if (!existentesSet.has(key)) {
        nuevas.push({ fecha: cursor, sectionId });
        existentesSet.add(key);
      }
    });
    cursor = addDays(cursor, 1);
  }

  const now = new Date().toISOString();
  for (let i = 0; i < nuevas.length; i += 400) {
    const chunk = nuevas.slice(i, i + 400);
    const batch = db.batch();
    chunk.forEach(n => {
      const id = uid('act');
      batch.set(db.collection('cronogramaActividades').doc(id), {
        fecha: n.fecha, sectionId: n.sectionId, horaInicio: null, horaFin: null, observaciones: '',
        createdBy: req.user.sub, createdByNombre: req.user.nombre, createdAt: now, generadaDesdeRotaciones: true
      });
    });
    await batch.commit();
  }
  await logActivity(`${req.user.nombre} generó ${nuevas.length} actividades del Cronograma a partir de las rotaciones (${desde} a ${hasta}).`);
  res.json({ creadas: nuevas.length });
}));

/* ---------------------------- portal del alumno (datos acotados a sí mismo) ---------------------------- */
app.get('/api/mi-portal', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const student = await docData('students', studentId);
  if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });

  const rotationsRaw = await whereEquals('rotations', 'studentId', studentId);
  const rotations = rotationsRaw.slice().sort((a, b) => a.orden - b.orden);
  // Fuente única de verdad: la fecha de hoy contra el cronograma (startDate/endDate de cada rotación),
  // nunca un campo "status" cargado a mano — así "Tu Sección Actual" nunca queda desactualizada.
  const today = todayISO();
  let current = rotations.find(r => today >= r.startDate && today <= r.endDate);
  if (!current) {
    // Vacío entre dos rotaciones (o fuera de rango): la última que ya arrancó, si no la próxima, si no la última cargada.
    current = rotations.filter(r => r.startDate <= today).sort((a, b) => b.startDate.localeCompare(a.startDate))[0]
      || rotations.find(r => r.startDate > today)
      || rotations[rotations.length - 1];
  }

  const cfgSnap = await db.collection('config').doc('main').get();
  const config = cfgSnap.data();
  const consignas = await allDocs('consignas');
  const currentSectionId = current ? current.sectionId : null;
  const objetivosSemanales = await objetivosSemanalesParaAlumno(student, currentSectionId);

  const rotationsSummary = await Promise.all(rotations.map(async r => {
    const section = await docData('sections', r.sectionId);
    return {
      id: r.id, orden: r.orden, sectionId: r.sectionId, sectionNombre: section ? section.nombre : '—',
      sectionColor: section ? (section.color || null) : null,
      startDate: r.startDate, endDate: r.endDate, status: r.status
    };
  }));

  let currentDetail = null;
  let objetivoGeneralSeccion = null;
  if (current) {
    const section = await docData('sections', current.sectionId);
    const teacher = current.teacherId ? await docData('teachers', current.teacherId) : null;
    currentDetail = {
      id: current.id, sectionNombre: section ? section.nombre : '—', profesorNombre: teacher ? teacher.nombre : '—',
      startDate: current.startDate, endDate: current.endDate, status: current.status,
      plan: current.plan || '', actividades: current.actividades || '', observaciones: current.observaciones || '',
      informesSemanales: current.informesSemanales || [], respuestasAlumno: current.respuestasAlumno || []
    };
    // El alumno solo ve el Objetivo General de la sección en la que está ahora, nunca el de otras.
    const og = (await whereEquals(OBJETIVOS_GENERALES_COL, 'sectionId', current.sectionId))[0];
    if (og && (og.generalObjective || (og.materials && og.materials.length))) {
      objetivoGeneralSeccion = { sectionId: current.sectionId, sectionName: og.sectionName, generalObjective: og.generalObjective, materials: (og.materials || []).map(m => ({ id: m.id, tipo: m.tipo, nombre: m.nombre })) };
    }
  }

  res.json({
    student: { nombre: student.nombre, apellido: student.apellido, curso: student.curso, division: student.division, legajo: student.legajo, estado: student.estado },
    totalWeeks: config.totalWeeks, semanaActual: student.estado === 'activo' ? currentWeekOf(student, config) : null,
    lineamientos: config.lineamientos, objetivoGeneralSeccion, consignas, objetivosSemanales,
    current: currentDetail, rotaciones: rotationsSummary
  });
}));

function currentWeekOf(student, config) {
  const d = Math.round((new Date(todayISO() + 'T00:00:00') - new Date(student.fechaInicio + 'T00:00:00')) / 86400000);
  const wk = Math.floor(d / 7) + 1;
  return Math.max(1, Math.min(wk, config.totalWeeks));
}
function currentWeekOfDate(student, config, dateISO) {
  const d = Math.round((new Date(dateISO + 'T00:00:00') - new Date(student.fechaInicio + 'T00:00:00')) / 86400000);
  const wk = Math.floor(d / 7) + 1;
  return Math.max(1, Math.min(wk, config.totalWeeks || 999));
}

app.post('/api/mi-portal/respuesta', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const { rotationId, semana, leido, actividadRealizada, observacion } = req.body || {};
  // Antes solo se aceptaba un documento por semana (documentoId, singular). Ahora se acepta
  // una lista (documentoIds) para permitir cargar todos los documentos que hagan falta esa
  // semana, sin reemplazar los ya subidos. Se mantiene compatibilidad si algo viejo todavía
  // manda "documentoId" suelto.
  const idsRecibidos = Array.isArray(req.body.documentoIds) ? req.body.documentoIds : (req.body.documentoId ? [req.body.documentoId] : []);
  const r = await docData('rotations', rotationId);
  if (!r || r.studentId !== studentId) return res.status(403).json({ error: 'No podés responder sobre una rotación que no es tuya' });

  const documentos = [];
  for (const documentoId of idsRecibidos) {
    if (!documentoId) continue;
    const doc = await docData('documentos', documentoId);
    if (!doc || doc.uploadedBy !== req.user.sub || doc.studentId !== studentId) {
      return res.status(403).json({ error: 'Uno de los documentos adjuntos no es válido' });
    }
    await db.collection('documentos').doc(documentoId).update({
      semana, rotationId, sectionId: r.sectionId, estado: 'entregado'
    });
    documentos.push({ documentoId, documentoNombre: doc.nombre });
  }

  const nuevo = {
    semana, leido: !!leido, actividadRealizada: !!actividadRealizada, observacion: observacion || '',
    fecha: todayISO(), documentos
  };
  const existingList = r.respuestasAlumno || [];
  const existingIdx = existingList.findIndex(e => e.semana === semana);
  const respuestasAlumno = existingIdx >= 0
    ? existingList.map((e, i) => i === existingIdx ? nuevo : e)
    : [...existingList, nuevo];
  await db.collection('rotations').doc(rotationId).update({ respuestasAlumno });
  const student = await docData('students', studentId);
  await logActivity(`${student.nombre} ${student.apellido} respondió el seguimiento de la semana ${semana}.`);
  res.status(201).json({ ok: true });
}));

/* ---------------------------- Planillas Digitales FAT (exclusivo admin + profesor de sección) ---------------------------- */
function blockAlumno(req, res, next) {
  if (req.user.role === 'alumno') return res.status(403).json({ error: 'Los alumnos no tienen acceso a este módulo' });
  next();
}

app.get('/api/criterios-desempeno', auth, blockAlumno, h(async (req, res) => {
  const criterios = await allDocs('criteriosDesempeno');
  criterios.sort((a, b) => (a.orden || 0) - (b.orden || 0));
  res.json({ criterios });
}));

app.post('/api/criterios-desempeno', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre del criterio es obligatorio' });
  const existing = await allDocs('criteriosDesempeno');
  const id = uid('crit');
  await db.collection('criteriosDesempeno').doc(id).set({ nombre, orden: existing.length + 1 });
  await logActivity(`Se agregó el criterio de desempeño "${nombre}".`);
  res.status(201).json({ id });
}));

app.put('/api/criterios-desempeno/:id', auth, requireRole('admin'), h(async (req, res) => {
  const c = await docData('criteriosDesempeno', req.params.id);
  if (!c) return res.status(404).json({ error: 'Criterio no encontrado' });
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre del criterio es obligatorio' });
  await db.collection('criteriosDesempeno').doc(req.params.id).update({ nombre });
  res.json({ ok: true });
}));

app.delete('/api/criterios-desempeno/:id', auth, requireRole('admin'), h(async (req, res) => {
  const c = await docData('criteriosDesempeno', req.params.id);
  if (!c) return res.status(404).json({ error: 'Criterio no encontrado' });
  await db.collection('criteriosDesempeno').doc(req.params.id).delete();
  res.json({ ok: true });
}));

function canTouchPlanilla(user, p) {
  if (user.role === 'admin') return true;
  if (user.role === 'seccion') return p.teacherId === user.teacherId;
  return false;
}
function canViewPlanilla(user, p) {
  if (user.role === 'viewadmin') return true;
  return canTouchPlanilla(user, p);
}

app.get('/api/planillas', auth, blockAlumno, h(async (req, res) => {
  let list = await allDocs('planillas');
  if (req.user.role === 'seccion') list = list.filter(p => p.teacherId === req.user.teacherId);
  const { studentId, teacherId, sectionId, desde, hasta } = req.query;
  if (studentId) list = list.filter(p => p.studentId === studentId);
  if (teacherId) list = list.filter(p => p.teacherId === teacherId);
  if (sectionId) list = list.filter(p => p.sectionId === sectionId);
  if (desde) list = list.filter(p => p.fecha >= desde);
  if (hasta) list = list.filter(p => p.fecha <= hasta);
  list.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  res.json({ planillas: list });
}));

app.get('/api/planillas/:id', auth, blockAlumno, h(async (req, res) => {
  const p = await docData('planillas', req.params.id);
  if (!p) return res.status(404).json({ error: 'Planilla no encontrada' });
  if (!canViewPlanilla(req.user, p)) return res.status(403).json({ error: 'No tenés permiso para ver esta planilla' });
  res.json(p);
}));

const ASISTENCIA_LABELS = { presente: 'Presente', ausente: 'Ausente', justificado: 'Justificado', tarde: 'Tarde' };
const CALIFICACION_LABELS = { E: 'E — Excelente', MB: 'MB — Muy Bueno', B: 'B — Bueno', R: 'R — Regular', M: 'M — Mal Logrado' };
const ACCENT_HEX = '2563EB';

function cellText(text, opts) {
  return new TableCell({
    width: { size: opts && opts.width || 50, type: WidthType.PERCENTAGE },
    shading: opts && opts.header ? { type: ShadingType.CLEAR, fill: 'DBEAFE' } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text: String(text == null ? '—' : text), bold: !!(opts && opts.header) })] })]
  });
}
function dataRow(label, value, label2, value2) {
  return new TableRow({ children: [cellText(label, { header: true, width: 22 }), cellText(value, { width: 28 }), cellText(label2, { header: true, width: 22 }), cellText(value2, { width: 28 })] });
}
function fullTable(rows) {
  return new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows, borders: {
    top: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' }, bottom: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' },
    left: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' }, right: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' },
    insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' }, insideVertical: { style: BorderStyle.SINGLE, size: 2, color: 'E5E7EB' }
  }});
}
function sectionHeading(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 260, after: 120 }, children: [new TextRun({ text, color: ACCENT_HEX, bold: true })] });
}
function bodyParagraph(text) {
  return new Paragraph({ spacing: { after: 200 }, children: [new TextRun({ text: text || '—' })] });
}
function slug(text) {
  return String(text || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'documento';
}

async function buildPlanillaDocx(p) {
  const student = await docData('students', p.studentId);
  const section = await docData('sections', p.sectionId);
  const teacher = p.teacherId ? await docData('teachers', p.teacherId) : null;
  const studentLabel = student ? `${student.nombre} ${student.apellido}` : '—';

  const asistenciaRows = [new TableRow({ children: [cellText('Fecha', { header: true, width: 50 }), cellText('Estado', { header: true, width: 50 })] })];
  (p.asistencia || []).slice().sort((a, b) => a.fecha.localeCompare(b.fecha)).forEach(a => {
    asistenciaRows.push(new TableRow({ children: [cellText(a.fecha, { width: 50 }), cellText(ASISTENCIA_LABELS[a.estado] || a.estado, { width: 50 })] }));
  });

  const calificacionRows = [new TableRow({ children: [cellText('Calificación final', { header: true, width: 60 }), cellText(p.calificacion ? (CALIFICACION_LABELS[p.calificacion] || p.calificacion) : '—', { width: 40 })] })];

  const doc = new Document({
    sections: [{
      properties: { page: { margin: { top: 1000, bottom: 1000, left: 1100, right: 1100 } } },
      children: [
        new Paragraph({ children: [new TextRun({ text: 'FAT MANAGER', bold: true, color: ACCENT_HEX, size: 20 })] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { after: 60 }, children: [new TextRun({ text: 'Planilla de Seguimiento FAT', bold: true })] }),
        new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: 'Formación en Ambiente de Trabajo', italics: true, color: '6B7280' })] }),

        fullTable([
          dataRow('Grupo', p.grupo || '—', 'Año', p.anio || '—'),
          dataRow('Estudiante', studentLabel, 'Fecha', p.fecha || '—'),
          dataRow('Docente', teacher ? teacher.nombre : '—', 'Sección', section ? section.nombre : '—')
        ]),

        sectionHeading('Asistencia'),
        (p.asistencia || []).length ? fullTable(asistenciaRows) : bodyParagraph('Sin registros de asistencia.'),

        sectionHeading('Entorno'),
        bodyParagraph(p.entorno),

        sectionHeading('Actividades realizadas'),
        bodyParagraph(p.actividades),

        sectionHeading('Calificación'),
        fullTable(calificacionRows),

        sectionHeading('Observaciones'),
        bodyParagraph(p.observaciones)
      ]
    }]
  });

  const buffer = await Packer.toBuffer(doc);
  const filename = `Planilla_FAT_${slug(studentLabel)}_${p.anio || new Date().getFullYear()}.docx`;
  return { buffer, filename };
}

app.get('/api/planillas/:id/export-docx', auth, blockAlumno, h(async (req, res) => {
  const p = await docData('planillas', req.params.id);
  if (!p) return res.status(404).json({ error: 'Planilla no encontrada' });
  if (!canViewPlanilla(req.user, p)) return res.status(403).json({ error: 'No tenés permiso para exportar esta planilla' });
  const { buffer, filename } = await buildPlanillaDocx(p);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
  res.send(buffer);
}));

app.post('/api/planillas', auth, requireRole('admin', 'seccion'), h(async (req, res) => {
  const { studentId, sectionId, grupo, anio, fecha } = req.body || {};
  if (!studentId || !sectionId) return res.status(400).json({ error: 'Faltan alumno o sección' });
  const section = await docData('sections', sectionId);
  const teacherId = req.user.role === 'seccion' ? req.user.teacherId : (section ? section.teacherId : null);
  if (req.user.role === 'seccion' && section && section.teacherId !== req.user.teacherId) {
    return res.status(403).json({ error: 'Solo podés crear planillas de tu propia sección' });
  }
  const id = uid('pln');
  const now = new Date().toISOString();
  const record = {
    studentId, sectionId, teacherId, grupo: grupo || '', anio: anio || new Date().getFullYear(),
    fecha: fecha || todayISO(), asistencia: [], entorno: '', actividades: '',
    desempeno: {}, observaciones: '', createdBy: req.user.sub, createdByNombre: req.user.nombre,
    createdAt: now, updatedAt: now
  };
  await db.collection('planillas').doc(id).set(record);
  const student = await docData('students', studentId);
  await logActivity(`${req.user.nombre} creó una Planilla Digital FAT para ${student ? student.nombre + ' ' + student.apellido : 'un alumno'}.`);
  res.status(201).json({ id, ...record });
}));

app.put('/api/planillas/:id', auth, h(async (req, res) => {
  const p = await docData('planillas', req.params.id);
  if (!p) return res.status(404).json({ error: 'Planilla no encontrada' });
  if (!canTouchPlanilla(req.user, p)) return res.status(403).json({ error: 'No tenés permiso para editar esta planilla' });
  const { grupo, anio, fecha, asistencia, entorno, actividades, desempeno, calificacion, observaciones } = req.body || {};
  const update = { updatedAt: new Date().toISOString() };
  if (grupo !== undefined) update.grupo = grupo;
  if (anio !== undefined) update.anio = anio;
  if (fecha !== undefined) update.fecha = fecha;
  if (asistencia !== undefined) update.asistencia = asistencia;
  if (entorno !== undefined) update.entorno = entorno;
  if (actividades !== undefined) update.actividades = actividades;
  if (desempeno !== undefined) update.desempeno = desempeno;
  if (calificacion !== undefined) update.calificacion = calificacion;
  if (observaciones !== undefined) update.observaciones = observaciones;
  await db.collection('planillas').doc(req.params.id).update(update);

  // Integración automática: cada ausencia cargada en la Planilla genera (una sola vez)
  // su propio registro en Contenidos Pendientes, sin que el profesor tenga que cargar nada dos veces.
  if (asistencia !== undefined) {
    const ausencias = (asistencia || []).filter(a => a.estado === 'ausente');
    if (ausencias.length) {
      const student = await docData('students', p.studentId);
      const cfgSnap = await db.collection('config').doc('main').get();
      const config = cfgSnap.data();
      const existingPendientes = await whereEquals('pendientes', 'studentId', p.studentId);
      for (const a of ausencias) {
        const yaExiste = existingPendientes.some(pe => pe.sectionId === p.sectionId && pe.fecha === a.fecha);
        if (yaExiste) continue;
        const semana = student ? currentWeekOfDate(student, config, a.fecha) : null;
        const id = uid('p');
        const record = {
          studentId: p.studentId, sectionId: p.sectionId, teacherId: p.teacherId,
          semana, fecha: a.fecha, motivo: 'Ausente el ' + a.fecha + ' (Planilla Digital FAT)',
          contenido: 'Recuperar el contenido de la semana correspondiente a esa fecha',
          estado: 'pendiente', createdAt: new Date().toISOString(), origen: 'planilla', planillaId: p.id
        };
        await db.collection('pendientes').doc(id).set(record);
        existingPendientes.push(record);
      }
      await logActivity(`Se generaron contenidos pendientes automáticos por ausencias cargadas en la Planilla FAT de ${student ? student.nombre + ' ' + student.apellido : 'un alumno'}.`);
    }
  }

  res.json({ ok: true, updatedAt: update.updatedAt });
}));

app.delete('/api/planillas/:id', auth, requireRole('admin'), h(async (req, res) => {
  const p = await docData('planillas', req.params.id);
  if (!p) return res.status(404).json({ error: 'Planilla no encontrada' });
  await db.collection('planillas').doc(req.params.id).delete();
  await logActivity('Se eliminó una Planilla Digital FAT.');
  res.json({ ok: true });
}));

/* =========================================================================
   REGISTRO DIARIO DE ACTIVIDADES (Panel del Alumno + Panel del Administrador)
   Bitácora diaria mobile-first que completa el propio alumno (reemplaza la
   planilla en papel). Es un feature aparte de "Planillas Digitales FAT" de
   arriba (esa la cargan los profesores; esta la carga el alumno día a día).
   No incluye firma digital por pedido explícito.
   ========================================================================= */
const REGISTROS_COL = 'registrosDiarios';
const NOTIFICACIONES_COL = 'notificacionesAlumno';
const REGISTRO_TRASH_DAYS = 30; // ventana para restaurar una planilla eliminada
const ALLOWED_ARCHIVO_EXT = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png'];
function archivoTipoOf(ext) {
  if (ext === '.pdf') return 'pdf';
  if (ext === '.doc' || ext === '.docx') return 'word';
  if (ext === '.jpg' || ext === '.jpeg' || ext === '.png') return 'imagen';
  return 'otro';
}

function canTouchRegistro(user, r) {
  if (user.role === 'admin') return true;
  if (user.role === 'seccion') return r.teacherId === user.teacherId;
  if (user.role === 'alumno') return r.studentId === user.studentId;
  return false;
}
function canViewRegistro(user, r) {
  if (user.role === 'viewadmin' || user.role === 'coordinador') return true;
  return canTouchRegistro(user, r);
}
async function agregarHistorial(id, entry) {
  const r = await docData(REGISTROS_COL, id);
  const historial = [...(r.historial || []), { ...entry, fecha: new Date().toISOString() }];
  await db.collection(REGISTROS_COL).doc(id).update({ historial });
}
async function notificarAlumno(studentId, mensaje, tipo, registroId) {
  const id = uid('notif');
  await db.collection(NOTIFICACIONES_COL).doc(id).set({
    studentId, mensaje, tipo, registroId, leida: false, fecha: new Date().toISOString()
  });
}

// Alumno: trae (o indica que no existe) el registro de una fecha puntual, más los
// datos de encabezado sugeridos (grupo, entorno productivo actual) para precargar el form.
app.get('/api/mi-portal/registros', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const student = await docData('students', studentId);
  if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });

  if (req.query.fecha) {
    const fecha = String(req.query.fecha);
    const existentes = (await whereEquals(REGISTROS_COL, 'studentId', studentId)).filter(r => !r.deletedAt);
    const registro = existentes.find(r => r.fecha === fecha) || null;

    const group = student.groupId ? await docData('groups', student.groupId) : null;
    const rotationsRaw = await whereEquals('rotations', 'studentId', studentId);
    const todayForRot = todayISO();
    const current = rotationsRaw.find(r => todayForRot >= r.startDate && todayForRot <= r.endDate) || null;
    const secciones = (await allDocs('sections')).map(s => ({ id: s.id, nombre: s.nombre }));
    const sectionIdParaObjetivo = registro ? registro.sectionId : (current ? current.sectionId : null);
    const objetivosSemanales = await objetivosSemanalesParaAlumno(student, sectionIdParaObjetivo);

    return res.json({
      registro,
      secciones,
      objetivosSemanales,
      sugerido: {
        alumno: student.nombre + ' ' + student.apellido,
        grupo: group ? group.nombre : null,
        sectionId: current ? current.sectionId : null,
        teacherId: current ? current.teacherId : null
      }
    });
  }

  // Sin ?fecha= -> historial completo del alumno ("Mis Planillas")
  const list = (await whereEquals(REGISTROS_COL, 'studentId', studentId)).filter(r => !r.deletedAt);
  list.sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  res.json({ registros: list.map(r => ({ id: r.id, fecha: r.fecha, sectionId: r.sectionId, sectionNombre: r.sectionNombre, modo: r.modo || 'formulario', cantidadActividades: (r.actividades || []).length, estado: r.estado })) });
}));

app.get('/api/mi-portal/registros/:id', auth, requireRole('alumno'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  const { comentarioPrivado, ...safe } = r; // el comentario privado nunca se expone al alumno
  res.json(safe);
}));

app.post('/api/mi-portal/registros', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const student = await docData('students', studentId);
  if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });
  const { fecha, sectionId, mep, modo } = req.body || {};
  if (!fecha) return res.status(400).json({ error: 'Falta la fecha' });

  const existentes = (await whereEquals(REGISTROS_COL, 'studentId', studentId)).filter(r => !r.deletedAt);
  const dupe = existentes.find(r => r.fecha === fecha);
  if (dupe) return res.status(200).json({ id: dupe.id }); // ya existe: idempotente, devolvemos el mismo

  const section = sectionId ? await docData('sections', sectionId) : null;
  const id = uid('reg');
  const record = {
    studentId, curso: student.curso, division: student.division, groupId: student.groupId || null,
    fecha, sectionId: sectionId || null, sectionNombre: section ? section.nombre : null,
    teacherId: section ? section.teacherId : null, mep: mep || '',
    modo: modo === 'archivo' ? 'archivo' : 'formulario', archivoAdjunto: null,
    actividades: [], datos: '', higieneSeguridad: '', bpa: '',
    estado: 'borrador', observacionesDocente: '', comentarioPrivado: '',
    historial: [{ fecha: new Date().toISOString(), usuario: student.nombre + ' ' + student.apellido, accion: 'creada', detalle: 'Planilla creada' }],
    deletedAt: null, deletedBy: null, lastModifiedBy: { nombre: student.nombre + ' ' + student.apellido, role: 'alumno' },
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  await db.collection(REGISTROS_COL).doc(id).set(record);
  res.status(201).json({ id });
}));

// Autoguardado: el alumno solo puede editar mientras está en borrador o corregida (una vez enviada/aprobada, se congela)
app.put('/api/mi-portal/registros/:id', auth, requireRole('alumno'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!['borrador', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Esta planilla ya fue enviada y no se puede editar' });

  const allowed = ['sectionId', 'mep', 'actividades', 'datos', 'higieneSeguridad', 'bpa', 'modo'];
  const update = { updatedAt: new Date().toISOString() };
  for (const k of allowed) if (req.body && req.body[k] !== undefined) update[k] = req.body[k];
  if (update.sectionId !== undefined) {
    const section = update.sectionId ? await docData('sections', update.sectionId) : null;
    update.sectionNombre = section ? section.nombre : null;
    update.teacherId = section ? section.teacherId : r.teacherId;
  }
  const student = await docData('students', r.studentId);
  update.lastModifiedBy = { nombre: student ? student.nombre + ' ' + student.apellido : 'Alumno', role: 'alumno' };
  await db.collection(REGISTROS_COL).doc(req.params.id).update(update);
  res.json({ ok: true });
}));

app.post('/api/mi-portal/registros/:id/enviar', auth, requireRole('alumno'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!['borrador', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Esta planilla ya fue enviada' });
  if (r.modo === 'archivo' && !r.archivoAdjunto) return res.status(400).json({ error: 'Subí el archivo de tu planilla antes de enviarla' });
  await db.collection(REGISTROS_COL).doc(req.params.id).update({ estado: 'enviada', updatedAt: new Date().toISOString() });
  const student = await docData('students', r.studentId);
  await agregarHistorial(req.params.id, { usuario: student ? student.nombre + ' ' + student.apellido : 'Alumno', accion: 'enviada', detalle: 'El alumno envió la planilla' });
  await logActivity(`${student ? student.nombre + ' ' + student.apellido : 'Un alumno'} envió su planilla diaria del ${r.fecha}.`);
  res.json({ ok: true });
}));

// Foto de evidencia para una actividad puntual (Cloudinary). Devuelve la URL para que el
// frontend la agregue al array "fotos" de esa actividad y la persista con el PUT normal.
app.post('/api/mi-portal/registros/:id/foto', auth, requireRole('alumno'), upload.single('file'), h(async (req, res) => {
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!['borrador', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Esta planilla ya fue enviada y no se puede editar' });
  if (!req.file) return res.status(400).json({ error: 'No se envió ninguna imagen' });
  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager/registros', resource_type: 'image', public_id: uid('foto') },
      (err, rr) => err ? reject(err) : resolve(rr)
    );
    stream.end(req.file.buffer);
  });
  res.status(201).json({ url: result.secure_url, publicId: result.public_id, nombre: req.file.originalname });
}));

// Opción 2 del alumno: subir una planilla ya realizada (PDF/DOC/DOCX/JPG/PNG) en vez de completarla en el formulario.
app.post('/api/mi-portal/registros/:id/archivo', auth, requireRole('alumno'), upload.single('file'), h(async (req, res) => {
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!['borrador', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Esta planilla ya fue enviada y no se puede editar' });
  if (!req.file) return res.status(400).json({ error: 'No se envió ningún archivo' });
  const ext = extOf(req.file.originalname);
  if (!ALLOWED_ARCHIVO_EXT.includes(ext)) return res.status(400).json({ error: 'Formato no permitido. Usá PDF, DOC, DOCX, JPG o PNG.' });
  const tipo = archivoTipoOf(ext);
  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager/registros-archivos', resource_type: tipo === 'imagen' ? 'image' : 'raw', public_id: uid('planilla') + ext },
      (err, rr) => err ? reject(err) : resolve(rr)
    );
    stream.end(req.file.buffer);
  });
  const archivoAdjunto = { url: result.secure_url, publicId: result.public_id, nombre: req.file.originalname, tamano: req.file.size, tipo };
  await db.collection(REGISTROS_COL).doc(req.params.id).update({ archivoAdjunto, updatedAt: new Date().toISOString() });
  res.status(201).json({ archivoAdjunto });
}));

// Reemplazar o quitar el archivo adjunto antes de enviar la planilla.
app.delete('/api/mi-portal/registros/:id/archivo', auth, requireRole('alumno'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || r.studentId !== req.user.studentId || r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!['borrador', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Esta planilla ya fue enviada y no se puede editar' });
  await db.collection(REGISTROS_COL).doc(req.params.id).update({ archivoAdjunto: null, updatedAt: new Date().toISOString() });
  res.json({ ok: true });
}));

/* ---------------------------- Notificaciones del alumno ---------------------------- */
app.get('/api/mi-portal/notificaciones', auth, requireRole('alumno'), h(async (req, res) => {
  const list = await whereEquals(NOTIFICACIONES_COL, 'studentId', req.user.studentId);
  list.sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  res.json({ notificaciones: list.slice(0, 30) });
}));
app.post('/api/mi-portal/notificaciones/:id/leida', auth, requireRole('alumno'), h(async (req, res) => {
  const n = await docData(NOTIFICACIONES_COL, req.params.id);
  if (!n || n.studentId !== req.user.studentId) return res.status(404).json({ error: 'Notificación no encontrada' });
  await db.collection(NOTIFICACIONES_COL).doc(req.params.id).update({ leida: true });
  res.json({ ok: true });
}));

/* ---------------------------- Panel del Docente / Administrador: gestión de registros diarios ---------------------------- */
app.get('/api/registros', auth, blockAlumno, h(async (req, res) => {
  let list = await allDocs(REGISTROS_COL);
  const papelera = req.query.papelera === '1';
  if (papelera && req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede ver la papelera' });
  list = list.filter(r => papelera ? !!r.deletedAt : !r.deletedAt);
  list = list.filter(r => r.estado !== 'borrador'); // los borradores solo los ve el alumno que los creó
  if (req.user.role === 'seccion') list = list.filter(r => r.teacherId === req.user.teacherId);
  const { curso, groupId, studentId, sectionId, fecha, estado } = req.query;
  if (curso) list = list.filter(r => r.curso === curso);
  if (groupId) list = list.filter(r => r.groupId === groupId);
  if (studentId) list = list.filter(r => r.studentId === studentId);
  if (sectionId) list = list.filter(r => r.sectionId === sectionId);
  if (fecha) list = list.filter(r => r.fecha === fecha);
  if (estado) list = list.filter(r => r.estado === estado);
  list.sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const students = await allDocs('students');
  const byId = Object.fromEntries(students.map(s => [s.id, s]));
  const enriched = list.map(r => {
    const s = byId[r.studentId];
    return { ...r, actividades: undefined, comentarioPrivado: undefined, cantidadActividades: (r.actividades || []).length, studentNombre: s ? s.nombre + ' ' + s.apellido : '—' };
  });
  res.json({ registros: enriched });
}));

app.get('/api/registros/:id', auth, blockAlumno, h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r) return res.status(404).json({ error: 'Registro no encontrado' });
  if (r.estado === 'borrador') return res.status(403).json({ error: 'Los borradores solo son visibles para el alumno que los creó' });
  if (!canViewRegistro(req.user, r)) return res.status(403).json({ error: 'No tenés permiso para ver este registro' });
  const student = await docData('students', r.studentId);
  res.json({ ...r, studentNombre: student ? student.nombre + ' ' + student.apellido : '—' });
}));

// Edición completa por parte del administrador (cualquier campo, cualquier planilla).
app.put('/api/registros/:id', auth, requireRole('admin'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r) return res.status(404).json({ error: 'Registro no encontrado' });
  const allowed = ['sectionId', 'mep', 'actividades', 'datos', 'higieneSeguridad', 'bpa', 'estado'];
  const update = { updatedAt: new Date().toISOString(), lastModifiedBy: { nombre: req.user.nombre, role: req.user.role } };
  for (const k of allowed) if (req.body && req.body[k] !== undefined) update[k] = req.body[k];
  if (update.sectionId !== undefined) {
    const section = update.sectionId ? await docData('sections', update.sectionId) : null;
    update.sectionNombre = section ? section.nombre : null;
  }
  await db.collection(REGISTROS_COL).doc(req.params.id).update(update);
  await agregarHistorial(req.params.id, { usuario: req.user.nombre, accion: 'editada', detalle: 'El administrador editó la planilla' });
  res.json({ ok: true });
}));

// Comentarios: uno privado (solo docentes/admin) y uno visible para el alumno.
app.post('/api/registros/:id/comentario', auth, requireRole('admin', 'seccion', 'coordinador'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!canTouchRegistro(req.user, r) && req.user.role !== 'coordinador') return res.status(403).json({ error: 'No tenés permiso sobre este registro' });
  const { texto, privado } = req.body || {};
  if (!texto || !texto.trim()) return res.status(400).json({ error: 'El comentario no puede estar vacío' });
  const update = { updatedAt: new Date().toISOString() };
  if (privado) update.comentarioPrivado = texto;
  else update.observacionesDocente = texto;
  await db.collection(REGISTROS_COL).doc(req.params.id).update(update);
  await agregarHistorial(req.params.id, { usuario: req.user.nombre, accion: privado ? 'comentario privado' : 'comentario para el alumno', detalle: texto });
  res.json({ ok: true });
}));

app.put('/api/registros/:id/revisar', auth, requireRole('admin', 'seccion', 'coordinador'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r) return res.status(404).json({ error: 'Registro no encontrado' });
  if (!canTouchRegistro(req.user, r) && req.user.role !== 'coordinador') return res.status(403).json({ error: 'No tenés permiso para revisar este registro' });
  const { estado, observacionesDocente } = req.body || {};
  if (!['en_revision', 'corregida', 'aprobada', 'rechazada'].includes(estado)) return res.status(400).json({ error: 'Estado inválido' });
  if (!['enviada', 'en_revision', 'corregida'].includes(r.estado)) return res.status(403).json({ error: 'Solo se pueden revisar planillas enviadas' });
  const update = { estado, updatedAt: new Date().toISOString(), lastModifiedBy: { nombre: req.user.nombre, role: req.user.role } };
  if (observacionesDocente !== undefined) update.observacionesDocente = observacionesDocente;
  await db.collection(REGISTROS_COL).doc(req.params.id).update(update);
  const student = await docData('students', r.studentId);
  const nombreCompleto = student ? student.nombre + ' ' + student.apellido : 'un alumno';
  const etiqueta = { en_revision: 'puso en revisión', corregida: 'pidió correcciones a', aprobada: 'aprobó', rechazada: 'rechazó' }[estado];
  await agregarHistorial(req.params.id, { usuario: req.user.nombre, accion: estado, detalle: observacionesDocente || '' });
  await logActivity(`${req.user.nombre} ${etiqueta} la planilla diaria de ${nombreCompleto} del ${r.fecha}.`);
  if (['aprobada', 'rechazada', 'corregida'].includes(estado)) {
    const mensajes = {
      aprobada: `Tu planilla del ${fmtDateEs(r.fecha)} fue aprobada.`,
      rechazada: `Tu planilla del ${fmtDateEs(r.fecha)} fue rechazada.`,
      corregida: `Te pidieron corregir la planilla del ${fmtDateEs(r.fecha)}.`
    };
    await notificarAlumno(r.studentId, mensajes[estado], estado, req.params.id);
  }
  res.json({ ok: true });
}));
function fmtDateEs(iso) {
  if (!iso) return '';
  const [y, m, d] = iso.split('-');
  return `${d}/${m}/${y}`;
}

// Eliminar (papelera, con restauración durante REGISTRO_TRASH_DAYS días) — solo admin.
app.delete('/api/registros/:id', auth, requireRole('admin'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r) return res.status(404).json({ error: 'Registro no encontrado' });
  await db.collection(REGISTROS_COL).doc(req.params.id).update({ deletedAt: new Date().toISOString(), deletedBy: { nombre: req.user.nombre } });
  await agregarHistorial(req.params.id, { usuario: req.user.nombre, accion: 'eliminada', detalle: `Enviada a la papelera (se puede restaurar hasta ${REGISTRO_TRASH_DAYS} días)` });
  await logActivity(`${req.user.nombre} eliminó una planilla diaria (enviada a la papelera).`);
  res.json({ ok: true });
}));

app.post('/api/registros/:id/restaurar', auth, requireRole('admin'), h(async (req, res) => {
  const r = await docData(REGISTROS_COL, req.params.id);
  if (!r || !r.deletedAt) return res.status(404).json({ error: 'Registro no encontrado en la papelera' });
  const dias = (Date.now() - new Date(r.deletedAt).getTime()) / 86400000;
  if (dias > REGISTRO_TRASH_DAYS) return res.status(410).json({ error: `Ya pasaron más de ${REGISTRO_TRASH_DAYS} días, esta planilla ya no se puede restaurar` });
  await db.collection(REGISTROS_COL).doc(req.params.id).update({ deletedAt: null, deletedBy: null });
  await agregarHistorial(req.params.id, { usuario: req.user.nombre, accion: 'restaurada', detalle: 'Restaurada desde la papelera' });
  res.json({ ok: true });
}));

/* ---------------------------- Gestión de Usuarios: administra cuentas VIEW ADMIN (solo el admin) ---------------------------- */
app.get('/api/usuarios', auth, requireRole('admin'), h(async (req, res) => {
  const users = await allDocs('users');
  const viewAdmins = users.filter(u => u.role === 'viewadmin')
    .map(u => ({ id: u.id, username: u.username, nombre: u.nombre, active: u.active !== false }));

  res.json({ usuarios: viewAdmins });
}));

app.post('/api/usuarios', auth, requireRole('admin'), h(async (req, res) => {
  const { nombre, username, password } = req.body || {};
  if (!nombre || !username || !password) return res.status(400).json({ error: 'Faltan campos obligatorios' });
  const dupe = await whereEquals('users', 'username', username);
  if (dupe.length) return res.status(409).json({ error: 'Ese usuario ya existe' });
  const id = uid('u');
  await db.collection('users').doc(id).set({
    username, passwordHash: bcrypt.hashSync(password, 10), role: 'viewadmin', nombre,
    teacherId: null, sectionId: null, studentId: null, active: true
  });
  await logActivity(`Se creó el usuario de solo lectura (VIEW ADMIN) "${nombre}".`);
  res.status(201).json({ id });
}));

app.put('/api/usuarios/:id', auth, requireRole('admin'), h(async (req, res) => {
  const u = await docData('users', req.params.id);
  if (!u || u.role !== 'viewadmin') return res.status(404).json({ error: 'Usuario VIEW ADMIN no encontrado' });
  const { nombre, username, password, active } = req.body || {};
  const update = {};
  if (nombre !== undefined) update.nombre = nombre;
  if (username !== undefined) {
    const dupe = await whereEquals('users', 'username', username);
    if (dupe.length && dupe[0].id !== req.params.id) return res.status(409).json({ error: 'Ese usuario ya existe' });
    update.username = username;
  }
  if (password) update.passwordHash = bcrypt.hashSync(password, 10);
  if (active !== undefined) update.active = !!active;
  await db.collection('users').doc(req.params.id).update(update);
  await logActivity(`Se actualizó el usuario VIEW ADMIN "${nombre || u.nombre}".`);
  res.json({ ok: true });
}));

app.delete('/api/usuarios/:id', auth, requireRole('admin'), h(async (req, res) => {
  const u = await docData('users', req.params.id);
  if (!u || u.role !== 'viewadmin') return res.status(404).json({ error: 'Usuario VIEW ADMIN no encontrado' });
  await db.collection('users').doc(req.params.id).delete();
  await logActivity(`Se eliminó el usuario VIEW ADMIN "${u.nombre}".`);
  res.json({ ok: true });
}));

app.get('/health', h(async (req, res) => {
  await db.collection('config').doc('main').get();
  res.json({ ok: true, db: 'firestore', cloudinary: CLOUDINARY_READY, time: new Date().toISOString() });
}));

ensureSeed()
  .then(() => app.listen(PORT, () => console.log(`[server] FAT Manager API real corriendo en http://localhost:${PORT}`)))
  .catch(err => { console.error('[server] No se pudo inicializar Firestore:', err.message); process.exit(1); });

module.exports = app;
