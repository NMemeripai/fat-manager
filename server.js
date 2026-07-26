require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { db, uid, todayISO, logActivity, getActivityLog, getSectionsOrdered, recomputeTotalWeeks, generateRotationsFor, ensureSeed } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'fat-manager-dev-secret-change-in-production';
const PORT = process.env.PORT || 3001;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const CLOUDINARY_READY = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
app.post('/api/auth/login', h(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  const matches = await whereEquals('users', 'username', username.trim());
  // Firestore no hace comparaciones case-insensitive nativas; buscamos también en minúsculas por si acaso.
  const u = matches[0] || (await whereEquals('users', 'username', username.trim().toLowerCase()))[0];
  if (!u || !bcrypt.compareSync(password, u.passwordHash)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
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
  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager', resource_type: 'auto', public_id: uid('doc') },
      (err, r) => err ? reject(err) : resolve(r)
    );
    stream.end(req.file.buffer);
  });
  res.status(201).json({ url: result.secure_url, name: req.file.originalname });
}));

/* ---------------------------- Centro de Documentos ---------------------------- */
const ALLOWED_DOC_EXT = ['.pdf', '.doc', '.docx'];
function extOf(filename) {
  const i = filename.lastIndexOf('.');
  return i >= 0 ? filename.slice(i).toLowerCase() : '';
}

app.post('/api/documentos', auth, upload.single('file'), h(async (req, res) => {
  if (!['admin', 'seccion', 'alumno'].includes(req.user.role)) return res.status(403).json({ error: 'No tenés permiso para subir documentos' });
  if (!req.file) return res.status(400).json({ error: 'No se envió ningún archivo' });
  const ext = extOf(req.file.originalname);
  if (!ALLOWED_DOC_EXT.includes(ext)) return res.status(400).json({ error: 'Formato no permitido. Solo se aceptan .pdf, .doc y .docx' });
  if (!CLOUDINARY_READY) return res.status(503).json({ error: 'Cloudinary no está configurado en el servidor.' });

  let tipo, studentId = null, curso = null;
  if (req.user.role === 'alumno') {
    tipo = 'alumno';
    studentId = req.user.studentId;
    const st = await docData('students', studentId);
    curso = st ? (st.curso + ' "' + st.division + '"') : null;
  } else if (req.user.role === 'seccion') {
    tipo = 'mep';
    studentId = req.body.studentId || null;
  } else {
    tipo = req.body.tipo === 'alumno' ? 'alumno' : 'mep';
    studentId = req.body.studentId || null;
  }

  const result = await new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'fat-manager/documentos', resource_type: 'raw', public_id: uid('file') },
      (err, r) => err ? reject(err) : resolve(r)
    );
    stream.end(req.file.buffer);
  });

  const now = new Date();
  const id = uid('doc');
  const docRecord = {
    tipo, nombre: req.file.originalname, url: result.secure_url,
    uploadedBy: req.user.sub, uploadedByNombre: req.user.nombre, uploadedByRole: req.user.role,
    studentId, curso, observaciones: req.body.observaciones || '',
    fecha: now.toISOString().slice(0, 10), hora: now.toTimeString().slice(0, 5),
    createdAt: now.toISOString()
  };
  await db.collection('documentos').doc(id).set(docRecord);
  await logActivity(`${req.user.nombre} subió el documento "${req.file.originalname}".`);
  res.status(201).json({ id, ...docRecord });
}));

app.get('/api/documentos', auth, requireRole('admin'), h(async (req, res) => {
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
  const cfgSnap = await db.collection('config').doc('main').get();
  const config = cfgSnap.data();
  const teachers = await allDocs('teachers');
  const sections = (await allDocs('sections')).sort((a, b) => a.orden - b.orden);
  const students = await allDocs('students');
  const rotations = await allDocs('rotations');
  const consignas = await allDocs('consignas');
  const objetivos = await allDocs('objetivos');
  const groups = await allDocs('groups');
  const pendientes = await allDocs('pendientes');
  const activityLog = await getActivityLog(40);
  const users = (await allDocs('users')).map(u => ({ id: u.id, username: u.username, role: u.role, nombre: u.nombre, teacherId: u.teacherId, sectionId: u.sectionId, studentId: u.studentId || null }));
  res.json({ config, teachers, sections, students, rotations, consignas, objetivos, groups, pendientes, activityLog, users });
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
  const { nombre, teacherId, weeks } = req.body || {};
  if (!nombre) return res.status(400).json({ error: 'El nombre de la sección es obligatorio' });
  const existing = await getSectionsOrdered();
  const id = uid('s');
  await db.collection('sections').doc(id).set({
    nombre, teacherId: teacherId || null, orden: existing.length + 1, weeks: Number(weeks) || 5
  });
  await recomputeTotalWeeks();
  await logActivity(`Se creó la sección ${nombre}.`);
  res.status(201).json({ id });
}));

app.put('/api/sections/:id', auth, requireRole('admin'), h(async (req, res) => {
  const sec = await docData('sections', req.params.id);
  if (!sec) return res.status(404).json({ error: 'Sección no encontrada' });
  const { nombre, teacherId, weeks } = req.body || {};
  await db.collection('sections').doc(req.params.id).update({
    nombre, teacherId: teacherId || null, weeks: weeks != null ? (Number(weeks) || 5) : (sec.weeks || 5)
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
  if (!['pendiente', 'en_recuperacion', 'completado'].includes(estado)) return res.status(400).json({ error: 'Estado inválido' });
  await db.collection('pendientes').doc(req.params.id).update({ estado });
  res.json({ ok: true });
}));

app.delete('/api/pendientes/:id', auth, requireRole('admin'), h(async (req, res) => {
  await db.collection('pendientes').doc(req.params.id).delete();
  res.json({ ok: true });
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

/* ---------------------------- portal del alumno (datos acotados a sí mismo) ---------------------------- */
app.get('/api/mi-portal', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const student = await docData('students', studentId);
  if (!student) return res.status(404).json({ error: 'Alumno no encontrado' });

  const rotationsRaw = await whereEquals('rotations', 'studentId', studentId);
  const rotations = rotationsRaw.slice().sort((a, b) => a.orden - b.orden);
  const current = rotations.find(r => r.status === 'en_curso') || rotations.find(r => r.status !== 'finalizada') || rotations[rotations.length - 1];

  const cfgSnap = await db.collection('config').doc('main').get();
  const config = cfgSnap.data();
  const consignas = await allDocs('consignas');
  const objetivos = await allDocs('objetivos');

  const rotationsSummary = await Promise.all(rotations.map(async r => {
    const section = await docData('sections', r.sectionId);
    return {
      id: r.id, orden: r.orden, sectionNombre: section ? section.nombre : '—',
      startDate: r.startDate, endDate: r.endDate, status: r.status
    };
  }));

  let currentDetail = null;
  if (current) {
    const section = await docData('sections', current.sectionId);
    const teacher = current.teacherId ? await docData('teachers', current.teacherId) : null;
    currentDetail = {
      id: current.id, sectionNombre: section ? section.nombre : '—', profesorNombre: teacher ? teacher.nombre : '—',
      startDate: current.startDate, endDate: current.endDate, status: current.status,
      plan: current.plan || '', actividades: current.actividades || '', observaciones: current.observaciones || '',
      informesSemanales: current.informesSemanales || [], respuestasAlumno: current.respuestasAlumno || []
    };
  }

  res.json({
    student: { nombre: student.nombre, apellido: student.apellido, curso: student.curso, division: student.division, legajo: student.legajo, estado: student.estado },
    totalWeeks: config.totalWeeks, semanaActual: student.estado === 'activo' ? currentWeekOf(student, config) : null,
    lineamientos: config.lineamientos, consignas, objetivos,
    current: currentDetail, rotaciones: rotationsSummary
  });
}));

function currentWeekOf(student, config) {
  const d = Math.round((new Date(todayISO() + 'T00:00:00') - new Date(student.fechaInicio + 'T00:00:00')) / 86400000);
  const wk = Math.floor(d / 7) + 1;
  return Math.max(1, Math.min(wk, config.totalWeeks));
}

app.post('/api/mi-portal/respuesta', auth, requireRole('alumno'), h(async (req, res) => {
  const studentId = req.user.studentId;
  if (!studentId) return res.status(400).json({ error: 'Esta cuenta no está vinculada a ningún alumno' });
  const { rotationId, semana, leido, actividadRealizada, observacion } = req.body || {};
  const r = await docData('rotations', rotationId);
  if (!r || r.studentId !== studentId) return res.status(403).json({ error: 'No podés responder sobre una rotación que no es tuya' });
  const nuevo = { semana, leido: !!leido, actividadRealizada: !!actividadRealizada, observacion: observacion || '', fecha: todayISO() };
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

app.get('/health', h(async (req, res) => {
  await db.collection('config').doc('main').get();
  res.json({ ok: true, db: 'firestore', cloudinary: CLOUDINARY_READY, time: new Date().toISOString() });
}));

ensureSeed()
  .then(() => app.listen(PORT, () => console.log(`[server] FAT Manager API real corriendo en http://localhost:${PORT}`)))
  .catch(err => { console.error('[server] No se pudo inicializar Firestore:', err.message); process.exit(1); });

module.exports = app;
