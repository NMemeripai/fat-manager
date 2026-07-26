const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const { randomUUID } = require('crypto');

/* ---------------------------- credenciales de Firebase ---------------------------- */
function loadServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    try { return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON); }
    catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON no es un JSON válido: ' + e.message); }
  }
  const filePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || path.join(__dirname, 'serviceAccountKey.json');
  if (fs.existsSync(filePath)) return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return null;
}

const serviceAccount = loadServiceAccount();
if (!serviceAccount) {
  console.error('[db] Falta la credencial de Firebase.');
  console.error('[db] Poné el archivo "serviceAccountKey.json" en esta carpeta, o definí FIREBASE_SERVICE_ACCOUNT_JSON en el .env.');
  process.exit(1);
}

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/* ---------------------------- helpers generales ---------------------------- */
function uid(prefix) { return prefix + '_' + randomUUID().slice(0, 8); }
function todayISO() { return new Date().toISOString().slice(0, 10); }
function addDays(iso, n) { const d = new Date(iso + 'T00:00:00'); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); }

async function logActivity(text) {
  await db.collection('activityLog').add({ text, ts: new Date().toISOString() });
}

async function getActivityLog(limit = 40) {
  const snap = await db.collection('activityLog').orderBy('ts', 'desc').limit(limit).get();
  return snap.docs.map(d => ({ text: d.data().text, ts: d.data().ts }));
}

/* ---------------------------- generación de rotaciones ---------------------------- */
async function getSectionsOrdered() {
  const snap = await db.collection('sections').orderBy('orden').get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function recomputeTotalWeeks() {
  const sections = await getSectionsOrdered();
  const totalWeeks = sections.reduce((sum, s) => sum + (s.weeks || 5), 0) || 20;
  await db.collection('config').doc('main').update({ totalWeeks });
  return totalWeeks;
}

async function generateRotationsFor(student) {
  const sections = await getSectionsOrdered();
  let cursor = student.fechaInicio;
  const rows = [];
  sections.forEach((section, idx) => {
    const dur = section.weeks || 5;
    const start = cursor;
    const end = addDays(start, dur * 7 - 1);
    cursor = addDays(end, 1);
    rows.push({
      id: uid('rot'), studentId: student.id, sectionId: section.id, orden: idx + 1,
      startDate: start, endDate: end, teacherId: section.teacherId || null,
      status: 'pendiente', plan: '', actividades: '', observaciones: '',
      informesSemanales: [], informeFinal: '', calificacion: null, comentarios: '',
      attachmentName: null, attachmentUrl: null, respuestasAlumno: [], empresa: ''
    });
  });
  const batch = db.batch();
  rows.forEach(r => batch.set(db.collection('rotations').doc(r.id), r));
  await batch.commit();
  return rows;
}

/* ---------------------------- semilla inicial y migraciones ---------------------------- */
async function migrateSectionsWeeksField() {
  const sections = await getSectionsOrdered();
  let changed = false;
  for (const s of sections) {
    if (s.weeks == null) {
      await db.collection('sections').doc(s.id).update({ weeks: 5 });
      changed = true;
    }
  }
  if (changed) await recomputeTotalWeeks();

  const cfgSnap = await db.collection('config').doc('main').get();
  if (cfgSnap.exists && cfgSnap.data().notaAprobacion == null) {
    await db.collection('config').doc('main').update({ notaAprobacion: 6 });
  }

  const existingCriterios = await db.collection('criteriosDesempeno').get();
  if (existingCriterios.empty) {
    const criteriosDefault = ['Puntualidad', 'Responsabilidad', 'Trabajo en equipo', 'Iniciativa', 'Calidad del trabajo', 'Comunicación', 'Adaptación al entorno laboral'];
    const critBatch = db.batch();
    criteriosDefault.forEach((nombre, idx) => critBatch.set(db.collection('criteriosDesempeno').doc(uid('crit')), { nombre, orden: idx + 1 }));
    await critBatch.commit();
  }
}

async function ensureSeed() {
  const cfgSnap = await db.collection('config').doc('main').get();
  if (cfgSnap.exists) {
    console.log('[db] Usando base de datos Firestore existente (los datos ya estaban cargados).');
    await migrateSectionsWeeksField();
    return;
  }

  console.log('[db] Base de datos nueva detectada, insertando datos semilla…');

  const teacherCoord = { id: uid('t'), nombre: 'María Gómez', rol: 'coordinador' };
  const teacherA = { id: uid('t'), nombre: 'Carlos Ibáñez', rol: 'seccion' };
  const teacherB = { id: uid('t'), nombre: 'Lucía Ferrero', rol: 'seccion' };
  const teacherC = { id: uid('t'), nombre: 'Diego Salvatierra', rol: 'seccion' };
  const teacherD = { id: uid('t'), nombre: 'Romina Paz', rol: 'seccion' };
  const teacherBatch = db.batch();
  [teacherCoord, teacherA, teacherB, teacherC, teacherD].forEach(t =>
    teacherBatch.set(db.collection('teachers').doc(t.id), { nombre: t.nombre, rol: t.rol }));
  await teacherBatch.commit();

  const secA = { id: uid('s'), nombre: 'Administración', teacherId: teacherA.id, orden: 1, weeks: 5 };
  const secB = { id: uid('s'), nombre: 'Atención al Público', teacherId: teacherB.id, orden: 2, weeks: 5 };
  const secC = { id: uid('s'), nombre: 'Producción / Taller', teacherId: teacherC.id, orden: 3, weeks: 5 };
  const secD = { id: uid('s'), nombre: 'Ventas y Marketing', teacherId: teacherD.id, orden: 4, weeks: 5 };
  const sectionBatch = db.batch();
  [secA, secB, secC, secD].forEach(s =>
    sectionBatch.set(db.collection('sections').doc(s.id), { nombre: s.nombre, teacherId: s.teacherId, orden: s.orden, weeks: s.weeks }));
  await sectionBatch.commit();

  const cfg = {
    totalWeeks: 20,
    notaAprobacion: 6,
    lineamientos: 'El proyecto FAT (Formación en Ambiente de Trabajo) tiene como objetivo que el estudiante transite experiencias reales de trabajo, rotando por las distintas secciones de la institución asociada, desarrollando competencias técnicas y actitudinales.'
  };
  await db.collection('config').doc('main').set(cfg);

  const mkHash = (pw) => bcrypt.hashSync(pw, 10);
  const userBatch = db.batch();
  const mkUser = (username, password, role, nombre, teacherId, sectionId) =>
    userBatch.set(db.collection('users').doc(uid('u')), {
      username, passwordHash: mkHash(password), role, nombre,
      teacherId: teacherId || null, sectionId: sectionId || null
    });
  mkUser('admin', 'admin2026', 'admin', 'Administrador FAT', null, null);
  mkUser('coordinador', 'coord2026', 'coordinador', teacherCoord.nombre, teacherCoord.id, null);
  mkUser('prof.administracion', 'prof2026', 'seccion', teacherA.nombre, teacherA.id, secA.id);
  mkUser('prof.atencion', 'prof2026', 'seccion', teacherB.nombre, teacherB.id, secB.id);
  mkUser('prof.produccion', 'prof2026', 'seccion', teacherC.nombre, teacherC.id, secC.id);
  mkUser('prof.ventas', 'prof2026', 'seccion', teacherD.nombre, teacherD.id, secD.id);
  await userBatch.commit();

  const students = [
    { id: uid('al'), nombre: 'Julieta', apellido: 'Rearte', dni: '46123456', curso: '6°', division: 'A', legajo: '2026-011', fechaInicio: addDays(todayISO(), -52), estado: 'activo', groupId: null },
    { id: uid('al'), nombre: 'Bruno', apellido: 'Cabral', dni: '45988112', curso: '6°', division: 'A', legajo: '2026-012', fechaInicio: addDays(todayISO(), -10), estado: 'activo', groupId: null },
    { id: uid('al'), nombre: 'Camila', apellido: 'Torletti', dni: '46201033', curso: '6°', division: 'B', legajo: '2026-013', fechaInicio: addDays(todayISO(), -140), estado: 'activo', groupId: null },
  ];
  for (const s of students) {
    const { id, ...data } = s;
    await db.collection('students').doc(id).set(data);
    await generateRotationsFor(s);
  }

  const criteriosDefault = ['Puntualidad', 'Responsabilidad', 'Trabajo en equipo', 'Iniciativa', 'Calidad del trabajo', 'Comunicación', 'Adaptación al entorno laboral'];
  const critBatch = db.batch();
  criteriosDefault.forEach((nombre, idx) => critBatch.set(db.collection('criteriosDesempeno').doc(uid('crit')), { nombre, orden: idx + 1 }));
  await critBatch.commit();

  await logActivity('Se inicializó el sistema FAT Manager con datos de demostración.');
  console.log('[db] Listo. Base de datos Firestore sembrada con datos de ejemplo.');
}

module.exports = { admin, db, FieldValue, uid, todayISO, addDays, logActivity, getActivityLog, getSectionsOrdered, recomputeTotalWeeks, generateRotationsFor, ensureSeed };
