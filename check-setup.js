/* Auto-diagnóstico: corré esto DESPUÉS de completar tu .env con las credenciales reales
   de Firebase y Cloudinary. No inventa nada ni asume que algo funciona: prueba cada
   pieza contra el servicio real y te dice exactamente qué falló si algo falla. */
require('dotenv').config();
let ok = 0, fail = 0;
function pass(label) { ok++; console.log('  ✓ ' + label); }
function bad(label, err) { fail++; console.log('  ✗ ' + label); if (err) console.log('    → ' + (err.message || err)); }

async function main() {
  console.log('=== 1) Variables de entorno presentes ===');
  const hasFirebase = !!(process.env.FIREBASE_SERVICE_ACCOUNT_JSON) || require('fs').existsSync(require('path').join(__dirname, 'serviceAccountKey.json'));
  hasFirebase ? pass('Encontré credenciales de Firebase (env var o serviceAccountKey.json)') : bad('Falta FIREBASE_SERVICE_ACCOUNT_JSON o serviceAccountKey.json');
  const hasCloudinary = process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET;
  hasCloudinary ? pass('Encontré las 3 variables de Cloudinary') : bad('Faltan variables de Cloudinary (CLOUDINARY_CLOUD_NAME / API_KEY / API_SECRET)');

  if (!hasFirebase) { console.log('\nNo puedo seguir sin credenciales de Firebase. Completá el .env y volvé a correr "npm run check".'); process.exit(1); }

  console.log('\n=== 2) Conexión real a Firestore ===');
  try {
    const { db, uid } = require('./db');
    const testId = uid('checktest');
    await db.collection('_selftest').doc(testId).set({ ts: new Date().toISOString() });
    pass('Pude ESCRIBIR un documento de prueba en Firestore');
    const snap = await db.collection('_selftest').doc(testId).get();
    (snap.exists && snap.data().ts) ? pass('Pude LEER ese mismo documento de vuelta') : bad('Escribió pero no pude leerlo de vuelta (raro)');
    await db.collection('_selftest').doc(testId).delete();
    pass('Pude BORRAR el documento de prueba (limpieza)');
  } catch (e) {
    bad('No pude conectarme a Firestore', e);
    console.log('    Motivos típicos: el archivo/():JSON de la cuenta de servicio está mal pegado,');
    console.log('    o el proyecto de Firebase no tiene Firestore habilitado todavía.');
  }

  if (hasCloudinary) {
    console.log('\n=== 3) Conexión real a Cloudinary ===');
    try {
      const cloudinary = require('cloudinary').v2;
      cloudinary.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET
      });
      // subimos un archivo de texto mínimo de prueba
      const tinyBuffer = Buffer.from('archivo de prueba de FAT Manager - se puede borrar');
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'fat-manager-selftest', resource_type: 'raw', public_id: 'selftest-' + Date.now() }, (err, r) => err ? reject(err) : resolve(r));
        stream.end(tinyBuffer);
      });
      pass('Pude SUBIR un archivo de prueba a Cloudinary: ' + result.secure_url);
      await cloudinary.uploader.destroy(result.public_id, { resource_type: 'raw' });
      pass('Pude BORRAR el archivo de prueba (limpieza)');
    } catch (e) {
      bad('No pude conectarme a Cloudinary', e);
      console.log('    Revisá que copiaste bien Cloud Name / API Key / API Secret desde tu dashboard.');
    }
  }

  console.log('\n=== RESULTADO ===');
  console.log(`${ok} OK, ${fail} con problemas.`);
  if (fail === 0) console.log('Todo listo — ya podés correr "npm start" con confianza.');
  else console.log('Corregí lo marcado con ✗ antes de desplegar en producción.');
  process.exitCode = fail ? 1 : 0;
}

main().catch(e => { console.error('Error inesperado en el diagnóstico:', e); process.exit(1); });
