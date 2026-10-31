// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION INSEGURA (rama inseguro) <<<
//
//  Endpoints:
//    GET  /salud       -> estado del servicio
//    GET  /llave       -> entrega la llave publica
//    POST /cifrar      -> cifra un texto
//    POST /descifrar   -> descifra un texto
//    GET  /buscar      -> consulta la bitacora (demostracion de SQLi)
//    POST /calcular    -> "utilidad" de calculo (demostracion de eval)
//    GET  /diagnostico -> ejecuta un ping (demostracion de command injection)
// ============================================================================

const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requiereAuth } = require('./auth');

const app = express();
app.use(express.json());

// [VULN-5] CORS totalmente abierto: cualquier origen puede consumir la API.
//   Lo reporta OWASP ZAP (DAST) y Semgrep. La solucion es restringir a los
//   origenes de confianza.  CWE-942 (Overly Permissive CORS)
const helmet = require('helmet');
app.use(helmet());
app.use(cors({ origin: config.ORIGEN_PERMITIDO }));

// [VULN-6] Faltan cabeceras de seguridad (no se usa Helmet):
//   sin Content-Security-Policy, X-Content-Type-Options, etc.
//   Lo reporta OWASP ZAP.  CWE-693 (Protection Mechanism Failure)
//   (La solucion es: app.use(require('helmet')()).)

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'inseguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

app.post('/cifrar', requiereAuth, (req, res) => {
  const texto = req.body?.texto;

  if (typeof texto !== 'string' || texto.trim().length === 0) {
    return res.status(400).json({ error: 'Texto inválido' });
  }

  if (Buffer.byteLength(texto, 'utf8') > 1000) {
    return res.status(400).json({ error: 'Texto demasiado grande' });
  }

  try {
    const resultado = cifrado.cifrar(texto, llaves.publicKey);
    return res.json({ cifrado: resultado });
  } catch (e) {
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/descifrar', requiereAuth, (req, res) => {
  const cifradoTxt = req.body?.cifrado;

  if (typeof cifradoTxt !== 'string' || cifradoTxt.trim().length === 0) {
    return res.status(400).json({ error: 'Cifrado inválido' });
  }

  if (cifradoTxt.length > 10000) {
    return res.status(400).json({ error: 'Cifrado demasiado grande' });
  }

  try {
    const resultado = cifrado.descifrar(cifradoTxt, llaves.privateKey);
    return res.json({ descifrado: resultado });
  } catch (e) {
    return res.status(400).json({ error: 'No se pudo descifrar el contenido' });
  }
});

// Demostracion de INYECCION SQL (CWE-89).
app.get('/buscar', (req, res) => {
  const nombre = req.query.nombre || '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [VULN-9] Uso de eval() sobre entrada del usuario: inyeccion de codigo.
//   Lo detectan Semgrep y CodeQL (js/code-injection).
//   CWE-95 (Eval Injection)
app.post('/calcular', (req, res) => {
  try {
    const nums = Array.isArray(req.body.numeros)
      ? req.body.numeros
      : [];

    if (!nums.every(n => typeof n === 'number' && Number.isFinite(n))) {
      return res.status(400).json({ error: 'Entrada inválida' });
    }

    const resultado = nums.reduce((a, b) => a + b, 0);
    return res.json({ resultado });
  } catch (e) {
    return res.status(400).json({
      error: 'Entrada inválida'
    });
  }
});
// [VULN-10] Inyeccion de comandos del sistema operativo.
//   El parametro 'host' entra sin sanitizar a exec(). Un atacante puede enviar
//   "8.8.8.8; cat /etc/passwd". Lo detectan CodeQL y Semgrep.
//   CWE-78 (OS Command Injection)
// Endpoint seguro: evita la inyección de comandos del sistema.
app.get('/diagnostico', (req, res) => {
  const host = req.query.host || '127.0.0.1';

  // Validación estricta: solo permite direcciones IPv4.
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (!ipv4Regex.test(host)) {
    return res.status(400).json({
      error: 'Dirección IP inválida'
    });
  }

  const octetos = host.split('.').map(Number);

  if (octetos.some(octeto => octeto < 0 || octeto > 255)) {
    return res.status(400).json({
      error: 'Dirección IP inválida'
    });
  }

  execFile('ping', ['-c', '1', host], (err, stdout, stderr) => {
    return res.json({
      salida: stdout,
      error: err ? stderr || err.message : null
    });
  });
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;
