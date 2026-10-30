// ============================================================================
//  db.js  -  Acceso a datos (bitacora de operaciones)
//  >>> VERSION INSEGURA <<<
// ============================================================================
//
//  Este modulo simula una pequena base de datos donde se guarda una bitacora
//  de las operaciones de cifrado. Se usa el driver 'mysql' (JavaScript puro)
//  para que el analisis estatico reconozca el "sink" de SQL.
//
//  Nota didactica: no se necesita un MySQL real corriendo. Si la conexion
//  falla, la consulta se atrapa y el servicio sigue vivo; lo importante para
//  el laboratorio es que SAST/CodeQL detecten la INYECCION SQL en el codigo.


// ============================================================================
// db.js - Acceso a datos (bitacora de operaciones)
// VERSION CORREGIDA
// ============================================================================

const mysql = require('mysql');
const config = require('./config');

let conexion = null;

try {
  conexion = mysql.createConnection(config.DATABASE_URL);
} catch (e) {
  conexion = null;
}

// [FIX VULN-3] Consulta parametrizada para prevenir SQL Injection.
// CWE-89: SQL Injection

function buscarBitacora(nombre, callback) {
  const sql = 'SELECT * FROM bitacora WHERE usuario = ?';
  const parametros = [nombre];

  if (!conexion) {
    return callback(null, {
      sqlEjecutado: sql,
      filas: []
    });
  }

  conexion.query(sql, parametros, function (err, filas) {
    if (err) {
      return callback(null, {
        sqlEjecutado: sql,
        filas: [],
        nota: err.code
      });
    }

    return callback(null, {
      sqlEjecutado: sql,
      filas: filas
    });
  });
}
