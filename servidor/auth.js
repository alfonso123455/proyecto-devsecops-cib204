const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const config = require('./config');

const verificarToken = expressjwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/certs`
  }),
  issuer: `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}`,
  algorithms: ['RS256'],
  requestProperty: 'usuario'
});

function requiereAuth(req, res, next) {
  if (!config.AUTH_ENABLED) {
    return next();
  }

  verificarToken(req, res, (err) => {
    if (err) {
      return res.status(401).json({ error: 'No autorizado' });
    }

    return next();
  });
}

module.exports = { requiereAuth };