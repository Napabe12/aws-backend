const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/env');

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.warn(`[ZERO TRUST] Intento de acceso sin token desde IP: ${req.ip}`);
    return res.status(401).json({ error: 'Acceso no autorizado: Token requerido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.warn(`[ZERO TRUST] Token inválido o expirado desde IP: ${req.ip}`);
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }
}

module.exports = { verifyToken };