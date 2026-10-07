require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || 'clave_segura_zero_trust_2026_unach',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h'
};