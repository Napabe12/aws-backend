const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../domain/user.entity');
const { JWT_SECRET, JWT_EXPIRES_IN } = require('../config/env');

// Usuario por defecto: admin / AdminPass2026!
const defaultHash = bcrypt.hashSync('AdminPass2026!', 10);
const usersStore = [
  new User(1, 'admin', defaultHash, 'Administrador')
];

class AuthService {
  async login(username, password) {
    const user = usersStore.find(u => u.username === username);
    if (!user) {
      throw new Error('Credenciales inválidas');
    }

    const isValid = await user.validatePassword(password);
    if (!isValid) {
      throw new Error('Credenciales inválidas');
    }

    const token = jwt.sign(
      { sub: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return {
      token,
      user: { username: user.username, role: user.role }
    };
  }

  getDashboardData(tokenPayload) {
    return {
      mensaje: 'Acceso autorizado al Dashboard Seguro',
      usuario: tokenPayload.username,
      rol: tokenPayload.role,
      arquitectura: 'Aislamiento Zero Trust en VPC Privada',
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = new AuthService();