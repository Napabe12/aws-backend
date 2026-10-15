const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../domain/user.entity');
const { JWT_SECRET, JWT_EXPIRES_IN } = require('../config/env');

// Generación de hashes seguros con bcrypt
const adminHash = bcrypt.hashSync('AdminPass2026!', 10);
const clienteHash = bcrypt.hashSync('ClientePass2026!', 10);

// Base de datos en memoria con roles de Administrador y Cliente
const usersStore = [
  new User(1, 'admin', adminHash, 'Administrador'),
  new User(2, 'cliente', clienteHash, 'Cliente')
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
    const baseData = {
      usuario: tokenPayload.username,
      rol: tokenPayload.role,
      arquitectura: 'Aislamiento Zero Trust en VPC Privada',
      timestamp: new Date().toISOString()
    };

    // Respuesta diferenciada por rol (RBAC)
    if (tokenPayload.role === 'Administrador') {
      return {
        ...baseData,
        mensaje: 'Acceso total autorizado al Dashboard de Administración'
      };
    }

    return {
      ...baseData,
      mensaje: 'Acceso autorizado al Portal de Cliente (Solo Consulta)'
    };
  }
}

module.exports = new AuthService();