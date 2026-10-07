const bcrypt = require('bcryptjs');

class User {
  constructor(id, username, passwordHash, role = 'Administrador') {
    this.id = id;
    this.username = username;
    this.passwordHash = passwordHash;
    this.role = role;
  }

  async validatePassword(plainPassword) {
    return await bcrypt.compare(plainPassword, this.passwordHash);
  }
}

module.exports = User;