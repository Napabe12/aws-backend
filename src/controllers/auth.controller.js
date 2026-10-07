const authService = require('../services/auth.service');

class AuthController {
  async handleLogin(req, res) {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }

    try {
      const result = await authService.login(username, password);
      console.log(`[AUTH SUCCESS] Sesión iniciada para: ${username}`);
      return res.status(200).json(result);
    } catch (error) {
      // Este 401 es capturado por Fail2Ban para bloquear IPs tras varios intentos
      console.error(`[AUTH FAILURE] 401 Unauthorized para usuario: ${username} desde IP: ${req.ip}`);
      return res.status(401).json({ error: error.message });
    }
  }

  handleDashboard(req, res) {
    const data = authService.getDashboardData(req.user);
    return res.status(200).json(data);
  }
}

module.exports = new AuthController();