const express = require('express');
const cors = require('cors');
const { PORT } = require('./src/config/env');
const authController = require('./src/controllers/auth.controller');
const { verifyToken } = require('./src/middlewares/auth.middleware');

const app = express();

app.use(cors());
app.use(express.json());

// Endpoints API
app.post('/api/auth/login', (req, res) => authController.handleLogin(req, res));
app.get('/api/dashboard/data', verifyToken, (req, res) => authController.handleDashboard(req, res));
app.get('/health', (req, res) => res.json({ status: 'UP', service: 'Backend VPC' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend Zero Trust escuchando en puerto ${PORT}`);
});