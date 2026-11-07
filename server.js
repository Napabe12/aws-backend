const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_farmacia_default';

app.use(cors());
app.use(express.json());

// Servir los archivos estáticos de la carpeta aws-frontend
app.use(express.static(path.join(__dirname, '../aws-frontend')));

// ==========================================
// BASE DE DATOS EN MEMORIA (INICIAL)
// ==========================================
const passAdmin = bcrypt.hashSync('Admin123!', 10);
const passFarm = bcrypt.hashSync('Farmacia2026!', 10);
const passCliente = bcrypt.hashSync('ClientePass2026!', 10);

let usuarios = [
  { id: 1, nombre: 'Jose Valle', email: 'admin@farmacia.com', password: passAdmin, rol: 'admin' },
  { id: 2, nombre: 'Carlos Farmacéutico', email: 'carlos@farmacia.com', password: passFarm, rol: 'farmaceutico' },
  { id: 3, nombre: 'Cliente Mostrador', email: 'cliente@farmacia.com', password: passCliente, rol: 'cliente' }
];

let medicamentos = [
  { id: 101, codigo: 'MED-001', nombre: 'Paracetamol 500mg', categoria: 'Analgésico', stock: 120, precio: 35.50, requiereReceta: false },
  { id: 102, codigo: 'MED-002', nombre: 'Amoxicilina 500mg', categoria: 'Antibiótico', stock: 45, precio: 110.00, requiereReceta: true },
  { id: 103, codigo: 'MED-003', nombre: 'Ibuprofeno 400mg', categoria: 'Antiinflamatorio', stock: 85, precio: 45.00, requiereReceta: false },
  { id: 104, codigo: 'MED-004', nombre: 'Clonazepam 2mg', categoria: 'Controlado', stock: 15, precio: 220.00, requiereReceta: true }
];

// ==========================================
// MIDDLEWARES DE SEGURIDAD (RBAC & JWT)
// ==========================================
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ mensaje: 'Acceso denegado: Token no proporcionado.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ mensaje: 'Token inválido o expirado.' });
    }
    req.usuario = decoded;
    next();
  });
}

function autorizarRoles(...rolesPermitidos) {
  return (req, res, next) => {
    if (!rolesPermitidos.includes(req.usuario.rol)) {
      return res.status(403).json({ 
        mensaje: `Acceso restringido: El rol '${req.usuario.rol}' no tiene permisos para esta acción.` 
      });
    }
    next();
  };
}

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = usuarios.find(u => u.email.toLowerCase() === (email || '').toLowerCase());

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ mensaje: 'Credenciales inválidas.' });
  }

  const token = jwt.sign(
    { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol },
    JWT_SECRET,
    { expiresIn: '3h' }
  );

  res.json({
    mensaje: 'Autenticación exitosa',
    token,
    usuario: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol }
  });
});

// REGISTRO PÚBLICO (NUEVO CLIENTE)
app.post('/api/auth/register', (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios.' });
  }

  if (usuarios.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ mensaje: 'Este correo electrónico ya está registrado.' });
  }

  const nuevoUsuario = {
    id: usuarios.length ? Math.max(...usuarios.map(u => u.id)) + 1 : 1,
    nombre,
    email,
    password: bcrypt.hashSync(password, 10),
    rol: 'cliente'
  };

  usuarios.push(nuevoUsuario);

  const token = jwt.sign(
    { id: nuevoUsuario.id, nombre: nuevoUsuario.nombre, email: nuevoUsuario.email, rol: nuevoUsuario.rol },
    JWT_SECRET,
    { expiresIn: '3h' }
  );

  res.status(201).json({
    mensaje: 'Cuenta creada con éxito',
    token,
    usuario: { id: nuevoUsuario.id, nombre: nuevoUsuario.nombre, email: nuevoUsuario.email, rol: nuevoUsuario.rol }
  });
});

// ==========================================
// RUTAS CRUD DE USUARIOS (SOLO ADMIN)
// ==========================================
app.get('/api/usuarios', autenticarToken, autorizarRoles('admin'), (req, res) => {
  const listaSegura = usuarios.map(({ password, ...u }) => u);
  res.json(listaSegura);
});

app.post('/api/usuarios', autenticarToken, autorizarRoles('admin'), (req, res) => {
  const { nombre, email, password, rol } = req.body;

  if (!nombre || !email || !password || !rol) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios.' });
  }

  if (usuarios.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ mensaje: 'El correo electrónico ya se encuentra registrado.' });
  }

  const nuevoUsuario = {
    id: usuarios.length ? Math.max(...usuarios.map(u => u.id)) + 1 : 1,
    nombre,
    email,
    password: bcrypt.hashSync(password, 10),
    rol
  };

  usuarios.push(nuevoUsuario);
  const { password: _, ...usuarioCreado } = nuevoUsuario;
  res.status(201).json({ mensaje: 'Usuario registrado correctamente.', usuario: usuarioCreado });
});

app.delete('/api/usuarios/:id', autenticarToken, autorizarRoles('admin'), (req, res) => {
  const idEliminar = parseInt(req.params.id);

  if (idEliminar === req.usuario.id) {
    return res.status(400).json({ mensaje: 'No puede eliminar su propia cuenta administrativa activa.' });
  }

  const index = usuarios.findIndex(u => u.id === idEliminar);
  if (index === -1) {
    return res.status(404).json({ mensaje: 'Usuario no encontrado.' });
  }

  const eliminado = usuarios.splice(index, 1)[0];
  res.json({ mensaje: `Usuario '${eliminado.nombre}' eliminado exitosamente.` });
});

// ==========================================
// RUTAS DE MEDICAMENTOS (INVENTARIO)
// ==========================================
app.get('/api/medicamentos', autenticarToken, (req, res) => {
  res.json(medicamentos);
});

app.post('/api/medicamentos', autenticarToken, autorizarRoles('admin', 'farmaceutico'), (req, res) => {
  const { codigo, nombre, categoria, stock, precio, requiereReceta } = req.body;

  if (!codigo || !nombre || stock === undefined || precio === undefined) {
    return res.status(400).json({ mensaje: 'Datos de medicamento incompletos.' });
  }

  const nuevoMed = {
    id: medicamentos.length ? Math.max(...medicamentos.map(m => m.id)) + 1 : 101,
    codigo,
    nombre,
    categoria: categoria || 'General',
    stock: parseInt(stock),
    precio: parseFloat(precio),
    requiereReceta: Boolean(requiereReceta)
  };

  medicamentos.push(nuevoMed);
  res.status(201).json({ mensaje: 'Medicamento ingresado al inventario.', medicamento: nuevoMed });
});

app.delete('/api/medicamentos/:id', autenticarToken, autorizarRoles('admin'), (req, res) => {
  const id = parseInt(req.params.id);
  const index = medicamentos.findIndex(m => m.id === id);

  if (index === -1) {
    return res.status(404).json({ mensaje: 'Medicamento no encontrado en inventario.' });
  }

  const eliminado = medicamentos.splice(index, 1)[0];
  res.json({ mensaje: `Medicamento '${eliminado.nombre}' eliminado del inventario.` });
});

// Fallback para SPA: redirigir cualquier otra petición a index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../aws-frontend/index.html'));
});

app.listen(PORT, () => {
  console.log(`[+] Sistema Farmacéutico seguro activo en el puerto ${PORT}`);
});