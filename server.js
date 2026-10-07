require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const { generateSecret, generateURI, verifySync } = require('otplib');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const db = require('./db');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-inseguro';
const MAX_LOGIN_ATTEMPTS = 5;
const MAX_MFA_ATTEMPTS = 3;
const LOCK_MINUTES = 15;
const ROLES = ['admin', 'gerente', 'ventas', 'auditor'];
const PASSWORD_RE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const app = express();
app.use(express.json());
app.use(express.static('public'));
app.use(session({ secret: process.env.SESSION_SECRET || 'dev-session', resave: false, saveUninitialized: false }));
app.use(passport.initialize());

// ---------- Helpers ----------
const getUserByEmail = (email) => db.prepare('SELECT * FROM users WHERE email = ?').get(email);
const getUserById = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
const publicUser = (u) => ({ id: u.id, email: u.email, fullName: u.full_name, store: u.store, role: u.role, mfaEnabled: !!u.mfa_enabled });

// Token temporal: solo sirve para completar el MFA (5 min). No da acceso a la API.
const signPending = (u) => jwt.sign({ sub: u.id, scope: 'mfa' }, JWT_SECRET, { expiresIn: '5m' });
// Token completo: se emite únicamente después de pasar el MFA.
const signFull = (u) => jwt.sign({ sub: u.id, role: u.role, store: u.store, scope: 'full' }, JWT_SECRET, { expiresIn: '1h' });

function verifyToken(scope) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (payload.scope !== scope) return res.status(401).json({ error: 'Token no válido para esta operación' });
      const user = getUserById(payload.sub);
      if (!user) return res.status(401).json({ error: 'Usuario no existe' });
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: 'Token inválido o expirado' });
    }
  };
}
const requireAuth = verifyToken('full');
const requirePending = verifyToken('mfa');
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: `Acceso denegado: el rol '${req.user.role}' no tiene permiso` });

// Paso común tras validar la primera credencial (password u OAuth)
function startMfaFlow(user) {
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0, mfa_attempts = 0 WHERE id = ?').run(user.id);
  return user.mfa_enabled
    ? { step: 'mfa_required', tempToken: signPending(user) }
    : { step: 'mfa_setup_required', tempToken: signPending(user) };
}

// ---------- Registro ----------
app.post('/api/register', (req, res) => {
  const { email, password, fullName, store } = req.body || {};
  const errors = [];
  if (!email || !EMAIL_RE.test(email)) errors.push('Email inválido');
  if (!password || !PASSWORD_RE.test(password))
    errors.push('La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial');
  if (!fullName || fullName.trim().length < 3) errors.push('Nombre completo requerido');
  if (!store || !store.trim()) errors.push('Tienda asignada requerida');
  if (errors.length) return res.status(400).json({ errors });

  const mail = email.trim().toLowerCase();
  if (getUserByEmail(mail)) return res.status(409).json({ errors: ['El email ya está registrado'] });

  // Seguridad: el rol NUNCA viene del cliente. El primer usuario es admin; el resto empieza como 'ventas'
  // y solo un admin puede cambiarlo.
  const isFirst = db.prepare('SELECT COUNT(*) c FROM users').get().c === 0;
  const hash = bcrypt.hashSync(password, 12);
  const r = db.prepare('INSERT INTO users (email, password_hash, full_name, store, role) VALUES (?,?,?,?,?)')
    .run(mail, hash, fullName.trim(), store.trim(), isFirst ? 'admin' : 'ventas');
  res.status(201).json({ message: 'Usuario registrado', user: publicUser(getUserById(r.lastInsertRowid)) });
});

// ---------- Login básico ----------
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = email && getUserByEmail(String(email).trim().toLowerCase());
  const generic = { error: 'Credenciales inválidas' };
  if (!user || !user.password_hash) return res.status(401).json(generic);

  if (user.locked_until > Date.now()) {
    const mins = Math.ceil((user.locked_until - Date.now()) / 60000);
    return res.status(423).json({ error: `Cuenta bloqueada por demasiados intentos. Intenta en ${mins} min` });
  }
  if (!bcrypt.compareSync(password || '', user.password_hash)) {
    const attempts = user.failed_attempts + 1;
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?').run(Date.now() + LOCK_MINUTES * 60000, user.id);
      return res.status(423).json({ error: `Cuenta bloqueada por ${LOCK_MINUTES} minutos tras ${MAX_LOGIN_ATTEMPTS} intentos fallidos` });
    }
    db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(attempts, user.id);
    return res.status(401).json({ ...generic, remainingAttempts: MAX_LOGIN_ATTEMPTS - attempts });
  }
  res.json(startMfaFlow(user));
});

// ---------- MFA (Opción A: TOTP) ----------
// 1) Enrolamiento: genera secreto y QR para Google Authenticator
app.post('/api/mfa/setup', requirePending, async (req, res) => {
  if (req.user.mfa_enabled) return res.status(400).json({ error: 'MFA ya está activado' });
  const secret = generateSecret();
  db.prepare('UPDATE users SET mfa_secret = ?, mfa_attempts = 0 WHERE id = ?').run(secret, req.user.id);
  const uri = generateURI({ issuer: 'TechStore', label: req.user.email, secret });
  res.json({ secret, qr: await QRCode.toDataURL(uri) });
});

// 2) Verificación del código de 6 dígitos (máx. 3 intentos)
app.post('/api/mfa/verify', requirePending, (req, res) => {
  const user = req.user;
  const code = String((req.body || {}).code || '').trim();
  if (!user.mfa_secret) return res.status(400).json({ error: 'Primero configura MFA' });
  if (user.mfa_attempts >= MAX_MFA_ATTEMPTS)
    return res.status(429).json({ error: 'Máximo de intentos MFA alcanzado. Vuelve a iniciar sesión' });

  const ok = /^\d{6}$/.test(code) && verifySync({ secret: user.mfa_secret, token: code, epochTolerance: 30 }).valid;
  if (!ok) {
    const attempts = user.mfa_attempts + 1;
    db.prepare('UPDATE users SET mfa_attempts = ? WHERE id = ?').run(attempts, user.id);
    const remaining = MAX_MFA_ATTEMPTS - attempts;
    return res.status(401).json({
      error: remaining > 0 ? 'Código incorrecto' : 'Código incorrecto. Sin intentos restantes, vuelve a iniciar sesión',
      remainingAttempts: remaining,
    });
  }
  db.prepare('UPDATE users SET mfa_enabled = 1, mfa_attempts = 0 WHERE id = ?').run(user.id);
  res.json({ token: signFull(user), user: publicUser(getUserById(user.id)) });
});

// ---------- Login social (Google / GitHub) ----------
// GitHub no siempre incluye el email en el perfil (si es privado): lo pedimos a su API.
async function githubEmail(accessToken, profile) {
  try {
    const r = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'techstore-lab', Accept: 'application/vnd.github+json' },
    });
    if (r.ok) {
      const list = await r.json();
      const best = list.find((e) => e.primary && e.verified) || list.find((e) => e.verified);
      if (best) return best.email;
    }
  } catch { /* se usa el correo noreply */ }
  return `${profile.id}+${profile.username}@users.noreply.github.com`;
}

async function socialUser(provider, profile, accessToken) {
  let email = (profile.emails && profile.emails[0] && profile.emails[0].value || '').toLowerCase();
  if (!email && provider === 'github') email = (await githubEmail(accessToken, profile)).toLowerCase();
  if (!email) throw new Error('El proveedor no entregó un email');
  let user = getUserByEmail(email);
  if (!user) {
    const isFirst = db.prepare('SELECT COUNT(*) c FROM users').get().c === 0;
    const r = db.prepare('INSERT INTO users (email, full_name, store, role, provider) VALUES (?,?,?,?,?)')
      .run(email, profile.displayName || profile.username || email, 'Sin asignar', isFirst ? 'admin' : 'ventas', provider);
    user = getUserById(r.lastInsertRowid);
  }
  return user;
}
const providers = {};
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy(
    { clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: `${BASE_URL}/auth/google/callback` },
    (a, r, profile, done) => socialUser('google', profile).then((u) => done(null, u), done)));
  providers.google = { scope: ['profile', 'email'] };
}
if (process.env.GITHUB_CLIENT_ID) {
  passport.use(new GitHubStrategy(
    { clientID: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET, callbackURL: `${BASE_URL}/auth/github/callback` },
    (accessToken, r, profile, done) => socialUser('github', profile, accessToken).then((u) => done(null, u), done)));
  providers.github = { scope: ['user:email'] };
}
app.get('/api/providers', (req, res) => res.json(Object.keys(providers)));
for (const name of ['google', 'github']) {
  app.get(`/auth/${name}`, (req, res, next) => {
    if (!providers[name]) return res.status(501).send(`Login con ${name} no configurado (faltan credenciales en .env)`);
    passport.authenticate(name, { scope: providers[name].scope, session: false })(req, res, next);
  });
  app.get(`/auth/${name}/callback`, (req, res, next) => {
    if (!providers[name]) return res.redirect('/');
    passport.authenticate(name, { session: false, failureRedirect: '/?error=oauth' })(req, res, next);
  }, (req, res) => {
    // Un login social NO salta el MFA: se entrega solo el token temporal.
    const flow = startMfaFlow(req.user);
    res.redirect(`/#step=${flow.step}&tempToken=${flow.tempToken}`);
  });
}

// Errores del flujo OAuth: volver al login con un mensaje en vez de mostrar el stack
app.use('/auth', (err, req, res, next) => {
  console.error('OAuth error:', err.message);
  res.redirect('/?error=oauth');
});

// ---------- Datos protegidos por rol ----------
const ownStore = (req, store) => req.user.role === 'admin' || req.user.store === store;

app.get('/api/me', requireAuth, (req, res) => res.json(publicUser(req.user)));

// Admin y auditor ven todo; gerente y ventas solo su tienda
app.get('/api/products', requireAuth, (req, res) => {
  const all = ['admin', 'auditor'].includes(req.user.role);
  const rows = all ? db.prepare('SELECT * FROM products').all()
    : db.prepare('SELECT * FROM products WHERE store = ?').all(req.user.store);
  res.json(rows);
});

app.post('/api/products', requireAuth, requireRole('admin', 'gerente'), (req, res) => {
  const { name, price, stock } = req.body || {};
  const store = req.user.role === 'admin' ? (req.body.store || req.user.store) : req.user.store;
  if (!name || !(price >= 0) || !Number.isInteger(stock) || stock < 0) return res.status(400).json({ error: 'Datos de producto inválidos' });
  const r = db.prepare('INSERT INTO products (name, price, stock, store) VALUES (?,?,?,?)').run(name, price, stock, store);
  res.status(201).json(db.prepare('SELECT * FROM products WHERE id = ?').get(r.lastInsertRowid));
});

// Precio: solo admin y gerente (ventas NO puede modificar precios)
app.put('/api/products/:id/price', requireAuth, requireRole('admin', 'gerente'), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  if (!ownStore(req, p.store)) return res.status(403).json({ error: 'Solo puedes modificar productos de tu tienda' });
  const price = Number(req.body.price);
  if (!(price >= 0)) return res.status(400).json({ error: 'Precio inválido' });
  db.prepare('UPDATE products SET price = ? WHERE id = ?').run(price, p.id);
  res.json({ ...p, price });
});

// Stock: admin, gerente y ventas (auditor es solo lectura)
app.patch('/api/products/:id/stock', requireAuth, requireRole('admin', 'gerente', 'ventas'), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  if (!ownStore(req, p.store)) return res.status(403).json({ error: 'Solo puedes modificar productos de tu tienda' });
  const stock = req.body.stock;
  if (!Number.isInteger(stock) || stock < 0) return res.status(400).json({ error: 'Stock inválido' });
  db.prepare('UPDATE products SET stock = ? WHERE id = ?').run(stock, p.id);
  res.json({ ...p, stock });
});

// Eliminar: admin cualquiera; gerente solo de su tienda
app.delete('/api/products/:id', requireAuth, requireRole('admin', 'gerente'), (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  if (!ownStore(req, p.store)) return res.status(403).json({ error: 'No puedes eliminar productos de otras tiendas' });
  db.prepare('DELETE FROM products WHERE id = ?').run(p.id);
  res.json({ message: 'Producto eliminado' });
});

// Reportes: admin y auditor (todas las tiendas); gerente (su tienda)
app.get('/api/reports', requireAuth, requireRole('admin', 'auditor', 'gerente'), (req, res) => {
  const where = req.user.role === 'gerente' ? 'WHERE store = ?' : '';
  const args = req.user.role === 'gerente' ? [req.user.store] : [];
  res.json(db.prepare(`SELECT store, COUNT(*) productos, SUM(stock) unidades, ROUND(SUM(stock*price),2) valor_inventario
                       FROM products ${where} GROUP BY store`).all(...args));
});

// Usuarios: admin gestiona; auditor solo lee
app.get('/api/users', requireAuth, requireRole('admin', 'auditor'), (req, res) =>
  res.json(db.prepare('SELECT * FROM users').all().map(publicUser)));

app.put('/api/users/:id/role', requireAuth, requireRole('admin'), (req, res) => {
  const { role } = req.body || {};
  if (!ROLES.includes(role)) return res.status(400).json({ error: `Rol inválido. Opciones: ${ROLES.join(', ')}` });
  const u = getUserById(req.params.id);
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, u.id);
  res.json(publicUser(getUserById(u.id)));
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`TechStore en ${BASE_URL}`));
}
module.exports = app;
