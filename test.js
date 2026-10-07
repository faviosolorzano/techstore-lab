// Pruebas end-to-end contra una BD en memoria. Uso: npm test
process.env.DB_FILE = ':memory:';
const { generateSync } = require('otplib');
const app = require('./server');

let pass = 0, fail = 0;
const check = (name, cond, extra = '') => { cond ? pass++ : fail++; console.log(`${cond ? '[OK]  ' : '[FAIL]'} ${name} ${extra}`); };

(async () => {
  const srv = app.listen(0);
  const base = `http://localhost:${srv.address().port}`;
  const call = async (url, method = 'GET', body, tok) => {
    const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { s: r.status, d: await r.json().catch(() => ({})) };
  };
  const pw = 'Segura#2026';
  const reg = (email, store = 'Lima Centro') => call('/api/register', 'POST', { email, password: pw, fullName: 'Usuario ' + email, store });
  const secrets = {};
  async function fullLogin(email) {            // login + MFA completo
    const l = await call('/api/login', 'POST', { email, password: pw });
    const tok = l.d.tempToken;
    if (l.d.step === 'mfa_setup_required') secrets[email] = (await call('/api/mfa/setup', 'POST', null, tok)).d.secret;
    const v = await call('/api/mfa/verify', 'POST', { code: generateSync({ secret: secrets[email] }) }, tok);
    return v.d.token;
  }

  console.log('\n== Parte 1: Registro ==');
  check('Contraseña débil rechazada', (await call('/api/register', 'POST', { email: 'a@a.com', password: 'abc', fullName: 'Abc Def', store: 'X' })).s === 400);
  check('Sin carácter especial rechazada', (await call('/api/register', 'POST', { email: 'a@a.com', password: 'Abcdefg1', fullName: 'Abc Def', store: 'X' })).s === 400);
  const r1 = await reg('admin@techstore.com');
  check('Registro válido (201)', r1.s === 201);
  check('Primer usuario es admin', r1.d.user.role === 'admin');
  check('Email duplicado rechazado (409)', (await reg('admin@techstore.com')).s === 409);
  const r2 = await call('/api/register', 'POST', { email: 'hack@x.com', password: pw, fullName: 'Hacker Uno', store: 'Miraflores', role: 'admin' });
  check('Cliente no puede elegir su rol', r2.d.user.role === 'ventas');
  await reg('gerente@techstore.com'); await reg('audit@techstore.com');

  console.log('\n== Parte 1: Login y bloqueo ==');
  const bad = await call('/api/login', 'POST', { email: 'hack@x.com', password: 'mala' });
  check('Credenciales malas -> 401', bad.s === 401, `(restantes: ${bad.d.remainingAttempts})`);
  for (let i = 0; i < 3; i++) await call('/api/login', 'POST', { email: 'hack@x.com', password: 'mala' });
  const lock = await call('/api/login', 'POST', { email: 'hack@x.com', password: 'mala' });
  check('5.o intento fallido bloquea la cuenta (423)', lock.s === 423);
  check('Con cuenta bloqueada, ni la clave correcta entra', (await call('/api/login', 'POST', { email: 'hack@x.com', password: pw })).s === 423);

  console.log('\n== Parte 2: MFA TOTP ==');
  const l = await call('/api/login', 'POST', { email: 'admin@techstore.com', password: pw });
  check('Login correcto pide configurar MFA', l.d.step === 'mfa_setup_required');
  check('Token temporal NO da acceso a la API', (await call('/api/products', 'GET', null, l.d.tempToken)).s === 401);
  const setup = await call('/api/mfa/setup', 'POST', null, l.d.tempToken);
  check('Se genera QR y secreto', !!setup.d.qr && setup.d.qr.startsWith('data:image/png') && !!setup.d.secret);
  for (let i = 1; i <= 3; i++) {
    const w = await call('/api/mfa/verify', 'POST', { code: '000000' }, l.d.tempToken);
    check(`Codigo incorrecto #${i}`, w.s === 401, `(restantes: ${w.d.remainingAttempts})`);
  }
  const blocked = await call('/api/mfa/verify', 'POST', { code: generateSync({ secret: setup.d.secret }) }, l.d.tempToken);
  check('Tras 3 fallos, ni el codigo correcto sirve (429)', blocked.s === 429);
  const l2 = await call('/api/login', 'POST', { email: 'admin@techstore.com', password: pw });
  const ok = await call('/api/mfa/verify', 'POST', { code: generateSync({ secret: setup.d.secret }) }, l2.d.tempToken);
  secrets['admin@techstore.com'] = setup.d.secret;
  check('Codigo correcto -> JWT completo', ok.s === 200 && !!ok.d.token);
  const l3 = await call('/api/login', 'POST', { email: 'admin@techstore.com', password: pw });
  check('Siguiente login pide MFA (ya enrolado)', l3.d.step === 'mfa_required');

  console.log('\n== Roles y permisos ==');
  const admin = await fullLogin('admin@techstore.com');
  await fullLogin('gerente@techstore.com'); await fullLogin('audit@techstore.com');
  check('Sin token -> 401', (await call('/api/products')).s === 401);
  const users = (await call('/api/users', 'GET', null, admin)).d;
  const setRole = (email, role) => call(`/api/users/${users.find(u => u.email === email).id}/role`, 'PUT', { role }, admin);
  check('Admin asigna rol gerente', (await setRole('gerente@techstore.com', 'gerente')).s === 200);
  check('Admin asigna rol auditor', (await setRole('audit@techstore.com', 'auditor')).s === 200);
  const gerente = await fullLogin('gerente@techstore.com'); // token nuevo con rol actualizado
  const audit = await fullLogin('audit@techstore.com');
  await reg('ventas@techstore.com');
  const ventas = await fullLogin('ventas@techstore.com');
  check('Gerente no puede cambiar roles (403)', (await call('/api/users/1/role', 'PUT', { role: 'admin' }, gerente)).s === 403);
  const all = (await call('/api/products', 'GET', null, admin)).d;
  const other = all.find((p) => p.store !== 'Lima Centro'), mine = all.find((p) => p.store === 'Lima Centro');
  check('Gerente solo ve su tienda', (await call('/api/products', 'GET', null, gerente)).d.every((p) => p.store === 'Lima Centro'));
  check('Gerente NO elimina producto de otra tienda (403)', (await call(`/api/products/${other.id}`, 'DELETE', null, gerente)).s === 403);
  check('Gerente modifica precio de su tienda', (await call(`/api/products/${mine.id}/price`, 'PUT', { price: 99 }, gerente)).s === 200);
  check('Ventas actualiza stock', (await call(`/api/products/${mine.id}/stock`, 'PATCH', { stock: 7 }, ventas)).s === 200);
  check('Ventas NO modifica precios (403)', (await call(`/api/products/${mine.id}/price`, 'PUT', { price: 1 }, ventas)).s === 403);
  check('Auditor lee todo', (await call('/api/products', 'GET', null, audit)).d.length === all.length);
  check('Auditor genera reportes', (await call('/api/reports', 'GET', null, audit)).s === 200);
  check('Auditor NO modifica stock (403)', (await call(`/api/products/${mine.id}/stock`, 'PATCH', { stock: 1 }, audit)).s === 403);
  check('Auditor NO elimina (403)', (await call(`/api/products/${mine.id}`, 'DELETE', null, audit)).s === 403);
  check('Admin elimina cualquier producto', (await call(`/api/products/${other.id}`, 'DELETE', null, admin)).s === 200);

  console.log(`\nResultado: ${pass} OK, ${fail} fallidos`);
  srv.close(); process.exit(fail ? 1 : 0);
})();
