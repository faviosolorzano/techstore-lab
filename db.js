const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, 'techstore.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  full_name TEXT NOT NULL,
  store TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'ventas',
  provider TEXT NOT NULL DEFAULT 'local',
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price REAL NOT NULL,
  stock INTEGER NOT NULL,
  store TEXT NOT NULL
);
`);

if (db.prepare('SELECT COUNT(*) c FROM products').get().c === 0) {
  const ins = db.prepare('INSERT INTO products (name, price, stock, store) VALUES (?,?,?,?)');
  [
    ['Laptop Lenovo IdeaPad', 2499.9, 12, 'Lima Centro'],
    ['Mouse Logitech M185', 49.9, 80, 'Lima Centro'],
    ['Monitor Samsung 24"', 699.0, 20, 'Miraflores'],
    ['Teclado Mecánico Redragon', 159.0, 35, 'Miraflores'],
    ['Audífonos Sony WH-CH520', 199.0, 25, 'San Isidro'],
  ].forEach((p) => ins.run(...p));
}

module.exports = db;
