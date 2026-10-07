# TechStore - Sistema de Gestión de Inventario

Laboratorio calificado de **Desarrollo de Soluciones en la Nube**: aplicación web con autenticación segura, MFA y control de acceso por roles.

## Funcionalidades

**Parte 1 - Registro e inicio de sesión**
- Registro con email único, contraseña fuerte (mín. 8 caracteres, mayúscula, número y carácter especial), nombre completo y tienda.
- Contraseñas guardadas con hash (bcrypt).
- Login con validación de credenciales y emisión de **JWT**.
- Bloqueo de la cuenta tras **5 intentos fallidos** (15 minutos).
- Login con **Google** y **GitHub** (OAuth 2.0).

**Parte 2 - MFA (Opción A: TOTP)**
- Código de 6 dígitos que cambia cada 30 segundos (Google Authenticator o similar), con QR de enrolamiento.
- Flujo: credenciales correctas → token temporal (5 min) → código MFA → JWT completo (1 h).
- Máximo **3 intentos** de código; luego hay que volver a iniciar sesión.
- El login social también pasa por MFA.

**Roles**

| Rol | Permisos |
|---|---|
| Administrador | Acceso total: usuarios, roles, productos de todas las tiendas |
| Gerente de Tienda | Gestiona productos y ve reportes de su tienda; no elimina productos de otras |
| Empleado de Ventas | Consulta productos y actualiza stock de su tienda; no modifica precios |
| Auditor | Solo lectura de todo y reportes; sin permisos de modificación |

El primer usuario registrado es Administrador. Los demás empiezan como `ventas` y solo un administrador puede cambiar el rol (el cliente nunca elige su rol).

## Tecnologías
Node.js 22+, Express, SQLite (`node:sqlite`), bcryptjs, jsonwebtoken, otplib, qrcode, Passport (Google y GitHub).

## Instalación

```bash
npm install
cp .env.example .env     # en Windows: copy .env.example .env
npm start
```

Abrir http://localhost:3000

### Variables de entorno (`.env`)
Ver `.env.example`. Cambia `JWT_SECRET` y `SESSION_SECRET` por valores largos y aleatorios.

### Login social (opcional)
- **GitHub:** Settings → Developer settings → OAuth Apps. Callback: `http://localhost:3000/auth/github/callback`.
- **Google:** Google Cloud Console → Google Auth Platform → crear cliente OAuth (aplicación web). Callback: `http://localhost:3000/auth/google/callback`. Agregar los correos de prueba en *Público*.

Completa `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID` y `GITHUB_CLIENT_SECRET` en `.env`. Sin ellos, los botones sociales no están disponibles.

## Pruebas

```bash
npm test
```

Ejecuta 32 pruebas end-to-end (registro, bloqueo, MFA, permisos por rol) contra una base de datos en memoria.

## API principal

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/register` | Registro |
| POST | `/api/login` | Login (devuelve token temporal para MFA) |
| POST | `/api/mfa/setup` | Genera secreto y QR (token temporal) |
| POST | `/api/mfa/verify` | Verifica el código y entrega el JWT completo |
| GET | `/api/products` | Productos (filtrados por rol/tienda) |
| POST | `/api/products` | Crear producto (admin, gerente) |
| PUT | `/api/products/:id/price` | Cambiar precio (admin, gerente) |
| PATCH | `/api/products/:id/stock` | Cambiar stock (admin, gerente, ventas) |
| DELETE | `/api/products/:id` | Eliminar (admin; gerente solo su tienda) |
| GET | `/api/reports` | Reporte (admin, auditor, gerente) |
| GET | `/api/users` | Usuarios (admin, auditor) |
| PUT | `/api/users/:id/role` | Cambiar rol (admin) |

## Seguridad
- Hash bcrypt, mensajes de error genéricos en login y bloqueo por intentos.
- JWT firmados con expiración; el token temporal de MFA no da acceso a la API.
- Secretos fuera del código (`.env` no se versiona).
