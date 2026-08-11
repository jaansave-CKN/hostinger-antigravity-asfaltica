const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Anthropic = require('@anthropic-ai/sdk');
const { pool, initDb, nextId, MODULES, ACTIONS } = require('./db');

const app = express();
const PORT = process.env.PORT || 5180;

// Sprint 4 — Auditor de Cumplimiento por IA. Sin ANTHROPIC_API_KEY el endpoint
// responde 503 con mensaje claro — nunca genera hallazgos simulados.
const AI_MODEL = process.env.AI_MODEL || 'claude-sonnet-4-6';
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;
if (!anthropic) {
  console.warn('[ia] ANTHROPIC_API_KEY no está definida — /api/auditoria-ia/ejecutar responderá 503 hasta que se configure.');
}

// SESSION_SECRET debe fijarse como variable de entorno real en el hosting
// (nunca commitear el valor real). El fallback de abajo es SOLO para
// desarrollo local y se regenera en cada arranque si falta.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[seguridad] SESSION_SECRET no está definida — usando una generada al azar en este arranque (las sesiones no sobreviven un reinicio). Defínela antes de publicar.');
}

app.use(helmet({
  contentSecurityPolicy: false, // el scaffold usa CDN de Tailwind + Google Fonts inline; CSP estricto lo rompería
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta de nuevo en unos minutos.' },
}));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }, // 8h
}));

app.use(express.json());

// ---------------------------------------------------------------------------
// Sprint 0 — Auth real por usuario (reemplaza el portón de contraseña única).
// ---------------------------------------------------------------------------

function asyncRoute(fn) {
  return (req, res) => fn(req, res).catch(err => {
    console.error(err);
    res.status(500).json({ error: 'Error interno', detalle: err.message });
  });
}

// Sprint 1 — Frente A: locking optimista, compartido por las 9 rutas PUT de edición
// genérica (matriz-legal/:id/avanzar es una transición de estado, no un edit — resuelve
// su propia concurrencia inline, ver esa ruta). `tabla` es siempre un literal fijo del
// código, nunca un valor del cliente — seguro interpolarlo en la sentencia.
async function actualizarConVersion(req, res, { tabla, campos, valores, entidad }) {
  const version = Number(req.body.version);
  if (!Number.isInteger(version)) {
    return res.status(400).json({ error: `Falta "version" (entero) en el cuerpo — recarga ${entidad} y vuelve a intentar` });
  }
  const asignaciones = campos.map((c, i) => `${c}=$${i + 1}`).join(', ');
  const { rows } = await req.db.query(
    `UPDATE ${tabla} SET ${asignaciones}, version = version + 1 WHERE id=$${campos.length + 1} AND version=$${campos.length + 2} RETURNING *`,
    [...valores, req.params.id, version]
  );
  if (rows.length) return res.json(rows[0]);
  const existe = await req.db.query(`SELECT 1 FROM ${tabla} WHERE id=$1`, [req.params.id]);
  return res.status(existe.rows.length ? 409 : 404).json({
    error: existe.rows.length
      ? `${entidad} fue editado por otro usuario mientras tanto — recarga antes de guardar`
      : `${entidad} no encontrado`,
  });
}

app.post('/api/login', asyncRoute(async (req, res) => {
  const { cedula, password } = req.body || {};
  if (!cedula || !password) return res.status(400).json({ error: 'cedula y password son obligatorios' });

  // Lookup de credenciales cruza tenants por diseño (no se sabe el tenant antes
  // de identificarse) — usa un cliente propio con app.is_superadmin LOCAL a esta
  // única transacción de login, nunca expuesto al request en sí.
  const client = await pool.connect();
  let user;
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL app.is_superadmin = 'true'");
    const { rows } = await client.query(
      `SELECT u.id, u.nombre, u.tenant_id, u.rol_id, u.estado_cuenta, c.password_hash
       FROM users_app u JOIN auth_credentials c ON c.user_id = u.id
       WHERE u.cedula = $1`,
      [cedula]
    );
    user = rows[0] || null;
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
  if (user.estado_cuenta !== 'Activo') return res.status(403).json({ error: 'Cuenta suspendida o inactiva' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

  req.session.user_id = user.id;
  req.session.tenant_id = user.tenant_id;
  req.session.rol_id = user.rol_id;
  req.session.nombre = user.nombre;

  await pool.query('UPDATE users_app SET ultimo_acceso = $1 WHERE id = $2', [new Date().toISOString(), user.id]);
  res.json({ ok: true, user: { id: user.id, nombre: user.nombre, tenant_id: user.tenant_id, rol_id: user.rol_id } });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/session', (req, res) => {
  if (!req.session.user_id) return res.status(401).json({ error: 'No autenticado' });
  res.json({ user_id: req.session.user_id, nombre: req.session.nombre, tenant_id: req.session.tenant_id, rol_id: req.session.rol_id });
});

// Puerta de autenticación: todo /api/* salvo login/health exige sesión real.
app.use((req, res, next) => {
  const openPaths = ['/api/login', '/api/health'];
  if (openPaths.includes(req.path) || req.session.user_id) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'No autenticado' });
  return next(); // páginas estáticas siguen sirviéndose; el front redirige a /login.html si no hay sesión activa
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Capa 2 de aislamiento — cliente por-request con SET LOCAL app.tenant_id /
// app.is_superadmin, dentro de una transacción por request (RLS real, ver
// migrations/001_sprint0_blindaje.sql). Nunca deriva el tenant de query/body.
// ---------------------------------------------------------------------------

async function tenantScope(req, res, next) {
  if (!req.session.user_id) return res.status(401).json({ error: 'No autenticado' });
  const client = await pool.connect();
  let released = false;
  const release = async (commit) => {
    if (released) return;
    released = true;
    try { await client.query(commit ? 'COMMIT' : 'ROLLBACK'); } catch { /* conexión ya pudo cerrarse */ }
    client.release();
  };
  try {
    await client.query('BEGIN');
    const esSuperadmin = req.session.rol_id === 'super-admin';
    await client.query("SET LOCAL app.is_superadmin = $1", [esSuperadmin ? 'true' : 'false']);
    await client.query('SET LOCAL app.tenant_id = $1', [req.session.tenant_id || '']);
    req.db = client;
    res.on('finish', () => release(res.statusCode < 500));
    res.on('close', () => release(false));
    next();
  } catch (err) {
    await release(false);
    next(err);
  }
}

function requireSuperadmin(req, res, next) {
  if (req.session.rol_id !== 'super-admin') return res.status(403).json({ error: 'Requiere rol Super-Admin' });
  next();
}

app.use('/api', tenantScope);

// --- Roles y permisos (parametrizacion) ---
app.get('/api/modules', (_req, res) => res.json({ modules: MODULES, actions: ACTIONS }));

app.get('/api/roles', asyncRoute(async (req, res) => {
  const { rows } = await req.db.query('SELECT * FROM roles ORDER BY id');
  res.json(rows);
}));

app.put('/api/roles/:id', requireSuperadmin, asyncRoute(async (req, res) => {
  const { permisos } = req.body;
  if (!permisos) return res.status(400).json({ error: 'Falta el objeto permisos' });
  await actualizarConVersion(req, res, { tabla: 'roles', campos: ['permisos'], valores: [permisos], entidad: 'El rol' });
}));

// --- Clientes (Tenant_Organizations) — gestión de plataforma, solo Super-Admin ---
app.get('/api/tenants', asyncRoute(async (req, res) => {
  const { rows } = await req.db.query('SELECT * FROM tenants ORDER BY id');
  res.json(rows);
}));

app.get('/api/tenants/:id', asyncRoute(async (req, res) => {
  const { rows } = await req.db.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json(rows[0]);
}));

app.post('/api/tenants', requireSuperadmin, asyncRoute(async (req, res) => {
  const { nit, razon_social, sector, plan_saas } = req.body;
  if (!nit || !razon_social || !sector || !plan_saas) {
    return res.status(400).json({ error: 'nit, razon_social, sector y plan_saas son obligatorios' });
  }
  const id = await nextId('tenants', 'TEN', 4);
  const { rows } = await req.db.query(
    `INSERT INTO tenants (id, nit, razon_social, sector, plan_saas, usuarios, obras_puestos, cumplimiento_sgsst, estado, fecha_alta)
     VALUES ($1,$2,$3,$4,$5,0,0,0,'Trial',$6) RETURNING *`,
    [id, nit, razon_social, sector, plan_saas, new Date().toISOString().slice(0, 10)]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/tenants/:id', requireSuperadmin, asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  await actualizarConVersion(req, res, {
    tabla: 'tenants',
    campos: ['nit', 'razon_social', 'sector', 'plan_saas', 'usuarios', 'obras_puestos', 'cumplimiento_sgsst', 'estado', 'fecha_alta'],
    valores: [merged.nit, merged.razon_social, merged.sector, merged.plan_saas, merged.usuarios, merged.obras_puestos, merged.cumplimiento_sgsst, merged.estado, merged.fecha_alta],
    entidad: 'El cliente',
  });
}));

app.delete('/api/tenants/:id', requireSuperadmin, asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM tenants WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.status(204).end();
}));

// --- Usuarios (Users_Profiles) ---
// tenant_id ya no se lee de req.query — la fila del propio tenant la impone RLS.
app.get('/api/users', asyncRoute(async (req, res) => {
  const { sector, rol_id, estado } = req.query;
  const { rows: users } = await req.db.query('SELECT * FROM users_app ORDER BY id');
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants');
  const { rows: roles } = await req.db.query('SELECT * FROM roles');
  let result = users.map(u => ({
    ...u,
    tenant: tenants.find(t => t.id === u.tenant_id) || null,
    rol: roles.find(r => r.id === u.rol_id) || null
  }));
  if (sector) result = result.filter(u => u.tenant && u.tenant.sector === sector);
  if (rol_id) result = result.filter(u => u.rol_id === rol_id);
  if (estado) result = result.filter(u => u.estado_arl === estado || u.estado_alturas === estado);
  res.json(result);
}));

app.post('/api/users', asyncRoute(async (req, res) => {
  const { nombre, cedula, rol_id } = req.body;
  if (!nombre || !cedula || !rol_id) {
    return res.status(400).json({ error: 'nombre, cedula y rol_id son obligatorios' });
  }
  // tenant_id SIEMPRE de la sesión, nunca del body — cierra el hueco de creación cross-tenant.
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('users_app', 'USR', 3);
  const { rows } = await req.db.query(
    `INSERT INTO users_app (id, nombre, cedula, tenant_id, rol_id, estado_arl, estado_alturas, estado_cuenta, ultimo_acceso)
     VALUES ($1,$2,$3,$4,$5,'Parcial','Parcial','Activo',NULL) RETURNING *`,
    [id, nombre, cedula, tenant_id, rol_id]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/users/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM users_app WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'users_app',
    campos: ['nombre', 'cedula', 'tenant_id', 'rol_id', 'estado_arl', 'estado_alturas', 'estado_cuenta', 'ultimo_acceso'],
    valores: [merged.nombre, merged.cedula, merged.tenant_id, merged.rol_id, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta, merged.ultimo_acceso],
    entidad: 'El usuario',
  });
}));

app.delete('/api/users/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM users_app WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.status(204).end();
}));

// --- Proyectos (Tenant_Branches_Projects) ---
app.get('/api/projects', asyncRoute(async (req, res) => {
  const { estado } = req.query;
  const { rows: projects } = await req.db.query('SELECT * FROM projects ORDER BY id');
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants');
  let result = projects.map(p => ({ ...p, tenant: tenants.find(t => t.id === p.tenant_id) || null }));
  if (estado) result = result.filter(p => p.estado === estado);
  res.json(result);
}));

app.get('/api/projects/:id', asyncRoute(async (req, res) => {
  const { rows } = await req.db.query('SELECT * FROM projects WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants WHERE id = $1', [rows[0].tenant_id]);
  res.json({ ...rows[0], tenant: tenants[0] || null });
}));

app.post('/api/projects', asyncRoute(async (req, res) => {
  const { nombre, tipo, ubicacion, fecha_inicio } = req.body;
  if (!nombre || !tipo) return res.status(400).json({ error: 'nombre y tipo son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('projects', 'PRY', 3);
  const { rows } = await req.db.query(
    `INSERT INTO projects (id, tenant_id, nombre, tipo, ubicacion, fecha_inicio, estado, horas_hombre_acumuladas)
     VALUES ($1,$2,$3,$4,$5,$6,'Activo',0) RETURNING *`,
    [id, tenant_id, nombre, tipo, ubicacion || '', fecha_inicio || new Date().toISOString().slice(0, 10)]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/projects/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM projects WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'projects',
    campos: ['tenant_id', 'nombre', 'tipo', 'ubicacion', 'fecha_inicio', 'estado', 'horas_hombre_acumuladas'],
    valores: [merged.tenant_id, merged.nombre, merged.tipo, merged.ubicacion, merged.fecha_inicio, merged.estado, merged.horas_hombre_acumuladas],
    entidad: 'El proyecto',
  });
}));

app.delete('/api/projects/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.status(204).end();
}));

// --- Empleados ---
app.get('/api/empleados', asyncRoute(async (req, res) => {
  const { project_id, cargo, estado } = req.query;
  const { rows: empleados } = await req.db.query('SELECT * FROM empleados ORDER BY id');
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants');
  const { rows: projects } = await req.db.query('SELECT * FROM projects');
  let result = empleados.map(e => ({
    ...e,
    tenant: tenants.find(t => t.id === e.tenant_id) || null,
    project: projects.find(p => p.id === e.project_id) || null
  }));
  if (project_id) result = result.filter(e => e.project_id === project_id);
  if (cargo) result = result.filter(e => e.cargo === cargo);
  if (estado) result = result.filter(e => e.estado_arl === estado || e.estado_alturas === estado || e.estado_cuenta === estado);
  res.json(result);
}));

app.post('/api/empleados', asyncRoute(async (req, res) => {
  const { project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps } = req.body;
  if (!nombre || !cedula || !cargo) return res.status(400).json({ error: 'nombre, cedula y cargo son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('empleados', 'EMP', 3);
  const { rows } = await req.db.query(
    `INSERT INTO empleados (id, tenant_id, project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps, estado_arl, estado_alturas, estado_cuenta)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Parcial','Parcial','Activo') RETURNING *`,
    [id, tenant_id, project_id || null, nombre, cedula, cargo, tipo_contrato || 'Término Fijo', fecha_ingreso || new Date().toISOString().slice(0, 10), eps || '']
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/empleados/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM empleados WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Empleado no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'empleados',
    campos: ['tenant_id', 'project_id', 'nombre', 'cedula', 'cargo', 'tipo_contrato', 'fecha_ingreso', 'eps', 'estado_arl', 'estado_alturas', 'estado_cuenta'],
    valores: [merged.tenant_id, merged.project_id, merged.nombre, merged.cedula, merged.cargo, merged.tipo_contrato, merged.fecha_ingreso, merged.eps, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta],
    entidad: 'El empleado',
  });
}));

app.delete('/api/empleados/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM empleados WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Empleado no encontrado' });
  res.status(204).end();
}));

// --- Charlas Diarias ---
app.get('/api/charlas', asyncRoute(async (req, res) => {
  const { project_id, fecha } = req.query;
  const { rows: charlas } = await req.db.query('SELECT * FROM charlas ORDER BY fecha DESC, id DESC');
  const { rows: projects } = await req.db.query('SELECT * FROM projects');
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants');
  let result = charlas.map(c => {
    const project = projects.find(p => p.id === c.project_id) || null;
    return { ...c, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(c => c.project_id === project_id);
  if (fecha) result = result.filter(c => c.fecha === fecha);
  res.json(result);
}));

app.post('/api/charlas', asyncRoute(async (req, res) => {
  const { project_id, fecha, tema, responsable, asistentes, duracion_min } = req.body;
  if (!project_id || !tema || !responsable) return res.status(400).json({ error: 'project_id, tema y responsable son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('charlas', 'CHD', 3);
  const { rows } = await req.db.query(
    `INSERT INTO charlas (id, project_id, tenant_id, fecha, tema, responsable, asistentes, duracion_min) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [id, project_id, tenant_id, fecha || new Date().toISOString().slice(0, 10), tema, responsable, Number(asistentes) || 0, Number(duracion_min) || 5]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/charlas/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM charlas WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Charla no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'charlas',
    campos: ['project_id', 'fecha', 'tema', 'responsable', 'asistentes', 'duracion_min'],
    valores: [merged.project_id, merged.fecha, merged.tema, merged.responsable, merged.asistentes, merged.duracion_min],
    entidad: 'La charla',
  });
}));

app.delete('/api/charlas/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM charlas WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Charla no encontrada' });
  res.status(204).end();
}));

// --- Bitácora por Proyecto ---
app.get('/api/bitacora', asyncRoute(async (req, res) => {
  const { project_id, tipo } = req.query;
  const { rows: bitacora } = await req.db.query('SELECT * FROM bitacora ORDER BY fecha DESC, id DESC');
  const { rows: projects } = await req.db.query('SELECT * FROM projects');
  const { rows: tenants } = await req.db.query('SELECT * FROM tenants');
  let result = bitacora.map(b => {
    const project = projects.find(p => p.id === b.project_id) || null;
    return { ...b, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(b => b.project_id === project_id);
  if (tipo) result = result.filter(b => b.tipo === tipo);
  res.json(result);
}));

app.post('/api/bitacora', asyncRoute(async (req, res) => {
  const { project_id, fecha, autor, tipo, descripcion } = req.body;
  if (!project_id || !autor || !tipo || !descripcion) return res.status(400).json({ error: 'project_id, autor, tipo y descripcion son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('bitacora', 'BIT', 3);
  const { rows } = await req.db.query(
    `INSERT INTO bitacora (id, project_id, tenant_id, fecha, autor, tipo, descripcion) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, project_id, tenant_id, fecha || new Date().toISOString().slice(0, 10), autor, tipo, descripcion]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/bitacora/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM bitacora WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Entrada no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'bitacora',
    campos: ['project_id', 'fecha', 'autor', 'tipo', 'descripcion'],
    valores: [merged.project_id, merged.fecha, merged.autor, merged.tipo, merged.descripcion],
    entidad: 'La entrada de bitácora',
  });
}));

app.delete('/api/bitacora/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM bitacora WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Entrada no encontrada' });
  res.status(204).end();
}));

// --- Presupuesto por Proyecto ---
app.get('/api/presupuesto', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await req.db.query('SELECT * FROM presupuesto WHERE project_id = $1 ORDER BY id', [project_id])
    : await req.db.query('SELECT * FROM presupuesto ORDER BY id');
  res.json(rows);
}));

app.post('/api/presupuesto', asyncRoute(async (req, res) => {
  const { project_id, rubro, presupuestado } = req.body;
  if (!project_id || !rubro || presupuestado == null) return res.status(400).json({ error: 'project_id, rubro y presupuestado son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('presupuesto', 'PRE', 3);
  const { rows } = await req.db.query(
    `INSERT INTO presupuesto (id, project_id, tenant_id, rubro, presupuestado, ejecutado) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [id, project_id, tenant_id, rubro, Number(presupuestado), Number(req.body.ejecutado) || 0]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/presupuesto/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM presupuesto WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Línea no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'presupuesto',
    campos: ['project_id', 'rubro', 'presupuestado', 'ejecutado'],
    valores: [merged.project_id, merged.rubro, merged.presupuestado, merged.ejecutado],
    entidad: 'La línea de presupuesto',
  });
}));

app.delete('/api/presupuesto/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM presupuesto WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Línea no encontrada' });
  res.status(204).end();
}));

// --- Plan Anual de Trabajo ---
app.get('/api/plan-anual', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await req.db.query('SELECT * FROM plan_anual WHERE project_id = $1 ORDER BY id', [project_id])
    : await req.db.query('SELECT * FROM plan_anual ORDER BY id');
  res.json(rows);
}));

app.post('/api/plan-anual', asyncRoute(async (req, res) => {
  const { project_id, actividad, mes_objetivo, responsable } = req.body;
  if (!project_id || !actividad || !responsable) return res.status(400).json({ error: 'project_id, actividad y responsable son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('plan_anual', 'PLN', 3);
  const { rows } = await req.db.query(
    `INSERT INTO plan_anual (id, project_id, tenant_id, actividad, mes_objetivo, responsable, estado) VALUES ($1,$2,$3,$4,$5,$6,'Pendiente') RETURNING *`,
    [id, project_id, tenant_id, actividad, mes_objetivo || '', responsable]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/plan-anual/:id', asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM plan_anual WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Actividad no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id, tenant_id: current.rows[0].tenant_id };
  await actualizarConVersion(req, res, {
    tabla: 'plan_anual',
    campos: ['project_id', 'actividad', 'mes_objetivo', 'responsable', 'estado'],
    valores: [merged.project_id, merged.actividad, merged.mes_objetivo, merged.responsable, merged.estado],
    entidad: 'La actividad del plan anual',
  });
}));

app.delete('/api/plan-anual/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM plan_anual WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Actividad no encontrada' });
  res.status(204).end();
}));

// --- Documentos por Proyecto ---
app.get('/api/documentos', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await req.db.query('SELECT * FROM documentos WHERE project_id = $1 ORDER BY id', [project_id])
    : await req.db.query('SELECT * FROM documentos ORDER BY id');
  res.json(rows);
}));

app.post('/api/documentos', asyncRoute(async (req, res) => {
  const { project_id, nombre, tipo, subido_por } = req.body;
  if (!project_id || !nombre || !tipo) return res.status(400).json({ error: 'project_id, nombre y tipo son obligatorios' });
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const id = await nextId('documentos', 'DOC', 3);
  const { rows } = await req.db.query(
    `INSERT INTO documentos (id, project_id, tenant_id, nombre, tipo, fecha_subida, subido_por) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, project_id, tenant_id, nombre, tipo, new Date().toISOString().slice(0, 10), subido_por || req.session.nombre || 'Usuario Actual']
  );
  res.status(201).json(rows[0]);
}));

app.delete('/api/documentos/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM documentos WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Documento no encontrado' });
  res.status(204).end();
}));

// --- Matriz de Requisitos Legales (Legal_Norms_Master_Catalog) ---
// Estado sigue el flujo de gobernanza: draft -> pendiente_revision -> aprobado_super_admin ->
// publicado_a_tenants. Lectura abierta a cualquier sesión (RLS legal_norms_read); escritura y
// avance de estado exigen Super-Admin (requireSuperadmin + policy legal_norms_write/update).
const LEGAL_ESTADOS = ['draft', 'pendiente_revision', 'aprobado_super_admin', 'publicado_a_tenants'];

app.get('/api/matriz-legal', asyncRoute(async (req, res) => {
  const { sector, estado } = req.query;
  let { rows } = await req.db.query('SELECT * FROM legal_norms ORDER BY id');
  if (sector) rows = rows.filter(n => n.sector_aplicable === sector || n.sector_aplicable === 'Ambas');
  if (estado) rows = rows.filter(n => n.estado === estado);
  res.json(rows);
}));

app.post('/api/matriz-legal', requireSuperadmin, asyncRoute(async (req, res) => {
  const { codigo_norma, nombre, version_year, sector_aplicable, resumen_requisito } = req.body;
  if (!codigo_norma || !nombre || !sector_aplicable) {
    return res.status(400).json({ error: 'codigo_norma, nombre y sector_aplicable son obligatorios' });
  }
  const id = await nextId('legal_norms', 'NRM', 3);
  const { rows } = await req.db.query(
    `INSERT INTO legal_norms (id, codigo_norma, nombre, version_year, sector_aplicable, estado, fecha_publicacion, resumen_requisito)
     VALUES ($1,$2,$3,$4,$5,'draft',NULL,$6) RETURNING *`,
    [id, codigo_norma, nombre, version_year || null, sector_aplicable, resumen_requisito || '']
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/matriz-legal/:id/avanzar', requireSuperadmin, asyncRoute(async (req, res) => {
  const current = await req.db.query('SELECT * FROM legal_norms WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Norma no encontrada' });
  const idx = LEGAL_ESTADOS.indexOf(current.rows[0].estado);
  if (idx === -1 || idx === LEGAL_ESTADOS.length - 1) {
    return res.status(409).json({ error: `La norma ya está en el último estado (${current.rows[0].estado}).` });
  }
  const nuevoEstado = LEGAL_ESTADOS[idx + 1];
  const fecha_publicacion = nuevoEstado === 'publicado_a_tenants' ? new Date().toISOString().slice(0, 10) : current.rows[0].fecha_publicacion;
  // Concurrencia inline: usa el version que esta misma request acaba de leer arriba,
  // no uno enviado por el cliente — la ventana de riesgo es SELECT→UPDATE de esta
  // request, no el ciclo GET-luego-PUT de un formulario (por eso no pasa por
  // actualizarConVersion, que asume ese segundo patrón).
  const { rows } = await req.db.query(
    'UPDATE legal_norms SET estado=$1, fecha_publicacion=$2, version=version+1 WHERE id=$3 AND version=$4 RETURNING *',
    [nuevoEstado, fecha_publicacion, req.params.id, current.rows[0].version]
  );
  if (!rows.length) return res.status(409).json({ error: 'La norma cambió de estado justo antes de esta solicitud — vuelve a intentar' });
  res.json(rows[0]);
}));

app.delete('/api/matriz-legal/:id', requireSuperadmin, asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM legal_norms WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Norma no encontrada' });
  res.status(204).end();
}));

// --- Permisos de Trabajo Alto Riesgo — "Portería Digital" (High_Risk_Work_Permits) ---
const TIPOS_REQUIEREN_ALTURAS = new Set(['Trabajo en Alturas', 'Espacios Confinados']);

app.get('/api/permisos-trabajo', asyncRoute(async (req, res) => {
  const { project_id, estado } = req.query;
  const { rows: permisos } = await req.db.query('SELECT * FROM permisos_trabajo ORDER BY fecha_creacion DESC, id DESC');
  const { rows: empleados } = await req.db.query('SELECT * FROM empleados');
  let result = permisos.map(p => ({ ...p, empleado: empleados.find(e => e.id === p.empleado_id) || null }));
  if (project_id) result = result.filter(p => p.project_id === project_id);
  if (estado) result = result.filter(p => p.estado === estado);
  res.json(result);
}));

app.post('/api/permisos-trabajo', asyncRoute(async (req, res) => {
  const { project_id, empleado_id, tipo, validez_inicio, validez_fin } = req.body;
  if (!project_id || !empleado_id || !tipo || !validez_fin) {
    return res.status(400).json({ error: 'project_id, empleado_id, tipo y validez_fin son obligatorios' });
  }
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const { rows: empRows } = await req.db.query('SELECT * FROM empleados WHERE id = $1', [empleado_id]);
  if (!empRows.length) return res.status(404).json({ error: 'Empleado no encontrado' });
  const emp = empRows[0];

  // Motor de exclusión: ARL debe estar 'Cumple' siempre; alturas solo si el tipo lo exige.
  let estado = 'Activo';
  let motivo_rechazo = null;
  if (emp.estado_arl !== 'Cumple') {
    estado = 'Rechazado';
    motivo_rechazo = `ARL en estado '${emp.estado_arl || 'Sin registro'}' — se requiere 'Cumple' para emitir el permiso.`;
  } else if (TIPOS_REQUIEREN_ALTURAS.has(tipo) && emp.estado_alturas !== 'Cumple') {
    estado = 'Rechazado';
    motivo_rechazo = `Curso de alturas (Res. 4272/2021) en estado '${emp.estado_alturas || 'Sin registro'}' — se requiere 'Cumple' para trabajo en alturas/espacios confinados.`;
  }

  const id = await nextId('permisos_trabajo', 'PMT', 3);
  const fecha_creacion = new Date().toISOString().slice(0, 10);
  const { rows } = await req.db.query(
    `INSERT INTO permisos_trabajo (id, tenant_id, project_id, empleado_id, tipo, validez_inicio, validez_fin, estado, motivo_rechazo, creado_por, fecha_creacion)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [id, tenant_id, project_id, empleado_id, tipo, validez_inicio || fecha_creacion, validez_fin, estado, motivo_rechazo, req.session.nombre || 'Usuario Actual', fecha_creacion]
  );
  res.status(estado === 'Rechazado' ? 422 : 201).json({ ...rows[0], empleado: emp });
}));

app.delete('/api/permisos-trabajo/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await req.db.query('DELETE FROM permisos_trabajo WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Permiso no encontrado' });
  res.status(204).end();
}));

// --- Inspecciones y Rondas (checklist de ronda, snapshot — no CAPA/causa raíz) ---
app.get('/api/inspecciones', asyncRoute(async (req, res) => {
  const { project_id, sector } = req.query;
  let { rows } = await req.db.query('SELECT * FROM inspecciones_rondas ORDER BY created_at DESC');
  if (project_id) rows = rows.filter(r => r.project_id === project_id);
  if (sector) rows = rows.filter(r => r.sector === sector);
  res.json(rows);
}));

app.post('/api/inspecciones', asyncRoute(async (req, res) => {
  const { project_id, sector, items } = req.body;
  if (!project_id || !sector || !Array.isArray(items) || !items.length) {
    return res.status(400).json({ error: 'project_id, sector e items (array no vacío) son obligatorios' });
  }
  const tenant_id = req.session.rol_id === 'super-admin' && req.body.tenant_id ? req.body.tenant_id : req.session.tenant_id;
  const cumplen = items.filter(i => i.cumple === true).length;
  const porcentaje = +((cumplen / items.length) * 100).toFixed(2);
  const id = await nextId('inspecciones_rondas', 'INS', 4);
  const { rows } = await req.db.query(
    `INSERT INTO inspecciones_rondas (id, tenant_id, project_id, sector, items, porcentaje_cumplimiento, realizado_por)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, tenant_id, project_id, sector, JSON.stringify(items), porcentaje, req.session.nombre || 'Usuario Actual']
  );
  res.status(201).json(rows[0]);
}));

// --- Botón de Pánico / SOS (emergency_alerts) ---
// Sin gate de permisos de módulo: cualquier sesión autenticada puede disparar o ver
// alertas de su tenant — un botón de pánico no debe poder bloquearse por rol.
app.post('/api/emergencias', asyncRoute(async (req, res) => {
  const { tipo, project_id, lat, lng } = req.body;
  const tiposValidos = new Set(['Panico', 'Medica', 'Incendio', 'Intrusion']);
  if (!tiposValidos.has(tipo)) return res.status(400).json({ error: `tipo inválido — debe ser uno de: ${[...tiposValidos].join(', ')}` });
  const id = await nextId('emergency_alerts', 'EMR', 4);
  const { rows } = await req.db.query(
    `INSERT INTO emergency_alerts (id, tenant_id, project_id, user_id, tipo, lat, lng)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, req.session.tenant_id, project_id || null, req.session.user_id, tipo, lat ?? null, lng ?? null]
  );
  res.status(201).json(rows[0]);
}));

app.get('/api/emergencias', asyncRoute(async (req, res) => {
  const { estado } = req.query;
  let { rows } = await req.db.query('SELECT * FROM emergency_alerts ORDER BY created_at DESC');
  if (estado) rows = rows.filter(r => r.estado === estado);
  res.json(rows);
}));

app.put('/api/emergencias/:id', asyncRoute(async (req, res) => {
  const { estado, version } = req.body;
  const estadosValidos = new Set(['Activa', 'Atendida', 'Falsa_Alarma']);
  if (!estadosValidos.has(estado)) return res.status(400).json({ error: `estado inválido — debe ser uno de: ${[...estadosValidos].join(', ')}` });
  if (!Number.isInteger(Number(version))) return res.status(400).json({ error: 'Falta "version" (entero) en el cuerpo' });
  const atendido_en = estado === 'Activa' ? null : new Date().toISOString();
  const { rows } = await req.db.query(
    `UPDATE emergency_alerts SET estado=$1, atendido_por=$2, atendido_en=$3, version=version+1
     WHERE id=$4 AND version=$5 RETURNING *`,
    [estado, req.session.nombre || 'Usuario Actual', atendido_en, req.params.id, version]
  );
  if (!rows.length) {
    const existe = await req.db.query('SELECT 1 FROM emergency_alerts WHERE id=$1', [req.params.id]);
    return res.status(existe.rows.length ? 409 : 404).json({
      error: existe.rows.length ? 'La alerta fue actualizada por otro usuario mientras tanto' : 'Alerta no encontrada',
    });
  }
  res.json(rows[0]);
}));

// --- Auditor de Cumplimiento por IA (ai_audit_findings) ---
// 'documentos' NO se evalúa: son solo metadatos (nombre/tipo/fecha), sin extracción
// real de contenido de archivo — no hay nada que un modelo pueda auditar ahí todavía.
const TOPE_REGISTROS_POR_FUENTE = 20;

function formatearCharla(r) { return `[${r.id}] ${r.fecha} — "${r.tema}" (responsable: ${r.responsable}, ${r.asistentes} asistentes)`; }
function formatearBitacora(r) { return `[${r.id}] ${r.fecha} — ${r.tipo}: ${r.descripcion}`; }
function formatearPermiso(r) { return `[${r.id}] ${r.tipo} — estado: ${r.estado}${r.motivo_rechazo ? ` (${r.motivo_rechazo})` : ''}`; }
function formatearInspeccion(r) {
  const items = (r.items || []).map(it => `${it.item}: ${it.cumple ? 'CUMPLE' : 'NO CUMPLE'}`).join('; ');
  return `[${r.id}] ${r.fecha_creacion || r.created_at} — sector ${r.sector}, ${r.porcentaje_cumplimiento}% cumplimiento. Ítems: ${items}`;
}

app.post('/api/auditoria-ia/ejecutar', requireSuperadmin, asyncRoute(async (req, res) => {
  if (!anthropic) return res.status(503).json({ error: 'IA no configurada — falta ANTHROPIC_API_KEY en el entorno.' });
  const { project_id } = req.body;
  if (!project_id) return res.status(400).json({ error: 'project_id es obligatorio — se audita un proyecto a la vez.' });

  const { rows: projectRows } = await req.db.query('SELECT * FROM projects WHERE id = $1', [project_id]);
  if (!projectRows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
  const project = projectRows[0];
  const { rows: tenantRows } = await req.db.query('SELECT sector FROM tenants WHERE id = $1', [project.tenant_id]);
  const sector = tenantRows[0]?.sector || 'Ambas';

  const { rows: normas } = await req.db.query(
    `SELECT codigo_norma, nombre, resumen_requisito FROM legal_norms
     WHERE estado = 'publicado_a_tenants' AND (sector_aplicable = $1 OR sector_aplicable = 'Ambas')`,
    [sector]
  );
  if (!normas.length) return res.status(422).json({ error: 'No hay normas publicado_a_tenants aplicables al sector de este tenant — no hay contra qué auditar.' });
  const bloqueNormas = normas.map(n => `- ${n.codigo_norma} (${n.nombre}): ${n.resumen_requisito}`).join('\n');

  const FUENTES = [
    { fuente: 'charlas', query: 'SELECT * FROM charlas WHERE project_id = $1 ORDER BY fecha DESC', formatear: formatearCharla },
    { fuente: 'bitacora', query: 'SELECT * FROM bitacora WHERE project_id = $1 ORDER BY fecha DESC', formatear: formatearBitacora },
    { fuente: 'permisos_trabajo', query: 'SELECT * FROM permisos_trabajo WHERE project_id = $1 ORDER BY fecha_creacion DESC', formatear: formatearPermiso },
    { fuente: 'inspecciones_rondas', query: 'SELECT * FROM inspecciones_rondas WHERE project_id = $1 ORDER BY created_at DESC', formatear: formatearInspeccion },
  ];

  let totalEvaluados = 0;
  let totalHallazgos = 0;

  for (const f of FUENTES) {
    const { rows: yaAuditados } = await req.db.query('SELECT fuente_id FROM ai_audit_findings WHERE fuente = $1', [f.fuente]);
    const idsAuditados = new Set(yaAuditados.map(r => r.fuente_id));
    const { rows: candidatos } = await req.db.query(f.query, [project_id]);
    const pendientes = candidatos.filter(r => !idsAuditados.has(r.id)).slice(0, TOPE_REGISTROS_POR_FUENTE);
    if (!pendientes.length) continue;
    totalEvaluados += pendientes.length;

    const bloqueRegistros = pendientes.map(f.formatear).join('\n');
    let respuesta;
    try {
      respuesta = await anthropic.messages.create({
        model: AI_MODEL,
        max_tokens: 2048,
        system: [
          {
            type: 'text',
            text: 'Eres un auditor de cumplimiento HSEQ para Colombia. Evalúa los registros contra las normas dadas. Responde ÚNICAMENTE con un array JSON (sin markdown, sin texto adicional): [{"fuente_id": "...", "hallazgo": "...", "norma_citada": "...", "severidad": "Baja"|"Media"|"Alta"|"Critica", "confianza": 0.0-1.0}]. Si un registro no presenta ningún problema de cumplimiento real, NO lo incluyas — el array puede quedar vacío. No inventes normas que no estén en la lista dada.',
          },
          { type: 'text', text: `Normas vigentes aplicables:\n${bloqueNormas}`, cache_control: { type: 'ephemeral' } },
        ],
        messages: [{ role: 'user', content: `Fuente: ${f.fuente}\n\n${bloqueRegistros}` }],
      });
    } catch (err) {
      console.error(`[ia] Error llamando a Claude para fuente ${f.fuente}:`, err.message);
      continue; // una fuente fallando no debe tumbar las demás
    }

    let hallazgos = [];
    try {
      const texto = respuesta.content.find(b => b.type === 'text')?.text || '[]';
      hallazgos = JSON.parse(texto.trim());
      if (!Array.isArray(hallazgos)) hallazgos = [];
    } catch {
      console.error(`[ia] Respuesta no parseable como JSON para fuente ${f.fuente}`);
      continue;
    }

    for (const h of hallazgos) {
      if (!h.fuente_id || !h.hallazgo || !h.severidad) continue;
      const id = await nextId('ai_audit_findings', 'AIF', 4);
      await req.db.query(
        `INSERT INTO ai_audit_findings (id, tenant_id, project_id, fuente, fuente_id, hallazgo, norma_citada, severidad, confianza_modelo)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [id, project.tenant_id, project_id, f.fuente, h.fuente_id, h.hallazgo, h.norma_citada || null, h.severidad, h.confianza ?? null]
      );
      totalHallazgos++;
    }
  }

  res.json({ evaluados: totalEvaluados, hallazgos_creados: totalHallazgos });
}));

app.get('/api/ai-audit-findings', asyncRoute(async (req, res) => {
  const { estado, project_id } = req.query;
  let { rows } = await req.db.query('SELECT * FROM ai_audit_findings ORDER BY created_at DESC');
  if (estado) rows = rows.filter(r => r.estado === estado);
  if (project_id) rows = rows.filter(r => r.project_id === project_id);
  res.json(rows);
}));

app.put('/api/ai-audit-findings/:id', asyncRoute(async (req, res) => {
  const { estado, version } = req.body;
  const estadosValidos = new Set(['Nuevo', 'Revisado', 'Descartado', 'Escalado']);
  if (!estadosValidos.has(estado)) return res.status(400).json({ error: `estado inválido — debe ser uno de: ${[...estadosValidos].join(', ')}` });
  if (!Number.isInteger(Number(version))) return res.status(400).json({ error: 'Falta "version" (entero) en el cuerpo' });
  const { rows } = await req.db.query(
    'UPDATE ai_audit_findings SET estado=$1, revisado_por=$2, version=version+1 WHERE id=$3 AND version=$4 RETURNING *',
    [estado, req.session.nombre || 'Usuario Actual', req.params.id, version]
  );
  if (!rows.length) {
    const existe = await req.db.query('SELECT 1 FROM ai_audit_findings WHERE id=$1', [req.params.id]);
    return res.status(existe.rows.length ? 409 : 404).json({
      error: existe.rows.length ? 'El hallazgo fue actualizado por otro usuario mientras tanto' : 'Hallazgo no encontrado',
    });
  }
  res.json(rows[0]);
}));

// --- Reportes Ejecutivos (Motor de Indicadores BI) ---
app.get('/api/reportes/resumen', asyncRoute(async (req, res) => {
  const [projects, tenants, accidentes, presupuesto, charlas, permisos, normas] = await Promise.all([
    req.db.query('SELECT * FROM projects').then(r => r.rows),
    req.db.query('SELECT * FROM tenants').then(r => r.rows),
    req.db.query('SELECT * FROM accidentes').then(r => r.rows),
    req.db.query('SELECT * FROM presupuesto').then(r => r.rows),
    req.db.query('SELECT * FROM charlas').then(r => r.rows),
    req.db.query('SELECT * FROM permisos_trabajo').then(r => r.rows),
    req.db.query('SELECT * FROM legal_norms').then(r => r.rows),
  ]);

  const porProyecto = projects.map(p => {
    const accProyecto = accidentes.filter(a => a.project_id === p.id);
    const incapacitantes = accProyecto.filter(a => a.tipo === 'Incapacitante' || a.tipo === 'Fatal').length;
    const diasPerdidos = accProyecto.reduce((sum, a) => sum + (a.dias_perdidos || 0), 0);
    const horas = Number(p.horas_hombre_acumuladas) || 0;
    const IF = horas > 0 ? +((incapacitantes / horas) * 240000).toFixed(2) : 0;
    const IS = horas > 0 ? +((diasPerdidos / horas) * 240000).toFixed(2) : 0;
    const tenant = tenants.find(t => t.id === p.tenant_id) || null;
    return { project_id: p.id, nombre: p.nombre, tenant_id: p.tenant_id, tenant_nombre: tenant ? tenant.razon_social : null, horas_hombre_acumuladas: horas, accidentes_incapacitantes: incapacitantes, dias_perdidos: diasPerdidos, IF, IS };
  });

  const presupuestoTotales = { presupuestado: 0, ejecutado: 0 };
  for (const r of presupuesto) { presupuestoTotales.presupuestado += Number(r.presupuestado) || 0; presupuestoTotales.ejecutado += Number(r.ejecutado) || 0; }

  const cumplimientoPromedioSgsst = tenants.length
    ? +(tenants.reduce((s, t) => s + (Number(t.cumplimiento_sgsst) || 0), 0) / tenants.length).toFixed(1)
    : 0;

  // dias_sin_accidentes: real, calculado desde la fecha del accidente más reciente — no inventado.
  // null si nunca hubo un accidente registrado (el frontend debe mostrar "sin registros", no un número.
  const fechaUltimoAccidente = accidentes.length
    ? accidentes.map(a => a.fecha).sort().slice(-1)[0]
    : null;
  const diasSinAccidentes = fechaUltimoAccidente
    ? Math.floor((Date.now() - new Date(fechaUltimoAccidente).getTime()) / 86400000)
    : null;

  res.json({
    por_proyecto: porProyecto,
    presupuesto_totales: presupuestoTotales,
    cumplimiento_promedio_sgsst: cumplimientoPromedioSgsst,
    dias_sin_accidentes: diasSinAccidentes,
    total_charlas: charlas.length,
    permisos: { activos: permisos.filter(p => p.estado === 'Activo').length, rechazados: permisos.filter(p => p.estado === 'Rechazado').length },
    normas_legales: { total: normas.length, pendientes_revision: normas.filter(n => n.estado === 'pendiente_revision').length, publicadas: normas.filter(n => n.estado === 'publicado_a_tenants').length },
  });
}));

// Alertas del Centro de Mando — 3 categorías, todas derivadas de datos reales existentes,
// ninguna inventada. Reemplaza las 3 tarjetas hardcodeadas de centro-mando.html.
app.get('/api/reportes/alertas', asyncRoute(async (req, res) => {
  const [empleadosVencidos, tenantsTrial, ultimoIncidente, projects] = await Promise.all([
    req.db.query("SELECT id, nombre, project_id, tenant_id FROM empleados WHERE estado_alturas = 'Vencido' ORDER BY nombre").then(r => r.rows),
    req.db.query("SELECT id, razon_social FROM tenants WHERE estado = 'Trial' ORDER BY razon_social").then(r => r.rows),
    req.db.query("SELECT id, project_id, descripcion, fecha FROM bitacora WHERE tipo = 'Incidente' ORDER BY fecha DESC, id DESC LIMIT 1").then(r => r.rows),
    req.db.query('SELECT id, nombre FROM projects').then(r => r.rows),
  ]);
  const nombreProyecto = (id) => projects.find(p => p.id === id)?.nombre || null;
  res.json({
    alturas_vencidas: empleadosVencidos.map(e => ({ ...e, project_nombre: nombreProyecto(e.project_id) })),
    tenants_trial: tenantsTrial,
    ultimo_incidente: ultimoIncidente[0] ? { ...ultimoIncidente[0], project_nombre: nombreProyecto(ultimoIncidente[0].project_id) } : null,
  });
}));

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.redirect('/login.html');
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`SIG HSEQ escuchando en http://localhost:${PORT} (PostgreSQL conectado, auth real activa)`);
    });
  })
  .catch(err => {
    console.error('[db] No se pudo inicializar la base de datos:', err.message);
    process.exit(1);
  });
