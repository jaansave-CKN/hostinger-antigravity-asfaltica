const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool, initDb, nextId, MODULES, ACTIONS } = require('./db');

const app = express();
const PORT = process.env.PORT || 5180;

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
  const { rows } = await req.db.query('UPDATE roles SET permisos = $1 WHERE id = $2 RETURNING *', [permisos, req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Rol no encontrado' });
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE tenants SET nit=$1, razon_social=$2, sector=$3, plan_saas=$4, usuarios=$5, obras_puestos=$6, cumplimiento_sgsst=$7, estado=$8, fecha_alta=$9 WHERE id=$10 RETURNING *`,
    [merged.nit, merged.razon_social, merged.sector, merged.plan_saas, merged.usuarios, merged.obras_puestos, merged.cumplimiento_sgsst, merged.estado, merged.fecha_alta, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE users_app SET nombre=$1, cedula=$2, tenant_id=$3, rol_id=$4, estado_arl=$5, estado_alturas=$6, estado_cuenta=$7, ultimo_acceso=$8 WHERE id=$9 RETURNING *`,
    [merged.nombre, merged.cedula, merged.tenant_id, merged.rol_id, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta, merged.ultimo_acceso, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE projects SET tenant_id=$1, nombre=$2, tipo=$3, ubicacion=$4, fecha_inicio=$5, estado=$6, horas_hombre_acumuladas=$7 WHERE id=$8 RETURNING *`,
    [merged.tenant_id, merged.nombre, merged.tipo, merged.ubicacion, merged.fecha_inicio, merged.estado, merged.horas_hombre_acumuladas, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE empleados SET tenant_id=$1, project_id=$2, nombre=$3, cedula=$4, cargo=$5, tipo_contrato=$6, fecha_ingreso=$7, eps=$8, estado_arl=$9, estado_alturas=$10, estado_cuenta=$11 WHERE id=$12 RETURNING *`,
    [merged.tenant_id, merged.project_id, merged.nombre, merged.cedula, merged.cargo, merged.tipo_contrato, merged.fecha_ingreso, merged.eps, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE charlas SET project_id=$1, fecha=$2, tema=$3, responsable=$4, asistentes=$5, duracion_min=$6 WHERE id=$7 RETURNING *`,
    [merged.project_id, merged.fecha, merged.tema, merged.responsable, merged.asistentes, merged.duracion_min, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE bitacora SET project_id=$1, fecha=$2, autor=$3, tipo=$4, descripcion=$5 WHERE id=$6 RETURNING *`,
    [merged.project_id, merged.fecha, merged.autor, merged.tipo, merged.descripcion, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE presupuesto SET project_id=$1, rubro=$2, presupuestado=$3, ejecutado=$4 WHERE id=$5 RETURNING *`,
    [merged.project_id, merged.rubro, merged.presupuestado, merged.ejecutado, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query(
    `UPDATE plan_anual SET project_id=$1, actividad=$2, mes_objetivo=$3, responsable=$4, estado=$5 WHERE id=$6 RETURNING *`,
    [merged.project_id, merged.actividad, merged.mes_objetivo, merged.responsable, merged.estado, req.params.id]
  );
  res.json(rows[0]);
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
  const { rows } = await req.db.query('UPDATE legal_norms SET estado=$1, fecha_publicacion=$2 WHERE id=$3 RETURNING *', [nuevoEstado, fecha_publicacion, req.params.id]);
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

  res.json({
    por_proyecto: porProyecto,
    presupuesto_totales: presupuestoTotales,
    cumplimiento_promedio_sgsst: cumplimientoPromedioSgsst,
    total_charlas: charlas.length,
    permisos: { activos: permisos.filter(p => p.estado === 'Activo').length, rechazados: permisos.filter(p => p.estado === 'Rechazado').length },
    normas_legales: { total: normas.length, pendientes_revision: normas.filter(n => n.estado === 'pendiente_revision').length, publicadas: normas.filter(n => n.estado === 'publicado_a_tenants').length },
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
