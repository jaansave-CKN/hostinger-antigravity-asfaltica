const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');
const { pool, initDb, nextId, MODULES, ACTIONS } = require('./db');

const app = express();
const PORT = process.env.PORT || 5180;

// SITE_PASSWORD y SESSION_SECRET deben fijarse como variables de entorno reales
// en el hosting (nunca commitear valores reales). Los fallback de aquí abajo
// son SOLO para desarrollo local y se regeneran en cada arranque si faltan.
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'hseq-demo-2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SITE_PASSWORD) {
  console.warn('[seguridad] SITE_PASSWORD no está definida en variables de entorno — usando clave de demo por defecto. Defínela antes de publicar esto.');
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

// ── Portón de acceso compartido (mínimo viable mientras no hay auth real) ──
app.post('/api/gate-login', express.json(), (req, res) => {
  if (req.body && req.body.password === SITE_PASSWORD) {
    req.session.authenticated = true;
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false, error: 'Contraseña incorrecta' });
});

app.use((req, res, next) => {
  const openPaths = ['/gate.html', '/api/gate-login', '/api/health'];
  if (openPaths.includes(req.path) || req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'No autenticado' });
  return res.redirect('/gate.html');
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Persistencia real en PostgreSQL (ver db.js). Todas las rutas son async.
// ---------------------------------------------------------------------------

function asyncRoute(fn) {
  return (req, res) => fn(req, res).catch(err => {
    console.error(err);
    res.status(500).json({ error: 'Error interno', detalle: err.message });
  });
}

// --- Roles y permisos (parametrizacion) ---
app.get('/api/modules', (_req, res) => res.json({ modules: MODULES, actions: ACTIONS }));

app.get('/api/roles', asyncRoute(async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM roles ORDER BY id');
  res.json(rows);
}));

app.put('/api/roles/:id', asyncRoute(async (req, res) => {
  const { permisos } = req.body;
  if (!permisos) return res.status(400).json({ error: 'Falta el objeto permisos' });
  const { rows } = await pool.query('UPDATE roles SET permisos = $1 WHERE id = $2 RETURNING *', [permisos, req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Rol no encontrado' });
  res.json(rows[0]);
}));

// --- Clientes (Tenant_Organizations) ---
app.get('/api/tenants', asyncRoute(async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM tenants ORDER BY id');
  res.json(rows);
}));

app.get('/api/tenants/:id', asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json(rows[0]);
}));

app.post('/api/tenants', asyncRoute(async (req, res) => {
  const { nit, razon_social, sector, plan_saas } = req.body;
  if (!nit || !razon_social || !sector || !plan_saas) {
    return res.status(400).json({ error: 'nit, razon_social, sector y plan_saas son obligatorios' });
  }
  const id = await nextId('tenants', 'TEN', 4);
  const { rows } = await pool.query(
    `INSERT INTO tenants (id, nit, razon_social, sector, plan_saas, usuarios, obras_puestos, cumplimiento_sgsst, estado, fecha_alta)
     VALUES ($1,$2,$3,$4,$5,0,0,0,'Trial',$6) RETURNING *`,
    [id, nit, razon_social, sector, plan_saas, new Date().toISOString().slice(0, 10)]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/tenants/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE tenants SET nit=$1, razon_social=$2, sector=$3, plan_saas=$4, usuarios=$5, obras_puestos=$6, cumplimiento_sgsst=$7, estado=$8, fecha_alta=$9 WHERE id=$10 RETURNING *`,
    [merged.nit, merged.razon_social, merged.sector, merged.plan_saas, merged.usuarios, merged.obras_puestos, merged.cumplimiento_sgsst, merged.estado, merged.fecha_alta, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/tenants/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM tenants WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.status(204).end();
}));

// --- Usuarios (Users_Profiles) ---
app.get('/api/users', asyncRoute(async (req, res) => {
  const { tenant_id, sector, rol_id, estado } = req.query;
  const { rows: users } = await pool.query('SELECT * FROM users_app ORDER BY id');
  const { rows: tenants } = await pool.query('SELECT * FROM tenants');
  const { rows: roles } = await pool.query('SELECT * FROM roles');
  let result = users.map(u => ({
    ...u,
    tenant: tenants.find(t => t.id === u.tenant_id) || null,
    rol: roles.find(r => r.id === u.rol_id) || null
  }));
  if (tenant_id) result = result.filter(u => u.tenant_id === tenant_id);
  if (sector) result = result.filter(u => u.tenant && u.tenant.sector === sector);
  if (rol_id) result = result.filter(u => u.rol_id === rol_id);
  if (estado) result = result.filter(u => u.estado_arl === estado || u.estado_alturas === estado);
  res.json(result);
}));

app.post('/api/users', asyncRoute(async (req, res) => {
  const { nombre, cedula, tenant_id, rol_id } = req.body;
  if (!nombre || !cedula || !tenant_id || !rol_id) {
    return res.status(400).json({ error: 'nombre, cedula, tenant_id y rol_id son obligatorios' });
  }
  const id = await nextId('users_app', 'USR', 3);
  const { rows } = await pool.query(
    `INSERT INTO users_app (id, nombre, cedula, tenant_id, rol_id, estado_arl, estado_alturas, estado_cuenta, ultimo_acceso)
     VALUES ($1,$2,$3,$4,$5,'Parcial','Parcial','Activo',NULL) RETURNING *`,
    [id, nombre, cedula, tenant_id, rol_id]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/users/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM users_app WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE users_app SET nombre=$1, cedula=$2, tenant_id=$3, rol_id=$4, estado_arl=$5, estado_alturas=$6, estado_cuenta=$7, ultimo_acceso=$8 WHERE id=$9 RETURNING *`,
    [merged.nombre, merged.cedula, merged.tenant_id, merged.rol_id, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta, merged.ultimo_acceso, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/users/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM users_app WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.status(204).end();
}));

// --- Proyectos (Tenant_Branches_Projects) ---
app.get('/api/projects', asyncRoute(async (req, res) => {
  const { tenant_id, estado } = req.query;
  const { rows: projects } = await pool.query('SELECT * FROM projects ORDER BY id');
  const { rows: tenants } = await pool.query('SELECT * FROM tenants');
  let result = projects.map(p => ({ ...p, tenant: tenants.find(t => t.id === p.tenant_id) || null }));
  if (tenant_id) result = result.filter(p => p.tenant_id === tenant_id);
  if (estado) result = result.filter(p => p.estado === estado);
  res.json(result);
}));

app.get('/api/projects/:id', asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM projects WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
  const { rows: tenants } = await pool.query('SELECT * FROM tenants WHERE id = $1', [rows[0].tenant_id]);
  res.json({ ...rows[0], tenant: tenants[0] || null });
}));

app.post('/api/projects', asyncRoute(async (req, res) => {
  const { tenant_id, nombre, tipo, ubicacion, fecha_inicio } = req.body;
  if (!tenant_id || !nombre || !tipo) {
    return res.status(400).json({ error: 'tenant_id, nombre y tipo son obligatorios' });
  }
  const id = await nextId('projects', 'PRY', 3);
  const { rows } = await pool.query(
    `INSERT INTO projects (id, tenant_id, nombre, tipo, ubicacion, fecha_inicio, estado, horas_hombre_acumuladas)
     VALUES ($1,$2,$3,$4,$5,$6,'Activo',0) RETURNING *`,
    [id, tenant_id, nombre, tipo, ubicacion || '', fecha_inicio || new Date().toISOString().slice(0, 10)]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/projects/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM projects WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Proyecto no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE projects SET tenant_id=$1, nombre=$2, tipo=$3, ubicacion=$4, fecha_inicio=$5, estado=$6, horas_hombre_acumuladas=$7 WHERE id=$8 RETURNING *`,
    [merged.tenant_id, merged.nombre, merged.tipo, merged.ubicacion, merged.fecha_inicio, merged.estado, merged.horas_hombre_acumuladas, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/projects/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.status(204).end();
}));

// --- Empleados ---
app.get('/api/empleados', asyncRoute(async (req, res) => {
  const { tenant_id, project_id, cargo, estado } = req.query;
  const { rows: empleados } = await pool.query('SELECT * FROM empleados ORDER BY id');
  const { rows: tenants } = await pool.query('SELECT * FROM tenants');
  const { rows: projects } = await pool.query('SELECT * FROM projects');
  let result = empleados.map(e => ({
    ...e,
    tenant: tenants.find(t => t.id === e.tenant_id) || null,
    project: projects.find(p => p.id === e.project_id) || null
  }));
  if (tenant_id) result = result.filter(e => e.tenant_id === tenant_id);
  if (project_id) result = result.filter(e => e.project_id === project_id);
  if (cargo) result = result.filter(e => e.cargo === cargo);
  if (estado) result = result.filter(e => e.estado_arl === estado || e.estado_alturas === estado || e.estado_cuenta === estado);
  res.json(result);
}));

app.post('/api/empleados', asyncRoute(async (req, res) => {
  const { tenant_id, project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps } = req.body;
  if (!tenant_id || !nombre || !cedula || !cargo) {
    return res.status(400).json({ error: 'tenant_id, nombre, cedula y cargo son obligatorios' });
  }
  const id = await nextId('empleados', 'EMP', 3);
  const { rows } = await pool.query(
    `INSERT INTO empleados (id, tenant_id, project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps, estado_arl, estado_alturas, estado_cuenta)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Parcial','Parcial','Activo') RETURNING *`,
    [id, tenant_id, project_id || null, nombre, cedula, cargo, tipo_contrato || 'Término Fijo', fecha_ingreso || new Date().toISOString().slice(0, 10), eps || '']
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/empleados/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM empleados WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Empleado no encontrado' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE empleados SET tenant_id=$1, project_id=$2, nombre=$3, cedula=$4, cargo=$5, tipo_contrato=$6, fecha_ingreso=$7, eps=$8, estado_arl=$9, estado_alturas=$10, estado_cuenta=$11 WHERE id=$12 RETURNING *`,
    [merged.tenant_id, merged.project_id, merged.nombre, merged.cedula, merged.cargo, merged.tipo_contrato, merged.fecha_ingreso, merged.eps, merged.estado_arl, merged.estado_alturas, merged.estado_cuenta, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/empleados/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM empleados WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Empleado no encontrado' });
  res.status(204).end();
}));

// --- Charlas Diarias ---
app.get('/api/charlas', asyncRoute(async (req, res) => {
  const { project_id, tenant_id, fecha } = req.query;
  const { rows: charlas } = await pool.query('SELECT * FROM charlas ORDER BY fecha DESC, id DESC');
  const { rows: projects } = await pool.query('SELECT * FROM projects');
  const { rows: tenants } = await pool.query('SELECT * FROM tenants');
  let result = charlas.map(c => {
    const project = projects.find(p => p.id === c.project_id) || null;
    return { ...c, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(c => c.project_id === project_id);
  if (tenant_id) result = result.filter(c => c.project && c.project.tenant_id === tenant_id);
  if (fecha) result = result.filter(c => c.fecha === fecha);
  res.json(result);
}));

app.post('/api/charlas', asyncRoute(async (req, res) => {
  const { project_id, fecha, tema, responsable, asistentes, duracion_min } = req.body;
  if (!project_id || !tema || !responsable) {
    return res.status(400).json({ error: 'project_id, tema y responsable son obligatorios' });
  }
  const id = await nextId('charlas', 'CHD', 3);
  const { rows } = await pool.query(
    `INSERT INTO charlas (id, project_id, fecha, tema, responsable, asistentes, duracion_min) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [id, project_id, fecha || new Date().toISOString().slice(0, 10), tema, responsable, Number(asistentes) || 0, Number(duracion_min) || 5]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/charlas/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM charlas WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Charla no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE charlas SET project_id=$1, fecha=$2, tema=$3, responsable=$4, asistentes=$5, duracion_min=$6 WHERE id=$7 RETURNING *`,
    [merged.project_id, merged.fecha, merged.tema, merged.responsable, merged.asistentes, merged.duracion_min, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/charlas/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM charlas WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Charla no encontrada' });
  res.status(204).end();
}));

// --- Bitácora por Proyecto ---
app.get('/api/bitacora', asyncRoute(async (req, res) => {
  const { project_id, tenant_id, tipo } = req.query;
  const { rows: bitacora } = await pool.query('SELECT * FROM bitacora ORDER BY fecha DESC, id DESC');
  const { rows: projects } = await pool.query('SELECT * FROM projects');
  const { rows: tenants } = await pool.query('SELECT * FROM tenants');
  let result = bitacora.map(b => {
    const project = projects.find(p => p.id === b.project_id) || null;
    return { ...b, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(b => b.project_id === project_id);
  if (tenant_id) result = result.filter(b => b.project && b.project.tenant_id === tenant_id);
  if (tipo) result = result.filter(b => b.tipo === tipo);
  res.json(result);
}));

app.post('/api/bitacora', asyncRoute(async (req, res) => {
  const { project_id, fecha, autor, tipo, descripcion } = req.body;
  if (!project_id || !autor || !tipo || !descripcion) {
    return res.status(400).json({ error: 'project_id, autor, tipo y descripcion son obligatorios' });
  }
  const id = await nextId('bitacora', 'BIT', 3);
  const { rows } = await pool.query(
    `INSERT INTO bitacora (id, project_id, fecha, autor, tipo, descripcion) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [id, project_id, fecha || new Date().toISOString().slice(0, 10), autor, tipo, descripcion]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/bitacora/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM bitacora WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Entrada no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE bitacora SET project_id=$1, fecha=$2, autor=$3, tipo=$4, descripcion=$5 WHERE id=$6 RETURNING *`,
    [merged.project_id, merged.fecha, merged.autor, merged.tipo, merged.descripcion, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/bitacora/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM bitacora WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Entrada no encontrada' });
  res.status(204).end();
}));

// --- Presupuesto por Proyecto ---
app.get('/api/presupuesto', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await pool.query('SELECT * FROM presupuesto WHERE project_id = $1 ORDER BY id', [project_id])
    : await pool.query('SELECT * FROM presupuesto ORDER BY id');
  res.json(rows);
}));

app.post('/api/presupuesto', asyncRoute(async (req, res) => {
  const { project_id, rubro, presupuestado } = req.body;
  if (!project_id || !rubro || presupuestado == null) {
    return res.status(400).json({ error: 'project_id, rubro y presupuestado son obligatorios' });
  }
  const id = await nextId('presupuesto', 'PRE', 3);
  const { rows } = await pool.query(
    `INSERT INTO presupuesto (id, project_id, rubro, presupuestado, ejecutado) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [id, project_id, rubro, Number(presupuestado), Number(req.body.ejecutado) || 0]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/presupuesto/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM presupuesto WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Línea no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE presupuesto SET project_id=$1, rubro=$2, presupuestado=$3, ejecutado=$4 WHERE id=$5 RETURNING *`,
    [merged.project_id, merged.rubro, merged.presupuestado, merged.ejecutado, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/presupuesto/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM presupuesto WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Línea no encontrada' });
  res.status(204).end();
}));

// --- Plan Anual de Trabajo ---
app.get('/api/plan-anual', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await pool.query('SELECT * FROM plan_anual WHERE project_id = $1 ORDER BY id', [project_id])
    : await pool.query('SELECT * FROM plan_anual ORDER BY id');
  res.json(rows);
}));

app.post('/api/plan-anual', asyncRoute(async (req, res) => {
  const { project_id, actividad, mes_objetivo, responsable } = req.body;
  if (!project_id || !actividad || !responsable) {
    return res.status(400).json({ error: 'project_id, actividad y responsable son obligatorios' });
  }
  const id = await nextId('plan_anual', 'PLN', 3);
  const { rows } = await pool.query(
    `INSERT INTO plan_anual (id, project_id, actividad, mes_objetivo, responsable, estado) VALUES ($1,$2,$3,$4,$5,'Pendiente') RETURNING *`,
    [id, project_id, actividad, mes_objetivo || '', responsable]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/plan-anual/:id', asyncRoute(async (req, res) => {
  const current = await pool.query('SELECT * FROM plan_anual WHERE id = $1', [req.params.id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Actividad no encontrada' });
  const merged = { ...current.rows[0], ...req.body, id: req.params.id };
  const { rows } = await pool.query(
    `UPDATE plan_anual SET project_id=$1, actividad=$2, mes_objetivo=$3, responsable=$4, estado=$5 WHERE id=$6 RETURNING *`,
    [merged.project_id, merged.actividad, merged.mes_objetivo, merged.responsable, merged.estado, req.params.id]
  );
  res.json(rows[0]);
}));

app.delete('/api/plan-anual/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM plan_anual WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Actividad no encontrada' });
  res.status(204).end();
}));

// --- Documentos por Proyecto ---
app.get('/api/documentos', asyncRoute(async (req, res) => {
  const { project_id } = req.query;
  const { rows } = project_id
    ? await pool.query('SELECT * FROM documentos WHERE project_id = $1 ORDER BY id', [project_id])
    : await pool.query('SELECT * FROM documentos ORDER BY id');
  res.json(rows);
}));

app.post('/api/documentos', asyncRoute(async (req, res) => {
  const { project_id, nombre, tipo, subido_por } = req.body;
  if (!project_id || !nombre || !tipo) {
    return res.status(400).json({ error: 'project_id, nombre y tipo son obligatorios' });
  }
  const id = await nextId('documentos', 'DOC', 3);
  const { rows } = await pool.query(
    `INSERT INTO documentos (id, project_id, nombre, tipo, fecha_subida, subido_por) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [id, project_id, nombre, tipo, new Date().toISOString().slice(0, 10), subido_por || 'Usuario Actual']
  );
  res.status(201).json(rows[0]);
}));

app.delete('/api/documentos/:id', asyncRoute(async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM documentos WHERE id = $1', [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'Documento no encontrado' });
  res.status(204).end();
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
      console.log(`SIG HSEQ escuchando en http://localhost:${PORT} (PostgreSQL conectado)`);
    });
  })
  .catch(err => {
    console.error('[db] No se pudo inicializar la base de datos:', err.message);
    process.exit(1);
  });
