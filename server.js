const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');

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
// Bloquea TODO (estáticos + API) excepto /gate.html, /api/gate-login y /api/health.
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
// Datos en memoria — scaffold de demostracion.
// Reemplazar por PostgreSQL (tablas Tenant_Organizations, Users_Profiles,
// Roles/Permisos) cuando el modelo de entidades quede cerrado.
// Ver docs/analisis_gaps_v1.md para las decisiones pendientes.
// ---------------------------------------------------------------------------

const MODULES = [
  { id: 'usuarios', label: 'Usuarios y Roles' },
  { id: 'clientes', label: 'Clientes (Tenants)' },
  { id: 'proyectos', label: 'Proyectos (Obras/Puestos)' },
  { id: 'empleados', label: 'Empleados' },
  { id: 'charlas_diarias', label: 'Charlas Diarias' },
  { id: 'bitacora', label: 'Bitácora de Proyecto' },
  { id: 'presupuesto', label: 'Presupuesto de Proyecto' },
  { id: 'plan_anual', label: 'Plan Anual de Trabajo' },
  { id: 'documentos', label: 'Documentos de Proyecto' },
  { id: 'permisos_trabajo', label: 'Permisos de Trabajo Alto Riesgo' },
  { id: 'inspecciones', label: 'Inspecciones y Rondas' },
  { id: 'matriz_legal', label: 'Matriz de Requisitos Legales' },
  { id: 'reportes', label: 'Reportes Ejecutivos' }
];

const ACTIONS = ['ver', 'imprimir', 'modificar', 'eliminar'];

function fullAccess() {
  return { ver: true, imprimir: true, modificar: true, eliminar: true };
}
function noAccess() {
  return { ver: false, imprimir: false, modificar: false, eliminar: false };
}
function readOnly() {
  return { ver: true, imprimir: true, modificar: false, eliminar: false };
}
function readWrite() {
  return { ver: true, imprimir: true, modificar: true, eliminar: false };
}

let roles = [
  {
    id: 'super-admin',
    nombre: 'Super Admin',
    descripcion: 'Control total de la plataforma y del catálogo maestro de normas.',
    permisos: Object.fromEntries(MODULES.map(m => [m.id, fullAccess()]))
  },
  {
    id: 'admin-tenant',
    nombre: 'Admin Tenant',
    descripcion: 'Administra la organización dentro de su propio tenant.',
    permisos: {
      usuarios: readWrite(),
      clientes: noAccess(),
      proyectos: readWrite(),
      empleados: readWrite(),
      charlas_diarias: readWrite(),
      bitacora: readWrite(),
      presupuesto: readWrite(),
      plan_anual: readWrite(),
      documentos: readWrite(),
      permisos_trabajo: readWrite(),
      inspecciones: readWrite(),
      matriz_legal: readOnly(),
      reportes: readOnly()
    }
  },
  {
    id: 'hseq-manager',
    nombre: 'HSEQ Manager',
    descripcion: 'Responsable de SST/Calidad/Ambiental del tenant.',
    permisos: {
      usuarios: readOnly(),
      clientes: noAccess(),
      proyectos: readOnly(),
      empleados: readWrite(),
      charlas_diarias: readWrite(),
      bitacora: readWrite(),
      presupuesto: readOnly(),
      plan_anual: readWrite(),
      documentos: readWrite(),
      permisos_trabajo: readWrite(),
      inspecciones: readWrite(),
      matriz_legal: readOnly(),
      reportes: readWrite()
    }
  },
  {
    id: 'supervisor-obra',
    nombre: 'Supervisor / Residente de Obra',
    descripcion: 'Autoriza permisos e inspecciones en campo.',
    permisos: {
      usuarios: { ver: true, imprimir: false, modificar: false, eliminar: false },
      clientes: noAccess(),
      proyectos: readOnly(),
      empleados: readOnly(),
      charlas_diarias: readWrite(),
      bitacora: readWrite(),
      presupuesto: noAccess(),
      plan_anual: readOnly(),
      documentos: readWrite(),
      permisos_trabajo: readWrite(),
      inspecciones: readWrite(),
      matriz_legal: readOnly(),
      reportes: readOnly()
    }
  },
  {
    id: 'guarda',
    nombre: 'Trabajador / Guarda',
    descripcion: 'Ejecuta inspecciones y diligencia permisos propios en campo.',
    permisos: {
      usuarios: { ver: true, imprimir: false, modificar: false, eliminar: false },
      clientes: noAccess(),
      proyectos: noAccess(),
      empleados: noAccess(),
      charlas_diarias: { ver: true, imprimir: true, modificar: false, eliminar: false },
      bitacora: { ver: true, imprimir: true, modificar: false, eliminar: false },
      presupuesto: noAccess(),
      plan_anual: noAccess(),
      documentos: { ver: true, imprimir: true, modificar: false, eliminar: false },
      permisos_trabajo: { ver: true, imprimir: true, modificar: false, eliminar: false },
      inspecciones: { ver: true, imprimir: true, modificar: false, eliminar: false },
      matriz_legal: noAccess(),
      reportes: noAccess()
    }
  },
  {
    id: 'auditor-externo',
    nombre: 'Auditor Externo',
    descripcion: 'Acceso de solo lectura para inspección de ARL/Ministerio.',
    permisos: Object.fromEntries(MODULES.map(m => [m.id, readOnly()]))
  }
];

let tenants = [
  { id: 'TEN-0001', nit: '900.123.456-1', razon_social: 'Construcciones El Roble SAS', sector: 'Construccion', plan_saas: 'Enterprise', usuarios: 128, obras_puestos: 4, cumplimiento_sgsst: 92, estado: 'Activo', fecha_alta: '2024-02-11' },
  { id: 'TEN-0002', nit: '860.987.654-2', razon_social: 'Seguridad Nacional Ltda', sector: 'Vigilancia', plan_saas: 'Business', usuarios: 67, obras_puestos: 9, cumplimiento_sgsst: 78, estado: 'Activo', fecha_alta: '2024-05-30' },
  { id: 'TEN-0003', nit: '891.455.003-8', razon_social: 'Logística & Vías del Caribe', sector: 'Construccion', plan_saas: 'Business', usuarios: 41, obras_puestos: 2, cumplimiento_sgsst: 64, estado: 'Trial', fecha_alta: '2026-06-02' },
  { id: 'TEN-0004', nit: '830.221.774-5', razon_social: 'Vigías del Norte SAS', sector: 'Vigilancia', plan_saas: 'Starter', usuarios: 15, obras_puestos: 3, cumplimiento_sgsst: 41, estado: 'Suspendido', fecha_alta: '2023-11-19' },
  { id: 'TEN-0005', nit: '901.556.221-0', razon_social: 'Infraestructura Andina SA', sector: 'Construccion', plan_saas: 'Enterprise', usuarios: 340, obras_puestos: 11, cumplimiento_sgsst: 88, estado: 'Activo', fecha_alta: '2022-08-04' }
];

let users = [
  { id: 'USR-001', nombre: 'Juan Delgado', cedula: '79.845.221', tenant_id: 'TEN-0001', rol_id: 'supervisor-obra', estado_arl: 'Cumple', estado_alturas: 'Cumple', estado_cuenta: 'Activo', ultimo_acceso: '2026-07-17T07:42:00Z' },
  { id: 'USR-002', nombre: 'Marta Rojas', cedula: '52.331.098', tenant_id: 'TEN-0002', rol_id: 'guarda', estado_arl: 'Vencido', estado_alturas: 'Cumple', estado_cuenta: 'Suspendido', ultimo_acceso: '2026-07-16T22:10:00Z' },
  { id: 'USR-003', nombre: 'Carlos Pérez', cedula: '1.020.456.789', tenant_id: 'TEN-0001', rol_id: 'guarda', estado_arl: 'Parcial', estado_alturas: 'Parcial', estado_cuenta: 'Activo', ultimo_acceso: '2026-07-14T10:00:00Z' },
  { id: 'USR-004', nombre: 'Andrea López', cedula: '43.678.912', tenant_id: 'TEN-0003', rol_id: 'hseq-manager', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-17T06:15:00Z' },
  { id: 'USR-005', nombre: 'Ricardo Salazar', cedula: '80.112.334', tenant_id: 'TEN-0002', rol_id: 'admin-tenant', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-10T09:00:00Z' },
  { id: 'USR-006', nombre: 'Elena Ávila (ARL)', cedula: 'Ext-00219', tenant_id: 'TEN-0003', rol_id: 'auditor-externo', estado_arl: null, estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-03T09:00:00Z' }
];

let projects = [
  { id: 'PRY-001', tenant_id: 'TEN-0001', nombre: 'Torre Norte - Etapa 2', tipo: 'Obra', ubicacion: 'Bogotá, Cundinamarca', fecha_inicio: '2025-03-01', estado: 'Activo', horas_hombre_acumuladas: 48250 },
  { id: 'PRY-002', tenant_id: 'TEN-0001', nombre: 'Urbanización Los Álamos', tipo: 'Obra', ubicacion: 'Chía, Cundinamarca', fecha_inicio: '2024-11-15', estado: 'Activo', horas_hombre_acumuladas: 112400 },
  { id: 'PRY-003', tenant_id: 'TEN-0002', nombre: 'Puesto CC Santafé', tipo: 'Puesto', ubicacion: 'Medellín, Antioquia', fecha_inicio: '2023-06-01', estado: 'Activo', horas_hombre_acumuladas: 210000 },
  { id: 'PRY-004', tenant_id: 'TEN-0002', nombre: 'Puesto Zona Franca', tipo: 'Puesto', ubicacion: 'Rionegro, Antioquia', fecha_inicio: '2025-01-10', estado: 'Activo', horas_hombre_acumuladas: 33500 },
  { id: 'PRY-005', tenant_id: 'TEN-0003', nombre: 'Vía Caribe Tramo 3', tipo: 'Obra', ubicacion: 'Barranquilla, Atlántico', fecha_inicio: '2026-06-05', estado: 'Activo', horas_hombre_acumuladas: 8600 }
];

let empleados = [
  { id: 'EMP-001', tenant_id: 'TEN-0001', project_id: 'PRY-001', nombre: 'Pedro Gómez', cedula: '11.222.333', cargo: 'Oficial de Alturas', tipo_contrato: 'Término Fijo', fecha_ingreso: '2025-04-01', eps: 'Sura EPS', estado_arl: 'Cumple', estado_alturas: 'Cumple', estado_cuenta: 'Activo' },
  { id: 'EMP-002', tenant_id: 'TEN-0001', project_id: 'PRY-002', nombre: 'Luisa Fernanda Ortiz', cedula: '44.555.666', cargo: 'Ayudante de Obra', tipo_contrato: 'Obra Labor', fecha_ingreso: '2025-01-20', eps: 'Nueva EPS', estado_arl: 'Parcial', estado_alturas: 'Vencido', estado_cuenta: 'Activo' },
  { id: 'EMP-003', tenant_id: 'TEN-0002', project_id: 'PRY-003', nombre: 'Jorge Iván Mesa', cedula: '77.888.999', cargo: 'Guarda de Seguridad', tipo_contrato: 'Indefinido', fecha_ingreso: '2023-07-01', eps: 'Sanitas', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo' },
  { id: 'EMP-004', tenant_id: 'TEN-0002', project_id: 'PRY-004', nombre: 'Diana Marcela Ruiz', cedula: '99.111.222', cargo: 'Guarda de Seguridad', tipo_contrato: 'Indefinido', fecha_ingreso: '2025-02-10', eps: 'Compensar', estado_arl: 'Vencido', estado_alturas: null, estado_cuenta: 'Suspendido' },
  { id: 'EMP-005', tenant_id: 'TEN-0003', project_id: 'PRY-005', nombre: 'Camilo Suárez', cedula: '30.444.555', cargo: 'Maestro de Obra', tipo_contrato: 'Término Fijo', fecha_ingreso: '2026-06-10', eps: 'Sura EPS', estado_arl: 'Cumple', estado_alturas: 'Parcial', estado_cuenta: 'Activo' }
];

let charlas = [
  { id: 'CHD-001', project_id: 'PRY-001', fecha: '2026-07-16', tema: 'Uso correcto de arnés y línea de vida', responsable: 'Juan Delgado', asistentes: 18, duracion_min: 10 },
  { id: 'CHD-002', project_id: 'PRY-002', fecha: '2026-07-16', tema: 'Manejo defensivo de maquinaria pesada', responsable: 'Juan Delgado', asistentes: 24, duracion_min: 15 },
  { id: 'CHD-003', project_id: 'PRY-003', fecha: '2026-07-17', tema: 'Protocolo de reacción ante intrusión', responsable: 'Ricardo Salazar', asistentes: 6, duracion_min: 8 }
];

let bitacora = [
  { id: 'BIT-001', project_id: 'PRY-001', fecha: '2026-07-16', autor: 'Juan Delgado', tipo: 'Avance', descripcion: 'Fundida de placa nivel 4 completada sin novedad.' },
  { id: 'BIT-002', project_id: 'PRY-001', fecha: '2026-07-15', autor: 'Juan Delgado', tipo: 'Incidente', descripcion: 'Casi-accidente: caída de material menor desde andamio, sin heridos. Se refuerza señalización.' },
  { id: 'BIT-003', project_id: 'PRY-003', fecha: '2026-07-17', autor: 'Ricardo Salazar', tipo: 'Novedad', descripcion: 'Cambio de turno sin novedad. Rondas nocturnas completadas.' }
];

let presupuesto = [
  { id: 'PRE-001', project_id: 'PRY-001', rubro: 'Mano de obra', presupuestado: 850000000, ejecutado: 512000000 },
  { id: 'PRE-002', project_id: 'PRY-001', rubro: 'Materiales', presupuestado: 620000000, ejecutado: 401000000 },
  { id: 'PRE-003', project_id: 'PRY-001', rubro: 'Maquinaria y equipos', presupuestado: 210000000, ejecutado: 98000000 },
  { id: 'PRE-004', project_id: 'PRY-001', rubro: 'HSEQ (EPP, capacitación)', presupuestado: 45000000, ejecutado: 31000000 }
];

let planAnual = [
  { id: 'PLN-001', project_id: 'PRY-001', actividad: 'Cimentación y estructura nivel 1-4', mes_objetivo: '2026-03', responsable: 'Juan Delgado', estado: 'Completado' },
  { id: 'PLN-002', project_id: 'PRY-001', actividad: 'Mampostería y fachada', mes_objetivo: '2026-07', responsable: 'Juan Delgado', estado: 'En Curso' },
  { id: 'PLN-003', project_id: 'PRY-001', actividad: 'Instalaciones eléctricas e hidráulicas', mes_objetivo: '2026-09', responsable: 'Carlos Pérez', estado: 'Pendiente' },
  { id: 'PLN-004', project_id: 'PRY-001', actividad: 'Entrega y cierre de obra', mes_objetivo: '2026-12', responsable: 'Juan Delgado', estado: 'Pendiente' }
];

let documentos = [
  { id: 'DOC-001', project_id: 'PRY-001', nombre: 'Licencia de Construcción.pdf', tipo: 'Permiso', fecha_subida: '2025-02-20', subido_por: 'Juan Delgado' },
  { id: 'DOC-002', project_id: 'PRY-001', nombre: 'Matriz de Riesgos SST.xlsx', tipo: 'HSEQ', fecha_subida: '2025-03-05', subido_por: 'Juan Delgado' },
  { id: 'DOC-003', project_id: 'PRY-001', nombre: 'Planos Estructurales Rev3.dwg', tipo: 'Plano', fecha_subida: '2026-01-10', subido_por: 'Carlos Pérez' }
];

let nextTenantSeq = 6;
let nextUserSeq = 7;
let nextProjectSeq = 6;
let nextEmpleadoSeq = 6;
let nextCharlaSeq = 4;
let nextBitacoraSeq = 4;
let nextPresupuestoSeq = 5;
let nextPlanSeq = 5;
let nextDocSeq = 4;

// --- Roles y permisos (parametrizacion) ---
app.get('/api/modules', (_req, res) => res.json({ modules: MODULES, actions: ACTIONS }));

app.get('/api/roles', (_req, res) => res.json(roles));

app.put('/api/roles/:id', (req, res) => {
  const role = roles.find(r => r.id === req.params.id);
  if (!role) return res.status(404).json({ error: 'Rol no encontrado' });
  const { permisos } = req.body;
  if (!permisos) return res.status(400).json({ error: 'Falta el objeto permisos' });
  role.permisos = permisos;
  res.json(role);
});

// --- Clientes (Tenant_Organizations) ---
app.get('/api/tenants', (_req, res) => res.json(tenants));

app.get('/api/tenants/:id', (req, res) => {
  const tenant = tenants.find(t => t.id === req.params.id);
  if (!tenant) return res.status(404).json({ error: 'Cliente no encontrado' });
  res.json(tenant);
});

app.post('/api/tenants', (req, res) => {
  const { nit, razon_social, sector, plan_saas } = req.body;
  if (!nit || !razon_social || !sector || !plan_saas) {
    return res.status(400).json({ error: 'nit, razon_social, sector y plan_saas son obligatorios' });
  }
  const tenant = {
    id: `TEN-${String(nextTenantSeq++).padStart(4, '0')}`,
    nit, razon_social, sector, plan_saas,
    usuarios: 0, obras_puestos: 0, cumplimiento_sgsst: 0,
    estado: 'Trial',
    fecha_alta: new Date().toISOString().slice(0, 10)
  };
  tenants.push(tenant);
  res.status(201).json(tenant);
});

app.put('/api/tenants/:id', (req, res) => {
  const tenant = tenants.find(t => t.id === req.params.id);
  if (!tenant) return res.status(404).json({ error: 'Cliente no encontrado' });
  Object.assign(tenant, req.body, { id: tenant.id });
  res.json(tenant);
});

app.delete('/api/tenants/:id', (req, res) => {
  const idx = tenants.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Cliente no encontrado' });
  tenants.splice(idx, 1);
  res.status(204).end();
});

// --- Usuarios (Users_Profiles) ---
app.get('/api/users', (req, res) => {
  const { tenant_id, sector, rol_id, estado } = req.query;
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
});

app.post('/api/users', (req, res) => {
  const { nombre, cedula, tenant_id, rol_id } = req.body;
  if (!nombre || !cedula || !tenant_id || !rol_id) {
    return res.status(400).json({ error: 'nombre, cedula, tenant_id y rol_id son obligatorios' });
  }
  const user = {
    id: `USR-${String(nextUserSeq++).padStart(3, '0')}`,
    nombre, cedula, tenant_id, rol_id,
    estado_arl: 'Parcial', estado_alturas: 'Parcial', estado_cuenta: 'Activo',
    ultimo_acceso: null
  };
  users.push(user);
  res.status(201).json(user);
});

app.put('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  Object.assign(user, req.body, { id: user.id });
  res.json(user);
});

app.delete('/api/users/:id', (req, res) => {
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Usuario no encontrado' });
  users.splice(idx, 1);
  res.status(204).end();
});

// --- Proyectos (Tenant_Branches_Projects) — un cliente puede tener varias obras/puestos ---
app.get('/api/projects', (req, res) => {
  const { tenant_id, estado } = req.query;
  let result = projects.map(p => ({ ...p, tenant: tenants.find(t => t.id === p.tenant_id) || null }));
  if (tenant_id) result = result.filter(p => p.tenant_id === tenant_id);
  if (estado) result = result.filter(p => p.estado === estado);
  res.json(result);
});

app.get('/api/projects/:id', (req, res) => {
  const project = projects.find(p => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  res.json({ ...project, tenant: tenants.find(t => t.id === project.tenant_id) || null });
});

app.post('/api/projects', (req, res) => {
  const { tenant_id, nombre, tipo, ubicacion, fecha_inicio } = req.body;
  if (!tenant_id || !nombre || !tipo) {
    return res.status(400).json({ error: 'tenant_id, nombre y tipo son obligatorios' });
  }
  const project = {
    id: `PRY-${String(nextProjectSeq++).padStart(3, '0')}`,
    tenant_id, nombre, tipo,
    ubicacion: ubicacion || '',
    fecha_inicio: fecha_inicio || new Date().toISOString().slice(0, 10),
    estado: 'Activo',
    horas_hombre_acumuladas: 0
  };
  projects.push(project);
  res.status(201).json(project);
});

app.put('/api/projects/:id', (req, res) => {
  const project = projects.find(p => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Proyecto no encontrado' });
  Object.assign(project, req.body, { id: project.id });
  res.json(project);
});

app.delete('/api/projects/:id', (req, res) => {
  const idx = projects.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Proyecto no encontrado' });
  projects.splice(idx, 1);
  res.status(204).end();
});

// --- Empleados (roster de campo, distinto de Usuarios del sistema) ---
app.get('/api/empleados', (req, res) => {
  const { tenant_id, project_id, cargo, estado } = req.query;
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
});

app.post('/api/empleados', (req, res) => {
  const { tenant_id, project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps } = req.body;
  if (!tenant_id || !nombre || !cedula || !cargo) {
    return res.status(400).json({ error: 'tenant_id, nombre, cedula y cargo son obligatorios' });
  }
  const empleado = {
    id: `EMP-${String(nextEmpleadoSeq++).padStart(3, '0')}`,
    tenant_id, project_id: project_id || null, nombre, cedula, cargo,
    tipo_contrato: tipo_contrato || 'Término Fijo',
    fecha_ingreso: fecha_ingreso || new Date().toISOString().slice(0, 10),
    eps: eps || '',
    estado_arl: 'Parcial', estado_alturas: 'Parcial', estado_cuenta: 'Activo'
  };
  empleados.push(empleado);
  res.status(201).json(empleado);
});

app.put('/api/empleados/:id', (req, res) => {
  const empleado = empleados.find(e => e.id === req.params.id);
  if (!empleado) return res.status(404).json({ error: 'Empleado no encontrado' });
  Object.assign(empleado, req.body, { id: empleado.id });
  res.json(empleado);
});

app.delete('/api/empleados/:id', (req, res) => {
  const idx = empleados.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Empleado no encontrado' });
  empleados.splice(idx, 1);
  res.status(204).end();
});

// --- Charlas Diarias (charla de 5 minutos / toolbox talk) ---
app.get('/api/charlas', (req, res) => {
  const { project_id, tenant_id, fecha } = req.query;
  let result = charlas.map(c => {
    const project = projects.find(p => p.id === c.project_id) || null;
    return { ...c, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(c => c.project_id === project_id);
  if (tenant_id) result = result.filter(c => c.project && c.project.tenant_id === tenant_id);
  if (fecha) result = result.filter(c => c.fecha === fecha);
  res.json(result);
});

app.post('/api/charlas', (req, res) => {
  const { project_id, fecha, tema, responsable, asistentes, duracion_min } = req.body;
  if (!project_id || !tema || !responsable) {
    return res.status(400).json({ error: 'project_id, tema y responsable son obligatorios' });
  }
  const charla = {
    id: `CHD-${String(nextCharlaSeq++).padStart(3, '0')}`,
    project_id,
    fecha: fecha || new Date().toISOString().slice(0, 10),
    tema, responsable,
    asistentes: Number(asistentes) || 0,
    duracion_min: Number(duracion_min) || 5
  };
  charlas.push(charla);
  res.status(201).json(charla);
});

app.put('/api/charlas/:id', (req, res) => {
  const charla = charlas.find(c => c.id === req.params.id);
  if (!charla) return res.status(404).json({ error: 'Charla no encontrada' });
  Object.assign(charla, req.body, { id: charla.id });
  res.json(charla);
});

app.delete('/api/charlas/:id', (req, res) => {
  const idx = charlas.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Charla no encontrada' });
  charlas.splice(idx, 1);
  res.status(204).end();
});

// --- Bitácora por Proyecto ---
app.get('/api/bitacora', (req, res) => {
  const { project_id, tenant_id, tipo } = req.query;
  let result = bitacora.map(b => {
    const project = projects.find(p => p.id === b.project_id) || null;
    return { ...b, project, tenant: project ? tenants.find(t => t.id === project.tenant_id) || null : null };
  });
  if (project_id) result = result.filter(b => b.project_id === project_id);
  if (tenant_id) result = result.filter(b => b.project && b.project.tenant_id === tenant_id);
  if (tipo) result = result.filter(b => b.tipo === tipo);
  result.sort((a, b) => (a.fecha < b.fecha ? 1 : -1));
  res.json(result);
});

app.post('/api/bitacora', (req, res) => {
  const { project_id, fecha, autor, tipo, descripcion } = req.body;
  if (!project_id || !autor || !tipo || !descripcion) {
    return res.status(400).json({ error: 'project_id, autor, tipo y descripcion son obligatorios' });
  }
  const entrada = {
    id: `BIT-${String(nextBitacoraSeq++).padStart(3, '0')}`,
    project_id,
    fecha: fecha || new Date().toISOString().slice(0, 10),
    autor, tipo, descripcion
  };
  bitacora.push(entrada);
  res.status(201).json(entrada);
});

app.put('/api/bitacora/:id', (req, res) => {
  const entrada = bitacora.find(b => b.id === req.params.id);
  if (!entrada) return res.status(404).json({ error: 'Entrada no encontrada' });
  Object.assign(entrada, req.body, { id: entrada.id });
  res.json(entrada);
});

app.delete('/api/bitacora/:id', (req, res) => {
  const idx = bitacora.findIndex(b => b.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Entrada no encontrada' });
  bitacora.splice(idx, 1);
  res.status(204).end();
});

// --- Presupuesto por Proyecto ---
app.get('/api/presupuesto', (req, res) => {
  const { project_id } = req.query;
  let result = presupuesto;
  if (project_id) result = result.filter(p => p.project_id === project_id);
  res.json(result);
});

app.post('/api/presupuesto', (req, res) => {
  const { project_id, rubro, presupuestado } = req.body;
  if (!project_id || !rubro || presupuestado == null) {
    return res.status(400).json({ error: 'project_id, rubro y presupuestado son obligatorios' });
  }
  const linea = { id: `PRE-${String(nextPresupuestoSeq++).padStart(3, '0')}`, project_id, rubro, presupuestado: Number(presupuestado), ejecutado: Number(req.body.ejecutado) || 0 };
  presupuesto.push(linea);
  res.status(201).json(linea);
});

app.put('/api/presupuesto/:id', (req, res) => {
  const linea = presupuesto.find(p => p.id === req.params.id);
  if (!linea) return res.status(404).json({ error: 'Línea no encontrada' });
  Object.assign(linea, req.body, { id: linea.id });
  res.json(linea);
});

app.delete('/api/presupuesto/:id', (req, res) => {
  const idx = presupuesto.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Línea no encontrada' });
  presupuesto.splice(idx, 1);
  res.status(204).end();
});

// --- Plan Anual de Trabajo ---
app.get('/api/plan-anual', (req, res) => {
  const { project_id } = req.query;
  let result = planAnual;
  if (project_id) result = result.filter(p => p.project_id === project_id);
  res.json(result);
});

app.post('/api/plan-anual', (req, res) => {
  const { project_id, actividad, mes_objetivo, responsable } = req.body;
  if (!project_id || !actividad || !responsable) {
    return res.status(400).json({ error: 'project_id, actividad y responsable son obligatorios' });
  }
  const item = { id: `PLN-${String(nextPlanSeq++).padStart(3, '0')}`, project_id, actividad, mes_objetivo: mes_objetivo || '', responsable, estado: 'Pendiente' };
  planAnual.push(item);
  res.status(201).json(item);
});

app.put('/api/plan-anual/:id', (req, res) => {
  const item = planAnual.find(p => p.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Actividad no encontrada' });
  Object.assign(item, req.body, { id: item.id });
  res.json(item);
});

app.delete('/api/plan-anual/:id', (req, res) => {
  const idx = planAnual.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Actividad no encontrada' });
  planAnual.splice(idx, 1);
  res.status(204).end();
});

// --- Documentos por Proyecto (metadatos; sin almacenamiento binario real en este scaffold) ---
app.get('/api/documentos', (req, res) => {
  const { project_id } = req.query;
  let result = documentos;
  if (project_id) result = result.filter(d => d.project_id === project_id);
  res.json(result);
});

app.post('/api/documentos', (req, res) => {
  const { project_id, nombre, tipo, subido_por } = req.body;
  if (!project_id || !nombre || !tipo) {
    return res.status(400).json({ error: 'project_id, nombre y tipo son obligatorios' });
  }
  const doc = { id: `DOC-${String(nextDocSeq++).padStart(3, '0')}`, project_id, nombre, tipo, fecha_subida: new Date().toISOString().slice(0, 10), subido_por: subido_por || 'Usuario Actual' };
  documentos.push(doc);
  res.status(201).json(doc);
});

app.delete('/api/documentos/:id', (req, res) => {
  const idx = documentos.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Documento no encontrado' });
  documentos.splice(idx, 1);
  res.status(204).end();
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.redirect('/login.html');
});

app.listen(PORT, () => {
  console.log(`SIG HSEQ scaffold escuchando en http://localhost:${PORT}`);
});
