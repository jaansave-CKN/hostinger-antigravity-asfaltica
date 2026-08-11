const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : false,
});

function fullAccess() { return { ver: true, imprimir: true, modificar: true, eliminar: true }; }
function noAccess() { return { ver: false, imprimir: false, modificar: false, eliminar: false }; }
function readOnly() { return { ver: true, imprimir: true, modificar: false, eliminar: false }; }
function readWrite() { return { ver: true, imprimir: true, modificar: true, eliminar: false }; }

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

const SEED_ROLES = [
  { id: 'super-admin', nombre: 'Super Admin', descripcion: 'Control total de la plataforma y del catálogo maestro de normas.', permisos: Object.fromEntries(MODULES.map(m => [m.id, fullAccess()])) },
  { id: 'admin-tenant', nombre: 'Admin Tenant', descripcion: 'Administra la organización dentro de su propio tenant.', permisos: { usuarios: readWrite(), clientes: noAccess(), proyectos: readWrite(), empleados: readWrite(), charlas_diarias: readWrite(), bitacora: readWrite(), presupuesto: readWrite(), plan_anual: readWrite(), documentos: readWrite(), permisos_trabajo: readWrite(), inspecciones: readWrite(), matriz_legal: readOnly(), reportes: readOnly() } },
  { id: 'hseq-manager', nombre: 'HSEQ Manager', descripcion: 'Responsable de SST/Calidad/Ambiental del tenant.', permisos: { usuarios: readOnly(), clientes: noAccess(), proyectos: readOnly(), empleados: readWrite(), charlas_diarias: readWrite(), bitacora: readWrite(), presupuesto: readOnly(), plan_anual: readWrite(), documentos: readWrite(), permisos_trabajo: readWrite(), inspecciones: readWrite(), matriz_legal: readOnly(), reportes: readWrite() } },
  { id: 'supervisor-obra', nombre: 'Supervisor / Residente de Obra', descripcion: 'Autoriza permisos e inspecciones en campo.', permisos: { usuarios: { ver: true, imprimir: false, modificar: false, eliminar: false }, clientes: noAccess(), proyectos: readOnly(), empleados: readOnly(), charlas_diarias: readWrite(), bitacora: readWrite(), presupuesto: noAccess(), plan_anual: readOnly(), documentos: readWrite(), permisos_trabajo: readWrite(), inspecciones: readWrite(), matriz_legal: readOnly(), reportes: readOnly() } },
  { id: 'guarda', nombre: 'Trabajador / Guarda', descripcion: 'Ejecuta inspecciones y diligencia permisos propios en campo.', permisos: { usuarios: { ver: true, imprimir: false, modificar: false, eliminar: false }, clientes: noAccess(), proyectos: noAccess(), empleados: noAccess(), charlas_diarias: { ver: true, imprimir: true, modificar: false, eliminar: false }, bitacora: { ver: true, imprimir: true, modificar: false, eliminar: false }, presupuesto: noAccess(), plan_anual: noAccess(), documentos: { ver: true, imprimir: true, modificar: false, eliminar: false }, permisos_trabajo: { ver: true, imprimir: true, modificar: false, eliminar: false }, inspecciones: { ver: true, imprimir: true, modificar: false, eliminar: false }, matriz_legal: noAccess(), reportes: noAccess() } },
  { id: 'auditor-externo', nombre: 'Auditor Externo', descripcion: 'Acceso de solo lectura para inspección de ARL/Ministerio.', permisos: Object.fromEntries(MODULES.map(m => [m.id, readOnly()])) }
];

const SEED_TENANTS = [
  { id: 'TEN-0001', nit: '900.123.456-1', razon_social: 'Construcciones El Roble SAS', sector: 'Construccion', plan_saas: 'Enterprise', usuarios: 128, obras_puestos: 4, cumplimiento_sgsst: 92, estado: 'Activo', fecha_alta: '2024-02-11' },
  { id: 'TEN-0002', nit: '860.987.654-2', razon_social: 'Seguridad Nacional Ltda', sector: 'Vigilancia', plan_saas: 'Business', usuarios: 67, obras_puestos: 9, cumplimiento_sgsst: 78, estado: 'Activo', fecha_alta: '2024-05-30' },
  { id: 'TEN-0003', nit: '891.455.003-8', razon_social: 'Logística & Vías del Caribe', sector: 'Construccion', plan_saas: 'Business', usuarios: 41, obras_puestos: 2, cumplimiento_sgsst: 64, estado: 'Trial', fecha_alta: '2026-06-02' },
  { id: 'TEN-0004', nit: '830.221.774-5', razon_social: 'Vigías del Norte SAS', sector: 'Vigilancia', plan_saas: 'Starter', usuarios: 15, obras_puestos: 3, cumplimiento_sgsst: 41, estado: 'Suspendido', fecha_alta: '2023-11-19' },
  { id: 'TEN-0005', nit: '901.556.221-0', razon_social: 'Infraestructura Andina SA', sector: 'Construccion', plan_saas: 'Enterprise', usuarios: 340, obras_puestos: 11, cumplimiento_sgsst: 88, estado: 'Activo', fecha_alta: '2022-08-04' }
];

const SEED_USERS = [
  { id: 'USR-001', nombre: 'Juan Delgado', cedula: '79.845.221', tenant_id: 'TEN-0001', rol_id: 'supervisor-obra', estado_arl: 'Cumple', estado_alturas: 'Cumple', estado_cuenta: 'Activo', ultimo_acceso: '2026-07-17T07:42:00Z' },
  { id: 'USR-002', nombre: 'Marta Rojas', cedula: '52.331.098', tenant_id: 'TEN-0002', rol_id: 'guarda', estado_arl: 'Vencido', estado_alturas: 'Cumple', estado_cuenta: 'Suspendido', ultimo_acceso: '2026-07-16T22:10:00Z' },
  { id: 'USR-003', nombre: 'Carlos Pérez', cedula: '1.020.456.789', tenant_id: 'TEN-0001', rol_id: 'guarda', estado_arl: 'Parcial', estado_alturas: 'Parcial', estado_cuenta: 'Activo', ultimo_acceso: '2026-07-14T10:00:00Z' },
  { id: 'USR-004', nombre: 'Andrea López', cedula: '43.678.912', tenant_id: 'TEN-0003', rol_id: 'hseq-manager', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-17T06:15:00Z' },
  { id: 'USR-005', nombre: 'Ricardo Salazar', cedula: '80.112.334', tenant_id: 'TEN-0002', rol_id: 'admin-tenant', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-10T09:00:00Z' },
  { id: 'USR-006', nombre: 'Elena Ávila (ARL)', cedula: 'Ext-00219', tenant_id: 'TEN-0003', rol_id: 'auditor-externo', estado_arl: null, estado_alturas: null, estado_cuenta: 'Activo', ultimo_acceso: '2026-07-03T09:00:00Z' }
];

const SEED_PROJECTS = [
  { id: 'PRY-001', tenant_id: 'TEN-0001', nombre: 'Torre Norte - Etapa 2', tipo: 'Obra', ubicacion: 'Bogotá, Cundinamarca', fecha_inicio: '2025-03-01', estado: 'Activo', horas_hombre_acumuladas: 48250 },
  { id: 'PRY-002', tenant_id: 'TEN-0001', nombre: 'Urbanización Los Álamos', tipo: 'Obra', ubicacion: 'Chía, Cundinamarca', fecha_inicio: '2024-11-15', estado: 'Activo', horas_hombre_acumuladas: 112400 },
  { id: 'PRY-003', tenant_id: 'TEN-0002', nombre: 'Puesto CC Santafé', tipo: 'Puesto', ubicacion: 'Medellín, Antioquia', fecha_inicio: '2023-06-01', estado: 'Activo', horas_hombre_acumuladas: 210000 },
  { id: 'PRY-004', tenant_id: 'TEN-0002', nombre: 'Puesto Zona Franca', tipo: 'Puesto', ubicacion: 'Rionegro, Antioquia', fecha_inicio: '2025-01-10', estado: 'Activo', horas_hombre_acumuladas: 33500 },
  { id: 'PRY-005', tenant_id: 'TEN-0003', nombre: 'Vía Caribe Tramo 3', tipo: 'Obra', ubicacion: 'Barranquilla, Atlántico', fecha_inicio: '2026-06-05', estado: 'Activo', horas_hombre_acumuladas: 8600 }
];

const SEED_EMPLEADOS = [
  { id: 'EMP-001', tenant_id: 'TEN-0001', project_id: 'PRY-001', nombre: 'Pedro Gómez', cedula: '11.222.333', cargo: 'Oficial de Alturas', tipo_contrato: 'Término Fijo', fecha_ingreso: '2025-04-01', eps: 'Sura EPS', estado_arl: 'Cumple', estado_alturas: 'Cumple', estado_cuenta: 'Activo' },
  { id: 'EMP-002', tenant_id: 'TEN-0001', project_id: 'PRY-002', nombre: 'Luisa Fernanda Ortiz', cedula: '44.555.666', cargo: 'Ayudante de Obra', tipo_contrato: 'Obra Labor', fecha_ingreso: '2025-01-20', eps: 'Nueva EPS', estado_arl: 'Parcial', estado_alturas: 'Vencido', estado_cuenta: 'Activo' },
  { id: 'EMP-003', tenant_id: 'TEN-0002', project_id: 'PRY-003', nombre: 'Jorge Iván Mesa', cedula: '77.888.999', cargo: 'Guarda de Seguridad', tipo_contrato: 'Indefinido', fecha_ingreso: '2023-07-01', eps: 'Sanitas', estado_arl: 'Cumple', estado_alturas: null, estado_cuenta: 'Activo' },
  { id: 'EMP-004', tenant_id: 'TEN-0002', project_id: 'PRY-004', nombre: 'Diana Marcela Ruiz', cedula: '99.111.222', cargo: 'Guarda de Seguridad', tipo_contrato: 'Indefinido', fecha_ingreso: '2025-02-10', eps: 'Compensar', estado_arl: 'Vencido', estado_alturas: null, estado_cuenta: 'Suspendido' },
  { id: 'EMP-005', tenant_id: 'TEN-0003', project_id: 'PRY-005', nombre: 'Camilo Suárez', cedula: '30.444.555', cargo: 'Maestro de Obra', tipo_contrato: 'Término Fijo', fecha_ingreso: '2026-06-10', eps: 'Sura EPS', estado_arl: 'Cumple', estado_alturas: 'Parcial', estado_cuenta: 'Activo' }
];

const SEED_CHARLAS = [
  { id: 'CHD-001', project_id: 'PRY-001', tenant_id: 'TEN-0001', fecha: '2026-07-16', tema: 'Uso correcto de arnés y línea de vida', responsable: 'Juan Delgado', asistentes: 18, duracion_min: 10 },
  { id: 'CHD-002', project_id: 'PRY-002', tenant_id: 'TEN-0001', fecha: '2026-07-16', tema: 'Manejo defensivo de maquinaria pesada', responsable: 'Juan Delgado', asistentes: 24, duracion_min: 15 },
  { id: 'CHD-003', project_id: 'PRY-003', tenant_id: 'TEN-0002', fecha: '2026-07-17', tema: 'Protocolo de reacción ante intrusión', responsable: 'Ricardo Salazar', asistentes: 6, duracion_min: 8 }
];

const SEED_BITACORA = [
  { id: 'BIT-001', project_id: 'PRY-001', tenant_id: 'TEN-0001', fecha: '2026-07-16', autor: 'Juan Delgado', tipo: 'Avance', descripcion: 'Fundida de placa nivel 4 completada sin novedad.' },
  { id: 'BIT-002', project_id: 'PRY-001', tenant_id: 'TEN-0001', fecha: '2026-07-15', autor: 'Juan Delgado', tipo: 'Incidente', descripcion: 'Casi-accidente: caída de material menor desde andamio, sin heridos. Se refuerza señalización.' },
  { id: 'BIT-003', project_id: 'PRY-003', tenant_id: 'TEN-0002', fecha: '2026-07-17', autor: 'Ricardo Salazar', tipo: 'Novedad', descripcion: 'Cambio de turno sin novedad. Rondas nocturnas completadas.' }
];

const SEED_PRESUPUESTO = [
  { id: 'PRE-001', project_id: 'PRY-001', tenant_id: 'TEN-0001', rubro: 'Mano de obra', presupuestado: 850000000, ejecutado: 512000000 },
  { id: 'PRE-002', project_id: 'PRY-001', tenant_id: 'TEN-0001', rubro: 'Materiales', presupuestado: 620000000, ejecutado: 401000000 },
  { id: 'PRE-003', project_id: 'PRY-001', tenant_id: 'TEN-0001', rubro: 'Maquinaria y equipos', presupuestado: 210000000, ejecutado: 98000000 },
  { id: 'PRE-004', project_id: 'PRY-001', tenant_id: 'TEN-0001', rubro: 'HSEQ (EPP, capacitación)', presupuestado: 45000000, ejecutado: 31000000 }
];

const SEED_PLAN = [
  { id: 'PLN-001', project_id: 'PRY-001', tenant_id: 'TEN-0001', actividad: 'Cimentación y estructura nivel 1-4', mes_objetivo: '2026-03', responsable: 'Juan Delgado', estado: 'Completado' },
  { id: 'PLN-002', project_id: 'PRY-001', tenant_id: 'TEN-0001', actividad: 'Mampostería y fachada', mes_objetivo: '2026-07', responsable: 'Juan Delgado', estado: 'En Curso' },
  { id: 'PLN-003', project_id: 'PRY-001', tenant_id: 'TEN-0001', actividad: 'Instalaciones eléctricas e hidráulicas', mes_objetivo: '2026-09', responsable: 'Carlos Pérez', estado: 'Pendiente' },
  { id: 'PLN-004', project_id: 'PRY-001', tenant_id: 'TEN-0001', actividad: 'Entrega y cierre de obra', mes_objetivo: '2026-12', responsable: 'Juan Delgado', estado: 'Pendiente' }
];

const SEED_DOCUMENTOS = [
  { id: 'DOC-001', project_id: 'PRY-001', tenant_id: 'TEN-0001', nombre: 'Licencia de Construcción.pdf', tipo: 'Permiso', fecha_subida: '2025-02-20', subido_por: 'Juan Delgado' },
  { id: 'DOC-002', project_id: 'PRY-001', tenant_id: 'TEN-0001', nombre: 'Matriz de Riesgos SST.xlsx', tipo: 'HSEQ', fecha_subida: '2025-03-05', subido_por: 'Juan Delgado' },
  { id: 'DOC-003', project_id: 'PRY-001', tenant_id: 'TEN-0001', nombre: 'Planos Estructurales Rev3.dwg', tipo: 'Plano', fecha_subida: '2026-01-10', subido_por: 'Carlos Pérez' }
];

// Legal_Norms_Master_Catalog — estado sigue el flujo de gobernanza decidido por el usuario
// 2026-07-17 (ver docs/analisis_gaps_v1.md): draft -> pendiente_revision -> aprobado_super_admin
// -> publicado_a_tenants. La propagación nunca es automática ni global.
const SEED_LEGAL_NORMS = [
  { id: 'NRM-001', codigo_norma: 'Decreto 1072 de 2015', nombre: 'Decreto Único Reglamentario del Sector Trabajo (SG-SST)', version_year: 2015, sector_aplicable: 'Ambas', estado: 'publicado_a_tenants', fecha_publicacion: '2015-05-26', resumen_requisito: 'Implementación obligatoria del Sistema de Gestión de Seguridad y Salud en el Trabajo.' },
  { id: 'NRM-002', codigo_norma: 'Resolución 0312 de 2019', nombre: 'Estándares Mínimos del SG-SST', version_year: 2019, sector_aplicable: 'Ambas', estado: 'publicado_a_tenants', fecha_publicacion: '2019-02-13', resumen_requisito: 'Define estándares mínimos según número de trabajadores y nivel de riesgo.' },
  { id: 'NRM-003', codigo_norma: 'Resolución 4272 de 2021', nombre: 'Reglamento Técnico de Trabajo Seguro en Alturas', version_year: 2021, sector_aplicable: 'Construccion', estado: 'publicado_a_tenants', fecha_publicacion: '2021-11-25', resumen_requisito: 'Certificación obligatoria de curso de alturas, reentrenamiento cada 2 años. Alimenta el motor de exclusión de Permisos de Trabajo.' },
  { id: 'NRM-004', codigo_norma: 'Resolución 2764 de 2022', nombre: 'Jornadas de Trabajo en Vigilancia y Seguridad Privada', version_year: 2022, sector_aplicable: 'Vigilancia', estado: 'publicado_a_tenants', fecha_publicacion: '2022-11-14', resumen_requisito: 'Límites de jornada y descanso obligatorio para guardas — riesgo de fatiga.' },
  { id: 'NRM-005', codigo_norma: 'Resolución 2404 de 2019', nombre: 'Batería de Riesgo Psicosocial', version_year: 2019, sector_aplicable: 'Ambas', estado: 'aprobado_super_admin', fecha_publicacion: '2019-07-22', resumen_requisito: 'Evaluación obligatoria de factores de riesgo psicosocial cada 2 años.' },
  { id: 'NRM-006', codigo_norma: 'Ajuste tarifario ARL Construcción 2026 (borrador)', nombre: 'Ajuste de tarifas ARL por clase de riesgo', version_year: 2026, sector_aplicable: 'Construccion', estado: 'pendiente_revision', fecha_publicacion: null, resumen_requisito: 'Norma en borrador — pendiente de revisión del Super-Admin antes de publicarse a los tenants del sector.' }
];

// High_Risk_Work_Permits — el estado se decide en el backend (motor de exclusión real
// contra empleados.estado_arl / estado_alturas), nunca se acepta "Activo" desde el cliente.
const SEED_PERMISOS_TRABAJO = [
  { id: 'PMT-001', tenant_id: 'TEN-0001', project_id: 'PRY-001', empleado_id: 'EMP-001', tipo: 'Trabajo en Alturas', validez_inicio: '2026-07-10', validez_fin: '2026-07-24', estado: 'Activo', motivo_rechazo: null, creado_por: 'Juan Delgado' },
  { id: 'PMT-002', tenant_id: 'TEN-0001', project_id: 'PRY-002', empleado_id: 'EMP-002', tipo: 'Trabajo en Alturas', validez_inicio: '2026-07-15', validez_fin: '2026-07-15', estado: 'Rechazado', motivo_rechazo: 'Curso de alturas vencido para EMP-002 (Luisa Fernanda Ortiz).', creado_por: 'Juan Delgado' }
];

// Base para IF/IS (Motor de Indicadores BI): IF = (accidentes incapacitantes / horas-hombre) * 240000
const SEED_ACCIDENTES = [
  { id: 'ACC-001', project_id: 'PRY-001', fecha: '2026-05-14', tipo: 'Leve', dias_perdidos: 0 },
  { id: 'ACC-002', project_id: 'PRY-002', fecha: '2026-06-02', tipo: 'Incapacitante', dias_perdidos: 12 },
  { id: 'ACC-003', project_id: 'PRY-003', fecha: '2026-04-20', tipo: 'Incapacitante', dias_perdidos: 5 }
];

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY, nombre TEXT NOT NULL, descripcion TEXT, permisos JSONB NOT NULL,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY, nit TEXT, razon_social TEXT, sector TEXT, plan_saas TEXT,
      usuarios INT DEFAULT 0, obras_puestos INT DEFAULT 0, cumplimiento_sgsst INT DEFAULT 0,
      estado TEXT, fecha_alta TEXT, arl_provider TEXT, version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS users_app (
      id TEXT PRIMARY KEY, nombre TEXT, cedula TEXT, tenant_id TEXT, rol_id TEXT,
      estado_arl TEXT, estado_alturas TEXT, estado_cuenta TEXT, ultimo_acceso TEXT,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY, tenant_id TEXT, nombre TEXT, tipo TEXT, ubicacion TEXT,
      fecha_inicio TEXT, estado TEXT, horas_hombre_acumuladas BIGINT DEFAULT 0,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS empleados (
      id TEXT PRIMARY KEY, tenant_id TEXT, project_id TEXT, nombre TEXT, cedula TEXT, cargo TEXT,
      tipo_contrato TEXT, fecha_ingreso TEXT, eps TEXT,
      estado_arl TEXT, estado_alturas TEXT, estado_cuenta TEXT, version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS charlas (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, fecha TEXT, tema TEXT, responsable TEXT,
      asistentes INT DEFAULT 0, duracion_min INT DEFAULT 5, version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS bitacora (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, fecha TEXT, autor TEXT, tipo TEXT, descripcion TEXT,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS presupuesto (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, rubro TEXT, presupuestado BIGINT DEFAULT 0, ejecutado BIGINT DEFAULT 0,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS plan_anual (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, actividad TEXT, mes_objetivo TEXT, responsable TEXT, estado TEXT,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS documentos (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, nombre TEXT, tipo TEXT, fecha_subida TEXT, subido_por TEXT
    );
    CREATE TABLE IF NOT EXISTS legal_norms (
      id TEXT PRIMARY KEY, codigo_norma TEXT, nombre TEXT, version_year INT, sector_aplicable TEXT,
      estado TEXT NOT NULL DEFAULT 'draft', fecha_publicacion TEXT, resumen_requisito TEXT,
      version INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS permisos_trabajo (
      id TEXT PRIMARY KEY, tenant_id TEXT, project_id TEXT, empleado_id TEXT, tipo TEXT,
      validez_inicio TEXT, validez_fin TEXT, estado TEXT NOT NULL, motivo_rechazo TEXT,
      creado_por TEXT, fecha_creacion TEXT
    );
    CREATE TABLE IF NOT EXISTS accidentes (
      id TEXT PRIMARY KEY, project_id TEXT, tenant_id TEXT, fecha TEXT, tipo TEXT, dias_perdidos INT DEFAULT 0
    );
    -- Sprint 0 — auth real por usuario (ver migrations/001_sprint0_blindaje.sql para RLS/backfill
    -- sobre una base ya existente; este CREATE cubre instalaciones nuevas desde cero).
    -- tenant_id es NULLABLE a propósito (Sprint 1, Frente B): un Super-Admin no pertenece
    -- a un tenant real, y RLS depende de app.is_superadmin, no de este FK.
    CREATE TABLE IF NOT EXISTS auth_credentials (
      user_id TEXT PRIMARY KEY REFERENCES users_app(id),
      tenant_id TEXT REFERENCES tenants(id),
      password_hash TEXT NOT NULL,
      must_change_password BOOLEAN NOT NULL DEFAULT true,
      last_login_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- Sprint 2 — Inspecciones y Rondas (snapshot de checklist, no CAPA/causa raíz — ver
    -- migrations/004_sprint2_inspecciones.sql para el porqué).
    CREATE TABLE IF NOT EXISTS inspecciones_rondas (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
      project_id TEXT NOT NULL REFERENCES projects(id), sector TEXT NOT NULL,
      items JSONB NOT NULL, porcentaje_cumplimiento NUMERIC(5,2) NOT NULL,
      realizado_por TEXT NOT NULL, version INT NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- Sprint 3 — Botón de Pánico / SOS. canal_notificacion/notificacion_estado son
    -- arquitectura abierta para el futuro proveedor de SMS/WhatsApp (sin implementar).
    -- Sprint 4 — Auditor de Cumplimiento por IA. 'documentos' está en el CHECK por
    -- compatibilidad futura pero no se evalúa hoy (ver server.js) — sin extracción
    -- real de contenido de archivo.
    CREATE TABLE IF NOT EXISTS ai_audit_findings (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
      project_id TEXT REFERENCES projects(id),
      fuente TEXT NOT NULL CHECK (fuente IN ('charlas','bitacora','permisos_trabajo','documentos','inspecciones_rondas')),
      fuente_id TEXT NOT NULL, hallazgo TEXT NOT NULL, norma_citada TEXT,
      severidad TEXT NOT NULL CHECK (severidad IN ('Baja','Media','Alta','Critica')),
      confianza_modelo NUMERIC(3,2) CHECK (confianza_modelo BETWEEN 0 AND 1),
      estado TEXT NOT NULL DEFAULT 'Nuevo' CHECK (estado IN ('Nuevo','Revisado','Descartado','Escalado')),
      revisado_por TEXT, version INT NOT NULL DEFAULT 1, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- Sprint 5 — patrón adaptador ARL. Solo 'manual' implementado (formaliza el flujo
    -- humano existente) — el CHECK se amplía cuando exista un proveedor real contratado.
    CREATE TABLE IF NOT EXISTS arl_verification_log (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
      empleado_id TEXT NOT NULL REFERENCES empleados(id),
      campo TEXT NOT NULL CHECK (campo IN ('estado_arl', 'estado_alturas')),
      valor_anterior TEXT, valor_nuevo TEXT NOT NULL,
      adaptador TEXT NOT NULL DEFAULT 'manual' CHECK (adaptador IN ('manual')),
      actualizado_por TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS emergency_alerts (
      id TEXT PRIMARY KEY, tenant_id TEXT REFERENCES tenants(id),
      project_id TEXT REFERENCES projects(id), user_id TEXT NOT NULL REFERENCES users_app(id),
      tipo TEXT NOT NULL CHECK (tipo IN ('Panico','Medica','Incendio','Intrusion')),
      lat DOUBLE PRECISION, lng DOUBLE PRECISION,
      estado TEXT NOT NULL DEFAULT 'Activa' CHECK (estado IN ('Activa','Atendida','Falsa_Alarma')),
      atendido_por TEXT, canal_notificacion TEXT,
      notificacion_estado TEXT NOT NULL DEFAULT 'sin_proveedor'
        CHECK (notificacion_estado IN ('sin_proveedor', 'pendiente_envio', 'enviado', 'fallido')),
      version INT NOT NULL DEFAULT 1, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      atendido_en TIMESTAMPTZ
    );
  `);

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM tenants');
  if (rows[0].n === 0) {
    await seedAll();
    console.log('[db] Tablas creadas y sembradas con datos de ejemplo.');
  } else {
    console.log('[db] Base de datos ya tenía datos — no se resembró.');
  }
}

async function seedAll() {
  for (const r of SEED_ROLES) {
    await pool.query('INSERT INTO roles (id, nombre, descripcion, permisos) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING', [r.id, r.nombre, r.descripcion, r.permisos]);
  }
  for (const t of SEED_TENANTS) {
    await pool.query('INSERT INTO tenants (id, nit, razon_social, sector, plan_saas, usuarios, obras_puestos, cumplimiento_sgsst, estado, fecha_alta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING',
      [t.id, t.nit, t.razon_social, t.sector, t.plan_saas, t.usuarios, t.obras_puestos, t.cumplimiento_sgsst, t.estado, t.fecha_alta]);
  }
  for (const u of SEED_USERS) {
    await pool.query('INSERT INTO users_app (id, nombre, cedula, tenant_id, rol_id, estado_arl, estado_alturas, estado_cuenta, ultimo_acceso) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING',
      [u.id, u.nombre, u.cedula, u.tenant_id, u.rol_id, u.estado_arl, u.estado_alturas, u.estado_cuenta, u.ultimo_acceso]);
  }
  for (const p of SEED_PROJECTS) {
    await pool.query('INSERT INTO projects (id, tenant_id, nombre, tipo, ubicacion, fecha_inicio, estado, horas_hombre_acumuladas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING',
      [p.id, p.tenant_id, p.nombre, p.tipo, p.ubicacion, p.fecha_inicio, p.estado, p.horas_hombre_acumuladas]);
  }
  for (const e of SEED_EMPLEADOS) {
    await pool.query('INSERT INTO empleados (id, tenant_id, project_id, nombre, cedula, cargo, tipo_contrato, fecha_ingreso, eps, estado_arl, estado_alturas, estado_cuenta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING',
      [e.id, e.tenant_id, e.project_id, e.nombre, e.cedula, e.cargo, e.tipo_contrato, e.fecha_ingreso, e.eps, e.estado_arl, e.estado_alturas, e.estado_cuenta]);
  }
  for (const c of SEED_CHARLAS) {
    await pool.query('INSERT INTO charlas (id, project_id, tenant_id, fecha, tema, responsable, asistentes, duracion_min) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING',
      [c.id, c.project_id, c.tenant_id, c.fecha, c.tema, c.responsable, c.asistentes, c.duracion_min]);
  }
  for (const b of SEED_BITACORA) {
    await pool.query('INSERT INTO bitacora (id, project_id, tenant_id, fecha, autor, tipo, descripcion) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
      [b.id, b.project_id, b.tenant_id, b.fecha, b.autor, b.tipo, b.descripcion]);
  }
  for (const p of SEED_PRESUPUESTO) {
    await pool.query('INSERT INTO presupuesto (id, project_id, tenant_id, rubro, presupuestado, ejecutado) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING',
      [p.id, p.project_id, p.tenant_id, p.rubro, p.presupuestado, p.ejecutado]);
  }
  for (const p of SEED_PLAN) {
    await pool.query('INSERT INTO plan_anual (id, project_id, tenant_id, actividad, mes_objetivo, responsable, estado) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
      [p.id, p.project_id, p.tenant_id, p.actividad, p.mes_objetivo, p.responsable, p.estado]);
  }
  for (const d of SEED_DOCUMENTOS) {
    await pool.query('INSERT INTO documentos (id, project_id, tenant_id, nombre, tipo, fecha_subida, subido_por) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING',
      [d.id, d.project_id, d.tenant_id, d.nombre, d.tipo, d.fecha_subida, d.subido_por]);
  }
  for (const n of SEED_LEGAL_NORMS) {
    await pool.query('INSERT INTO legal_norms (id, codigo_norma, nombre, version_year, sector_aplicable, estado, fecha_publicacion, resumen_requisito) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING',
      [n.id, n.codigo_norma, n.nombre, n.version_year, n.sector_aplicable, n.estado, n.fecha_publicacion, n.resumen_requisito]);
  }
  for (const p of SEED_PERMISOS_TRABAJO) {
    await pool.query('INSERT INTO permisos_trabajo (id, tenant_id, project_id, empleado_id, tipo, validez_inicio, validez_fin, estado, motivo_rechazo, creado_por, fecha_creacion) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING',
      [p.id, p.tenant_id, p.project_id, p.empleado_id, p.tipo, p.validez_inicio, p.validez_fin, p.estado, p.motivo_rechazo, p.creado_por, p.validez_inicio]);
  }
  for (const a of SEED_ACCIDENTES) {
    await pool.query('INSERT INTO accidentes (id, project_id, fecha, tipo, dias_perdidos) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING',
      [a.id, a.project_id, a.fecha, a.tipo, a.dias_perdidos]);
  }
}

async function nextId(table, prefix, padLength) {
  const { rows } = await pool.query(`SELECT id FROM ${table} WHERE id LIKE $1 ORDER BY id DESC LIMIT 1`, [`${prefix}-%`]);
  let n = 1;
  if (rows.length) {
    const last = parseInt(rows[0].id.split('-')[1], 10);
    if (!isNaN(last)) n = last + 1;
  }
  return `${prefix}-${String(n).padStart(padLength, '0')}`;
}

module.exports = { pool, initDb, nextId, MODULES, ACTIONS };
