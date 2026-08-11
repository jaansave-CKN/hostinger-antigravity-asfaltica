-- Sprint 0 — Blindaje crítico (Gate 2, docs/02_gate2_planimetria_tecnica.md §A-B)
-- Alcance: SOLO auth real + aislamiento de tenant + RLS. La columna `version`
-- (concurrencia) es Sprint 1, deliberadamente fuera de esta migración.
--
-- Cómo aplicar: revisar completo antes de correr. NO se ejecuta automáticamente
-- contra Render — requiere `psql $DATABASE_URL -f migrations/001_sprint0_blindaje.sql`
-- corrido a mano por decisión explícita, con backup previo de la base real.

BEGIN;

-- ── 1. Backfill de tenant_id en tablas que hoy solo tienen project_id ──────────
ALTER TABLE charlas     ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE bitacora    ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE presupuesto ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE plan_anual  ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE documentos  ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE accidentes  ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);

UPDATE charlas     c  SET tenant_id = p.tenant_id FROM projects p WHERE p.id = c.project_id  AND c.tenant_id IS NULL;
UPDATE bitacora    b  SET tenant_id = p.tenant_id FROM projects p WHERE p.id = b.project_id  AND b.tenant_id IS NULL;
UPDATE presupuesto pr SET tenant_id = p.tenant_id FROM projects p WHERE p.id = pr.project_id AND pr.tenant_id IS NULL;
UPDATE plan_anual  pl SET tenant_id = p.tenant_id FROM projects p WHERE p.id = pl.project_id AND pl.tenant_id IS NULL;
UPDATE documentos  d  SET tenant_id = p.tenant_id FROM projects p WHERE p.id = d.project_id  AND d.tenant_id IS NULL;
UPDATE accidentes  a  SET tenant_id = p.tenant_id FROM projects p WHERE p.id = a.project_id  AND a.tenant_id IS NULL;

ALTER TABLE charlas     ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE bitacora    ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE presupuesto ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE plan_anual  ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE documentos  ALTER COLUMN tenant_id SET NOT NULL;
-- accidentes.tenant_id se deja NULLABLE: es histórico y no se expone por API propia todavía.

CREATE INDEX IF NOT EXISTS idx_charlas_tenant     ON charlas(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bitacora_tenant    ON bitacora(tenant_id);
CREATE INDEX IF NOT EXISTS idx_presupuesto_tenant ON presupuesto(tenant_id);
CREATE INDEX IF NOT EXISTS idx_plan_anual_tenant  ON plan_anual(tenant_id);
CREATE INDEX IF NOT EXISTS idx_documentos_tenant  ON documentos(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_app_tenant   ON users_app(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_tenant    ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_empleados_tenant   ON empleados(tenant_id);
CREATE INDEX IF NOT EXISTS idx_permisos_tenant    ON permisos_trabajo(tenant_id);

-- ── 2. Auth real por usuario — reemplaza el portón de contraseña única ─────────
CREATE TABLE IF NOT EXISTS auth_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users_app(id),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  password_hash TEXT NOT NULL,
  must_change_password BOOLEAN NOT NULL DEFAULT true,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── 3. RLS por GUC de sesión — sin depender de roles de conexión de Render ─────
-- Nota de diseño (se aparta de docs/02_gate2_planimetria_tecnica.md §B.1, que
-- proponía roles Postgres app_tenant/app_superadmin con BYPASSRLS): esa versión
-- exige GRANT sobre el usuario real de conexión de Render, que este proceso de
-- migración no conoce ni puede administrar sin acceso al dashboard. En su lugar,
-- ambas capas viven en la misma policy vía dos GUCs de sesión, fijados SOLO por
-- el middleware del servidor a partir de la sesión ya autenticada — nunca desde
-- el cliente. Resultado equivalente: sin `app.tenant_id` ni `app.is_superadmin`
-- en 'true', ninguna fila es visible.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['users_app','projects','empleados','permisos_trabajo',
                            'charlas','bitacora','presupuesto','plan_anual','documentos']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t); -- aplica incluso al dueño de la tabla
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (
         current_setting(''app.is_superadmin'', true) = ''true''
         OR tenant_id = current_setting(''app.tenant_id'', true)
       )',
      t
    );
  END LOOP;
END
$$;

-- tenants: cada sesión de tenant ve SOLO su propia fila (id = app.tenant_id);
-- Super-Admin ve y administra todas (gestión de la plataforma, no de un tenant).
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_self_or_superadmin ON tenants;
CREATE POLICY tenant_self_or_superadmin ON tenants USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR id = current_setting('app.tenant_id', true)
);

-- Catálogos compartidos: lectura abierta a cualquier sesión autenticada,
-- escritura restringida a Super-Admin (misma GUC app.is_superadmin).
ALTER TABLE legal_norms ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS legal_norms_read ON legal_norms;
DROP POLICY IF EXISTS legal_norms_write ON legal_norms;
CREATE POLICY legal_norms_read ON legal_norms FOR SELECT USING (true);
CREATE POLICY legal_norms_write ON legal_norms FOR INSERT USING (current_setting('app.is_superadmin', true) = 'true');
CREATE POLICY legal_norms_update ON legal_norms FOR UPDATE USING (current_setting('app.is_superadmin', true) = 'true');
CREATE POLICY legal_norms_delete ON legal_norms FOR DELETE USING (current_setting('app.is_superadmin', true) = 'true');

COMMIT;

-- ── Verificación post-migración (correr a mano, no forma parte de la transacción) ──
-- BEGIN;
-- SET LOCAL app.tenant_id = 'TEN-0001';
-- SELECT count(*) FROM empleados;  -- debe ver SOLO empleados de TEN-0001, no de TEN-0002..TEN-0005
-- ROLLBACK;
