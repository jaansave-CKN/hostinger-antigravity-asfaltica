-- Sprint 2 — Frente A: tabla real para Inspecciones y Rondas.
-- Deliberadamente NO es la tabla audits_and_capa del documento maestro original
-- (esa era para hallazgos/CAPA con causa raíz — no hay pantalla que la use todavía).
-- Esta es un snapshot simple del checklist de ronda, que es lo que la UI real captura.

BEGIN;

CREATE TABLE IF NOT EXISTS inspecciones_rondas (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  sector TEXT NOT NULL,
  items JSONB NOT NULL,                     -- [{ item: '...', cumple: true|false }, ...]
  porcentaje_cumplimiento NUMERIC(5,2) NOT NULL,
  realizado_por TEXT NOT NULL,
  version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE inspecciones_rondas ENABLE ROW LEVEL SECURITY;
ALTER TABLE inspecciones_rondas FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON inspecciones_rondas;
CREATE POLICY tenant_isolation ON inspecciones_rondas USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR tenant_id = current_setting('app.tenant_id', true)
);

CREATE INDEX IF NOT EXISTS idx_inspecciones_tenant ON inspecciones_rondas(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inspecciones_project ON inspecciones_rondas(project_id);

COMMIT;
