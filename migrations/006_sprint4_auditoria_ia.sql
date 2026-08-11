-- Sprint 4 — Auditor de Cumplimiento por IA. Tabla nueva de verdad: ai_audit_findings
-- solo existía en el documento maestro hasta ahora, nunca se creó.
-- 'documentos' queda en el CHECK por compatibilidad futura pero esta versión NO lo
-- evalúa (ver server.js) — no hay extracción real de contenido de archivo, solo
-- metadatos, y no vamos a fingir una auditoría de contenido que no existe.

BEGIN;

CREATE TABLE IF NOT EXISTS ai_audit_findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  project_id TEXT REFERENCES projects(id),
  fuente TEXT NOT NULL CHECK (fuente IN ('charlas','bitacora','permisos_trabajo','documentos','inspecciones_rondas')),
  fuente_id TEXT NOT NULL,
  hallazgo TEXT NOT NULL,
  norma_citada TEXT,
  severidad TEXT NOT NULL CHECK (severidad IN ('Baja','Media','Alta','Critica')),
  confianza_modelo NUMERIC(3,2) CHECK (confianza_modelo BETWEEN 0 AND 1),
  estado TEXT NOT NULL DEFAULT 'Nuevo' CHECK (estado IN ('Nuevo','Revisado','Descartado','Escalado')),
  revisado_por TEXT,
  version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ai_audit_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_audit_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_audit_findings;
CREATE POLICY tenant_isolation ON ai_audit_findings USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR tenant_id = current_setting('app.tenant_id', true)
);

CREATE INDEX IF NOT EXISTS idx_ai_findings_tenant ON ai_audit_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_findings_fuente ON ai_audit_findings(fuente, fuente_id);

COMMIT;
