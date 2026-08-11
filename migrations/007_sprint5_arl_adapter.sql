-- Sprint 5 — Patrón adaptador para ARL. Solo se implementa 'manual' (formaliza el
-- flujo humano que ya existe) — el CHECK de adaptador se amplía en una migración
-- futura el día que haya un proveedor real contratado, no antes.

BEGIN;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS arl_provider TEXT;

CREATE TABLE IF NOT EXISTS arl_verification_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  empleado_id TEXT NOT NULL REFERENCES empleados(id),
  campo TEXT NOT NULL CHECK (campo IN ('estado_arl', 'estado_alturas')),
  valor_anterior TEXT,
  valor_nuevo TEXT NOT NULL,
  adaptador TEXT NOT NULL DEFAULT 'manual' CHECK (adaptador IN ('manual')),
  actualizado_por TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE arl_verification_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE arl_verification_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON arl_verification_log;
CREATE POLICY tenant_isolation ON arl_verification_log USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR tenant_id = current_setting('app.tenant_id', true)
);

CREATE INDEX IF NOT EXISTS idx_arl_log_empleado ON arl_verification_log(empleado_id);
CREATE INDEX IF NOT EXISTS idx_arl_log_tenant ON arl_verification_log(tenant_id);

COMMIT;
