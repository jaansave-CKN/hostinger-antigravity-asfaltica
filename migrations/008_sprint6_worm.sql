-- Sprint 6 — WORM técnico (hash-chain SHA-256 + bloqueo real en BD). NO es
-- certificación ONAC (eso sigue sin proveedor) — sello_tiempo_estado queda en
-- 'sin_proveedor' hasta que se contrate un prestador acreditado.

BEGIN;

-- ── ai_audit_findings: WORM desde creación, estado/revisado_por/version siguen mutables ──
ALTER TABLE ai_audit_findings ADD COLUMN IF NOT EXISTS contenido_hash TEXT;
ALTER TABLE ai_audit_findings ADD COLUMN IF NOT EXISTS hash_anterior TEXT;
ALTER TABLE ai_audit_findings ADD COLUMN IF NOT EXISTS sello_tiempo_estado TEXT NOT NULL DEFAULT 'sin_proveedor';

CREATE OR REPLACE FUNCTION worm_bloquear_ai_audit_findings() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ai_audit_findings es WORM — no se permite DELETE (id=%)', OLD.id;
  END IF;
  IF NEW.hallazgo IS DISTINCT FROM OLD.hallazgo
     OR NEW.norma_citada IS DISTINCT FROM OLD.norma_citada
     OR NEW.severidad IS DISTINCT FROM OLD.severidad
     OR NEW.confianza_modelo IS DISTINCT FROM OLD.confianza_modelo
     OR NEW.fuente IS DISTINCT FROM OLD.fuente
     OR NEW.fuente_id IS DISTINCT FROM OLD.fuente_id
     OR NEW.contenido_hash IS DISTINCT FROM OLD.contenido_hash
     OR NEW.hash_anterior IS DISTINCT FROM OLD.hash_anterior THEN
    RAISE EXCEPTION 'ai_audit_findings es WORM — el contenido del hallazgo no se puede modificar (id=%)', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_worm_ai_audit_findings ON ai_audit_findings;
CREATE TRIGGER trg_worm_ai_audit_findings
  BEFORE UPDATE OR DELETE ON ai_audit_findings
  FOR EACH ROW EXECUTE FUNCTION worm_bloquear_ai_audit_findings();

-- ── legal_norms: WORM condicional — solo una vez llega a publicado_a_tenants ──
ALTER TABLE legal_norms ADD COLUMN IF NOT EXISTS contenido_hash TEXT;
ALTER TABLE legal_norms ADD COLUMN IF NOT EXISTS hash_anterior TEXT;
ALTER TABLE legal_norms ADD COLUMN IF NOT EXISTS sello_tiempo_estado TEXT NOT NULL DEFAULT 'sin_proveedor';

CREATE OR REPLACE FUNCTION worm_bloquear_legal_norms() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.estado = 'publicado_a_tenants' THEN
    RAISE EXCEPTION 'Norma % ya publicada a tenants — WORM, es inmutable (sin UPDATE ni DELETE)', OLD.id;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_worm_legal_norms ON legal_norms;
CREATE TRIGGER trg_worm_legal_norms
  BEFORE UPDATE OR DELETE ON legal_norms
  FOR EACH ROW EXECUTE FUNCTION worm_bloquear_legal_norms();

-- ── accidentes: tabla nueva de verdad (nunca tuvo ruta de API) — WORM desde el día uno ──
ALTER TABLE accidentes ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE accidentes ADD COLUMN IF NOT EXISTS contenido_hash TEXT;
ALTER TABLE accidentes ADD COLUMN IF NOT EXISTS hash_anterior TEXT;
ALTER TABLE accidentes ADD COLUMN IF NOT EXISTS sello_tiempo_estado TEXT NOT NULL DEFAULT 'sin_proveedor';

-- accidentes nunca tuvo RLS (nunca tuvo ruta que protegerle) — se agrega ahora que sí la tiene.
ALTER TABLE accidentes ENABLE ROW LEVEL SECURITY;
ALTER TABLE accidentes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON accidentes;
CREATE POLICY tenant_isolation ON accidentes USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR tenant_id = current_setting('app.tenant_id', true)
);

CREATE OR REPLACE FUNCTION worm_bloquear_accidentes() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'accidentes es WORM — no se permite UPDATE ni DELETE (id=%)', OLD.id;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_worm_accidentes ON accidentes;
CREATE TRIGGER trg_worm_accidentes
  BEFORE UPDATE OR DELETE ON accidentes
  FOR EACH ROW EXECUTE FUNCTION worm_bloquear_accidentes();

COMMIT;

-- Verificación post-migración (correr a mano):
-- INSERT ... INTO ai_audit_findings ...; luego UPDATE ai_audit_findings SET hallazgo='x' WHERE id=...;
-- debe fallar con la excepción del trigger.
