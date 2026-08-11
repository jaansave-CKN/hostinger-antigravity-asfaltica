-- Sprint 3 — Botón de Pánico / SOS. Alcance real: persistencia + GPS real +
-- visibilidad en vivo. Push/SMS/WhatsApp real NO está implementado (sin proveedor
-- contratado) — canal_notificacion / notificacion_estado dejan la estructura lista
-- para conectar esa integración después sin otra migración de esquema.

BEGIN;

CREATE TABLE IF NOT EXISTS emergency_alerts (
  id TEXT PRIMARY KEY,
  -- NULLABLE a propósito: una alerta disparada por una sesión Super-Admin sin tenant
  -- seleccionado (ej. desde seleccion-empresa.html) no tiene un tenant único al que
  -- pertenecer — mismo patrón que auth_credentials.tenant_id (Sprint 1, Frente B).
  tenant_id TEXT REFERENCES tenants(id),
  project_id TEXT REFERENCES projects(id),
  user_id TEXT NOT NULL REFERENCES users_app(id),
  tipo TEXT NOT NULL CHECK (tipo IN ('Panico','Medica','Incendio','Intrusion')),
  lat DOUBLE PRECISION,
  lng DOUBLE PRECISION,
  estado TEXT NOT NULL DEFAULT 'Activa' CHECK (estado IN ('Activa','Atendida','Falsa_Alarma')),
  atendido_por TEXT,
  -- Arquitectura abierta para el futuro proveedor de notificación (sin implementar todavía):
  canal_notificacion TEXT,             -- 'sms' | 'whatsapp' | 'push' | NULL mientras no exista integración
  notificacion_estado TEXT NOT NULL DEFAULT 'sin_proveedor'
    CHECK (notificacion_estado IN ('sin_proveedor', 'pendiente_envio', 'enviado', 'fallido')),
  version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  atendido_en TIMESTAMPTZ
);

ALTER TABLE emergency_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE emergency_alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON emergency_alerts;
CREATE POLICY tenant_isolation ON emergency_alerts USING (
  current_setting('app.is_superadmin', true) = 'true'
  OR tenant_id = current_setting('app.tenant_id', true)
);

CREATE INDEX IF NOT EXISTS idx_emergency_alerts_tenant ON emergency_alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_emergency_alerts_estado ON emergency_alerts(estado);

COMMIT;
