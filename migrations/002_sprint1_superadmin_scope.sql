-- Sprint 1 — Frente B: Super-Admin sin FK a tenant ficticio.
-- Se aplica ANTES de 003 (concurrencia) — es la deuda táctica más chica y ya
-- señalada explícitamente como temporal (ancla TEN-0001 del Sprint 0).
--
-- Cómo aplicar: psql $DATABASE_URL -f migrations/002_sprint1_superadmin_scope.sql
-- Seguro de re-correr (idempotente): DROP NOT NULL y UPDATE con condición son no-ops
-- si ya se aplicaron antes.

BEGIN;

ALTER TABLE auth_credentials ALTER COLUMN tenant_id DROP NOT NULL;

UPDATE auth_credentials SET tenant_id = NULL
  WHERE user_id IN (SELECT id FROM users_app WHERE rol_id = 'super-admin');
UPDATE users_app SET tenant_id = NULL WHERE rol_id = 'super-admin';

COMMIT;

-- Verificación post-migración (correr a mano):
-- SELECT id, nombre, tenant_id, rol_id FROM users_app WHERE rol_id = 'super-admin';
-- tenant_id debe salir NULL. El login de ese usuario debe seguir funcionando igual
-- (RLS depende de app.is_superadmin, no de este valor — ver migrations/001_sprint0_blindaje.sql).
