-- Sprint 1 — Frente A: control de concurrencia optimista.
-- Se aplica DESPUÉS de 002 (Super-Admin scope). Cubre exactamente las 10 tablas
-- con ruta PUT real en server.js: roles, tenants, users_app, projects, empleados,
-- charlas, bitacora, presupuesto, plan_anual, legal_norms. `documentos` no tiene
-- PUT hoy (solo POST/DELETE) — se excluye a propósito, no por omisión.
--
-- Cómo aplicar: psql $DATABASE_URL -f migrations/003_sprint1_concurrencia.sql

BEGIN;

ALTER TABLE roles        ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE tenants      ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE users_app    ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE projects     ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE empleados    ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE charlas      ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE bitacora     ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE presupuesto  ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE plan_anual   ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;
ALTER TABLE legal_norms  ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;

COMMIT;

-- Verificación post-migración (correr a mano):
-- SELECT id, version FROM empleados LIMIT 5;  -- todas las filas existentes deben quedar en version=1
