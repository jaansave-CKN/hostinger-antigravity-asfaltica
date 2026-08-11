// Aprovisiona un usuario real con contraseña hasheada. Reemplaza al portón de
// contraseña única (Gap #8) — no existe ningún valor por defecto hardcodeado
// a propósito: si no pasas --password, el script se detiene y no crea nada.
//
// Uso:
//   node scripts/crear-usuario.js --nombre "Ricardo Salazar" --cedula 80112334 \
//     --tenant TEN-0002 --rol admin-tenant --password "una-clave-real-y-larga"
//
// Requiere DATABASE_URL en el entorno (mismo valor que usa server.js).

const { pool, nextId } = require('../db');
const bcrypt = require('bcryptjs');

function parseArgs() {
  const args = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '');
    args[key] = argv[i + 1];
  }
  return args;
}

async function main() {
  const { nombre, cedula, tenant, rol, password } = parseArgs();
  if (!nombre || !cedula || !tenant || !rol || !password) {
    console.error('Faltan argumentos. Uso: node scripts/crear-usuario.js --nombre "..." --cedula ... --tenant TEN-XXXX --rol admin-tenant --password "..."');
    process.exitCode = 1;
    return;
  }
  if (password.length < 10) {
    console.error('La contraseña debe tener al menos 10 caracteres.');
    process.exitCode = 1;
    return;
  }

  const { rows: tenantRows } = await pool.query('SELECT id FROM tenants WHERE id = $1', [tenant]);
  if (!tenantRows.length) {
    console.error(`Tenant ${tenant} no existe.`);
    process.exitCode = 1;
    return;
  }
  const { rows: rolRows } = await pool.query('SELECT id FROM roles WHERE id = $1', [rol]);
  if (!rolRows.length) {
    console.error(`Rol ${rol} no existe. Roles válidos: super-admin, admin-tenant, hseq-manager, supervisor-obra, guarda, auditor-externo.`);
    process.exitCode = 1;
    return;
  }

  const id = await nextId('users_app', 'USR', 3);
  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    `INSERT INTO users_app (id, nombre, cedula, tenant_id, rol_id, estado_arl, estado_alturas, estado_cuenta, ultimo_acceso)
     VALUES ($1,$2,$3,$4,$5,'Parcial','Parcial','Activo',NULL)`,
    [id, nombre, cedula, tenant, rol]
  );
  await pool.query(
    `INSERT INTO auth_credentials (user_id, tenant_id, password_hash) VALUES ($1,$2,$3)`,
    [id, tenant, passwordHash]
  );

  console.log(`Usuario creado: ${id} — ${nombre} (${rol}, tenant ${tenant}). Ya puede iniciar sesión con su cédula y la contraseña provista.`);
  await pool.end();
}

main().catch(err => {
  console.error('Error creando usuario:', err.message);
  process.exitCode = 1;
});
