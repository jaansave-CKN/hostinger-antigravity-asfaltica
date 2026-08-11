// Contrato de adaptador ARL: verificar(empleado) -> { adaptador, resultado, detalle }
//
// Este es el ÚNICO adaptador real hoy. No llama a ningún servicio externo — refleja
// el valor que un humano ya escribió a mano en empleados.estado_arl/estado_alturas.
// No existe proveedor de ARL contratado (ver docs/analisis_gaps_v1.md #3: tampoco
// existe una API pública unificada en Colombia).
//
// Cuando exista un proveedor real, se agrega otro archivo en este mismo directorio
// (ej. sura-adapter.js) que implemente el mismo contrato. server.js no cambia: sigue
// leyendo empleados.estado_arl/estado_alturas igual, sin importar qué adaptador los
// escribió.

const NOMBRE = 'manual';

async function verificar(empleado) {
  return {
    adaptador: NOMBRE,
    resultado: { estado_arl: empleado.estado_arl, estado_alturas: empleado.estado_alturas },
    detalle: { fuente: 'Ingreso manual por un usuario del sistema — sin verificación automática contra ninguna ARL.' },
  };
}

module.exports = { NOMBRE, verificar };
