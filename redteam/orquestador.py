"""Orquestador de secuencia de ataques (Bloque D, Paso 18).

Dispara los módulos de redteam/ correspondientes a escenario.tipos_ataque,
respetando timing según escenario.sofisticacion (SPEC.md / Paso 18 literal):
- ruidoso: todos los ataques en simultáneo real (asyncio.gather), no solo
  "uno detrás de otro sin pausa" — un atacante ruidoso no se ordena.
- medio / sigiloso: en secuencia, con espaciado moderado o amplio entre cada
  uno, imitando actividad esporádica para evadir detección basada en ráfagas.

scan/replay/spoofing usan llamadas síncronas de scapy (bloqueantes); se
ejecutan con asyncio.to_thread para no trabar el event loop — necesario para
que la simultaneidad de "ruidoso" sea real y no solo aparente.

Recibe el PLCVirtual (no solo host/puerto sueltos) porque la escritura
ilegítima necesita sus registros para elegir el objetivo según
escenario.criticidad_objetivo (SPEC.md sección 2, variable #3) — antes
atacaba siempre la dirección 0 sin importar la criticidad pedida.

TODO(equipo): los segundos de espaciado son una propuesta razonable de
arranque (mismo criterio que las otras tablas de SPEC.md), no un valor
validado contra la demo real.
"""

import asyncio

from core.plc_virtual import PLCVirtual, seleccionar_registro_por_criticidad
from core.schemas import Escenario, Sofisticacion, TipoAtaque
from redteam.escritura_ilegitima import escribir_registro_no_autorizado
from redteam.flood import inundar
from redteam.replay import capturar_paquetes_modbus, reinyectar_paquetes
from redteam.scan import escanear_rango
from redteam.spoofing import enviar_paquete_spoofed

# Segundos de espera entre ataques encadenados, para sofisticacion != ruidoso.
_ESPACIADO_SEG = {
    Sofisticacion.MEDIO: 1.5,
    Sofisticacion.SIGILOSO: 4.0,
}

# Valor con el que la escritura ilegítima pisa el registro elegido: dentro
# del rango de un registro Modbus de 16 bits (0-65535, si no pymodbus lo
# rechaza antes de salir a la red) pero por encima de cualquier
# rango_valido_crudo definido en registros.json (el máximo ahí es 9999), para
# que blueteam/deteccion.py lo detecte siempre por la regla de rango (Paso 19).
_VALOR_ESCRITURA_ILEGITIMA = 65000


async def _ejecutar_uno(tipo: TipoAtaque, escenario: Escenario, plc: PLCVirtual) -> str:
    """Ejecuta un único ataque contra `plc`. Devuelve tipo.value si tuvo
    éxito; propaga cualquier excepción para que el llamador decida cómo
    reportarla.
    """
    host, puerto = plc.host, plc.puerto

    if tipo == TipoAtaque.ESCRITURA_ILEGITIMA:
        objetivo = seleccionar_registro_por_criticidad(plc.registros, escenario.criticidad_objetivo)
        print(
            f"[orquestador] escritura_ilegitima -> '{objetivo['nombre']}' "
            f"(dirección {objetivo['direccion']}, criticidad {objetivo['criticidad']})"
        )
        await escribir_registro_no_autorizado(
            host, puerto, direccion=objetivo["direccion"], valor=_VALOR_ESCRITURA_ILEGITIMA
        )
    elif tipo == TipoAtaque.FLOOD:
        await inundar(host, puerto, intensidad_pps=escenario.intensidad_pps, duracion_seg=2.0)
    elif tipo == TipoAtaque.SCAN:
        await asyncio.to_thread(escanear_rango, [host], puerto)
    elif tipo == TipoAtaque.REPLAY:
        paquetes = await asyncio.to_thread(capturar_paquetes_modbus, host, 5, 3.0)
        await asyncio.to_thread(reinyectar_paquetes, paquetes)
    elif tipo == TipoAtaque.SPOOFING:
        await asyncio.to_thread(enviar_paquete_spoofed, "10.0.0.99", host, puerto)
    else:
        raise ValueError(f"Tipo de ataque sin implementación en el orquestador: {tipo}")
    return tipo.value


async def ejecutar_campania(escenario: Escenario, plc: PLCVirtual) -> list[str]:
    """Ejecuta los módulos de redteam/ correspondientes a
    escenario.tipos_ataque contra `plc`.

    scan/replay/spoofing necesitan que scapy pueda armar paquetes crudos
    (Npcap en Windows / root en Linux). Si el entorno no lo permite, ese
    ataque puntual se salta con una advertencia en vez de tirar abajo toda
    la campaña — el resto sigue igual.

    Devuelve la lista de ataques efectivamente ejecutados. Con sofisticacion
    ruidoso el orden no está garantizado (corren en simultáneo); con
    medio/sigiloso, el orden es el de escenario.tipos_ataque.
    """
    if escenario.sofisticacion == Sofisticacion.RUIDOSO:
        resultados = await asyncio.gather(
            *(_ejecutar_uno(tipo, escenario, plc) for tipo in escenario.tipos_ataque),
            return_exceptions=True,
        )
        ejecutados = []
        for tipo, resultado in zip(escenario.tipos_ataque, resultados):
            if isinstance(resultado, Exception):
                print(f"[orquestador] {tipo.value} no se pudo ejecutar (¿falta Npcap/root?): {resultado}")
            else:
                ejecutados.append(resultado)
        return ejecutados

    espera = _ESPACIADO_SEG[escenario.sofisticacion]
    ejecutados = []
    for i, tipo in enumerate(escenario.tipos_ataque):
        if i > 0:
            await asyncio.sleep(espera)
        try:
            ejecutados.append(await _ejecutar_uno(tipo, escenario, plc))
        except Exception as exc:
            print(f"[orquestador] {tipo.value} no se pudo ejecutar (¿falta Npcap/root?): {exc}")

    return ejecutados
