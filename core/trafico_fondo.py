"""Tráfico Modbus legítimo de fondo (Bloque C, Paso 11).

Cliente Modbus que hace polling periódico a un PLCVirtual, imitando a un
maestro SCADA real: intervalo regular perturbado por un jitter acotado (no
aleatoriedad uniforme, que se vería como ruido de ataque). La frecuencia base
la fija `ruido_fondo_pps` del Escenario (Bloque A, Paso 3).
"""

import asyncio
import random

from pymodbus.client import AsyncModbusTcpClient

# Jitter máximo como fracción del período base — imita la variabilidad real de
# un polling SCADA (latencia de red/CPU), sin ser aleatoriedad uniforme.
_JITTER_FRACCION = 0.15


async def generar_trafico_fondo(
    host: str,
    puerto: int,
    direcciones: list[int],
    ruido_fondo_pps: int,
    duracion_seg: float,
    slave: int = 1,
) -> int:
    """Hace polling periódico de `direcciones` (contiguas) durante `duracion_seg`.

    `ruido_fondo_pps` son paquetes/seg de lectura; se traduce a un intervalo
    base entre polls. Cada intervalo se perturba con jitter gaussiano acotado,
    no aleatoriedad uniforme, para parecerse a polling SCADA real.

    Devuelve la cantidad de polls realizados.
    """
    if ruido_fondo_pps <= 0:
        raise ValueError("ruido_fondo_pps debe ser > 0 para generar tráfico de fondo")
    if not direcciones:
        raise ValueError("direcciones no puede estar vacío")

    periodo_base = 1.0 / ruido_fondo_pps
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()

    polls = 0
    loop = asyncio.get_event_loop()
    fin = loop.time() + duracion_seg
    try:
        while loop.time() < fin:
            inicio_iter = loop.time()
            await client.read_holding_registers(
                address=direcciones[0], count=len(direcciones), slave=slave
            )
            polls += 1

            # Descontar el tiempo que ya consumió la llamada de red antes de
            # dormir el resto del período — si no, el pps real cae por debajo
            # del pedido a medida que sube ruido_fondo_pps (mismo bug que se
            # encontró en redteam/flood.py).
            transcurrido = loop.time() - inicio_iter
            jitter = random.gauss(0, periodo_base * _JITTER_FRACCION)
            espera = max(0.0, periodo_base - transcurrido + jitter)
            await asyncio.sleep(espera)
    finally:
        client.close()

    return polls
