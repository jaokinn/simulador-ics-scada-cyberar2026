"""Escaneo de descubrimiento de servidores Modbus (Bloque D, Paso 13).

Dos implementaciones del mismo ataque de reconocimiento:

  - `escanear_rango` (SYN scan con scapy): requiere armar paquetes IP/TCP
    crudos — en Windows hace falta Npcap; en Linux, root o CAP_NET_RAW. Es el
    caso normal dentro de los contenedores aislados de Bloque G.
  - `escanear_modbus` (portable): connect-scan TCP + enumeración del mapa de
    holding registers por lecturas Modbus reales. No usa scapy ni privilegios;
    corre igual en Windows, Linux o Docker. Es la que usa el ejecutable de demo.

Ambas son reconocimiento real contra el objetivo; la portable es más ruidosa
(un connect-scan completa el handshake TCP y enumera el banco entero), y por eso
la detecta la regla de ritmo del IDS igual que un nmap agresivo.
"""

import asyncio
import time
from dataclasses import dataclass

from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusException

PUERTO_MODBUS = 502


@dataclass
class ResultadoScan:
    ip: str
    puerto: int
    tiempo_respuesta_ms: float


def escanear_rango(
    ips: list[str], puerto: int = PUERTO_MODBUS, timeout: float = 1.0
) -> list[ResultadoScan]:
    """Envía un SYN a `puerto` en cada IP de `ips` y reporta las que
    responden SYN-ACK (servidor Modbus activo), con IP, puerto y tiempo de
    respuesta.
    """
    from scapy.all import IP, TCP, sr1

    resultados = []
    for ip in ips:
        paquete = IP(dst=ip) / TCP(dport=puerto, flags="S")
        inicio = time.monotonic()
        respuesta = sr1(paquete, timeout=timeout, verbose=0)
        transcurrido_ms = (time.monotonic() - inicio) * 1000

        if respuesta is not None and respuesta.haslayer(TCP) and respuesta[TCP].flags == "SA":
            resultados.append(
                ResultadoScan(ip=ip, puerto=puerto, tiempo_respuesta_ms=round(transcurrido_ms, 2))
            )
            # Cerrar la conexión a medias abierta con un RST (buena práctica de escaneo SYN).
            sr1(IP(dst=ip) / TCP(dport=puerto, flags="R"), timeout=timeout, verbose=0)

    return resultados


def sondear_syn_rafaga(host: str, puerto: int, cantidad: int) -> int:
    """Ráfaga de SYN crudos (half-open scan) con scapy contra `host:puerto`.

    Equivalente ruidoso a un `nmap -sS` agresivo: manda `cantidad` SYN seguidos
    sin esperar respuesta (por eso es rápido, a diferencia de `escanear_rango`
    que hace sr1 por probe). Requiere privilegios de red cruda (root en Linux /
    Npcap en Windows). Devuelve la cantidad de SYN enviados.
    """
    from scapy.all import IP, TCP, send

    paquetes = [
        IP(dst=host) / TCP(dport=puerto, sport=40000 + (i % 20000), flags="S")
        for i in range(cantidad)
    ]
    send(paquetes, verbose=0)
    return cantidad


async def _puerto_abierto(host: str, puerto: int, timeout: float = 0.5) -> bool:
    """Connect-scan de un puerto: intenta un handshake TCP completo (sin scapy).

    Un servidor Modbus activo acepta la conexión; si el puerto está cerrado, el
    connect falla de inmediato.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, puerto), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def escanear_modbus(
    host: str, puerto: int, direcciones: list[int], pasadas: int = 2, slave: int = 1
) -> tuple[bool, int]:
    """Reconocimiento portable, sin scapy ni privilegios (equivalente de demo a
    `escanear_rango`):

      1. connect-scan TCP para confirmar que el servicio Modbus está activo, y
      2. enumeración del mapa de holding registers leyendo cada dirección de
         `direcciones` (`pasadas` veces), como haría un `nmap --script
         modbus-discover` o un `mbtget` mapeando el PLC.

    Devuelve `(puerto_abierto, paquetes_enviados)`. La ráfaga de lecturas es lo
    que dispara la regla de ritmo del IDS (R-RITMO-001): enumerar el banco es
    ruidoso por naturaleza.
    """
    abierto = await _puerto_abierto(host, puerto)
    if not abierto:
        return False, 0

    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()
    enviados = 0
    try:
        for _ in range(pasadas):
            for direccion in direcciones:
                try:
                    await client.read_holding_registers(address=direccion, count=1, slave=slave)
                except (ModbusException, ConnectionError, OSError):
                    # un registro que no responde no frena el barrido: enumerar
                    # el banco entero es justamente lo que hace ruidoso al scan.
                    pass
                enviados += 1
    finally:
        client.close()

    return abierto, enviados
