"""PLC virtual — servidor Modbus TCP puro (Bloque C, Paso 9).

Solo el servidor Modbus: sin lógica de ataque (redteam/) ni de detección
(blueteam/). Usa la API asíncrona de pymodbus 3.x — no mezclar con ejemplos
de pymodbus 2.x (síncrona), rompe la compatibilidad (ver SPEC.md sección 5 /
requirements.txt).
"""

import json
from pathlib import Path

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import ModbusTcpServer

_REGISTROS_PATH = Path(__file__).resolve().parent.parent / "config" / "registros.json"

# Tamaño del banco de holding registers por PLC. Los registros definidos en
# registros.json usan direcciones bajas (0-9); se deja margen para crecer sin
# tener que tocar esta constante en Bloque D/E.
_TAMANIO_BANCO = 100


def cargar_registros(dependencia: str) -> list[dict]:
    """Carga la definición de registros de una dependencia desde registros.json."""
    with _REGISTROS_PATH.open(encoding="utf-8") as f:
        mapa = json.load(f)
    if dependencia not in mapa:
        opciones = [k for k in mapa if not k.startswith("_")]
        raise ValueError(f"No hay registros definidos para {dependencia!r}. Opciones: {opciones}")
    return mapa[dependencia]


_ORDEN_CRITICIDAD = ["baja", "media", "alta"]


def seleccionar_registro_por_criticidad(registros: list[dict], criticidad_objetivo) -> dict:
    """Elige qué registro atacar según escenario.criticidad_objetivo (SPEC.md
    sección 2, variable #3: "qué registros del PLC se atacan").

    Preferencia: el registro cuya 'criticidad' coincide exactamente con
    `criticidad_objetivo`; si no hay ninguno, el disponible más cercano por
    debajo; si tampoco, el de criticidad más baja disponible. Así un
    escenario "alta" ataca la válvula/breaker (dramático y defendible), no
    siempre el mismo registro sin importar la dificultad.
    """
    objetivo = criticidad_objetivo.value if hasattr(criticidad_objetivo, "value") else criticidad_objetivo
    idx_objetivo = _ORDEN_CRITICIDAD.index(objetivo)

    exactos = [r for r in registros if r["criticidad"] == objetivo]
    if exactos:
        return exactos[0]

    for idx in range(idx_objetivo - 1, -1, -1):
        candidatos = [r for r in registros if r["criticidad"] == _ORDEN_CRITICIDAD[idx]]
        if candidatos:
            return candidatos[0]

    return min(registros, key=lambda r: _ORDEN_CRITICIDAD.index(r["criticidad"]))


class PLCVirtual:
    """Simula el PLC de una dependencia crítica (agua, energia o accesos).

    Levanta un ModbusTcpServer con un banco de holding registers inicializado
    desde config/registros.json, y expone leer/escribir cualquier registro por
    dirección — tanto para el propio servidor Modbus (clientes de red externos,
    incluido el red team) como para uso interno (tráfico de fondo, arranque).
    """

    def __init__(self, dependencia: str, puerto: int, host: str = "127.0.0.1"):
        self.dependencia = dependencia
        self.host = host
        self.puerto = puerto
        self.registros = cargar_registros(dependencia)

        valores_iniciales = [0] * _TAMANIO_BANCO
        for reg in self.registros:
            valores_iniciales[reg["direccion"]] = reg["valor_inicial"]

        # zero_mode=True: la dirección 0 de una request mapea directo al slot 0
        # del banco, sin el corrimiento -1 heredado de la notación Modbus
        # clásica. Verificar con un cliente Modbus real en la integración
        # (Bloque G) que el direccionamiento efectivamente calza con
        # registros.json — es el bug más común al levantar un servidor Modbus.
        bloque = ModbusSequentialDataBlock(0, valores_iniciales)
        self._slave_context = ModbusSlaveContext(hr=bloque, zero_mode=True)
        self._context = ModbusServerContext(slaves=self._slave_context, single=True)
        self._server: ModbusTcpServer | None = None

    def leer_registro(self, direccion: int) -> int:
        """Lee el valor crudo (sin escalar) de un registro por dirección."""
        return self._slave_context.getValues(3, direccion, count=1)[0]

    def escribir_registro(self, direccion: int, valor: int) -> None:
        """Escribe un valor crudo (sin escalar) en un registro por dirección."""
        self._slave_context.setValues(3, direccion, [valor])

    async def iniciar(self) -> None:
        """Levanta el servidor Modbus TCP. No retorna hasta llamar a detener()."""
        self._server = ModbusTcpServer(
            context=self._context, address=(self.host, self.puerto)
        )
        await self._server.serve_forever()

    async def detener(self) -> None:
        if self._server is not None:
            await self._server.shutdown()
