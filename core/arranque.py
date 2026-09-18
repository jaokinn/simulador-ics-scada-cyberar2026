"""Arranque de la planta según el perfil de jurisdicción (Bloque C, Paso 12).

Conecta el modelaje del defensor (Bloque B) con el motor Modbus (Bloque C):
integración mecánica, sin reglas nuevas que definir.
"""

from core.plc_virtual import PLCVirtual
from core.schemas import PerfilJurisdiccion

# Puerto inicial para el primer PLC de una planta; cada PLC siguiente usa el
# próximo puerto secuencial. Deja margen bajo _PUERTO_BASE para otros
# servicios (API, dashboard) definidos en Bloque G.
_PUERTO_BASE = 15100


def inicializar_planta(perfil: PerfilJurisdiccion, host: str = "127.0.0.1") -> list[PLCVirtual]:
    """Instancia un PLCVirtual por cada dependencia_critica del perfil.

    Si una dependencia se repite (ej. perfil provincial con dos sitios de
    agua, ver SPEC.md sección 3.1), cada repetición recibe su propio
    PLCVirtual y puerto — son sitios físicos distintos, no el mismo PLC.
    """
    return [
        PLCVirtual(dependencia=dependencia, puerto=_PUERTO_BASE + i, host=host)
        for i, dependencia in enumerate(perfil.dependencias_criticas)
    ]
