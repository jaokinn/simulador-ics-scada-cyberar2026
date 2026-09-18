"""Motor de mitigación (Bloque E, Paso 20).

Acciones automáticas disparadas por un EventoDeteccion del IDS (Paso 19):
alertar, bloquear_ip, aislar_segmento (simulado, no real). Qué acciones están
activas depende de perfil.presupuesto_ciberseguridad (SPEC.md sección 3):
menos presupuesto = menos reglas de mitigación activas.

TODO(equipo): los umbrales de presupuesto (2, 4) son una propuesta razonable
de arranque, mismo criterio que las otras tablas de SPEC.md — no un valor
validado.
"""

from dataclasses import dataclass

from blueteam.deteccion import EventoDeteccion
from core.schemas import PerfilJurisdiccion


@dataclass
class AccionMitigacion:
    accion: str
    detalle: str
    timestamp: float


class MotorMitigacion:
    """Aplica acciones de mitigación a eventos de detección, acotadas por el
    presupuesto_ciberseguridad del perfil que se está defendiendo.
    """

    def __init__(self, perfil: PerfilJurisdiccion):
        self.perfil = perfil
        self.ips_bloqueadas: set[str] = set()
        self.acciones: list[AccionMitigacion] = []

    def procesar(self, evento: EventoDeteccion) -> list[AccionMitigacion]:
        """Aplica las acciones de mitigación correspondientes a `evento`:
          - presupuesto >= 1: alertar (siempre disponible, es solo loguear).
          - presupuesto >= 2: bloquear_ip.
          - presupuesto >= 4: aislar_segmento, solo ante ráfaga/flood (es la
            acción más disruptiva, reservada a perfiles con más recursos).

        Devuelve las acciones efectivamente aplicadas, en el orden en que se
        ejecutaron.
        """
        aplicadas = [self._alertar(evento)]

        if self.perfil.presupuesto_ciberseguridad >= 2:
            aplicadas.append(self._bloquear_ip(evento))

        if self.perfil.presupuesto_ciberseguridad >= 4 and evento.tipo_ataque_probable == "flood_o_scan":
            aplicadas.append(self._aislar_segmento(evento))

        return aplicadas

    def _alertar(self, evento: EventoDeteccion) -> AccionMitigacion:
        accion = AccionMitigacion(
            accion="alertar", detalle=evento.evidencia, timestamp=evento.timestamp
        )
        self.acciones.append(accion)
        return accion

    def _bloquear_ip(self, evento: EventoDeteccion) -> AccionMitigacion:
        self.ips_bloqueadas.add(evento.ip_origen)
        accion = AccionMitigacion(
            accion="bloquear_ip",
            detalle=f"IP {evento.ip_origen} agregada a la blacklist.",
            timestamp=evento.timestamp,
        )
        self.acciones.append(accion)
        return accion

    def _aislar_segmento(self, evento: EventoDeteccion) -> AccionMitigacion:
        accion = AccionMitigacion(
            accion="aislar_segmento",
            detalle="[SIMULADO] segmento de red aislado — no desconecta hardware real.",
            timestamp=evento.timestamp,
        )
        self.acciones.append(accion)
        return accion
