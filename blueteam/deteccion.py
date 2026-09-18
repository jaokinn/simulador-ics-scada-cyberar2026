"""Motor de reglas de detección — IDS (Bloque E, Paso 19).

3 reglas sobre eventos de escritura Modbus ya parseados (IP origen, dirección
de registro, valor escrito, timestamp):
  1. Ráfaga anómala: más paquetes/seg que el baseline de ruido de fondo.
  2. IP fuera de la whitelist configurada.
  3. Escritura a un registro fuera de su rango válido (config/registros.json).

Separado en dos capas a propósito:
  - Las reglas en sí (evaluar_rango, evaluar_whitelist, DetectorRafaga) y el
    parseo de paquetes (extraer_evento_escritura) son funciones puras,
    testeables con paquetes construidos en memoria — sin capturar tráfico
    real.
  - `iniciar_sniffer` es la capa que las conecta a scapy sniff() para tráfico
    en vivo — necesita privilegios de captura (Npcap en Windows / root en
    Linux), igual que redteam/scan.py, replay.py y spoofing.py.

TODO(equipo): con estas 3 reglas, un ataque de replay (Paso 15) que reenvía
un paquete legítimo tal cual (misma IP, mismo valor válido) NO dispara
ninguna de las 3 salvo que además supere el umbral de ráfaga por la
velocidad de reinyección. Es una limitación real del diseño de 3 reglas de
este paso, no un bug — cubrir replay a fondo necesitaría una 4ta regla (ej.
detectar una escritura idéntica repetida en una ventana corta), fuera del
alcance de este paso.
"""

import time
from collections import deque
from dataclasses import dataclass, field

from blueteam.reglas import cargar_reglas

PUERTO_MODBUS = 502

_REGLAS_POR_ID = {r["id"]: r for r in cargar_reglas()}


@dataclass
class EventoTrafico:
    ip_origen: str
    direccion_registro: int
    valor: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class EventoDeteccion:
    tipo_ataque_probable: str
    timestamp: float
    ip_origen: str
    evidencia: str
    regla_id: str
    severidad: str  # "alta" | "media" | "baja" — ver blueteam/reglas.py
    # None para detecciones que no son sobre un registro puntual (ej. ráfaga
    # de lecturas durante un flood, que no tiene una única dirección).
    direccion_registro: int | None = None


def extraer_evento_escritura(paquete) -> EventoTrafico | None:
    """Extrae un EventoTrafico de un paquete si es una escritura Modbus
    (function code 06 o 16, los mismos que usa redteam/escritura_ilegitima.py
    y un cliente Modbus legítimo). Devuelve None para cualquier otro paquete
    (lecturas, tráfico no-Modbus, etc.) — el IDS solo analiza escrituras.
    """
    from scapy.contrib.modbus import (
        ModbusPDU06WriteSingleRegisterRequest,
        ModbusPDU10WriteMultipleRegistersRequest,
    )
    from scapy.layers.inet import IP

    if not paquete.haslayer(IP):
        return None
    ip_origen = paquete[IP].src

    if paquete.haslayer(ModbusPDU06WriteSingleRegisterRequest):
        capa = paquete[ModbusPDU06WriteSingleRegisterRequest]
        return EventoTrafico(
            ip_origen=ip_origen, direccion_registro=capa.registerAddr, valor=capa.registerValue
        )

    if paquete.haslayer(ModbusPDU10WriteMultipleRegistersRequest):
        capa = paquete[ModbusPDU10WriteMultipleRegistersRequest]
        return EventoTrafico(
            ip_origen=ip_origen, direccion_registro=capa.startAddr, valor=capa.outputsValue[0]
        )

    return None


def evaluar_rango(evento: EventoTrafico, registros: list[dict]) -> EventoDeteccion | None:
    """Regla 3: escritura fuera del rango válido del registro."""
    definicion = next((r for r in registros if r["direccion"] == evento.direccion_registro), None)
    if definicion is None:
        return None

    minimo, maximo = definicion["rango_valido_crudo"]
    if minimo <= evento.valor <= maximo:
        return None

    regla = _REGLAS_POR_ID["R-RANGO-001"]
    return EventoDeteccion(
        tipo_ataque_probable="escritura_ilegitima",
        timestamp=evento.timestamp,
        ip_origen=evento.ip_origen,
        direccion_registro=evento.direccion_registro,
        regla_id=regla["id"],
        severidad=regla["severidad"],
        evidencia=(
            f"IP {evento.ip_origen} escribió {evento.valor} en '{definicion['nombre']}' "
            f"(dirección {evento.direccion_registro}), fuera del rango válido "
            f"[{minimo}, {maximo}]."
        ),
    )


def evaluar_whitelist(evento: EventoTrafico, ips_permitidas: set[str]) -> EventoDeteccion | None:
    """Regla 2: IP fuera de la whitelist configurada."""
    if evento.ip_origen in ips_permitidas:
        return None

    regla = _REGLAS_POR_ID["R-ALLOW-001"]
    return EventoDeteccion(
        tipo_ataque_probable="spoofing_o_acceso_no_autorizado",
        timestamp=evento.timestamp,
        ip_origen=evento.ip_origen,
        direccion_registro=evento.direccion_registro,
        regla_id=regla["id"],
        severidad=regla["severidad"],
        evidencia=f"Tráfico de escritura Modbus desde IP no autorizada: {evento.ip_origen}.",
    )


class DetectorRafaga:
    """Regla 1: ráfaga anómala — más de `umbral_pps` paquetes Modbus (de
    cualquier tipo: lecturas o escrituras) en una ventana deslizante de
    `ventana_seg` segundos.

    Deliberadamente NO toma un EventoTrafico (que es específico de
    escrituras): un flood (Paso 17) satura al PLC con LECTURAS, no
    escrituras, así que esta regla tiene que poder contar cualquier paquete
    Modbus, no solo los que además disparan las reglas 2/3.
    """

    def __init__(self, umbral_pps: int, ventana_seg: float = 1.0):
        self.umbral_pps = umbral_pps
        self.ventana_seg = ventana_seg
        self._timestamps: deque[float] = deque()

    def registrar_y_evaluar(self, ip_origen: str, timestamp: float) -> EventoDeteccion | None:
        self._timestamps.append(timestamp)
        limite = timestamp - self.ventana_seg
        while self._timestamps and self._timestamps[0] < limite:
            self._timestamps.popleft()

        if len(self._timestamps) <= self.umbral_pps:
            return None

        regla = _REGLAS_POR_ID["R-RITMO-001"]
        return EventoDeteccion(
            tipo_ataque_probable="flood_o_scan",
            timestamp=timestamp,
            ip_origen=ip_origen,
            regla_id=regla["id"],
            severidad=regla["severidad"],
            evidencia=(
                f"{len(self._timestamps)} paquetes Modbus en {self.ventana_seg}s desde "
                f"{ip_origen}, supera el umbral de {self.umbral_pps} pps."
            ),
        )


def iniciar_sniffer(
    host_objetivo: str,
    ips_permitidas: set[str],
    registros: list[dict],
    umbral_pps: int,
    on_deteccion,
    interfaz: str | None = None,
    timeout: float | None = None,
) -> None:
    """Captura tráfico Modbus en vivo dirigido a `host_objetivo` y aplica las
    3 reglas, invocando `on_deteccion(evento)` por cada alerta generada.

    La regla de ráfaga (1) se evalúa sobre CUALQUIER paquete Modbus/TCP
    capturado (lecturas incluidas, ver DetectorRafaga). Las reglas de
    whitelist (2) y rango (3) solo aplican a escrituras (fc06/16).

    Requiere privilegios de captura de paquetes (Npcap en Windows / root en
    Linux) — mismo requisito que redteam/scan.py, replay.py y spoofing.py.
    """
    from scapy.all import sniff
    from scapy.layers.inet import IP

    detector_rafaga = DetectorRafaga(umbral_pps=umbral_pps)

    def _procesar(paquete):
        if not paquete.haslayer(IP):
            return
        ip_origen = paquete[IP].src
        timestamp = time.time()

        deteccion_rafaga = detector_rafaga.registrar_y_evaluar(ip_origen, timestamp)
        if deteccion_rafaga is not None:
            on_deteccion(deteccion_rafaga)

        evento = extraer_evento_escritura(paquete)
        if evento is None:
            return
        for deteccion in (evaluar_rango(evento, registros), evaluar_whitelist(evento, ips_permitidas)):
            if deteccion is not None:
                on_deteccion(deteccion)

    filtro = f"tcp and port {PUERTO_MODBUS} and host {host_objetivo}"
    sniff(iface=interfaz, filter=filtro, prn=_procesar, timeout=timeout)
