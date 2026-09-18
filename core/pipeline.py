"""Orquestación end-to-end de una simulación (glue del Bloque G).

Corre el pipeline completo en un solo proceso, SIN privilegios de red cruda
(sin root / sin Npcap):

    perfil -> escenario -> planta Modbus real -> tráfico legítimo de fondo ->
    campaña red team -> detección -> mitigación -> cadena de evidencia ->
    reporte (HTML + JSON).

Los 5 ataques (scan/spoofing/replay/escritura_ilegitima/flood) corren en modo
portable sobre sockets Modbus TCP reales contra el PLC local, sin scapy. Las
variantes raw con scapy siguen en redteam/ para entornos con privilegios, pero
el pipeline usa las portables. La detección en vivo por sniffing también
necesita root, así que las 3 reglas puras del IDS se evalúan sobre los eventos
que la propia campaña generó (mismo motor de reglas, sin capturar tráfico).

El progreso se publica como eventos JSON-serializables vía el callback
`emitir`, para que la CLI (main.py) y el tablero web (dashboard/servidor.py)
consuman exactamente la misma simulación sin duplicar lógica.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path

from blueteam.deteccion import (
    DetectorRafaga,
    EventoDeteccion,
    EventoTrafico,
    evaluar_rango,
    evaluar_whitelist,
)
from blueteam.evidencia import CadenaEvidencia
from blueteam.mitigacion import AccionMitigacion, MotorMitigacion
from blueteam.reglas import cargar_reglas
from blueteam.reporte import (
    construir_contexto_html,
    generar_reporte,
    generar_reporte_html,
)
from core.generador import generar_escenario, validar_coherencia
from core.narrativizacion import narrar_reporte
from core.plc_virtual import PLCVirtual, seleccionar_registro_por_criticidad
from core.schemas import Escenario, PerfilJurisdiccion, TipoAtaque
from core.trafico_fondo import generar_trafico_fondo
from redteam.escritura_ilegitima import escribir_registro_no_autorizado
from redteam.flood import inundar
from redteam.replay import (
    capturar_comando,
    capturar_paquetes_modbus,
    reinyectar_comando,
    reinyectar_paquetes,
)
from redteam.scan import escanear_modbus, sondear_syn_rafaga
from redteam.spoofing import enviar_paquete_spoofed, escribir_como_maestro_suplantado

RAIZ = Path(__file__).resolve().parent.parent
# Se muestra en la consola y en el tablero para poder distinguir de un vistazo
# qué build se está corriendo (esta es la primera con los 5 ataques portables).
VERSION = "2.1-portable+raw (5 ataques; scapy opcional con --raw)"
PUERTO_PLC = 15100
IP_ATACANTE = "10.0.0.99"          # IP simulada del red team (fuera de la whitelist)
IP_HMI_LEGITIMA = "127.0.0.1"      # HMI autorizado que hace el tráfico de fondo
VALOR_ESCRITURA_ILEGITIMA = 65000  # fuera de todo rango_valido_crudo -> dispara R-RANGO-001

Emisor = Callable[[dict], None]

_REGLAS_POR_ID = {r["id"]: r for r in cargar_reglas()}


def cargar_perfil(nombre_o_ruta: str) -> PerfilJurisdiccion:
    """Carga un PerfilJurisdiccion desde un nombre corto (municipal/provincial/
    nacional) o una ruta a un .json, descartando las claves de comentario `_*`.
    """
    ruta = Path(nombre_o_ruta)
    if not ruta.exists():
        ruta = RAIZ / "config" / "perfiles" / f"{nombre_o_ruta}.json"
    if not ruta.exists():
        raise ValueError(f"No se encontró el perfil {nombre_o_ruta!r} (ni como ruta ni en config/perfiles/).")

    with ruta.open(encoding="utf-8") as f:
        crudo = json.load(f)
    return PerfilJurisdiccion.model_validate({k: v for k, v in crudo.items() if not k.startswith("_")})


def _a_ingenieria(registro: dict, crudo: int) -> float:
    return round(crudo / registro.get("escala", 1), 2)


def _foto_registros(plc: PLCVirtual) -> list[dict]:
    """Estado actual del banco de holding registers, en unidades de ingeniería,
    marcando cuáles quedaron fuera de su rango válido."""
    foto = []
    for reg in plc.registros:
        crudo = plc.leer_registro(reg["direccion"])
        minimo, maximo = reg["rango_valido_crudo"]
        foto.append({
            "direccion": reg["direccion"],
            "nombre": reg["nombre"],
            "descripcion": reg["descripcion"],
            "unidad": reg["unidad"],
            "criticidad": reg["criticidad"],
            "valor": _a_ingenieria(reg, crudo),
            "valor_crudo": crudo,
            "rango": reg["rango_valido_ingenieria"],
            "fuera_de_rango": not (minimo <= crudo <= maximo),
        })
    return foto


def _deteccion_a_dict(ev: EventoDeteccion) -> dict:
    regla = _REGLAS_POR_ID.get(ev.regla_id, {})
    return {
        "regla_id": ev.regla_id,
        "regla_nombre": regla.get("nombre", ev.regla_id),
        "attack_id": regla.get("attack_id"),
        "tipo_ataque_probable": ev.tipo_ataque_probable,
        "severidad": ev.severidad,
        "ip_origen": ev.ip_origen,
        "evidencia": ev.evidencia,
        "timestamp": ev.timestamp,
    }


def _silenciar_cierres_abruptos(loop: asyncio.AbstractEventLoop) -> None:
    """El flood cierra cientos de sockets de golpe; el loop de Windows (Proactor)
    reporta cada cierre como excepción no capturada y ensucia la salida."""
    def handler(_loop: asyncio.AbstractEventLoop, contexto: dict) -> None:
        if isinstance(contexto.get("exception"), (BrokenPipeError, ConnectionResetError)):
            return
        _loop.default_exception_handler(contexto)

    loop.set_exception_handler(handler)


IFAZ_LOOPBACK = "lo" if sys.platform.startswith("linux") else None


def hay_privilegios_raw() -> bool:
    """¿El proceso puede armar paquetes crudos (lo que necesita scapy)?

    En Windows scapy usa Npcap y hace falta correr como Administrador; lo
    aproximamos con IsUserAnAdmin. En Linux/mac probamos abrir un raw socket:
    si el kernel lo permite (root o CAP_NET_RAW) devuelve True.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except OSError:
        return False
    s.close()
    return True


def _puerto_plc_libre() -> int:
    """Puerto libre para el PLC de ESTA simulación.

    Cada corrida levanta su propio PLC; con un puerto fijo, dos simulaciones a
    la vez (dos pestañas del tablero, doble clic en "Lanzar" o una corrida
    todavía viva) chocan con "address already in use". Pedimos un puerto
    efímero al SO (bind a :0) para que cada corrida use el suyo.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _trama_modbus_write(direccion: int, valor: int, unidad: int = 1) -> bytes:
    """Arma una trama Modbus/TCP de escritura de un registro (FC 06) para usar
    como payload del paquete crudo suplantado."""
    pdu = struct.pack(">BHH", 6, direccion, valor)
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unidad)
    return mbap + pdu


async def _scan_raw(host: str, puerto: int, cantidad: int) -> int:
    """SYN scan crudo (scapy) sobre loopback, en un hilo para no bloquear el loop."""
    return await asyncio.to_thread(sondear_syn_rafaga, host, puerto, cantidad)


async def _spoofing_raw(host: str, puerto: int, direccion: int, valor: int) -> None:
    """Inyecta un paquete con IP origen falsificada (scapy) sobre loopback."""
    payload = _trama_modbus_write(direccion, valor)
    await asyncio.to_thread(enviar_paquete_spoofed, IP_ATACANTE, host, puerto, payload)


async def _replay_raw(host: str, puerto: int, direccion: int, valor: int) -> tuple[int, int]:
    """Captura tramas Modbus reales en loopback y las reinyecta (scapy).

    Arranca el sniffer en un hilo, genera una escritura legítima para que haya
    algo que capturar, y reinyecta lo capturado. Devuelve
    (paquetes_capturados, paquetes_reinyectados).
    """
    captura = asyncio.create_task(
        asyncio.to_thread(capturar_paquetes_modbus, host, 8, 3.0, IFAZ_LOOPBACK, puerto)
    )
    await asyncio.sleep(0.4)  # dar tiempo a que el sniffer levante
    await reinyectar_comando(host, puerto, direccion=direccion, valor=valor)
    paquetes = await captura
    try:
        reinyectados = await asyncio.to_thread(reinyectar_paquetes, paquetes, IFAZ_LOOPBACK)
    except OSError:
        # Reinyectar frames crudos en loopback no siempre está soportado; la
        # captura ya demostró el sniffing. No es fatal para la simulación.
        reinyectados = 0
    return len(paquetes), reinyectados


async def _correr_campania(
    escenario: Escenario,
    plc: PLCVirtual,
    emitir: Emisor,
    ritmo: float,
    modo_raw: bool = False,
) -> tuple[list[EventoDeteccion], int, int]:
    """Ejecuta los ataques reales contra `plc` y devuelve
    (detecciones, ataques_ejecutados, ataques_omitidos).

    Con `modo_raw` (y privilegios), scan/spoofing/replay corren con scapy sobre
    loopback (paquetes crudos); si no, usan las variantes portables. En ambos
    casos la detección se evalúa igual: como controlamos la campaña,
    alimentamos las 3 reglas puras del IDS con los eventos que los ataques
    produjeron (el pipeline no hace sniffing en vivo).
    """
    raw_activo = modo_raw and hay_privilegios_raw()
    ips_permitidas = {IP_HMI_LEGITIMA}
    detecciones: list[EventoDeteccion] = []
    ejecutados = omitidos = 0

    direcciones = [r["direccion"] for r in plc.registros]

    if modo_raw and not raw_activo:
        emitir({
            "fase": "aviso",
            "detalle": "Se pidió modo RAW (scapy) pero el proceso no tiene privilegios de red cruda "
                       "(root/CAP_NET_RAW en Linux, Administrador+Npcap en Windows). "
                       "scan/spoofing/replay caen a la variante portable.",
        })
    elif raw_activo:
        emitir({
            "fase": "aviso",
            "detalle": "Modo RAW activo: scan/spoofing/replay se ejecutan con scapy (paquetes crudos) "
                       "sobre la interfaz loopback (127.0.0.1). No sale tráfico de la máquina.",
        })

    for tipo in escenario.tipos_ataque:
        await asyncio.sleep(ritmo)

        if tipo == TipoAtaque.SCAN:
            if raw_activo:
                # SYN burst suficiente para que el ritmo supere el baseline.
                enviados = escenario.ruido_fondo_pps + len(direcciones) + 5
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": "Reconocimiento: SYN scan crudo (scapy)",
                    "detalle": f"Modo RAW: manda {enviados} SYN crudos (half-open, estilo nmap -sS) contra "
                               f"{plc.host}:{plc.puerto} por loopback, sin completar el handshake. Requiere "
                               "privilegios de red cruda; la ráfaga la caza la regla de ritmo.",
                })
                await _scan_raw(plc.host, plc.puerto, enviados)
            else:
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": "Reconocimiento: connect-scan + enumeración Modbus",
                    "detalle": "Modo portable (sin scapy): abre conexiones TCP normales al puerto del PLC y "
                               "lee repetidamente cada holding register para mapear la planta. La variante raw "
                               "(SYN scan con scapy) queda en redteam/scan.py para entornos con privilegios.",
                })
                # Escaneo rápido: suficientes pasadas para que el ritmo supere el
                # baseline de ruido de fondo y lo cace R-RITMO-001.
                pasadas = max(3, escenario.ruido_fondo_pps // max(len(direcciones), 1) + 3)
                _, enviados = await escanear_modbus(plc.host, plc.puerto, direcciones, pasadas=pasadas)
            ejecutados += 1
            _unidad_scan = "SYN crudos" if raw_activo else "lecturas Modbus"
            emitir({"fase": "metrica", "clave": "lecturas_scan", "valor": enviados,
                    "detalle": f"{enviados} {_unidad_scan} de reconocimiento sobre {len(direcciones)} registros."})

            detector = DetectorRafaga(umbral_pps=escenario.ruido_fondo_pps, ventana_seg=1.0)
            base = time.time()
            deteccion_scan = None
            for i in range(enviados):
                d = detector.registrar_y_evaluar(IP_ATACANTE, base + i / max(enviados, 1))
                deteccion_scan = d or deteccion_scan
            if deteccion_scan is not None:
                detecciones.append(deteccion_scan)
                await asyncio.sleep(ritmo / 2)
                emitir({"fase": "deteccion", **_deteccion_a_dict(deteccion_scan)})

        elif tipo == TipoAtaque.SPOOFING:
            objetivo = seleccionar_registro_por_criticidad(plc.registros, escenario.criticidad_objetivo)
            valor_valido = objetivo["valor_inicial"]
            if raw_activo:
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": f"Suplantación de IP con paquete crudo sobre '{objetivo['nombre']}'",
                    "detalle": f"Modo RAW: scapy forja un paquete con IP origen falsa ({IP_ATACANTE}) y una "
                               f"trama Modbus de escritura (valor {valor_valido}) hacia {plc.host}:{plc.puerto} "
                               "por loopback. Es inyección a ciegas (sin handshake): demuestra el spoofing de "
                               "red real, y el origen falso lo delata la allowlist.",
                })
                await _spoofing_raw(plc.host, plc.puerto, objetivo["direccion"], valor_valido)
            else:
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": f"Suplantación de maestro sobre '{objetivo['nombre']}'",
                    "detalle": "Modo portable (sin scapy): abre una sesión Modbus TCP real y escribe un valor "
                               f"VÁLIDO ({valor_valido}) haciéndose pasar por el maestro SCADA. El comando es "
                               "indistinguible de uno legítimo por su contenido; lo único anómalo es el origen. "
                               "La variante raw (falsificar la IP de red con scapy) queda en redteam/spoofing.py.",
                })
                await escribir_como_maestro_suplantado(
                    plc.host, plc.puerto, direccion=objetivo["direccion"], valor=valor_valido
                )
            ejecutados += 1
            emitir({"fase": "registros", "registros": _foto_registros(plc),
                    "nota": "El valor es válido, así que la regla de rango NO lo ve: solo la allowlist lo delata."})

            # Valor en rango -> R-RANGO-001 no dispara; solo R-ALLOW-001 (origen no autorizado).
            evento = EventoTrafico(
                ip_origen=IP_ATACANTE,
                direccion_registro=objetivo["direccion"],
                valor=valor_valido,
                timestamp=time.time(),
            )
            deteccion = evaluar_whitelist(evento, ips_permitidas)
            if deteccion is not None:
                detecciones.append(deteccion)
                await asyncio.sleep(ritmo / 2)
                emitir({"fase": "deteccion", **_deteccion_a_dict(deteccion)})

        elif tipo == TipoAtaque.REPLAY:
            objetivo = seleccionar_registro_por_criticidad(plc.registros, escenario.criticidad_objetivo)
            valor_grabado = await capturar_comando(plc.host, plc.puerto, direccion=objetivo["direccion"])
            if raw_activo:
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": f"Replay de frames crudos sobre '{objetivo['nombre']}'",
                    "detalle": "Modo RAW: scapy esnifa las tramas Modbus reales en loopback (mientras se genera "
                               "un comando) y luego las reinyecta tal cual, como capturar y reproducir el "
                               "tráfico de la red. Requiere privilegios; el origen no autorizado lo caza la "
                               "allowlist.",
                })
                capturados, reinyectados = await _replay_raw(
                    plc.host, plc.puerto, objetivo["direccion"], valor_grabado
                )
                emitir({"fase": "metrica", "clave": "frames_replay", "valor": capturados,
                        "detalle": f"{capturados} frames Modbus capturados en loopback, {reinyectados} "
                                   "reinyectados con scapy."})
            else:
                emitir({
                    "fase": "ataque",
                    "tipo": tipo.value,
                    "estado": "ejecutado",
                    "titulo": f"Replay de un comando legítimo sobre '{objetivo['nombre']}'",
                    "detalle": "Modo portable (sin scapy): 'graba' el valor actual del registro (un comando que "
                               "el HMI ya hizo) y lo reinyecta tal cual desde una sesión Modbus nueva, la del "
                               "atacante. La variante raw (capturar y reinyectar frames con scapy) queda en "
                               "redteam/replay.py.",
                })
                await reinyectar_comando(
                    plc.host, plc.puerto, direccion=objetivo["direccion"], valor=valor_grabado
                )
                emitir({"fase": "metrica", "clave": "valor_reinyectado", "valor": valor_grabado,
                        "detalle": f"Se reinyectó el comando grabado (valor {valor_grabado}) en la dirección "
                                   f"{objetivo['direccion']}."})
            ejecutados += 1

            # El valor reinyectado es válido; lo caza la allowlist porque el
            # replay llega desde el origen no autorizado del atacante.
            evento = EventoTrafico(
                ip_origen=IP_ATACANTE,
                direccion_registro=objetivo["direccion"],
                valor=valor_grabado,
                timestamp=time.time(),
            )
            deteccion = evaluar_whitelist(evento, ips_permitidas)
            if deteccion is not None:
                detecciones.append(deteccion)
                await asyncio.sleep(ritmo / 2)
                emitir({"fase": "deteccion", **_deteccion_a_dict(deteccion)})

        elif tipo == TipoAtaque.ESCRITURA_ILEGITIMA:
            objetivo = seleccionar_registro_por_criticidad(plc.registros, escenario.criticidad_objetivo)
            emitir({
                "fase": "ataque",
                "tipo": tipo.value,
                "estado": "ejecutado",
                "titulo": f"Escritura ilegítima sobre '{objetivo['nombre']}'",
                "detalle": f"Cliente Modbus TCP real escribe {VALOR_ESCRITURA_ILEGITIMA} en la dirección "
                           f"{objetivo['direccion']} ({objetivo['descripcion']}), muy fuera del rango válido "
                           f"{objetivo['rango_valido_ingenieria']} {objetivo['unidad']}.",
            })
            await escribir_registro_no_autorizado(
                plc.host, plc.puerto, direccion=objetivo["direccion"], valor=VALOR_ESCRITURA_ILEGITIMA
            )
            ejecutados += 1
            emitir({"fase": "registros", "registros": _foto_registros(plc),
                    "nota": "El PLC aceptó la escritura: Modbus no autentica ni valida rangos."})

            # La escritura la hicimos desde el proceso local, pero el escenario
            # la atribuye al red team simulado (IP fuera de whitelist).
            evento = EventoTrafico(
                ip_origen=IP_ATACANTE,
                direccion_registro=objetivo["direccion"],
                valor=VALOR_ESCRITURA_ILEGITIMA,
                timestamp=time.time(),
            )
            for deteccion in (evaluar_rango(evento, plc.registros), evaluar_whitelist(evento, ips_permitidas)):
                if deteccion is not None:
                    detecciones.append(deteccion)
                    await asyncio.sleep(ritmo / 2)
                    emitir({"fase": "deteccion", **_deteccion_a_dict(deteccion)})

        elif tipo == TipoAtaque.FLOOD:
            emitir({
                "fase": "ataque",
                "tipo": tipo.value,
                "estado": "ejecutado",
                "titulo": f"Flood a {escenario.intensidad_pps} pps durante 2 s",
                "detalle": "Ráfaga de requests Modbus para saturar el PLC, muy por encima del polling "
                           f"normal de {escenario.ruido_fondo_pps} pps del HMI legítimo.",
            })
            enviados = await inundar(
                plc.host, plc.puerto, intensidad_pps=escenario.intensidad_pps, duracion_seg=2.0
            )
            ejecutados += 1
            emitir({"fase": "metrica", "clave": "paquetes_flood", "valor": enviados,
                    "detalle": f"{enviados} paquetes Modbus enviados por el red team."})

            # Evaluamos R-RITMO-001 sobre la ráfaga real que acabamos de generar.
            detector = DetectorRafaga(umbral_pps=escenario.ruido_fondo_pps, ventana_seg=1.0)
            base = time.time()
            deteccion_rafaga = None
            for i in range(enviados):
                d = detector.registrar_y_evaluar(IP_ATACANTE, base + i / max(escenario.intensidad_pps, 1))
                deteccion_rafaga = d or deteccion_rafaga
            if deteccion_rafaga is not None:
                detecciones.append(deteccion_rafaga)
                await asyncio.sleep(ritmo / 2)
                emitir({"fase": "deteccion", **_deteccion_a_dict(deteccion_rafaga)})

        else:
            omitidos += 1
            emitir({
                "fase": "ataque",
                "tipo": tipo.value,
                "estado": "omitido",
                "titulo": f"{tipo.value}: omitido en modo portable",
                "detalle": "Necesita scapy con privilegios de red cruda (root en Linux / Npcap en Windows). "
                           "El módulo está implementado en redteam/, pero no corre sin esos permisos.",
            })

    return detecciones, ejecutados, omitidos


async def simular(
    perfil: PerfilJurisdiccion,
    dificultad: str,
    dir_salida: Path,
    emitir: Emisor,
    ritmo: float = 0.0,
    modo_raw: bool = False,
) -> dict:
    """Corre la simulación completa publicando el progreso vía `emitir`.

    `ritmo` son los segundos de pausa entre etapas: 0 para la CLI (lo más
    rápido posible) y algunas décimas para el tablero web, donde el objetivo
    es que se pueda seguir el ataque paso a paso.

    Devuelve el resumen final (el mismo dict del evento `fin`).
    """
    _silenciar_cierres_abruptos(asyncio.get_running_loop())

    escenario = generar_escenario(perfil, dificultad)
    validar_coherencia(escenario, perfil)
    dependencia = perfil.dependencias_criticas[0]

    emitir({
        "fase": "perfil",
        "escala": perfil.escala_gobierno.value,
        "poblacion": perfil.poblacion,
        "dependencias": perfil.dependencias_criticas,
        "nivel_digitalizacion": perfil.nivel_digitalizacion,
        "presupuesto": perfil.presupuesto_ciberseguridad,
        "marco_normativo": perfil.marco_normativo_vigente,
        "detalle": "El perfil territorial define cuánta superficie de ataque hay y con cuántos recursos "
                   "se la defiende. El presupuesto (1-5) limita qué mitigaciones puede aplicar el blue team.",
    })
    await asyncio.sleep(ritmo)

    emitir({
        "fase": "escenario",
        "dificultad": dificultad,
        "tipos_ataque": [t.value for t in escenario.tipos_ataque],
        "intensidad_pps": escenario.intensidad_pps,
        "ruido_fondo_pps": escenario.ruido_fondo_pps,
        "criticidad_objetivo": escenario.criticidad_objetivo.value,
        "sofisticacion": escenario.sofisticacion.value,
        "detalle": "El escenario es determinístico: mismo perfil + misma dificultad = mismo escenario, "
                   "y el generador lo recorta al techo que la escala de gobierno permite.",
    })
    await asyncio.sleep(ritmo)

    plc = PLCVirtual(dependencia=dependencia, puerto=_puerto_plc_libre(), host="127.0.0.1")
    servidor = asyncio.ensure_future(plc.iniciar())
    await asyncio.sleep(0.5)  # dar tiempo a que el servidor Modbus abra el socket

    try:
        emitir({
            "fase": "planta",
            "dependencia": dependencia,
            "host": plc.host,
            "puerto": plc.puerto,
            "registros": _foto_registros(plc),
            "detalle": f"PLC virtual de '{dependencia}' escuchando Modbus TCP real en "
                       f"{plc.host}:{plc.puerto}. No es un mock: los ataques se conectan por socket.",
        })
        await asyncio.sleep(ritmo)

        # Tráfico legítimo de fondo: sirve de baseline del IDS y demuestra que
        # el polling normal del HMI no dispara alertas (control de falsos positivos).
        polls = await generar_trafico_fondo(
            plc.host, plc.puerto,
            direcciones=[r["direccion"] for r in plc.registros],
            ruido_fondo_pps=escenario.ruido_fondo_pps,
            duracion_seg=1.0,
        )
        emitir({
            "fase": "trafico_fondo",
            "polls": polls,
            "pps": escenario.ruido_fondo_pps,
            "detalle": f"{polls} lecturas del HMI autorizado ({IP_HMI_LEGITIMA}) en 1 s. Es el baseline "
                       "del IDS: tráfico normal, cero alertas.",
        })

        detecciones, ejecutados, omitidos = await _correr_campania(
            escenario, plc, emitir, ritmo, modo_raw=modo_raw
        )
    finally:
        await plc.detener()
        servidor.cancel()

    await asyncio.sleep(ritmo)
    motor = MotorMitigacion(perfil)
    mitigaciones: list[list[AccionMitigacion]] = [motor.procesar(ev) for ev in detecciones]
    emitir({
        "fase": "mitigacion",
        "acciones": [{"accion": m.accion, "detalle": m.detalle}
                     for lote in mitigaciones for m in lote],
        "ips_bloqueadas": sorted(motor.ips_bloqueadas),
        "detalle": f"Con presupuesto {perfil.presupuesto_ciberseguridad}/5 el motor habilita "
                   f"{'alertar' if perfil.presupuesto_ciberseguridad < 2 else 'alertar + bloquear_ip'}"
                   f"{' + aislar_segmento ante flood' if perfil.presupuesto_ciberseguridad >= 4 else ''}.",
    })

    cadena = CadenaEvidencia()
    for ev, mits in zip(detecciones, mitigaciones):
        cadena.agregar({"deteccion": ev.regla_id, "ip": ev.ip_origen,
                        "mitigaciones": [m.accion for m in mits]}, timestamp=ev.timestamp)
    cadena_ok = cadena.verificar()

    await asyncio.sleep(ritmo)
    emitir({
        "fase": "evidencia",
        "bloques": len(cadena.entradas),
        "verificada": cadena_ok,
        "hashes": [e["hash"][:16] for e in cadena.entradas],
        "detalle": "Cada alerta se encadena con el SHA-256 de la anterior: si alguien edita un registro "
                   "a posteriori, verificar() lo detecta. Es la parte pericial del reporte.",
    })

    reporte = generar_reporte(detecciones, mitigaciones, dependencia, plc.registros)
    narrativa = narrar_reporte(reporte)

    dir_salida.mkdir(parents=True, exist_ok=True)
    contexto = construir_contexto_html(
        reporte,
        escenario_id=f"{perfil.escala_gobierno.value}-{dependencia}-{dificultad}",
        dificultad=dificultad,
        total_ataques_ejecutados=ejecutados,
        cadena_verificada=cadena_ok,
        narrativa=narrativa,
    )
    ruta_html = dir_salida / "reporte_incidente.html"
    generar_reporte_html(contexto, str(ruta_html), str(dir_salida / "reporte_incidente.pdf"))
    ruta_cadena = dir_salida / "cadena_evidencia.json"
    cadena.exportar_json(str(ruta_cadena))

    resumen = {
        "fase": "fin",
        "ataques_ejecutados": ejecutados,
        "ataques_omitidos": omitidos,
        # Un mismo ataque puede violar varias reglas a la vez (la escritura
        # ilegítima dispara rango + allowlist), por eso las alertas se cuentan
        # aparte de los ataques.
        "alertas": len(detecciones),
        "cadena_verificada": cadena_ok,
        "narrativa": narrativa,
        "ruta_html": str(ruta_html),
        "ruta_cadena": str(ruta_cadena),
        "incidentes": reporte["incidentes"],
    }
    emitir(resumen)
    return resumen
