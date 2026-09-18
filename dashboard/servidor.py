"""Tablero web del simulador (Bloque G).

Servidor HTTP de stdlib — sin FastAPI/uvicorn/streamlit a propósito: el
ejecutable de demo tiene que arrancar con doble clic en una máquina sin
Python, y cada dependencia extra son megabytes y un modo de falla más.

Rutas:
    GET /                     tablero (dashboard/ui.html)
    GET /api/contexto         perfiles, dificultades y reglas del IDS
    GET /api/simular?...      corre una simulación y la transmite por SSE
    GET /reporte              último reporte de incidente generado
    GET /evidencia            última cadena de evidencia (JSON)

La simulación corre en el hilo del request (ThreadingHTTPServer da uno por
conexión) y cada evento del pipeline se escribe al socket apenas ocurre, así
el tablero muestra el ataque y la detección en vivo y no al final.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from blueteam.reglas import cargar_reglas
from core.pipeline import RAIZ, VERSION, cargar_perfil, hay_privilegios_raw, simular

_DIFICULTADES = [
    {
        "id": "facil",
        "nombre": "Fácil",
        "resumen": "Un solo ataque ruidoso contra un registro de criticidad baja.",
        "detalle": "40 pps sobre un baseline de 5 pps: el IDS lo ve de inmediato. Sirve para mostrar "
                   "el pipeline completo sin ruido.",
    },
    {
        "id": "normal",
        "nombre": "Normal",
        "resumen": "Reconocimiento + escritura ilegítima + replay, criticidad media.",
        "detalle": "120 pps sobre 20 pps de fondo. Los tres ataques corren en modo portable por "
                   "sockets Modbus reales, sin permisos de administrador.",
    },
    {
        "id": "dificil",
        "nombre": "Difícil",
        "resumen": "Campaña completa: scan, spoofing, replay, escritura ilegítima y flood.",
        "detalle": "250 pps de pico sobre 60 pps de fondo, apuntando al registro de criticidad alta "
                   "(la válvula o el breaker). Es el escenario de demo.",
    },
]

_EXPLICACION_ATAQUES = {
    "scan": "Reconocimiento: connect-scan TCP + enumeración del banco de registros por lecturas Modbus "
            "reales, para mapear el PLC. La ráfaga de lecturas lo delata (regla de ritmo).",
    "escritura_ilegitima": "Escribe un valor fuera de rango en un registro crítico. Modbus no "
                           "autentica: el PLC obedece (regla de rango).",
    "replay": "'Graba' un comando legítimo (el valor actual del registro) y lo reinyecta tal cual desde "
              "una sesión Modbus del atacante. El valor es válido; lo caza la allowlist por el origen.",
    "spoofing": "Se hace pasar por el maestro SCADA y manda un comando VÁLIDO. Lo único anómalo es el "
                "origen no autorizado, así que lo detecta la allowlist, no la regla de rango.",
    "flood": "Satura el PLC con requests para que deje de responder al operador real (regla de ritmo).",
}


class _Handler(BaseHTTPRequestHandler):
    server_version = "SimuladorICS/1.0"
    dir_salida = Path("reporte")
    modo_raw = False

    def log_message(self, formato: str, *args) -> None:  # firma de stdlib
        """Silencia el log por request de stdlib: la consola es para el usuario,
        no para el access log."""

    def do_GET(self) -> None:  # firma de stdlib
        ruta = urlparse(self.path)
        if ruta.path == "/":
            self._enviar_archivo(RAIZ / "dashboard" / "ui.html", "text/html; charset=utf-8")
        elif ruta.path == "/api/contexto":
            self._enviar_json(_contexto())
        elif ruta.path == "/api/simular":
            self._transmitir_simulacion(parse_qs(ruta.query))
        elif ruta.path == "/reporte":
            self._enviar_archivo(self.dir_salida / "reporte_incidente.html", "text/html; charset=utf-8")
        elif ruta.path == "/evidencia":
            self._enviar_archivo(self.dir_salida / "cadena_evidencia.json", "application/json; charset=utf-8")
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _enviar_archivo(self, ruta: Path, tipo: str) -> None:
        if not ruta.exists():
            self.send_error(HTTPStatus.NOT_FOUND, f"No existe {ruta.name}")
            return
        cuerpo = ruta.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _enviar_json(self, dato: dict) -> None:
        cuerpo = json.dumps(dato, ensure_ascii=False).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _transmitir_simulacion(self, params: dict[str, list[str]]) -> None:
        nombre_perfil = params.get("perfil", ["municipal"])[0]
        dificultad = params.get("dificultad", ["normal"])[0]
        if dificultad not in {d["id"] for d in _DIFICULTADES}:
            self.send_error(HTTPStatus.BAD_REQUEST, "Dificultad inválida")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        raw = params.get("raw", ["1" if self.modo_raw else "0"])[0].lower() in {"1", "true", "on"}

        def emitir(evento: dict) -> None:
            self.wfile.write(f"data: {json.dumps(evento, ensure_ascii=False)}\n\n".encode())
            self.wfile.flush()

        try:
            perfil = cargar_perfil(nombre_perfil)
            asyncio.run(simular(perfil, dificultad, self.dir_salida, emitir, ritmo=0.7, modo_raw=raw))
        except (BrokenPipeError, ConnectionResetError):
            pass  # el navegador cortó el stream (recarga o cambio de escenario)
        except Exception as e:  # noqa: BLE001 - el tablero tiene que mostrar el error, no morir
            emitir({"fase": "error", "detalle": f"{type(e).__name__}: {e}"})


def _contexto() -> dict:
    # Ordenados por escala creciente, no alfabéticamente: el tablero se lee de
    # menor a mayor superficie de ataque.
    orden = {"municipal": 0, "provincial": 1, "nacional": 2}
    rutas = sorted((RAIZ / "config" / "perfiles").glob("*.json"),
                   key=lambda r: orden.get(r.stem, 99))
    perfiles = []
    for ruta in rutas:
        perfil = cargar_perfil(str(ruta))
        perfiles.append({
            "id": ruta.stem,
            "escala": perfil.escala_gobierno.value,
            "poblacion": perfil.poblacion,
            "dependencias": perfil.dependencias_criticas,
            "nivel_digitalizacion": perfil.nivel_digitalizacion,
            "presupuesto": perfil.presupuesto_ciberseguridad,
            "marco_normativo": perfil.marco_normativo_vigente,
        })
    return {
        "version": VERSION,
        "raw_por_defecto": _Handler.modo_raw,
        "privilegios_raw": hay_privilegios_raw(),
        "perfiles": perfiles,
        "dificultades": _DIFICULTADES,
        "reglas": cargar_reglas(),
        "explicacion_ataques": _EXPLICACION_ATAQUES,
    }


def _puerto_libre(preferido: int, intentos: int = 20) -> int:
    """Devuelve el primer puerto libre desde `preferido`. Evita que un segundo
    doble clic (o cualquier otra app en 8501) rompa el arranque."""
    for puerto in range(preferido, preferido + intentos):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", puerto)) != 0:
                return puerto
    raise RuntimeError(f"No hay puertos libres entre {preferido} y {preferido + intentos}.")


def servir(puerto: int = 8501, abrir_navegador: bool = True, dir_salida: Path | None = None,
           modo_raw: bool = False) -> None:
    """Levanta el tablero y bloquea hasta Ctrl+C (o hasta cerrar la consola)."""
    puerto = _puerto_libre(puerto)
    _Handler.dir_salida = dir_salida or Path("reporte")
    _Handler.modo_raw = modo_raw
    url = f"http://127.0.0.1:{puerto}/"

    servidor = ThreadingHTTPServer(("127.0.0.1", puerto), _Handler)
    servidor.daemon_threads = True

    # flush explícito: al hacer doble clic la consola puede quedar con el buffer
    # sin volcar y el usuario no ve ni la URL ni cómo salir.
    print(f"\n  SIMULADOR ICS/SCADA — tablero de postura defensiva  [{VERSION}]", flush=True)
    print(f"  Abrí {url} en el navegador si no se abrió solo.", flush=True)
    print("  Cerrá esta ventana (o Ctrl+C) para apagar el tablero.\n", flush=True)

    if abrir_navegador:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n  Tablero apagado.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    sys.exit(servir())
