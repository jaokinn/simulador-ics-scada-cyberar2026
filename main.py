"""Entrypoint del simulador ICS/SCADA (Bloque G).

Por defecto levanta el tablero web interactivo en el navegador — que es lo que
pasa al hacer doble clic en el ejecutable. Con `--cli` corre la misma
simulación de una sola pasada por consola.

Uso:
    simulador-ics-scada                                   # tablero web
    simulador-ics-scada --cli                             # municipal, normal
    simulador-ics-scada --cli --perfil nacional --dificultad dificil
    simulador-ics-scada --puerto 8080 --no-navegador      # tablero en otro puerto
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import sys
from pathlib import Path

from core.pipeline import VERSION, cargar_perfil, simular
from dashboard.servidor import servir


def _imprimir(evento: dict) -> None:
    fase = evento["fase"]
    if fase == "perfil":
        print(f"\n=== Perfil {evento['escala']} | dependencias: {evento['dependencias']} "
              f"| presupuesto {evento['presupuesto']}/5 ===")
    elif fase == "escenario":
        print(f"=== Escenario ({evento['dificultad']}): ataques={evento['tipos_ataque']} "
              f"criticidad={evento['criticidad_objetivo']} sofisticacion={evento['sofisticacion']} ===\n")
    elif fase == "planta":
        print(f"[planta] PLC '{evento['dependencia']}' Modbus TCP en {evento['host']}:{evento['puerto']}")
    elif fase == "trafico_fondo":
        print(f"[baseline] {evento['polls']} lecturas legítimas del HMI, 0 alertas")
    elif fase == "aviso":
        print(f"[aviso] {evento['detalle']}")
    elif fase == "metrica":
        print(f"  [metrica] {evento['detalle']}")
    elif fase == "ataque":
        marca = "->" if evento["estado"] == "ejecutado" else "--"
        print(f"  [redteam] {marca} {evento['titulo']}")
    elif fase == "deteccion":
        print(f"  [blueteam] {evento['regla_id']} ({evento['severidad']}): {evento['evidencia']}")
    elif fase == "mitigacion":
        acciones = ", ".join(sorted({a["accion"] for a in evento["acciones"]})) or "ninguna"
        print(f"[blueteam] mitigaciones aplicadas: {acciones}")
    elif fase == "evidencia":
        print(f"[evidencia] {evento['bloques']} bloques encadenados; "
              f"cadena {'OK' if evento['verificada'] else 'ALTERADA'}")
    elif fase == "fin":
        print(f"\n[resumen] {evento['ataques_ejecutados']} ataques ejecutados "
              f"({evento['ataques_omitidos']} omitidos) -> {evento['alertas']} alertas")
        print(f"[salida] reporte HTML: {evento['ruta_html']}")
        print(f"[salida] cadena de evidencia: {evento['ruta_cadena']}\n")


def _salida_por_defecto() -> Path:
    """Al hacer doble clic, el directorio de trabajo no es el del ejecutable (y
    puede no ser escribible), así que el reporte se escribe al lado del .exe."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "reporte"
    return Path("reporte")


def _consola_utf8() -> None:
    """La consola de Windows arranca en una code page legacy (cp850/cp1252) y
    rompe los acentos del reporte narrado."""
    if sys.platform != "win32":
        return
    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _consola_utf8()
    ap = argparse.ArgumentParser(description="Simulador de postura defensiva ICS/SCADA.")
    ap.add_argument("--version", action="version", version=f"simulador-ics-scada {VERSION}")
    ap.add_argument("--cli", action="store_true",
                    help="Corre una simulación por consola en vez de abrir el tablero web.")
    ap.add_argument("--perfil", default="municipal",
                    help="municipal | provincial | nacional, o ruta a un .json de perfil (solo con --cli).")
    ap.add_argument("--dificultad", default="normal", choices=["facil", "normal", "dificil"])
    ap.add_argument("--salida", default=None, help="Directorio donde escribir el reporte.")
    ap.add_argument("--puerto", type=int, default=8501, help="Puerto del tablero web.")
    ap.add_argument("--no-navegador", action="store_true",
                    help="No abrir el navegador automáticamente.")
    ap.add_argument("--raw", action="store_true",
                    help="Ejecuta scan/spoofing/replay con scapy (paquetes crudos) sobre loopback. "
                         "Necesita privilegios de red cruda (root/CAP_NET_RAW o Administrador+Npcap); "
                         "sin ellos cae automáticamente a las variantes portables.")
    args = ap.parse_args()
    print(f"simulador-ics-scada {VERSION}")
    salida = Path(args.salida) if args.salida else _salida_por_defecto()

    if not args.cli:
        servir(puerto=args.puerto, abrir_navegador=not args.no_navegador,
               dir_salida=salida, modo_raw=args.raw)
        return

    try:
        perfil = cargar_perfil(args.perfil)
    except ValueError as e:
        raise SystemExit(str(e)) from e
    asyncio.run(simular(perfil, args.dificultad, salida, _imprimir, modo_raw=args.raw))


if __name__ == "__main__":
    main()
