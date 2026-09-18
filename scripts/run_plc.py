"""Entrypoint de contenedor: levanta un PLCVirtual y queda escuchando.

Uso: python scripts/run_plc.py <dependencia> [puerto]
"""

import asyncio
import sys

from core.plc_virtual import PLCVirtual


async def main():
    dependencia = sys.argv[1] if len(sys.argv) > 1 else "agua"
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 502

    plc = PLCVirtual(dependencia=dependencia, puerto=puerto, host="0.0.0.0")
    print(f"PLCVirtual '{dependencia}' escuchando en 0.0.0.0:{puerto}", flush=True)
    await plc.iniciar()


if __name__ == "__main__":
    asyncio.run(main())
