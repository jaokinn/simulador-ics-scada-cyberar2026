# Simulador de Postura Defensiva ICS/SCADA

Generador de escenarios de ciberataque a infraestructura crítica (energía, agua, control
de accesos) sobre una red industrial simulada con Modbus TCP. A partir del perfil de una
jurisdicción (municipio, provincia o nación) y 5 variables de dificultad, arma
determinísticamente un escenario, lo ejecuta con un red team simulado, lo detecta con un
blue team basado en reglas y genera un reporte de incidente.

Hackathon CyberAR 2026 (FIE-UNDEF) · Equipo Malvinas Argentinas. Ver
[`SPEC.md`](./SPEC.md) para la arquitectura completa y [`DECLARACION-IA.md`](./DECLARACION-IA.md)
para el detalle de qué es diseño humano y qué se generó con asistencia de IA.

## Qué hace

- Modela el "defensor" (perfil territorial: escala de gobierno, dependencias críticas,
  presupuesto de ciberseguridad, etc.) sin usar nunca datos reales de una jurisdicción
  concreta.
- Genera escenarios de ataque de forma **determinística** (misma entrada → misma salida,
  sin IA ni aleatoriedad) combinando ese perfil con un preset de dificultad
  (fácil/normal/difícil).
- Simula una planta industrial (PLC virtual vía `pymodbus`, protocolo Modbus TCP real) con
  tráfico legítimo de fondo. Cada corrida levanta su propio PLC en un puerto libre de
  loopback, así se pueden lanzar varias simulaciones a la vez sin chocar.
- Ejecuta 5 ataques: scan, escritura ilegítima, replay, spoofing y flood/DoS — el ataque
  elige qué registro golpear según la criticidad pedida por el escenario. Por defecto corre
  en **modo portable** (sockets Modbus TCP reales, sin `scapy`, sin root/Npcap/Administrador),
  de modo que los 5 ataques se ejecutan siempre. Con el flag `--raw`, scan/replay/spoofing se
  ejecutan con `scapy` (paquetes crudos) sobre la interfaz loopback si hay privilegios de red
  cruda; si no los hay, cae automáticamente a las variantes portables. Todo ocurre contra
  `127.0.0.1`: nunca sale tráfico de la máquina.
- Detecta esos ataques con un motor de reglas (IDS) con ID formal por regla
  (`R-RANGO-001`, `R-ALLOW-001`, `R-RITMO-001`), aplica mitigación automática escalonada
  por presupuesto, y genera un reporte de incidente (texto y HTML, con cadena de evidencia
  por hash para detectar manipulación).
- Exporta las reglas de detección a formato **Sigma** (interoperable con SIEMs reales).
- Opcionalmente narra el reporte en lenguaje natural con un modelo local chico (Ollama); si
  no está disponible, cae automáticamente a una plantilla de texto fija.

## Cómo instalar y correr

**Opción A — ejecutable (sin instalar nada):** hay binarios de un solo archivo para Windows
(`simulador-ics-scada.exe`) y Linux (`simulador-ics-scada`). Doble clic abre el **tablero web
local** en el navegador (queda una consola chica abierta = el servidor, no cerrarla). Para
usar la consola en su lugar: `simulador-ics-scada --cli --perfil nacional --dificultad dificil`.
Cómo generarlos está en [`BUILD-EJECUTABLE.md`](./BUILD-EJECUTABLE.md).

**Opción B — entorno local (Python):**
```bash
python -m venv .venv
source .venv/bin/activate  # en Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Tablero web (se abre en el navegador):
python main.py

# Consola:
python main.py --cli --perfil nacional --dificultad dificil

# Ataques crudos con scapy sobre loopback (requiere privilegios; cae a portable si faltan):
sudo python main.py --cli --raw --perfil nacional --dificultad dificil
```

Privilegios para `--raw`: en Linux, root o `setcap cap_net_raw,cap_net_admin+eip`; en Windows,
Npcap instalado (modo "WinPcap API-compatible") y ejecutar como Administrador. Sin ellos, el
simulador avisa y corre las variantes portables.

Dependencias opcionales (no imprescindibles, ver [`requirements-opcional.txt`](./requirements-opcional.txt)):
`weasyprint` para exportar el reporte también a PDF (si no está, el reporte queda en HTML).

## Estructura de carpetas

```
main.py       # entrypoint: pipeline completo en un proceso (tablero web por defecto, --cli para consola)
core/         # schemas, generador determinístico, PLC virtual, tráfico de fondo, pipeline, narrativización
redteam/      # módulos de ataque (scan, escritura ilegítima, replay, spoofing, flood) portables y raw (scapy) + orquestador
blueteam/     # motor de detección (IDS), reglas con ID, mitigación, evidencia (hash chain), reporte, export Sigma
dashboard/    # tablero web local (http.server + SSE) estilo SCADA que explica y muestra la corrida en vivo
config/       # perfiles de jurisdicción, presets de dificultad, mapa de registros Modbus
scripts/      # entrypoints de contenedor (arrancar un PLC, probar ataques con scapy en Linux)
```

## Estado

Pipeline completo de punta a punta **probado por ejecución real** (perfil → escenario →
PLC Modbus TCP real → tráfico de fondo → ataque → detección → mitigación → evidencia →
reporte): Modbus real, detección contra paquetes Modbus reales y cadena de evidencia
verificada contra manipulación. Los 5 ataques corren siempre en modo portable; el modo
`--raw` con scapy sobre loopback se verificó en Linux con privilegios.

Entrega actual: `main.py` unificado (CLI + tablero web), tablero web local estilo SCADA y
ejecutables de un archivo para Windows y Linux.

Pendiente / roadmap: más protocolos además de Modbus (OPC-UA, DNP3, S7 — el motor de
detección/evidencia/reporte ya es agnóstico al protocolo), física de proceso y detección
estadística.
