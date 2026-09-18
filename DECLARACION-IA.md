# Declaración de uso de IA

> Obligatoria por reglamento CYBER.AR 2026. Equipo Malvinas Argentinas.
> Proyecto: Simulador ICS/SCADA — Generador de escenarios de ciberataque a infraestructura crítica.

Este proyecto combina diseño humano original con asistencia de IA para la implementación.
Declaramos con transparencia qué es cada cosa.

## Diseño humano original (sin IA)

- **La idea del simulador Modbus.** La estructura técnica de 4 puntos —red simulada Modbus →
  inyección de ataques → detección → mitigación/reporte— es concepción de **Joaquín**, integrante
  del equipo. Es la base técnica no negociable del proyecto (ver `SPEC.md` sección 1).
- **La estructura de variables generalizable.** La decisión de convertir el demo fijo en un modelo
  de simulación parametrizable por jurisdicción y por dificultad (las variables de modelaje del
  defensor y las 5 perillas de escenario) es diseño de **Francisco Martín**.
- **Las reglas de detección (qué mirar).** El criterio de qué constituye un comportamiento
  sospechoso en una red OT —rango seguro, IP fuera de whitelist, ritmo de polling anómalo— es
  diseño humano basado en conocimiento del dominio industrial. La IA ayudó a expresarlo en código
  y a probarlo, no a decidirlo.
- **La arquitectura de bloques (A-G) y la lógica territorial** (que la escala de gobierno limite la
  superficie de ataque posible) están definidas en el informe original del equipo
  (`INFORME - OPCION B SIMULADOR ICS-SCADA.html`) y en los prompts de construcción
  (`scada.docx.pdf`), ambos aportados por el equipo antes de escribir código.
- **El pitch y el encuadre de producto/mercado.** El análisis del Estado argentino en 3 niveles
  como mercado desatendido es trabajo humano del equipo.

## Generado con asistencia de IA

Todo el código de este repositorio (`core/`, `redteam/`, `blueteam/`, `config/`, `Dockerfile`,
`scripts/`) fue escrito por un asistente de código de IA (Claude, Anthropic — vía Claude Code) a
partir de la especificación humana descripta arriba, en sesiones de trabajo conjunto con el
equipo. Esto incluye:

- El motor Modbus (`core/plc_virtual.py`, `core/trafico_fondo.py`, `core/arranque.py`).
- El generador determinístico y el validador de coherencia territorial (`core/generador.py`).
- Los 5 módulos de red team y el orquestador de campaña (`redteam/`).
- El motor de reglas del IDS, la mitigación y el reporte de incidente (`blueteam/`).
- La narrativización opcional con fallback a plantilla fija (`core/narrativizacion.py`).
- La configuración de contenedores (`Dockerfile`) y los scripts de arranque (`scripts/`).

**Particularidad de este proceso:** el código no solo fue generado, sino **ejecutado y probado de
verdad** en cada paso (Windows nativo y contenedores Linux/Docker, con clientes Modbus reales y
paquetes de red reales vía `scapy`), lo que permitió encontrar y corregir varios errores reales
antes de la entrega (por ejemplo: la variable de "criticidad del objetivo" no seleccionaba ningún
registro real; la regla de detección de ráfaga no contaba las lecturas de un ataque de flood; la
ejecución "ruidosa" no corría en simultáneo de verdad). El detalle de estas correcciones queda en
el historial de esta conversación de desarrollo.

### Segunda fase de asistencia de IA (integración, portabilidad y empaquetado)

Una segunda etapa de trabajo, también con asistencia de IA (Devin, de Cognition AI), sobre la
misma especificación humana, produjo la capa de integración y entrega que faltaba. Incluye:

- El entrypoint unificado `main.py`, que corre el pipeline completo en un solo proceso
  (perfil → escenario → PLC → ataque → detección → mitigación → evidencia → reporte).
- El tablero web local estilo SCADA (`dashboard/servidor.py`, `dashboard/ui.html`) con
  eventos en vivo (SSE), sobre la librería estándar de Python (sin FastAPI ni Streamlit),
  ligado solo a `127.0.0.1`.
- Las **variantes portables** de scan/replay/spoofing (`redteam/`) sobre sockets Modbus TCP
  reales, para que los 5 ataques corran sin `scapy` ni privilegios; y el modo `--raw` que usa
  `scapy` sobre loopback cuando hay privilegios, con fallback automático a portable.
- Los ejecutables de un solo archivo para Windows y Linux (`simulador-ics-scada.spec`,
  PyInstaller) y su documentación (`BUILD-EJECUTABLE.md`).
- Correcciones de errores reales encontrados por ejecución (por ejemplo: acentos rotos en
  consola de Windows, traceback al cerrar sockets en el flood, y el choque de puerto del PLC
  cuando se lanzaban varias simulaciones a la vez — ahora cada corrida usa un puerto libre
  propio en loopback).

Igual que en la primera fase, las decisiones de diseño (variables, reglas, arquitectura) son
del equipo humano; la IA se usó para implementar, empaquetar y probar.

### Piezas adaptadas del trabajo de un compañero de equipo

Tres componentes de este repositorio (`blueteam/export_sigma.py`, `blueteam/evidencia.py`, y la
plantilla de reporte `blueteam/plantilla_reporte.html.j2`) están **adaptados con asistencia de IA**
a partir del diseño e implementación original de **Francisco**, en su repositorio paralelo
`OPCION-B-SIMULADOR-ICS` (exportación a formato Sigma para SIEMs, cadena de evidencia por hash, y
plantilla de reporte de incidente). La IA tradujo esas piezas al modelo de datos de este
repositorio; el diseño de esas tres funcionalidades es de Francisco.

## Cómo se usó la IA

La IA (asistente de código) se usó como herramienta de implementación y de pruebas: traducir a
código Python funcional un diseño y una arquitectura decididos por el equipo humano, y validar ese
código contra comportamiento real (servidores Modbus, tráfico de red, contenedores) en vez de
solo generarlo. Ninguna decisión de diseño —qué variables, qué reglas, qué arquitectura, qué
mercado— fue delegada a la IA. El equipo revisó y es responsable de todo el contenido.

## Datos

**No se usaron datos reales de ninguna jurisdicción.** Todos los perfiles de ejemplo (`municipal`,
`provincial`, `nacional`) llevan valores placeholder razonables y el campo `fuente` marcado como
placeholder. Al instanciar una jurisdicción real, los datos deben cargarse de fuentes públicas
citadas en ese campo.
