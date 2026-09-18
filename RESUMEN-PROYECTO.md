# Resumen del proyecto — Simulador ICS/SCADA (Equipo Malvinas Argentinas)

> Hackathon CyberAR 2026 (FIE-UNDEF). Este resumen reconstruye qué se hizo durante el
> desarrollo de este repositorio, con qué criterio, y qué queda pendiente. Escrito para
> alguien que no estuvo en cada paso de la construcción.

## 1. Qué es el proyecto

Un simulador que genera escenarios de ciberataque contra infraestructura crítica (agua,
energía, control de accesos) y los ejecuta de punta a punta: arma una planta industrial
simulada con el protocolo real que usan estos sistemas (Modbus TCP), la ataca, la defiende
con un motor de detección automático, y produce un reporte del incidente.

La idea central, ya definida por el equipo antes de escribir código (ver `SPEC.md` y el
informe original): no es "un" demo de un ataque fijo, sino un **generador**. A partir de
datos de una jurisdicción (municipio, provincia o nación) y 5 variables de dificultad, arma
un escenario distinto cada vez, de forma determinística — reinstanciable para cualquier
organización cambiando un archivo de configuración, no código.

## 2. Qué se construyó (Bloques A-F del plan original)

- **Perfiles y generador (Bloques A-B):** modelos de datos tipados (Pydantic) para el perfil
  de una jurisdicción y para un escenario de ataque; 3 perfiles de ejemplo (municipal,
  provincial, nacional) con placeholders, nunca datos reales; un generador determinístico
  que combina perfil + dificultad respetando una regla territorial dura: la escala de
  gobierno pone un techo a la superficie de ataque posible (un municipio nunca puede generar
  un ataque tan grande como el de una nación, aunque se pida dificultad "difícil").
- **Motor Modbus (Bloque C):** un PLC virtual real (servidor Modbus TCP con `pymodbus`), con
  un mapa de registros por dependencia (agua/energía/accesos) anclado a convenciones reales
  de la industria (rangos de cloro residual, frecuencia de red argentina de 50Hz, etc.), y
  tráfico legítimo de fondo que imita el polling de un SCADA real.
- **Red team (Bloque D):** 5 módulos de ataque — scan, escritura no autorizada, replay,
  spoofing de IP, y flood/DoS — más un orquestador que los encadena respetando el timing
  pedido por el escenario (ataques "sigilosos" espaciados, "ruidosos" en simultáneo real).
- **Blue team (Bloque E):** motor de detección con 3 reglas identificadas
  (`R-RANGO-001`: escritura fuera de rango; `R-ALLOW-001`: IP no autorizada; `R-RITMO-001`:
  ráfaga de tráfico anómala), mitigación automática escalonada según el presupuesto de
  ciberseguridad del perfil, cadena de evidencia por hash (para probar que un reporte no fue
  alterado), reporte de incidente en texto y HTML, y exportación de las reglas a formato
  **Sigma** (el formato abierto que usan SIEMs reales, para mostrar interoperabilidad).
- **Narrativización opcional (Bloque F):** redacción del reporte en lenguaje natural con un
  modelo de IA local (Ollama, sin nube); si no hay modelo disponible, cae automáticamente a
  una plantilla de texto fija — la IA nunca decide parámetros técnicos del sistema.

## 3. Cómo se construyó, y por qué eso importa

Todo el código se escribió con asistencia de un agente de IA (Claude, vía Claude Code) a
partir de la especificación humana del equipo (detalle completo de autoría en
`DECLARACION-IA.md`). La diferencia importante frente a "generar código y listo": **cada
pieza se ejecutó de verdad** antes de darla por terminada — primero en Windows nativo, y
después dentro de contenedores Docker/Linux para los ataques que necesitan privilegios de
red cruda (scan, replay, spoofing).

Ese proceso de ejecución encontró y corrigió errores reales que una simple revisión de
código no hubiera visto:

- La variable "criticidad del objetivo" (una de las 5 perillas centrales del pitch) no
  elegía ningún registro concreto — el ataque siempre golpeaba el mismo, sin importar qué
  criticidad pidiera el escenario. Se corrigió agregando una criticidad por registro y una
  función real de selección.
- La ejecución "ruidosa" de una campaña de ataque corría todo secuencialmente en vez de en
  simultáneo real, contradiciendo el propio diseño ("ruidoso = simultáneo").
- La regla de detección de ráfaga solo contaba escrituras, así que un ataque de flood (que
  es puramente lecturas) nunca la hubiera disparado en la práctica.
- El registro Modbus se inicializaba en el mínimo de su rango válido en vez de en un valor
  de "planta operando normal" — la demo hubiera arrancado con la planta ya apagada.
- Un valor de prueba usado para forzar una detección (999999) excedía el límite de un
  registro Modbus real de 16 bits y el propio protocolo lo rechazaba.
- Varios bugs de temporización en Windows (el sistema operativo tiene un piso de ~15.6ms
  para pausas cortas, que no existe en Linux — relevante para no confundir un número bajo en
  desarrollo local con un bug real).

## 4. Un hallazgo importante durante el desarrollo: dos backends en paralelo

A mitad de camino apareció un documento de diseño de interfaz que asumía un backend
distinto al que se estaba construyendo acá: un archivo `OPCION-B-SIMULADOR-ICS.zip`, una
implementación completa e independiente hecha por Francisco (compañero de equipo), con una
arquitectura diferente (por lotes/replay en vez de tiempo real) y algunas piezas que a este
repositorio le faltaban (exportación a Sigma, cadena de evidencia por hash, reporte HTML con
plantilla). La diferencia clave: el backend de Francisco, según su propia auditoría interna,
**nunca se había ejecutado** ("auditoría por lectura de código, sin ejecutar nada"); este
repositorio sí, de punta a punta, varias veces.

Decisión tomada (con el equipo): usar este backend como base — por estar probado de verdad —
y portar a él las 3 piezas valiosas del backend de Francisco (exportación Sigma, cadena de
evidencia, plantilla de reporte HTML), adaptándolas al modelo de datos de este repositorio.
Esas 3 piezas ya están integradas y probadas acá (ver `DECLARACION-IA.md` para el crédito
completo de autoría).

## 5. Estado del entorno de desarrollo

- Python 3.12 instalado y funcionando (no venía instalado originalmente en la máquina de
  desarrollo).
- Docker Desktop + WSL2 instalados y funcionando — necesarios porque 3 de los 5 ataques
  (scan, replay, spoofing) requieren privilegios de red cruda que Windows nativo no da sin
  Npcap.
- Npcap (para probar esos mismos 3 ataques directamente en Windows sin Docker) se descargó
  pero la instalación quedó pendiente — requiere aprobar un cuadro de administrador de forma
  interactiva. No es bloqueante: Docker ya permite probar los 5 ataques igual.

## 6. Qué queda pendiente (Bloque G y entrega final)

- **Interfaz gráfica / dashboard:** no está construida todavía. Hay un documento de
  investigación muy completo del equipo (research de simuladores de referencia, mapeo a
  MITRE ATT&CK for ICS verificado, modelo Purdue para la geometría visual, niveles de
  amenaza doctrinales tipo DEFCON adaptados — "CPC") que sirve de base, pero falta decidir
  el enfoque final (interfaz propia vs. herramienta SCADA/HMI real de código abierto
  apuntando a los PLCs, esto último quedó pausado a pedido del equipo para más adelante).
- **API HTTP** (carpeta `api/`) y **docker-compose.yml definitivo** con las redes de los 3
  niveles de gobierno corriendo en simultáneo: no están construidos.
- **Valores marcados `TODO(equipo)` en el código:** varios números concretos (umbrales de
  dificultad, techos de superficie de ataque por escala de gobierno, umbrales de presupuesto
  para mitigación) son propuestas razonables para poder avanzar, no valores validados por el
  equipo — conviene revisarlos antes de la entrega final.
- **Guion de demo de 3 minutos:** ya está armado (documento aparte, no en este repo) con
  tiempos exactos, texto para narrador y operador, checklist técnico pre-escenario y
  preguntas esperables del jurado.
- **Verificar la demo sin internet:** construir la imagen Docker necesita internet;
  correrla no. Falta probar explícitamente que la demo funciona con la conexión apagada,
  ya que el reglamento asume sala sin internet.

## 7. Estructura del repositorio

```
core/         # schemas, generador determinístico, PLC virtual, tráfico de fondo, narrativización
redteam/      # módulos de ataque + orquestador de campaña
blueteam/     # detección (reglas con ID), mitigación, evidencia (hash chain), reporte, export Sigma
config/       # perfiles de jurisdicción, presets de dificultad, mapa de registros Modbus
scripts/      # entrypoints de contenedor (arrancar un PLC, probar ataques con scapy en Linux)
api/          # pendiente
dashboard/    # pendiente
```

Ver `README.md` para instrucciones de instalación y ejecución, `SPEC.md` para la
arquitectura técnica completa, y `DECLARACION-IA.md` para el detalle de autoría humana vs.
asistida por IA.
