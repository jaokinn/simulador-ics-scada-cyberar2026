# SPEC — Simulador de Postura Defensiva ICS/SCADA

> Fuente: "Opción B — Simulador ICS/SCADA — Hackathon CyberAR 2026" (Equipo Malvinas
> Argentinas, FIE-UNDEF, 15.09.2026). Este archivo es el contexto fijo del proyecto:
> cualquier prompt de generación de código debe ser consistente con lo que sigue.

## 1. La idea en una frase

No es "un" demo de ataque a una planta. Es un **generador de escenarios de ciberataque a
infraestructura crítica**: a partir de datos de una jurisdicción (municipio, provincia,
nación) y 5 variables de dificultad, arma una red industrial simulada, le inyecta ataques,
los detecta y los reporta — reinstanciable para cualquier organización cambiando un
archivo de configuración.

El motor Modbus (protocolo estándar de comunicación industrial — energía, agua, control de
accesos) es el núcleo técnico. La capa de modelaje territorial + generador de escenarios es
lo que convierte ese demo fijo en un producto generalizable.

**Decisión clave:** el generador de escenarios es determinístico, por reglas — corre en
cualquier laptop, sin GPU, con cero riesgo de fallo en la demo. La IA es una capa opcional
(Bloque F) que solo redacta texto descriptivo; si no está disponible, se usa una plantilla
fija. La IA nunca decide parámetros técnicos.

Flujo de capas: L0 datos de jurisdicción → L1 modelaje del defensor + L3 perillas de
dificultad → generador determinístico → escenario.json → L2 planta Modbus / L2b red team →
L4 blue team (IDS) → L5 mitigación/reporte → L6 narrativización opcional con IA.

## 2. Las 5 variables de escenario

Cada variable es una perilla que el generador traduce a un parámetro técnico concreto de
pymodbus y scapy.

| # | Variable | Qué modula técnicamente |
|---|----------|--------------------------|
| 1 | Tipo de ataque | Qué módulo del red team se activa (scan, escritura ilegítima, replay, spoofing, flood/DoS) y en qué orden — encadenados en difícil. |
| 2 | Intensidad / velocidad | Ritmo de paquetes por segundo. Baja = escritura puntual difícil de ver; alta = flood evidente. |
| 3 | Criticidad del objetivo | Qué registros del PLC se atacan — de telemetría no crítica a válvula de agua o breaker de energía. |
| 4 | Sofisticación del atacante | Evasión: sigiloso imita tráfico legítimo; ruidoso opera fuera de rango y a los saltos. |
| 5 | Ruido de fondo | Volumen de tráfico legítimo simultáneo que enmascara el ataque — la perilla que más cambia la dificultad de detección. |

## 3. Variables del defensor — territorio y jurisdicción

Se cargan desde `config/perfiles/*.json` por entidad, siempre con placeholders — nunca
datos reales de un municipio concreto — y cada indicador cuantitativo con su `fuente`
citada.

| Variable | Cómo modula la simulación |
|----------|----------------------------|
| Escala de gobierno | Multiplicador de topología: municipal 1-3 PLCs, provincial varios sitios federados, nacional federación de provincias. |
| Población | Ajusta cuántos servicios digitalizados expuestos tiene cada nodo. |
| Dependencias críticas | Cada dependencia (energía/agua/accesos) instancia un PLC virtual propio con sus registros. |
| Nivel de digitalización | Cuántos registros quedan expuestos y escribibles remotamente por PLC. |
| Presupuesto de ciberseguridad | Defensa de arranque: cuántas reglas de detección activas, si hay segmentación de red, si hay whitelist de direcciones. |
| Marco normativo vigente | Traduce "existe una norma" en "hay un control activado" en el escenario simulado. |

**Lógica territorial (regla dura):** la escala de gobierno manda sobre cualquier otra
variable — un perfil municipal nunca puede generar la superficie de ataque de una nación.
El generador debe validar esta coherencia automáticamente (ver Paso 8).

### 3.1 Reglas de combinación perfil + dificultad (Bloque B, Pasos 7-8)

> TODO(equipo): igual que la tabla de dificultad, esta es una propuesta razonable de
> arranque para poder codificar el generador y el validador ya, no un valor cerrado.
> Ajustar antes de la entrega si no refleja bien el guion de demo.

Cantidad de dependencias críticas por plantilla de perfil (Paso 6) — proxy de "cantidad de
PLCs/sitios" de la sección anterior, ya que `dependencias_criticas` puede repetir un tipo
para representar varios sitios del mismo tipo:

| Escala | Dependencias críticas (ejemplo) | Total (≈ PLCs) |
|---|---|---|
| Municipal | `[agua, accesos]` | 2 |
| Provincial | `[agua, agua, energia, accesos]` (varios sitios federados) | 4 |
| Nacional | `[energia, energia, agua, agua, agua, accesos, accesos]` (federación de provincias) | 7 |

Techo de superficie de ataque que un `Escenario` puede tener según la `escala_gobierno`
del perfil, sin importar qué pida el preset de dificultad — esto es lo que
`generar_escenario` recorta y lo que `validar_coherencia` rechaza si no se cumple:

| Escala | Máx. tipos_ataque encadenados | Tope de criticidad_objetivo |
|---|---|---|
| Municipal | 3 | media |
| Provincial | 4 | alta |
| Nacional | 5 | alta |

Regla adicional: el número de `tipos_ataque` de un escenario tampoco puede superar el
número de `dependencias_criticas` reales del perfil (no se puede atacar más superficies de
las que existen), aunque el techo de la tabla de arriba lo permita.

## 4. Los 3 escenarios de dificultad

| Perilla | Fácil | Normal | Difícil |
|---|---|---|---|
| Tipo de ataque | 1 tipo aislado | 2-3 encadenados | 4-5 en cadena coordinada |
| Intensidad | Baja, evidente | Media | Mixta (lenta + ráfaga) |
| Criticidad objetivo | Baja/media | Media/alta | Alta, multi-registro |
| Sofisticación | Ruidoso | Medio | Sigiloso |
| Ruido de fondo | Bajo | Medio | Alto |

> Nota: la tabla original solo da rangos cualitativos. Los valores numéricos concretos
> (pps, criticidad, tipos de ataque exactos) usados en `config/presets_dificultad.yaml`
> son una propuesta razonable marcada `TODO(equipo)` — deben validarse contra el guion de
> demo real antes de la entrega final.

**Escenario MVP de cierre:** 3 defensores en paralelo (nación, provincia, municipio-ejemplo)
recibiendo una campaña en cascada simultánea. El tablero muestra los 3 niveles reaccionando
en paralelo, contrastando cómo el municipio (menos presupuesto/digitalización) cae distinto
que la nación.

## 5. Stack técnico

- `pymodbus` (3.x, API asíncrona) — PLC virtual y tráfico legítimo de fondo.
- `scapy` — inyección de ataques y sniffing para el IDS.
- `fastapi` + `pydantic` — orquestador y contratos de datos tipados.
- `streamlit` — tablero de demo en vivo.
- `docker compose` — redes aisladas por nivel, sin salida a internet.
- Narrativización con IA: opcional, plantilla fija por defecto; si hay modelo chico
  disponible (Llama 3.2 3B / Phi-3 mini) corre local en CPU. Nunca decide parámetros
  técnicos ni es requisito para que el sistema funcione.

## 6. Roadmap (Bloques A–G)

| Bloque | Qué produce |
|---|---|
| A · Contratos y esqueleto | README, dependencias, schemas (perfil y escenario), presets de dificultad, escenario.json de ejemplo. |
| B · Modelaje y generador | Plantillas de perfil (municipal/provincial/nacional) y generador determinístico perfil+dificultad → escenario. |
| C · Motor Modbus | PLC virtual y tráfico legítimo de fondo (núcleo técnico — máxima atención humana). |
| D · Red team | Un módulo por ataque (scan, escritura ilegítima, replay, spoofing, flood) + orquestador de secuencia. |
| E · Blue team + reporte | Motor de reglas de detección, mitigación, reporte de incidente. |
| F · Narrativización opcional | Capa de texto con IA, aislada, con fallback a plantilla fija. |
| G · Integración (aparte) | Redes Docker aisladas, API del orquestador, escenario MVP de 3 niveles, tablero final. |

**Regla de seguridad no negociable:** los módulos de red team (Bloque D) son funcionalmente
equivalentes a técnicas usadas en ataques reales a infraestructura crítica. Deben correr
siempre dentro de la red Docker aislada sin salida a internet (Bloque G), nunca contra un
objetivo real ni una red que no sea la simulación propia.
