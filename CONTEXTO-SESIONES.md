# Contexto de sesiones — Simulador ICS/SCADA (Hackathon CyberAR 2026)

> Este archivo es el puente entre sesiones de Claude Code. Cada sesión nueva
> que retome este proyecto debe leerlo primero. Se actualiza en cada avance
> importante — no se reescribe desde cero, se agrega al final.

## Estado al 17.09.2026 (commit inicial del repo)

- Repo git inicializado en esta carpeta (`SIMULADOR-ICS-SCADA-TEAM/`), a partir
  del zip `simulador-ics-scada_16-09-2026.zip` recibido de un compañero de
  equipo. Auditado por seguridad antes de extraer: sin alarmas (sin eval/exec,
  sin credenciales, sin IPs externas — todo el código "red team" apunta al PLC
  simulado propio, red interna/local).
- Estructura: `core/`, `redteam/`, `blueteam/`, `config/`, `scripts/` completos
  y probados (Bloques A-F del plan). `api/` y `dashboard/` vacíos, pendientes
  (Bloque G).
- Ver `RESUMEN-PROYECTO.md` (dentro de esta misma carpeta) para el detalle
  completo de qué se construyó y por qué.
- Existe otra carpeta hermana `../OPCION-B-SIMULADOR-ICS/` — es el zip viejo de
  Francisco (backend alternativo, nunca ejecutado de punta a punta). Decisión
  ya tomada por el equipo: este repo (`SIMULADOR-ICS-SCADA-TEAM/`) es la base;
  de ahí se portaron 3 piezas valiosas del backend de Francisco (export Sigma,
  cadena de evidencia, plantilla HTML de reporte) — ya integradas acá.

## Pendiente — bloqueante para el .exe

1. **No hay entrypoint único.** El flujo completo (perfil → escenario →
   ataque → detección → reporte) se orquesta programáticamente vía
   `redteam/orquestador.py`, sin un `main.py`/CLI unificado todavía.
   **Decidido por Francisco (17.09.2026): el `.exe` abre un MENÚ DE INICIO**
   con las distintas opciones configurables (perfil, dificultad, modo —
   libre/demo guiada/tutorial, ver `DISENO-INTERFAZ/concepto-modos-de-uso.md`)
   — no arranca directo con una presentación predefinida/preset fijo. Falta
   construir ese menú antes de armar el build con PyInstaller.
2. **scapy + Npcap.** Los 3 ataques que usan `scapy` (scan, replay, spoofing)
   necesitan Npcap instalado en Windows para funcionar nativo — sin eso, no
   corren fuera de Docker. Decisión pendiente: dejarlos afuera del `.exe` o
   instalar Npcap en la PC de prueba.

## Próximos pasos

- Esperando instrucciones de Joaquín (compañero de equipo) sobre cómo seguir.
- Menú de inicio configurable: definido como requisito (ver arriba), falta
  diseño de pantalla concreto (se hace junto con el resto de la interfaz,
  subagente Fable, cuando Francisco lo pida — ver
  `../DISENO-INTERFAZ/plan-diseno-pixel-art_v1.md`).
- Una vez resueltos scapy/Npcap y el menú: armar entrypoint, build a `.exe`
  con PyInstaller, enviar por Telegram (zip con `.exe` + este archivo de
  contexto actualizado).

---
