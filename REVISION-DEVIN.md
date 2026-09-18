# Revisión del simulador ICS/SCADA — opiniones y mejoras

Revisión de código del repositorio `simulador-ics-scada-cyberar2026` (Hackathon CyberAR
2026). Basada en leer todo el código y **ejecutarlo de punta a punta** en Linux.

## Veredicto corto

Proyecto muy sólido para un hackathon: arquitectura limpia por bloques, contratos tipados
con Pydantic, Modbus TCP **real** (no un mock), reglas de detección con ID formal + export a
Sigma, cadena de evidencia por hash, y una separación honesta entre "lo que decide la IA" y
"lo que decide el sistema". Los comentarios del código son de una calidad poco común: dicen
el *porqué*, no el *qué*.

El hueco más grande no era de calidad sino de **integración**: no había ningún entrypoint
que corriera el pipeline completo (`api/` y `dashboard/` están vacíos), pese a que el README
afirma que el pipeline "de punta a punta" está probado. Eso lo resolví (ver abajo).

## Lo que está muy bien

- **Modbus real con `pymodbus` 3.x async** y mapa de registros anclado a valores de
  ingeniería reales (cloro OMS/EPA, 50 Hz de red argentina, etc.). Verifiqué el
  round-trip: la escritura ilegítima efectivamente pisa el registro en el servidor.
- **Generador determinístico con techo territorial** (`core/generador.py`): la escala de
  gobierno recorta la superficie de ataque aunque el preset pida más. Regla clara y bien
  testeable.
- **Blue team desacoplado en dos capas**: reglas puras (`evaluar_rango`,
  `evaluar_whitelist`, `DetectorRafaga`) testeables sin capturar tráfico, y una capa de
  sniffing aparte. Es la decisión de diseño correcta.
- **Cadena de evidencia** (`blueteam/evidencia.py`): SHA-256 encadenado, `verificar()`
  detecta alteración. Simple y correcto.
- **Honestidad técnica** documentada: la limitación de replay frente a las 3 reglas, el
  piso de 15.6 ms de `asyncio.sleep` en Windows, el logsource custom de Sigma para Modbus.
  Esto suma muchísimo frente a un jurado.

## Mejoras (por prioridad)

### P0 — lo que agregué en esta revisión

1. **Entrypoint end-to-end (`main.py`)** — glue del Bloque G que faltaba. Corre
   perfil→escenario→planta→ataque→detección→mitigación→evidencia→reporte en un proceso,
   **sin root** (los ataques scapy se saltan con aviso). Antes no había forma de correr "el
   sistema", solo piezas sueltas.
2. **Ejecutable** (`simulador-ics-scada.spec` + `BUILD-EJECUTABLE.md`) — binario
   autocontenido con PyInstaller que embebe `config/` y la plantilla del reporte.

### P1 — recomendadas antes de la entrega

3. **No hay tests automatizados en el repo.** El README dice "probado por ejecución real"
   pero no hay carpeta `tests/`. Las funciones puras se testean en minutos y blindan la
   demo: techos del generador, `evaluar_rango`/`evaluar_whitelist`, `DetectorRafaga`,
   tamper de `CadenaEvidencia`, y el export a Sigma. Alto valor, bajo esfuerzo.
4. **`blueteam/deteccion.py` importa scapy a nivel de módulo.** `from scapy... import sniff`
   arriba de todo obliga a tener scapy (y engorda el ejecutable ~15 MB) incluso para usar
   solo las reglas puras. Mover los imports de scapy dentro de `iniciar_sniffer` deja las
   reglas, los tests y el ejecutable **sin dependencia de scapy**.
5. **Dependencias muertas en `requirements.txt`.** `fastapi`, `uvicorn` y `streamlit` están
   pineados pero `api/` y `dashboard/` están vacíos. Inflan install, imagen Docker y
   ejecutable. Moverlas a un extra hasta que exista el Bloque G.
6. **Guardas de seguridad en los módulos de ataque.** `escanear_rango`,
   `enviar_paquete_spoofed`, etc. aceptan cualquier IP sin validar. Como son técnicas de
   ataque reales, conviene rechazar destinos que no sean loopback/RFC-1918 salvo un flag
   explícito tipo `--laboratorio-aislado`. Refuerza el mensaje de uso responsable.

### P2 — pulido

7. **Reporte "2/1 detectados".** `cantidad_incidentes` cuenta *reglas disparadas*, no
   *ataques*: una escritura ilegítima dispara 2 reglas (rango + whitelist), así que el
   contador puede superar la cantidad de ataques. Conviene distinguir "ataques detectados"
   de "alertas generadas" para que no confunda al jurado.
8. **`asyncio.get_event_loop()` está deprecado** dentro de corrutinas (3.10+). Usar
   `asyncio.get_running_loop()` en `redteam/flood.py` y `core/trafico_fondo.py`.
9. **`Dockerfile`** tiene un `CMD` placeholder y no hay `docker-compose.yml`. `main.py`
   ahora sirve como entrypoint real del contenedor.
10. **CI mínima**: agregar `pyproject.toml` + `ruff` + un workflow de GitHub Actions que
    corra lint y los tests del punto 3.

## Cómo probé

```
python main.py --perfil municipal  --dificultad normal
python main.py --perfil nacional   --dificultad dificil
./dist/simulador-ics-scada --perfil municipal --dificultad facil   # binario, en dir limpio
```

Los tres corren el pipeline completo y generan el reporte HTML + la cadena de evidencia
verificada.
