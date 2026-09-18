"""Narrativización opcional del reporte de incidente (Bloque F, Paso 22).

Redacta en lenguaje natural el reporte que arma blueteam/reporte.py. Nunca
decide parámetros técnicos — el reporte ya trae todos los datos resueltos
por el resto del sistema (Bloques C-E); esta capa solo los pone en prosa.

Plantilla fija primero (sin dependencias, siempre funciona) — el intento de
modelo local es una capa opcional que puede fallar por cualquier motivo (no
hay modelo instalado, timeout, servicio caído) y cae en la plantilla sin
romper nada. Si el reloj de la hackathon aprieta, todo este bloque se puede
recortar sin afectar Bloques A-E (SPEC.md sección 1).
"""

import json
import urllib.error
import urllib.request

# TODO(equipo): asume Ollama (http://localhost:11434) como runtime local para
# Llama 3.2 3B / Phi-3 mini — es la forma más liviana de correr un modelo
# chico en CPU sin agregar una librería de ML pesada a requirements.txt. Si
# el equipo prefiere llama-cpp-python u otro runtime, reemplazar solo
# _narrar_con_modelo(); el resto del sistema no depende de cuál se elija.
_OLLAMA_URL = "http://localhost:11434/api/generate"
_MODELOS_PREFERIDOS = ["llama3.2:3b", "phi3:mini"]
_TIMEOUT_SEG = 3


def _narrar_con_plantilla(reporte: dict) -> str:
    """Plantilla de texto fija — sin IA, cero dependencias externas.

    Es el camino garantizado: siempre funciona, sin importar si hay un
    modelo local disponible o no.
    """
    dependencia = reporte["dependencia"]
    cantidad = reporte["cantidad_incidentes"]

    if cantidad == 0:
        return f"No se detectaron incidentes de seguridad en la dependencia '{dependencia}'."

    lineas = [f"Se detectaron {cantidad} incidente(s) de seguridad en la dependencia '{dependencia}':"]
    for i, incidente in enumerate(reporte["incidentes"], start=1):
        mitigaciones = ", ".join(m["accion"] for m in incidente["mitigaciones_aplicadas"]) or "ninguna"
        lineas.append(
            f"{i}. [{incidente['tipo_ataque_probable']}] desde {incidente['ip_origen']} "
            f"sobre '{incidente['registro_afectado']}'. {incidente['evidencia']} "
            f"Mitigación aplicada: {mitigaciones}."
        )
    return "\n".join(lineas)


def _narrar_con_modelo(reporte: dict) -> str | None:
    """Intenta redactar con un modelo local chico servido por Ollama.

    Import/conexión diferidos al momento de uso: si Ollama no está corriendo
    o no tiene ninguno de los modelos preferidos cargado, devuelve None y el
    llamador cae a la plantilla. No debe levantar excepciones hacia afuera.
    """
    prompt = (
        "Redactá en español, en 2-3 oraciones y sin inventar datos técnicos "
        "nuevos, un resumen para un operador de sala de control a partir de "
        "este reporte de incidente ICS/SCADA (JSON):\n" + json.dumps(reporte, ensure_ascii=False)
    )

    for modelo in _MODELOS_PREFERIDOS:
        try:
            payload = json.dumps({"model": modelo, "prompt": prompt, "stream": False}).encode("utf-8")
            solicitud = urllib.request.Request(
                _OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(solicitud, timeout=_TIMEOUT_SEG) as respuesta:
                cuerpo = json.loads(respuesta.read())
                texto = cuerpo.get("response", "").strip()
                if texto:
                    return texto
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue  # este modelo no está disponible; probar el siguiente o caer a la plantilla

    return None


def narrar_reporte(reporte: dict) -> str:
    """Redacta el reporte de incidente en lenguaje natural.

    Intenta un modelo local chico primero; si no está disponible por
    cualquier motivo, usa la plantilla fija. Nunca decide parámetros
    técnicos: el reporte ya trae todo resuelto por Bloques C-E.
    """
    try:
        texto_modelo = _narrar_con_modelo(reporte)
    except Exception:
        texto_modelo = None  # cualquier fallo inesperado del intento de IA no debe romper el sistema

    return texto_modelo if texto_modelo is not None else _narrar_con_plantilla(reporte)
