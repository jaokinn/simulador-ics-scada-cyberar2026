"""Generador de reporte de incidente (Bloque E, Paso 21).

Combina un EventoDeteccion (Paso 19) con las AccionMitigacion que disparó
(Paso 20) en un reporte estructurado por ataque: qué pasó, cuándo, qué
registro/dependencia se vio afectado, qué mitigación se aplicó. Esto alimenta
después la narrativización opcional (Bloque F).

`generar_reporte_html`/`render_pdf` producen además una versión legible del
mismo reporte (HTML siempre; PDF si `weasyprint` está instalado — es opcional,
requiere librerías de sistema pesadas, ver requirements-opcional.txt).
"""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from blueteam.deteccion import EventoDeteccion
from blueteam.mitigacion import AccionMitigacion

_DIR = os.path.dirname(os.path.abspath(__file__))


def generar_reporte(
    eventos: list[EventoDeteccion],
    mitigaciones_por_evento: list[list[AccionMitigacion]],
    dependencia: str,
    registros: list[dict],
) -> dict:
    """Arma un reporte de incidente a partir de los eventos detectados y las
    mitigaciones aplicadas a cada uno (mismo índice en ambas listas).

    `dependencia` y `registros` identifican qué PLC generó los eventos (ver
    core/arranque.py) para poder nombrar el registro/dependencia afectada en
    vez de solo su dirección numérica.
    """
    if len(eventos) != len(mitigaciones_por_evento):
        raise ValueError("eventos y mitigaciones_por_evento deben tener la misma longitud")

    incidentes = []
    for evento, mitigaciones in zip(eventos, mitigaciones_por_evento):
        if evento.direccion_registro is None:
            registro_afectado = "tráfico general (no un registro puntual, ej. ráfaga de lecturas)"
        else:
            definicion = next(
                (r for r in registros if r["direccion"] == evento.direccion_registro), None
            )
            registro_afectado = (
                definicion["nombre"] if definicion else f"dirección {evento.direccion_registro}"
            )

        incidentes.append(
            {
                "tipo_ataque_probable": evento.tipo_ataque_probable,
                "timestamp": evento.timestamp,
                "ip_origen": evento.ip_origen,
                "dependencia_afectada": dependencia,
                "registro_afectado": registro_afectado,
                "evidencia": evento.evidencia,
                "regla_id": evento.regla_id,
                "severidad": evento.severidad,
                "mitigaciones_aplicadas": [
                    {"accion": m.accion, "detalle": m.detalle} for m in mitigaciones
                ],
            }
        )

    return {
        "dependencia": dependencia,
        "cantidad_incidentes": len(incidentes),
        "incidentes": incidentes,
    }


def _entorno() -> Environment:
    return Environment(loader=FileSystemLoader(_DIR), autoescape=select_autoescape(["html", "j2"]))


def construir_contexto_html(
    reporte: dict,
    escenario_id: str,
    dificultad: str,
    total_ataques_ejecutados: int,
    cadena_verificada: bool,
    narrativa: str | None = None,
) -> dict:
    """Arma el contexto que consume plantilla_reporte.html.j2 a partir del
    dict que ya arma `generar_reporte`.

    `total_ataques_ejecutados` puede ser mayor a `reporte['cantidad_incidentes']`
    — la diferencia son los falsos negativos: ataques que el red team ejecutó
    pero que ninguna de las 3 reglas del IDS detectó (SPEC.md / blueteam/deteccion.py,
    limitación documentada de replay).
    """
    return {
        "escenario_id": escenario_id,
        "dificultad": dificultad,
        "dependencia": reporte["dependencia"],
        "narrativa": narrativa,
        "incidentes": reporte["incidentes"],
        "n_ataques": total_ataques_ejecutados,
        "n_detectados": reporte["cantidad_incidentes"],
        "cadena_verificada": cadena_verificada,
    }


def render_html(contexto: dict) -> str:
    tpl = _entorno().get_template("plantilla_reporte.html.j2")
    return tpl.render(**contexto)


def render_pdf(html: str, ruta_pdf: str) -> bool:
    """Convierte el HTML a PDF con weasyprint (import perezoso, opcional).

    Devuelve True si generó el PDF. Si weasyprint no está instalado (requiere
    librerías de sistema — GTK/Cairo/Pango — no solo `pip install`), devuelve
    False sin romper nada: el HTML ya se generó y sirve igual para la demo.
    """
    try:
        from weasyprint import HTML
    except ImportError:
        return False
    HTML(string=html).write_pdf(ruta_pdf)
    return True


def generar_reporte_html(contexto: dict, ruta_html: str, ruta_pdf: str | None = None) -> dict:
    html = render_html(contexto)
    with open(ruta_html, "w", encoding="utf-8") as f:
        f.write(html)
    pdf_ok = False
    if ruta_pdf:
        pdf_ok = render_pdf(html, ruta_pdf)
    return {"html": ruta_html, "pdf": ruta_pdf if pdf_ok else None}
