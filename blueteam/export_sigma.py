"""Exporta las reglas propias del IDS a formato Sigma (Bloque E — interoperabilidad).

Demuestra que el motor de reglas no es una caja cerrada: cada regla se puede
llevar a un SIEM real (Splunk, Elastic, Sentinel, etc. — todos tienen backend
Sigma). No es imprescindible para que el sistema funcione; es la prueba de
"esto no muere en el hackathon".

Salvedad honesta (declarar si el jurado pregunta): Sigma no tiene una
taxonomía `logsource` nativa para Modbus — se usa un logsource custom
(`product: ics, service: modbus`), como hace cualquier regla ICS real.

Uso:
    python -m blueteam.export_sigma --salida sigma/
"""

import argparse
import os

import yaml

from blueteam.reglas import cargar_reglas

_SEVERIDAD_SIGMA = {"alta": "high", "media": "medium", "baja": "low"}


def a_sigma(regla: dict) -> dict:
    """Convierte una regla propia a un dict con la estructura de una regla Sigma."""
    tags = ["ics.modbus"]
    if regla.get("attack_id"):
        tags.append(f"attack.{regla['attack_id'].lower()}")

    return {
        "title": regla["nombre"],
        "id": regla["id"],
        "status": "experimental",
        "description": regla.get("descripcion", ""),
        "logsource": {"product": "ics", "service": "modbus"},
        "detection": {
            "seleccion": {"tipo_regla": regla["tipo"]},
            "condition": "seleccion",
        },
        "level": _SEVERIDAD_SIGMA.get(regla["severidad"], "medium"),
        "tags": tags,
    }


def exportar(dir_salida: str) -> list[str]:
    os.makedirs(dir_salida, exist_ok=True)
    rutas = []
    for regla in cargar_reglas():
        doc = a_sigma(regla)
        ruta = os.path.join(dir_salida, f"{regla['id'].lower()}.yml")
        with open(ruta, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
        rutas.append(ruta)
    return rutas


def main() -> None:
    ap = argparse.ArgumentParser(description="Exporta las reglas del IDS a formato Sigma.")
    ap.add_argument("--salida", default="sigma")
    args = ap.parse_args()
    for ruta in exportar(args.salida):
        print(f"[OK] {ruta}")


if __name__ == "__main__":
    main()
