"""Metadatos de las reglas de detección del IDS (Bloque E, Paso 19).

IDs y nombres alineados a propósito con `blue_team/reglas.yaml` del otro
backend del equipo (OPCION-B-SIMULADOR-ICS) para que ambos proyectos hablen
el mismo lenguaje de reglas — permite exportar a Sigma (blueteam/export_sigma.py)
con IDs reconocibles y consistentes entre ambas implementaciones.

`attack_id` es la técnica MITRE ATT&CK for ICS verificada más cercana
(ver el research del equipo, Parte C §10) — v19.2, no un ID inventado.
"""

REGLAS = [
    {
        "id": "R-RANGO-001",
        "nombre": "Escritura fuera de rango seguro",
        "tipo": "rango",
        "severidad": "alta",
        "descripcion": "Un write cuyo valor cae fuera del rango válido del registro es sospechoso.",
        "attack_id": "T0836",  # Modify Parameter (Impair Process Control)
    },
    {
        "id": "R-ALLOW-001",
        "nombre": "Dirección de origen no permitida",
        "tipo": "allowlist",
        "severidad": "alta",
        "descripcion": "Tráfico Modbus de escritura desde una IP que no está en la whitelist de HMIs autorizados.",
        "attack_id": "T0848",  # Rogue Master (Initial Access)
    },
    {
        "id": "R-RITMO-001",
        "nombre": "Ritmo anómalo (pico sobre el polling base)",
        "tipo": "ritmo",
        "severidad": "media",
        "descripcion": "Volumen de paquetes Modbus muy por encima del baseline de ruido de fondo.",
        "attack_id": "T0814",  # Denial of Service (Inhibit Response Function)
    },
]


def cargar_reglas() -> list[dict]:
    return REGLAS
