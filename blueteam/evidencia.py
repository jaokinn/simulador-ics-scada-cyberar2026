"""Cadena de evidencia — log encadenado por hash (tamper-evident) de cada
detección (Bloque E — integridad).

Cada entrada incluye el hash de la anterior (estilo blockchain liviano): si
alguien altera un registro después de generado, la cadena deja de verificar.
Responde al criterio transversal de criptografía del jurado sin agregar
lógica de negocio nueva. Determinístico, sin dependencias externas (solo
hashlib de stdlib).
"""

import hashlib
import json
import time

GENESIS = "0" * 64


class CadenaEvidencia:
    """Log append-only encadenado por SHA-256. verificar() detecta cualquier alteración."""

    def __init__(self):
        self._entradas: list[dict] = []

    @property
    def entradas(self) -> list[dict]:
        return list(self._entradas)

    def _hash_anterior(self) -> str:
        return self._entradas[-1]["hash"] if self._entradas else GENESIS

    @staticmethod
    def _calcular_hash(indice: int, timestamp: float, dato: dict, hash_anterior: str) -> str:
        cuerpo = json.dumps(
            {"indice": indice, "timestamp": timestamp, "dato": dato, "prev": hash_anterior},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()

    def agregar(self, dato: dict, timestamp: float | None = None) -> dict:
        """Agrega una entrada (ej. una detección o una mitigación) a la cadena."""
        indice = len(self._entradas)
        ts = timestamp if timestamp is not None else time.time()
        prev = self._hash_anterior()
        h = self._calcular_hash(indice, ts, dato, prev)
        entrada = {"indice": indice, "timestamp": ts, "dato": dato, "prev": prev, "hash": h}
        self._entradas.append(entrada)
        return entrada

    def verificar(self) -> bool:
        """Recalcula toda la cadena; devuelve False si alguna entrada fue alterada."""
        prev = GENESIS
        for e in self._entradas:
            esperado = self._calcular_hash(e["indice"], e["timestamp"], e["dato"], prev)
            if esperado != e["hash"] or e["prev"] != prev:
                return False
            prev = e["hash"]
        return True

    def exportar_json(self, ruta: str) -> None:
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(self._entradas, f, indent=2, default=str)
