"""Generador determinístico de escenarios (Bloque B, Pasos 7-8).

Combina un PerfilJurisdiccion con un preset de dificultad en un Escenario final,
por reglas explícitas — sin aleatoriedad ni llamadas a IA (SPEC.md sección 1:
"la IA nunca decide parámetros técnicos").

Reglas de combinación fijadas en SPEC.md sección 3.1: la escala_gobierno del
perfil manda sobre cualquier otra variable, aunque el preset de dificultad pida
más. Los valores del techo de abajo son la misma propuesta de arranque marcada
TODO(equipo) en SPEC.md — no un valor cerrado.
"""

from pathlib import Path

import yaml

from core.schemas import CriticidadObjetivo, Escenario, EscalaGobierno, PerfilJurisdiccion

_PRESETS_PATH = Path(__file__).resolve().parent.parent / "config" / "presets_dificultad.yaml"

_CRITICIDAD_ORDEN = [CriticidadObjetivo.BAJA, CriticidadObjetivo.MEDIA, CriticidadObjetivo.ALTA]

# Techo de superficie de ataque permitido por escala de gobierno (SPEC.md 3.1).
_TECHO_SUPERFICIE = {
    EscalaGobierno.MUNICIPAL: {
        "max_tipos_ataque": 3,
        "criticidad_tope": CriticidadObjetivo.MEDIA,
    },
    EscalaGobierno.PROVINCIAL: {
        "max_tipos_ataque": 4,
        "criticidad_tope": CriticidadObjetivo.ALTA,
    },
    EscalaGobierno.NACIONAL: {
        "max_tipos_ataque": 5,
        "criticidad_tope": CriticidadObjetivo.ALTA,
    },
}


def _cargar_presets() -> dict:
    with _PRESETS_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def generar_escenario(perfil: PerfilJurisdiccion, dificultad: str) -> Escenario:
    """Genera un Escenario combinando `perfil` y el preset `dificultad`.

    100% determinística: la misma entrada produce siempre la misma salida.
    Recorta tipos_ataque y criticidad_objetivo del preset para que nunca superen
    lo que la escala_gobierno y las dependencias_criticas reales del perfil
    permiten (reglas en SPEC.md sección 3.1).
    """
    presets = _cargar_presets()
    if dificultad not in presets:
        raise ValueError(f"Dificultad desconocida: {dificultad!r}. Opciones: {sorted(presets)}")

    escenario = Escenario.model_validate(presets[dificultad])
    techo = _TECHO_SUPERFICIE[perfil.escala_gobierno]

    # Regla 1: no encadenar más tipos de ataque que dependencias críticas reales
    # tenga el perfil, ni más que el techo de su escala de gobierno.
    max_tipos = min(techo["max_tipos_ataque"], len(perfil.dependencias_criticas))
    max_tipos = max(max_tipos, 1)  # todo perfil admite al menos 1 tipo de ataque
    tipos_recortados = escenario.tipos_ataque[:max_tipos]

    # Regla 2: la criticidad del objetivo nunca supera el tope de la escala de
    # gobierno, aunque el preset de dificultad pida más.
    criticidad_recortada = min(
        escenario.criticidad_objetivo,
        techo["criticidad_tope"],
        key=_CRITICIDAD_ORDEN.index,
    )

    return escenario.model_copy(
        update={
            "tipos_ataque": tipos_recortados,
            "criticidad_objetivo": criticidad_recortada,
        }
    )


def validar_coherencia(escenario: Escenario, perfil: PerfilJurisdiccion) -> bool:
    """Rechaza cualquier escenario cuya superficie de ataque supere lo que la
    escala_gobierno del perfil permite (SPEC.md sección 3.1).

    Devuelve True si el escenario es coherente; lanza ValueError con el detalle
    de qué regla se violó en caso contrario.
    """
    techo = _TECHO_SUPERFICIE[perfil.escala_gobierno]

    if len(escenario.tipos_ataque) > techo["max_tipos_ataque"]:
        raise ValueError(
            f"Escenario inválido para perfil {perfil.escala_gobierno.value}: "
            f"{len(escenario.tipos_ataque)} tipos de ataque encadenados supera el "
            f"techo de {techo['max_tipos_ataque']} para esta escala de gobierno."
        )

    if len(escenario.tipos_ataque) > len(perfil.dependencias_criticas):
        raise ValueError(
            f"Escenario inválido: {len(escenario.tipos_ataque)} tipos de ataque "
            f"supera las {len(perfil.dependencias_criticas)} dependencias críticas "
            "reales del perfil."
        )

    if _CRITICIDAD_ORDEN.index(escenario.criticidad_objetivo) > _CRITICIDAD_ORDEN.index(
        techo["criticidad_tope"]
    ):
        raise ValueError(
            f"Escenario inválido para perfil {perfil.escala_gobierno.value}: "
            f"criticidad_objetivo={escenario.criticidad_objetivo.value} supera el "
            f"tope {techo['criticidad_tope'].value} para esta escala de gobierno."
        )

    return True
