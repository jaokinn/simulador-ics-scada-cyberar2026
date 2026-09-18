"""Contratos de datos tipados del simulador (Bloque A, Pasos 2-3).

Ver SPEC.md secciones 2 y 3 para el significado de cada campo.
"""

from enum import Enum

from pydantic import BaseModel, Field


class EscalaGobierno(str, Enum):
    MUNICIPAL = "municipal"
    PROVINCIAL = "provincial"
    NACIONAL = "nacional"


class TipoAtaque(str, Enum):
    SCAN = "scan"
    ESCRITURA_ILEGITIMA = "escritura_ilegitima"
    REPLAY = "replay"
    SPOOFING = "spoofing"
    FLOOD = "flood"


class CriticidadObjetivo(str, Enum):
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"


class Sofisticacion(str, Enum):
    RUIDOSO = "ruidoso"
    MEDIO = "medio"
    SIGILOSO = "sigiloso"


class PerfilJurisdiccion(BaseModel):
    """Caracteriza a quién se defiende (SPEC.md sección 3).

    Siempre se instancia con valores placeholder — nunca datos reales de una
    jurisdicción concreta. `fuente` cita de dónde sale cada indicador cuantitativo.
    """

    escala_gobierno: EscalaGobierno
    poblacion: int = Field(gt=0)
    poblacion_fuente: str
    dependencias_criticas: list[str] = Field(
        description="Ej: energia, agua, accesos. Cada una instancia un PLC virtual propio."
    )
    nivel_digitalizacion: int = Field(ge=1, le=5)
    nivel_digitalizacion_fuente: str
    presupuesto_ciberseguridad: int = Field(ge=1, le=5)
    presupuesto_ciberseguridad_fuente: str
    marco_normativo_vigente: bool


class Escenario(BaseModel):
    """Las 5 variables de escenario (SPEC.md sección 2).

    Los campos numéricos mapean directamente a un valor usable por pymodbus/scapy
    (paquetes por segundo), no a una etiqueta cualitativa.
    """

    tipos_ataque: list[TipoAtaque] = Field(min_length=1)
    intensidad_pps: int = Field(gt=0, description="Paquetes por segundo del ataque.")
    criticidad_objetivo: CriticidadObjetivo
    sofisticacion: Sofisticacion
    ruido_fondo_pps: int = Field(
        ge=0, description="Paquetes por segundo de tráfico legítimo simultáneo."
    )
