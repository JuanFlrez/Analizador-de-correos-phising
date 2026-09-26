"""
Logica principal del detector de phishing.

Expone la funcion `analizar_correo`, que recibe los datos de un correo
(asunto, cuerpo, remitente, dominio esperado, adjuntos) y devuelve un
objeto ResultadoAnalisis con el puntaje de riesgo y los hallazgos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .patterns import ACORTADORES_URL, CATEGORIAS_PALABRAS_CLAVE, EXTENSIONES_SOSPECHOSAS

# ---------------------------------------------------------------------------
# Expresiones regulares
# ---------------------------------------------------------------------------

REGEX_URL = re.compile(r"https?://[^\s\)\]\"'<>]+", re.IGNORECASE)
REGEX_IP_EN_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
REGEX_CORREO = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
REGEX_EXCESO_SIGNOS = re.compile(r"[!?]{2,}")
REGEX_MAYUSCULAS_SEGUIDAS = re.compile(r"\b[A-Z]{5,}\b")
REGEX_ADJUNTO = re.compile(
    r"[\w\-. ]+(" + "|".join(re.escape(ext) for ext in EXTENSIONES_SOSPECHOSAS) + r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Resultado del analisis
# ---------------------------------------------------------------------------

@dataclass
class ResultadoAnalisis:
    puntaje: int = 0
    nivel_riesgo: str = "Ninguno"
    coincidencias: dict[str, list[str]] = field(default_factory=dict)

    def agregar(self, categoria: str, hallazgo: str, peso: int) -> None:
        self.coincidencias.setdefault(categoria, []).append(hallazgo)
        self.puntaje += peso

    def to_dict(self) -> dict:
        return {
            "puntaje": self.puntaje,
            "nivel_riesgo": self.nivel_riesgo,
            "coincidencias": self.coincidencias,
        }


# ---------------------------------------------------------------------------
# Funciones de analisis internas
# ---------------------------------------------------------------------------

def _normalizar_texto(texto: str) -> str:
    texto = texto.lower()
    reemplazos = {"á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u", "ñ": "n"}
    for original, plano in reemplazos.items():
        texto = texto.replace(original, plano)
    return texto


def _analizar_palabras_clave(texto_normalizado: str, resultado: ResultadoAnalisis) -> None:
    for categoria, datos in CATEGORIAS_PALABRAS_CLAVE.items():
        for palabra in datos["palabras"]:
            if palabra in texto_normalizado:
                resultado.agregar(categoria, palabra, datos["peso"])


def _analizar_urls(texto: str, resultado: ResultadoAnalisis) -> None:
    for url in REGEX_URL.findall(texto):
        if REGEX_IP_EN_URL.match(url):
            resultado.agregar("url_sospechosa", f"URL con IP directa: {url}", 3)
        if any(acortador in url.lower() for acortador in ACORTADORES_URL):
            resultado.agregar("url_sospechosa", f"URL acortada: {url}", 2)
        if url.count("-") >= 3 or url.count(".") >= 4:
            resultado.agregar("url_sospechosa", f"URL con estructura inusual: {url}", 1)


def _analizar_remitente(remitente: str, dominio_esperado: str, resultado: ResultadoAnalisis) -> None:
    coincidencia = REGEX_CORREO.search(remitente)
    if not coincidencia:
        return
    dominio_remitente = coincidencia.group(0).split("@")[-1].lower()
    if dominio_esperado and dominio_remitente != dominio_esperado.lower():
        resultado.agregar(
            "remitente_sospechoso",
            f"Dominio '{dominio_remitente}' no coincide con el esperado '{dominio_esperado}'",
            3,
        )


def _analizar_estilo(texto: str, resultado: ResultadoAnalisis) -> None:
    if REGEX_EXCESO_SIGNOS.search(texto):
        resultado.agregar("estilo_sospechoso", "Uso excesivo de !! o ??", 1)
    mayus = REGEX_MAYUSCULAS_SEGUIDAS.findall(texto)
    if len(mayus) >= 2:
        resultado.agregar("estilo_sospechoso", f"Multiples palabras en mayusculas: {mayus}", 1)


def _analizar_adjuntos(nombres_adjuntos: Optional[Iterable[str]], resultado: ResultadoAnalisis) -> None:
    for nombre in nombres_adjuntos or []:
        if REGEX_ADJUNTO.search(nombre):
            resultado.agregar("adjunto_sospechoso", nombre, 3)


def _calcular_nivel_riesgo(puntaje: int) -> str:
    if puntaje >= 8:
        return "Alto"
    if puntaje >= 4:
        return "Medio"
    if puntaje >= 1:
        return "Bajo"
    return "Ninguno"


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

def analizar_correo(
    asunto: str,
    cuerpo: str,
    remitente: str = "",
    dominio_esperado: str = "",
    adjuntos: Optional[Iterable[str]] = None,
) -> ResultadoAnalisis:
    """Analiza un correo y devuelve un ResultadoAnalisis con puntaje,
    nivel de riesgo y el detalle de los hallazgos por categoria."""
    resultado = ResultadoAnalisis()
    texto_completo = f"{asunto}\n{cuerpo}"
    texto_normalizado = _normalizar_texto(texto_completo)

    _analizar_palabras_clave(texto_normalizado, resultado)
    _analizar_urls(texto_completo, resultado)
    _analizar_estilo(texto_completo, resultado)
    if remitente:
        _analizar_remitente(remitente, dominio_esperado, resultado)
    if adjuntos:
        _analizar_adjuntos(adjuntos, resultado)

    resultado.nivel_riesgo = _calcular_nivel_riesgo(resultado.puntaje)
    return resultado
