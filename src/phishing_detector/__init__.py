"""Detector de patrones de phishing en correos electronicos."""

from .detector import ResultadoAnalisis, analizar_correo

__all__ = ["analizar_correo", "ResultadoAnalisis"]
__version__ = "0.1.0"
