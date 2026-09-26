"""Rutas de la aplicacion web."""

from __future__ import annotations

from flask import Blueprint, render_template, request

from ..detector import analizar_correo

bp = Blueprint("routes", __name__)

# Clase CSS por nivel de riesgo, usada en la plantilla de resultado
CLASE_POR_NIVEL = {
    "Ninguno": "nivel-ninguno",
    "Bajo": "nivel-bajo",
    "Medio": "nivel-medio",
    "Alto": "nivel-alto",
}

# Etiquetas legibles para cada categoria de hallazgo
ETIQUETAS_CATEGORIA = {
    "urgencia": "Lenguaje de urgencia",
    "credenciales": "Solicitud de credenciales",
    "amenaza_financiera": "Senuelo financiero",
    "saludo_generico": "Saludo generico",
    "suplantacion_autoridad": "Suplantacion de autoridad",
    "url_sospechosa": "URL sospechosa",
    "remitente_sospechoso": "Remitente sospechoso",
    "estilo_sospechoso": "Estilo de escritura sospechoso",
    "adjunto_sospechoso": "Adjunto de riesgo",
}


@bp.route("/", methods=["GET"])
def inicio():
    return render_template("index.html")


@bp.route("/analizar", methods=["POST"])
def analizar():
    asunto = request.form.get("asunto", "")
    cuerpo = request.form.get("cuerpo", "")
    remitente = request.form.get("remitente", "")
    dominio_esperado = request.form.get("dominio_esperado", "")
    adjuntos_raw = request.form.get("adjuntos", "")
    adjuntos = [a.strip() for a in adjuntos_raw.split(",") if a.strip()]

    resultado = analizar_correo(
        asunto=asunto,
        cuerpo=cuerpo,
        remitente=remitente,
        dominio_esperado=dominio_esperado,
        adjuntos=adjuntos,
    )

    return render_template(
        "resultado.html",
        resultado=resultado,
        clase_nivel=CLASE_POR_NIVEL.get(resultado.nivel_riesgo, "nivel-ninguno"),
        etiquetas=ETIQUETAS_CATEGORIA,
        datos_entrada={
            "asunto": asunto,
            "cuerpo": cuerpo,
            "remitente": remitente,
            "dominio_esperado": dominio_esperado,
            "adjuntos": adjuntos_raw,
        },
    )
