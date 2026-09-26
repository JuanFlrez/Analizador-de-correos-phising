"""
Interfaz de linea de comandos del detector de phishing.

Ejemplos de uso:
    phishing-detector --demo
    phishing-detector --eml correo_sospechoso.eml
    phishing-detector --asunto "Urgente" --cuerpo "Verifique su cuenta..."
    phishing-detector --eml correo.eml --json
"""

from __future__ import annotations

import argparse
import email
import json
import sys
from email.policy import default as email_default_policy

from .detector import ResultadoAnalisis, analizar_correo


def _extraer_de_eml(ruta: str) -> dict:
    with open(ruta, "rb") as f:
        mensaje = email.message_from_binary_file(f, policy=email_default_policy)

    asunto = mensaje.get("subject", "") or ""
    remitente = mensaje.get("from", "") or ""

    cuerpo = ""
    if mensaje.is_multipart():
        for parte in mensaje.walk():
            if parte.get_content_type() == "text/plain":
                cuerpo = parte.get_content()
                break
    else:
        cuerpo = mensaje.get_content()

    adjuntos = [
        parte.get_filename()
        for parte in mensaje.iter_attachments()
        if parte.get_filename()
    ]

    return {"asunto": asunto, "cuerpo": cuerpo, "remitente": remitente, "adjuntos": adjuntos}


def _imprimir_reporte_texto(resultado: ResultadoAnalisis) -> None:
    print("=" * 60)
    print(f"Puntaje total de riesgo: {resultado.puntaje}")
    print(f"Nivel de riesgo: {resultado.nivel_riesgo}")
    print("-" * 60)
    if not resultado.coincidencias:
        print("No se detectaron patrones sospechosos.")
    else:
        for categoria, hallazgos in resultado.coincidencias.items():
            print(f"[{categoria}]")
            for hallazgo in hallazgos:
                print(f"   - {hallazgo}")
    print("=" * 60)


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Detecta patrones de phishing en el texto de un correo.",
    )
    parser.add_argument("--eml", metavar="ARCHIVO", help="Ruta a un archivo .eml a analizar")
    parser.add_argument("--asunto", default="", help="Asunto del correo")
    parser.add_argument("--cuerpo", default="", help="Cuerpo del correo")
    parser.add_argument("--remitente", default="", help="Direccion del remitente")
    parser.add_argument("--dominio-esperado", default="", help="Dominio oficial esperado del remitente")
    parser.add_argument("--demo", action="store_true", help="Ejecuta con un correo de ejemplo")
    parser.add_argument("--json", action="store_true", help="Imprime el resultado en formato JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)

    if args.demo:
        datos = {
            "asunto": "URGENTE: Verificacion requerida de su cuenta",
            "cuerpo": (
                "Estimado cliente, hemos detectado actividad inusual. "
                "Su cuenta sera suspendida en 24 horas si no confirma sus datos. "
                "Ingrese sus credenciales aqui: http://192.168.45.12/verificacion-banco-seguro"
            ),
            "remitente": "soporte@paypa1-seguridad.com",
            "adjuntos": ["factura_urgente.pdf.exe"],
        }
        dominio_esperado = "paypal.com"
    elif args.eml:
        datos = _extraer_de_eml(args.eml)
        dominio_esperado = args.dominio_esperado
    elif args.asunto or args.cuerpo:
        datos = {
            "asunto": args.asunto,
            "cuerpo": args.cuerpo,
            "remitente": args.remitente,
            "adjuntos": [],
        }
        dominio_esperado = args.dominio_esperado
    else:
        parser.print_help()
        return 1

    resultado = analizar_correo(
        asunto=datos["asunto"],
        cuerpo=datos["cuerpo"],
        remitente=datos.get("remitente", ""),
        dominio_esperado=dominio_esperado,
        adjuntos=datos.get("adjuntos"),
    )

    if args.json:
        print(json.dumps(resultado.to_dict(), ensure_ascii=False, indent=2))
    else:
        _imprimir_reporte_texto(resultado)

    return 0


if __name__ == "__main__":
    sys.exit(main())
