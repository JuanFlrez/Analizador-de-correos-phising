"""
Bases de conocimiento usadas por el detector: palabras clave por categoria,
extensiones de adjuntos sospechosas y acortadores de URL conocidos.

Mantener estas listas en un modulo aparte permite ampliarlas o ajustarlas
(por ejemplo, agregar nuevas categorias o idiomas) sin tocar la logica de
analisis en detector.py.
"""

# Cada categoria tiene un peso (que tan fuerte es el indicio de phishing)
# y una lista de frases/palabras en minusculas y sin tildes.
CATEGORIAS_PALABRAS_CLAVE = {
    "urgencia": {
        "peso": 2,
        "palabras": [
            "urgente", "inmediatamente", "accion requerida", "accion inmediata",
            "ultima advertencia", "cuenta suspendida", "cuenta bloqueada",
            "expira hoy", "expira en", "plazo limite", "actua ahora",
            "verificacion requerida", "confirmar ahora", "dentro de 24 horas",
            "sera desactivada", "sera eliminada",
        ],
    },
    "credenciales": {
        "peso": 3,
        "palabras": [
            "contraseña", "clave de acceso", "usuario y contraseña",
            "verificar su cuenta", "confirmar su cuenta", "actualizar sus datos",
            "inicie sesion aqui", "ingrese sus credenciales",
            "numero de tarjeta", "codigo de seguridad", "cvv", "pin",
            "numero de cuenta", "datos bancarios", "actualizar informacion de pago",
        ],
    },
    "amenaza_financiera": {
        "peso": 2,
        "palabras": [
            "premio", "ha ganado", "transferencia pendiente", "reembolso",
            "factura adjunta", "pago rechazado", "deuda pendiente",
            "cargo no autorizado", "reclame su premio", "loteria",
        ],
    },
    "saludo_generico": {
        "peso": 1,
        "palabras": [
            "estimado cliente", "estimado usuario", "querido cliente",
            "dear customer", "dear user", "apreciado usuario",
        ],
    },
    "suplantacion_autoridad": {
        "peso": 2,
        "palabras": [
            "departamento de seguridad", "soporte tecnico", "administrador del sistema",
            "equipo de seguridad", "servicio al cliente oficial", "banco central",
        ],
    },
}

EXTENSIONES_SOSPECHOSAS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".zip.exe", ".hta",
]

ACORTADORES_URL = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
]
