from phishing_detector import analizar_correo


def test_correo_limpio_no_genera_alertas():
    resultado = analizar_correo(
        asunto="Reunion de equipo manana",
        cuerpo="Hola, recordemos la reunion de manana a las 10am. Saludos.",
    )
    assert resultado.puntaje == 0
    assert resultado.nivel_riesgo == "Ninguno"


def test_detecta_palabras_de_urgencia():
    resultado = analizar_correo(
        asunto="Accion requerida",
        cuerpo="Su cuenta sera suspendida si no actua ahora.",
    )
    assert "urgencia" in resultado.coincidencias
    assert resultado.puntaje > 0


def test_detecta_solicitud_de_credenciales():
    resultado = analizar_correo(
        asunto="Verificacion de cuenta",
        cuerpo="Por favor ingrese sus credenciales para verificar su cuenta.",
    )
    assert "credenciales" in resultado.coincidencias


def test_detecta_url_con_ip():
    resultado = analizar_correo(
        asunto="Aviso",
        cuerpo="Ingrese aqui: http://192.168.1.10/login",
    )
    assert "url_sospechosa" in resultado.coincidencias


def test_detecta_url_acortada():
    resultado = analizar_correo(
        asunto="Aviso",
        cuerpo="Revise esto: http://bit.ly/abc123",
    )
    assert "url_sospechosa" in resultado.coincidencias


def test_detecta_dominio_remitente_no_coincide():
    resultado = analizar_correo(
        asunto="Hola",
        cuerpo="Contenido normal.",
        remitente="soporte@paypa1-seguridad.com",
        dominio_esperado="paypal.com",
    )
    assert "remitente_sospechoso" in resultado.coincidencias


def test_dominio_remitente_correcto_no_genera_alerta():
    resultado = analizar_correo(
        asunto="Hola",
        cuerpo="Contenido normal.",
        remitente="soporte@paypal.com",
        dominio_esperado="paypal.com",
    )
    assert "remitente_sospechoso" not in resultado.coincidencias


def test_detecta_adjunto_sospechoso():
    resultado = analizar_correo(
        asunto="Factura",
        cuerpo="Revise el adjunto.",
        adjuntos=["factura.pdf.exe"],
    )
    assert "adjunto_sospechoso" in resultado.coincidencias


def test_nivel_riesgo_alto_para_correo_muy_sospechoso():
    resultado = analizar_correo(
        asunto="URGENTE: Verificacion requerida",
        cuerpo=(
            "Estimado cliente, su cuenta sera suspendida. "
            "Ingrese sus credenciales aqui: http://192.168.1.1/login"
        ),
        remitente="soporte@paypa1.com",
        dominio_esperado="paypal.com",
        adjuntos=["factura.exe"],
    )
    assert resultado.nivel_riesgo == "Alto"
