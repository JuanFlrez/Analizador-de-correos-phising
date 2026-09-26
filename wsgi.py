"""
Punto de entrada WSGI para desplegar la aplicacion web.

Desarrollo local:
    flask --app wsgi run --debug

Produccion (ej. gunicorn):
    gunicorn wsgi:app
"""

from phishing_detector.web import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
