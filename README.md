# Phishing Detector

Detector de patrones de phishing en correos electronicos, basado en reglas:
palabras clave por categoria, expresiones regulares sobre URLs, comparacion
de dominio del remitente y deteccion de adjuntos con extensiones de riesgo.

Proyecto academico de ciberseguridad, pensado tambien como pieza de
portafolio.

## Caracteristicas

- Deteccion de frases asociadas a **urgencia**, **solicitud de credenciales**,
  **amenazas financieras**, **saludos genericos** y **suplantacion de
  autoridad**.
- Analisis de URLs: direcciones IP directas, acortadores conocidos y
  estructuras inusuales.
- Comparacion del dominio del remitente contra un dominio oficial esperado
  (detecta dominios "look-alike", ej. `paypa1.com` vs `paypal.com`).
- Deteccion de adjuntos con extensiones de riesgo (`.exe`, `.scr`, `.js`,
  etc.).
- Sistema de puntuacion ponderado con niveles de riesgo: Ninguno, Bajo,
  Medio, Alto.
- Lectura directa de archivos `.eml`.
- CLI (`phishing-detector`) con salida en texto o JSON.
- Suite de pruebas con `pytest` e integracion continua con GitHub Actions.

## Instalacion

```bash
git clone <url-del-repo>
cd phishing-detector
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Uso

### Como CLI

```bash
# Correo de ejemplo
phishing-detector --demo

# Analizar un archivo .eml
phishing-detector --eml correo_sospechoso.eml --dominio-esperado paypal.com

# Pasar texto directamente
phishing-detector --asunto "Urgente" --cuerpo "Verifique su cuenta aqui: http://192.168.1.1"

# Salida en JSON (util para integrarlo con otras herramientas)
phishing-detector --demo --json
```

### Como aplicacion web

```bash
pip install -e ".[web]"
flask --app wsgi run --debug
```

Abre `http://127.0.0.1:5000`, pega el correo (o carga el ejemplo con el
boton de la pagina) y obten el reporte de riesgo.

Para produccion (ej. Render, Railway):

```bash
gunicorn wsgi:app
```

### Como libreria en Python

```python
from phishing_detector import analizar_correo

resultado = analizar_correo(
    asunto="URGENTE: Verificacion requerida",
    cuerpo="Su cuenta sera suspendida. Ingrese sus credenciales aqui: http://192.168.1.1",
    remitente="soporte@paypa1-seguridad.com",
    dominio_esperado="paypal.com",
    adjuntos=["factura.pdf.exe"],
)

print(resultado.puntaje)        # ej. 15
print(resultado.nivel_riesgo)   # "Alto"
print(resultado.coincidencias)  # dict con los hallazgos por categoria
```

## Ejecutar los tests

```bash
pytest -v
```

## Estructura del proyecto

```
phishing-detector/
├── src/phishing_detector/
│   ├── __init__.py       # API publica (analizar_correo)
│   ├── patterns.py        # Palabras clave, extensiones y acortadores
│   ├── detector.py        # Logica de analisis y scoring
│   ├── cli.py              # Interfaz de linea de comandos
│   └── web/                 # Aplicacion web (Flask)
│       ├── __init__.py       # application factory
│       ├── routes.py          # rutas: formulario y reporte
│       ├── templates/
│       └── static/style.css
├── tests/
│   └── test_detector.py
├── .github/workflows/
│   └── tests.yml           # CI: corre pytest en cada push/PR
├── wsgi.py                  # punto de entrada para desplegar la web
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## Roadmap / posibles mejoras

- [ ] Exportar reportes a PDF o CSV
- [ ] Integracion con una API de reputacion de dominios/IPs
- [ ] Soporte para analizar bandejas de entrada completas (IMAP)
- [ ] Ajuste de pesos mediante un archivo de configuracion externo

## Licencia

MIT — ver [LICENSE](LICENSE).
