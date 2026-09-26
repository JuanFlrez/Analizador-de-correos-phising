"""Fabrica de la aplicacion web (patron application factory de Flask)."""

from __future__ import annotations

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    from .routes import bp as routes_bp

    app.register_blueprint(routes_bp)
    return app
