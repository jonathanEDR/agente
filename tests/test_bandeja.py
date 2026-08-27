"""Pruebas de la bandeja del sistema y del arranque en modo servidor.

No abre un ícono real ni un navegador: eso es integración con el sistema
operativo y no tiene sentido automatizarlo. Lo que se prueba es la lógica
que rodea eso — que el ícono se pueda dibujar, y que
`agente.crear_servidor()` arme el mismo `FastAPI` que ya usan el resto de
los tests.
"""

from __future__ import annotations

from dataclasses import replace

from sunat import bandeja
from sunat.agente import crear_servidor
from sunat.config import Config


def test_el_icono_es_una_imagen_valida():
    img = bandeja._icono()
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_crear_servidor_arma_el_mismo_app(tmp_path):
    cfg = replace(Config(data_dir=tmp_path), api_url="")
    servidor = crear_servidor(cfg, puerto=17999)

    rutas = {r.path for r in servidor.config.app.routes}
    assert "/api/handshake" in rutas
    assert "/api/estado" in rutas
    assert servidor.config.port == 17999


def test_crear_servidor_funciona_sin_stdout(tmp_path, monkeypatch):
    """Regresión: el `.exe` --windowed corre con sys.stdout/stderr en None
    cuando se abre con doble clic desde el Explorador (no cuando se lanza
    desde una terminal, que hereda un stream real aunque esté oculta).

    Sin `log_config=None` en `uvicorn.Config`, esto fallaba con
    `ValueError: Unable to configure formatter 'default'`: uvicorn arma su
    propio logging con color y llama `.isatty()` sobre stdout/stderr para
    decidir si lo soporta, y `None.isatty()` revienta. El síntoma en
    Windows era un diálogo de "El agente no pudo iniciar" en el primer
    doble clic real, que ninguna prueba lanzada desde una terminal —donde
    stdout siempre existe— podía reproducir.
    """
    monkeypatch.setattr("sys.stdout", None)
    monkeypatch.setattr("sys.stderr", None)

    cfg = replace(Config(data_dir=tmp_path), api_url="")
    crear_servidor(cfg, puerto=17996)  # no debe lanzar


def test_arranque_respeta_sunat_sin_bandeja(monkeypatch):
    from sunat import arranque

    monkeypatch.setenv("SUNAT_SIN_BANDEJA", "1")
    assert arranque._quiere_bandeja() is False


def test_arranque_usa_bandeja_por_defecto(monkeypatch):
    from sunat import arranque

    monkeypatch.delenv("SUNAT_SIN_BANDEJA", raising=False)
    # pystray esta instalado en el entorno de pruebas, asi que por defecto
    # se intenta la bandeja.
    assert arranque._quiere_bandeja() is True
