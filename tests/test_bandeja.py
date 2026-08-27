"""Pruebas de la bandeja del sistema y del arranque en modo servidor.

No abre un ícono real ni un navegador: eso es integración con el sistema
operativo y no tiene sentido automatizarlo. Lo que se prueba es la lógica
que rodea eso — que el ícono se pueda dibujar, que ocultar/mostrar la
consola no reviente cuando no hay consola (el caso normal bajo pytest), y
que `agente.crear_servidor()` arme el mismo `FastAPI` que ya usan el resto
de los tests.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sunat import bandeja
from sunat.agente import crear_servidor
from sunat.config import Config


def test_el_icono_es_una_imagen_valida():
    img = bandeja._icono()
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_ocultar_consola_no_revienta_sin_consola():
    # Bajo pytest normalmente no hay consola propia (GetConsoleWindow
    # devuelve 0), que es justo el caso que este código tiene que tolerar.
    bandeja.ocultar_consola()
    bandeja.mostrar_consola()


def test_crear_servidor_arma_el_mismo_app(tmp_path):
    cfg = replace(Config(data_dir=tmp_path), api_url="")
    servidor = crear_servidor(cfg, puerto=17999)

    rutas = {r.path for r in servidor.config.app.routes}
    assert "/api/handshake" in rutas
    assert "/api/estado" in rutas
    assert servidor.config.port == 17999


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
