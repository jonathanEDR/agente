"""Pruebas del arranque para el .exe empaquetado.

No compilan nada ni lanzan Chromium — eso ya se verificó a mano, una vez
por plataforma, con `packaging/build.py`. Lo que se prueba aquí es la
lógica pura: dónde busca el navegador y cómo decide si ya está.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def modulo(monkeypatch):
    """Reimporta `arranque` con LOCALAPPDATA controlado por el test.

    Hace falta reimportar y no solo parchear la variable ya calculada:
    `_RUTA_NAVEGADORES` se fija una vez, al importar el módulo, que es
    justo el comportamiento que se está probando.
    """
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.delenv("SUNAT_BROWSERS_PATH", raising=False)
    import sunat.arranque as m

    return importlib.reload(m)


def test_usa_localappdata_por_defecto(modulo, monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    m = importlib.reload(modulo)
    assert m._cache_navegadores() == tmp_path / "ms-playwright"


def test_sunat_browsers_path_gana_sobre_localappdata(modulo, monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "otro"))
    monkeypatch.setenv("SUNAT_BROWSERS_PATH", str(tmp_path / "elegido"))
    m = importlib.reload(modulo)
    assert m._cache_navegadores() == tmp_path / "elegido"


def test_fija_playwright_browsers_path_al_importar(modulo):
    import os

    # La razón de ser de este módulo: que Playwright busque en la MISMA
    # carpeta sin importar si corre desde un venv o desde el .exe.
    assert os.environ["PLAYWRIGHT_BROWSERS_PATH"] == str(modulo._RUTA_NAVEGADORES)


def test_no_instalado_si_la_carpeta_no_existe(modulo, tmp_path, monkeypatch):
    monkeypatch.setattr(modulo, "_RUTA_NAVEGADORES", tmp_path / "no-existe")
    assert modulo._chromium_instalado() is False


def test_no_instalado_si_la_carpeta_esta_vacia(modulo, tmp_path, monkeypatch):
    monkeypatch.setattr(modulo, "_RUTA_NAVEGADORES", tmp_path)
    assert modulo._chromium_instalado() is False


def test_instalado_si_hay_una_carpeta_chromium(modulo, tmp_path, monkeypatch):
    (tmp_path / "chromium-1234").mkdir()
    monkeypatch.setattr(modulo, "_RUTA_NAVEGADORES", tmp_path)
    assert modulo._chromium_instalado() is True


def test_ignora_carpetas_que_no_son_chromium(modulo, tmp_path, monkeypatch):
    # ffmpeg-1011, winldd-1007: existen en la misma caché y no cuentan.
    (tmp_path / "ffmpeg-1011").mkdir()
    monkeypatch.setattr(modulo, "_RUTA_NAVEGADORES", tmp_path)
    assert modulo._chromium_instalado() is False
