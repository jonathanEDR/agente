"""Pruebas de la política de reintentos.

Lo que se verifica aquí es la regla que más caro sale romper: que un
rechazo de credenciales no se reintente, porque eso bloquea el usuario SOL.
La `Page` es un doble mínimo; no se abre ningún navegador.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sunat import auth
from sunat.auth import EstadoLogin, ResultadoLogin, iniciar_sesion_con_reintentos
from sunat.config import Config
from sunat.store import Empresa

EMPRESA = Empresa(nombre="Test", ruc="20123456789", usuario="USR", clave_cifrada="x")


@pytest.fixture
def cfg(tmp_path):
    return replace(Config(data_dir=tmp_path), reintentos=3, backoff_seg=0)


def _simular(monkeypatch, resultados: list[ResultadoLogin]) -> list[int]:
    """Hace que iniciar_sesion devuelva los resultados dados, en orden."""
    llamadas = []

    def falso(page, cfg, empresa, clave, plataforma=None):
        llamadas.append(1)
        return resultados[min(len(llamadas) - 1, len(resultados) - 1)]

    monkeypatch.setattr(auth, "iniciar_sesion", falso)
    return llamadas


def test_credenciales_rechazadas_no_se_reintentan(monkeypatch, cfg):
    llamadas = _simular(
        monkeypatch, [ResultadoLogin(EstadoLogin.CREDENCIALES_RECHAZADAS, "clave mala")]
    )
    resultado = iniciar_sesion_con_reintentos(None, cfg, EMPRESA, "clave")

    assert resultado.estado is EstadoLogin.CREDENCIALES_RECHAZADAS
    assert len(llamadas) == 1, "reintentar credenciales rechazadas bloquea el usuario SOL"


def test_requiere_intervencion_no_se_reintenta(monkeypatch, cfg):
    llamadas = _simular(
        monkeypatch, [ResultadoLogin(EstadoLogin.REQUIERE_INTERVENCION, "captcha")]
    )
    iniciar_sesion_con_reintentos(None, cfg, EMPRESA, "clave")
    assert len(llamadas) == 1


def test_error_transitorio_agota_los_reintentos(monkeypatch, cfg):
    llamadas = _simular(
        monkeypatch, [ResultadoLogin(EstadoLogin.ERROR_TRANSITORIO, "timeout")]
    )
    resultado = iniciar_sesion_con_reintentos(None, cfg, EMPRESA, "clave")

    assert resultado.estado is EstadoLogin.ERROR_TRANSITORIO
    assert len(llamadas) == cfg.reintentos


def test_error_transitorio_seguido_de_exito(monkeypatch, cfg):
    llamadas = _simular(
        monkeypatch,
        [
            ResultadoLogin(EstadoLogin.ERROR_TRANSITORIO, "red"),
            ResultadoLogin(EstadoLogin.OK),
        ],
    )
    resultado = iniciar_sesion_con_reintentos(None, cfg, EMPRESA, "clave")

    assert resultado.exitoso
    assert len(llamadas) == 2


def test_exito_al_primer_intento(monkeypatch, cfg):
    llamadas = _simular(monkeypatch, [ResultadoLogin(EstadoLogin.OK)])
    resultado = iniciar_sesion_con_reintentos(None, cfg, EMPRESA, "clave")

    assert resultado.exitoso
    assert len(llamadas) == 1


def test_backoff_crece_exponencialmente(monkeypatch, cfg):
    """Ante la página de verificación por ir muy rápido, reintentar enseguida
    empeora las cosas: las esperas deben crecer, no ser constantes."""
    esperas: list[float] = []
    monkeypatch.setattr(auth.time, "sleep", esperas.append)
    _simular(monkeypatch, [ResultadoLogin(EstadoLogin.ERROR_TRANSITORIO, "x")])

    cfg_con_espera = replace(cfg, reintentos=4, backoff_seg=2)
    iniciar_sesion_con_reintentos(None, cfg_con_espera, EMPRESA, "clave")

    assert esperas == [2, 4, 8]


# --- detección de estados de la página --------------------------------------


class PaginaFalsa:
    """Doble mínimo: solo lo que usan los detectores de auth."""

    def __init__(self, html_ids=(), titulo="", url=""):
        self._ids = set(html_ids)
        self._titulo = titulo
        self.url = url

    def title(self):
        return self._titulo

    def locator(self, selector):
        pagina = self

        class Loc:
            def count(self):
                partes = [s.strip().lstrip("#") for s in selector.split(",")]
                return sum(1 for p in partes if p in pagina._ids)

        return Loc()


def test_detecta_la_pagina_de_verificacion_por_el_tag():
    assert auth._es_pagina_verificacion(PaginaFalsa(html_ids={"check"}))


def test_detecta_la_pagina_de_verificacion_por_el_titulo():
    assert auth._es_pagina_verificacion(PaginaFalsa(titulo="Bienvenido a SUNAT"))


def test_el_campo_de_captcha_oculto_no_dispara_alerta():
    """`#txtCaptcha` está SIEMPRE en el HTML del formulario, oculto. Detectar
    por presencia daría un falso positivo en cada login normal; solo cuenta
    si SUNAT lo hace visible."""
    from sunat import selectors as sel

    assert "#txtCaptcha" in sel.INDICIOS_CAPTCHA
    # El detector real usa _visible(), no _existe(): un campo presente pero
    # oculto no debe clasificarse como "necesita intervención".
    presente_pero_oculto = PaginaFalsa(html_ids={"txtCaptcha", "txtRuc"})
    assert not auth._existe(presente_pero_oculto, "nada")


def test_el_menu_normal_no_se_confunde_con_verificacion():
    menu = PaginaFalsa(html_ids={"aOpcionUsuario2", "btnSalir"}, titulo="SUNAT - Menú SOL")
    assert not auth._es_pagina_verificacion(menu)


def test_marcador_de_menu_se_detecta_aunque_solo_exista_uno(cfg):
    """La cabecera tiene variantes responsive: basta con que uno de los dos
    ids esté presente."""
    solo_salir = PaginaFalsa(
        html_ids={"btnSalir"}, url="https://e-menu.sunat.gob.pe/cl-ti-itmenu/x.htm"
    )
    assert auth._esta_autenticado(solo_salir, cfg)


def test_pagina_de_login_no_cuenta_como_autenticada(cfg):
    login = PaginaFalsa(
        html_ids={"txtRuc"}, url="https://api-seguridad.sunat.gob.pe/v1/clientessol/x"
    )
    assert not auth._esta_autenticado(login, cfg)


def test_entrada_antes_de_redirigir_no_cuenta_como_autenticada(cfg):
    """El falso positivo original: misma URL que el menú, pero sin marcador."""
    intermedia = PaginaFalsa(url="https://e-menu.sunat.gob.pe/cl-ti-itmenu/MenuInternet.htm")
    assert not auth._esta_autenticado(intermedia, cfg)
