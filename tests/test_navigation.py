"""Pruebas de la selección de frames.

La lógica que importa: distinguir el frame donde vive el contenido de los
frames de infraestructura (control de sesión) y de los que siguen vacíos.
Los dobles imitan lo mínimo de la API de Playwright que usa el módulo.
"""

from __future__ import annotations

from sunat import selectors as sel
from sunat.navigation import GrabadoraXHR, LlamadaXHR, frames_de_contenido


class FrameFalso:
    def __init__(self, name: str, url: str, parent=None):
        self.name = name
        self.url = url
        self.parent_frame = parent


class PageFalsa:
    def __init__(self, frames):
        self.frames = frames


def _menu_con_buzon_abierto() -> PageFalsa:
    """Reproduce lo observado en vivo tras abrir el Buzón Electrónico."""
    principal = FrameFalso("", "https://e-menu.sunat.gob.pe/cl-ti-itmenu/x.htm")
    return PageFalsa(
        [
            principal,
            FrameFalso("ifrVCE", "about:blank", principal),
            FrameFalso("iframeTime", "https://ww1.sunat.gob.pe/time/gettime.pl", principal),
            FrameFalso("iframeAnterior", "https://ww1.sunat.gob.pe/time/gettime.pl?a=o", principal),
            FrameFalso("iframeApplication", "https://ww1.sunat.gob.pe/ol-ti-itvisornoti/visor/master", principal),
            FrameFalso("contenedorMensaje", "https://ww1.sunat.gob.pe/cl-ti-iagenerador/gendoc", principal),
        ]
    )


def test_prioriza_el_frame_de_aplicacion():
    encontrados = frames_de_contenido(_menu_con_buzon_abierto())
    assert encontrados[0].name == sel.FRAME_APP


def test_descarta_frames_de_infraestructura():
    nombres = [f.name for f in frames_de_contenido(_menu_con_buzon_abierto())]
    for infra in sel.FRAMES_INFRAESTRUCTURA:
        assert infra not in nombres


def test_descarta_el_frame_principal():
    # Sin esto, un lector podría leer la cabecera del menú creyendo que es
    # el contenido del módulo.
    assert all(f.parent_frame is not None for f in frames_de_contenido(_menu_con_buzon_abierto()))


def test_ifrvce_vacio_no_cuenta_como_contenido():
    # ifrVCE existe desde el arranque pero se queda en about:blank: es la
    # trampa que hizo fallar el primer diseño.
    nombres = [f.name for f in frames_de_contenido(_menu_con_buzon_abierto())]
    assert "ifrVCE" not in nombres


def test_menu_sin_modulo_abierto_no_tiene_contenido():
    principal = FrameFalso("", "https://e-menu.sunat.gob.pe/cl-ti-itmenu/x.htm")
    page = PageFalsa(
        [
            principal,
            FrameFalso("ifrVCE", "about:blank", principal),
            FrameFalso("iframeTime", "https://ww1.sunat.gob.pe/time/gettime.pl", principal),
        ]
    )
    assert frames_de_contenido(page) == []


def test_grabadora_filtra_solo_json():
    g = GrabadoraXHR()
    g.llamadas = [
        LlamadaXHR("GET", "https://x/api/lista", 200, "application/json"),
        LlamadaXHR("GET", "https://x/estilos.css", 200, "text/css"),
        LlamadaXHR("POST", "https://x/api/detalle", 200, "application/json"),
    ]
    assert [c.url for c in g.json()] == [
        "https://x/api/lista",
        "https://x/api/detalle",
    ]
