"""Navegación dentro del Menú SOL.

El problema que resuelve este módulo: los módulos de SOL (Buzón, deudas,
consultas) NO se renderizan en la página principal. Viven dentro de un
iframe que aparece recién después del clic, y algunos módulos abren una
ventana nueva. `page.locator("...")` no ve nada de eso.

Todo lector (`readers/*.py`) debería empezar llamando a `abrir_modulo` y
trabajar sobre el `Modulo.raiz` que devuelve, sin volver a preocuparse de
si el contenido acabó en un frame o en otra ventana.

Observado en vivo con el Buzón Electrónico:
  - se queda en la misma página (no abre ventana nueva)
  - el contenido carga en el iframe `iframeApplication`
  - `ifrVCE` existe desde el arranque pero se queda en about:blank
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from playwright.sync_api import BrowserContext, Frame, Page
from playwright.sync_api import Error as PlaywrightError

from . import selectors as sel
from .config import Config
from .errors import SunatError
from .log import obtener

_log = obtener("navigation")

VACIO = "about:blank"


class NavegacionError(SunatError):
    """No se pudo llegar al contenido de un módulo."""


@dataclass
class Modulo:
    """Un módulo de SOL ya abierto y listo para leer."""

    nombre: str
    page: Page
    frame: Frame
    en_ventana_nueva: bool = False

    @property
    def raiz(self) -> Frame:
        """Dónde buscar el contenido. Tiene la misma API que una Page para
        localizar elementos: `.locator()`, `.wait_for_selector()`, etc."""
        return self.frame

    @property
    def url(self) -> str:
        return self.frame.url


# --- inspección -------------------------------------------------------------


def frames_de_contenido(page: Page) -> list[Frame]:
    """Frames que pueden tener contenido real, más probable primero.

    Descarta el principal, los de infraestructura (control de sesión) y los
    que siguen vacíos.
    """
    candidatos = [
        f
        for f in page.frames
        if f.parent_frame is not None
        and f.name not in sel.FRAMES_INFRAESTRUCTURA
        and f.url
        and f.url != VACIO
    ]
    # El frame de aplicación primero; el resto en el orden en que aparecen.
    candidatos.sort(key=lambda f: 0 if f.name == sel.FRAME_APP else 1)
    return candidatos


def describir_frames(page: Page) -> str:
    """Resumen legible de los frames. Para logs y diagnóstico."""
    lineas = []
    for f in page.frames:
        tipo = "principal" if f.parent_frame is None else "iframe"
        lineas.append(f"  [{tipo}] name={f.name or '-'!r} url={f.url[:100]}")
    return "\n".join(lineas)


def _buscar_frame(page: Page, nombre: str) -> Frame | None:
    for f in page.frames:
        if f.name == nombre and f.url and f.url != VACIO:
            return f
    return None


# --- apertura de módulos ----------------------------------------------------


def _esperar_destino(
    context: BrowserContext,
    page: Page,
    nuevas: list[Page],
    nombre_frame: str,
    timeout_ms: int,
) -> tuple[Page, Frame]:
    """Espera a que el módulo aparezca, sea donde sea que haya cargado."""
    limite = time.monotonic() + timeout_ms / 1000

    while time.monotonic() < limite:
        # Caso 1: se abrió en una ventana nueva.
        if nuevas:
            destino = nuevas[-1]
            try:
                destino.wait_for_load_state("domcontentloaded")
            except PlaywrightError:
                pass
            frame = _buscar_frame(destino, nombre_frame) or destino.main_frame
            return destino, frame

        # Caso 2: cargó en el iframe esperado de la misma página.
        frame = _buscar_frame(page, nombre_frame)
        if frame is not None:
            return page, frame

        page.wait_for_timeout(250)

    # Caso 3: no apareció el iframe esperado, pero quizá cargó en otro.
    otros = frames_de_contenido(page)
    if otros:
        _log.warning(
            "No apareció el iframe %r; uso %r. ¿Cambió el portal?",
            nombre_frame,
            otros[0].name,
        )
        return page, otros[0]

    raise NavegacionError(
        f"El módulo no cargó en ningún frame reconocible.\n"
        f"Frames presentes:\n{describir_frames(page)}"
    )


def abrir_modulo(
    context: BrowserContext,
    page: Page,
    cfg: Config,
    selector: str,
    *,
    nombre: str,
    nombre_frame: str = sel.FRAME_APP,
    espera_extra_ms: int = 2_000,
) -> Modulo:
    """Hace clic en una opción del menú y devuelve el módulo ya cargado.

    Maneja las dos formas en que SOL abre un módulo (iframe o ventana
    nueva) para que quien llame no tenga que distinguirlas.
    """
    nuevas: list[Page] = []
    escucha: Callable[[Page], None] = nuevas.append
    context.on("page", escucha)
    try:
        _log.debug("Abriendo módulo %r con selector %s", nombre, selector)
        try:
            page.locator(selector).first.click()
        except PlaywrightError as e:
            raise NavegacionError(
                f"No se pudo hacer clic en la opción '{nombre}' ({selector}). "
                f"Probablemente cambió el menú: {e}"
            ) from e

        destino, frame = _esperar_destino(
            context, page, nuevas, nombre_frame, cfg.nav_timeout_ms
        )
    finally:
        context.remove_listener("page", escucha)

    # El iframe aparece antes de terminar de pintar su contenido.
    if espera_extra_ms:
        destino.wait_for_timeout(espera_extra_ms)

    modulo = Modulo(
        nombre=nombre,
        page=destino,
        frame=frame,
        en_ventana_nueva=bool(nuevas),
    )
    _log.info(
        "Módulo '%s' abierto en %s: %s",
        nombre,
        "ventana nueva" if modulo.en_ventana_nueva else f"iframe {frame.name!r}",
        frame.url[:100],
    )
    return modulo


def abrir_buzon(context: BrowserContext, page: Page, cfg: Config) -> Modulo:
    """Abre el Buzón Electrónico desde la cabecera del menú."""
    return abrir_modulo(
        context, page, cfg, sel.MENU_BUZON, nombre="Buzón Electrónico"
    )


# --- captura de red ---------------------------------------------------------


@dataclass
class LlamadaXHR:
    metodo: str
    url: str
    status: int | None = None
    tipo: str = ""


@dataclass
class GrabadoraXHR:
    """Registra las llamadas XHR/fetch de un contexto.

    Reemplaza el paso manual de "abre DevTools → Network → filtro Fetch/XHR":
    si un módulo trae sus datos por JSON, esto lo delata, y leer ese JSON es
    mucho más simple y estable que raspar el DOM.
    """

    llamadas: list[LlamadaXHR] = field(default_factory=list)

    def _on_response(self, response) -> None:
        try:
            tipo = (response.request.resource_type or "").lower()
            if tipo not in {"xhr", "fetch"}:
                return
            self.llamadas.append(
                LlamadaXHR(
                    metodo=response.request.method,
                    url=response.url,
                    status=response.status,
                    tipo=(response.header_value("content-type") or "").split(";")[0],
                )
            )
        except PlaywrightError:
            pass

    def escuchar(self, context: BrowserContext) -> None:
        context.on("response", self._on_response)

    def json(self) -> list[LlamadaXHR]:
        """Solo las respuestas JSON: las candidatas a fuente de datos."""
        return [c for c in self.llamadas if "json" in c.tipo]
