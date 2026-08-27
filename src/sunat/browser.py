"""Ciclo de vida del navegador.

Separado de la autenticación a propósito: `auth.py` recibe una `Page` ya
lista y no sabe nada de cómo se lanzó. Eso permite reusar la misma sesión
para los lectores (buzón, deudas) sin repetir login.

Nota de seguridad: el perfil persistente guarda cookies de sesión SOL en
disco sin cifrar. Por eso vive en %LOCALAPPDATA%, no en el proyecto (ver
config.py). Si eso te incomoda para un RUC en particular, usa
`efimero=True` y aceptá tener que loguear siempre.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
from playwright.sync_api import Error as PlaywrightError

from .config import Config
from .log import obtener

_log = obtener("browser")


@contextmanager
def sesion_navegador(
    cfg: Config, ruc: str, *, plataforma: str = "tramites", efimero: bool = False
) -> Iterator[tuple[BrowserContext, Page]]:
    """Abre un contexto de Chromium y lo cierra al salir del bloque."""
    with sync_playwright() as p:
        navegador: Browser | None = None

        # SUNAT corta la conexión si ve el user-agent de Chromium headless,
        # así que el UA realista no es opcional (ver config.USER_AGENT).
        comunes = {
            "user_agent": cfg.user_agent,
            "locale": "es-PE",
            "no_viewport": not cfg.headless,
        }

        if efimero:
            navegador = p.chromium.launch(headless=cfg.headless)
            context = navegador.new_context(**comunes)
            _log.debug("Contexto efímero (sin perfil persistente).")
        else:
            perfil = cfg.perfil_de(ruc, plataforma)
            perfil.mkdir(parents=True, exist_ok=True)
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(perfil),
                headless=cfg.headless,
                args=[] if cfg.headless else ["--start-maximized"],
                **comunes,
            )
            _log.debug("Perfil persistente: %s", perfil)

        context.set_default_timeout(cfg.timeout_ms)
        context.set_default_navigation_timeout(cfg.nav_timeout_ms)

        page = context.pages[0] if context.pages else context.new_page()
        try:
            yield context, page
        finally:
            try:
                context.close()
            except Exception:  # el usuario ya cerró la ventana
                pass
            if navegador is not None:
                try:
                    navegador.close()
                except Exception:
                    pass


def esperar_cierre_manual(context: BrowserContext) -> str:
    """Bloquea hasta que el usuario cierre todas las pestañas.

    Devuelve por qué terminó: "cerrado" si fue un cierre normal, o un texto
    con el fallo si no lo fue.

    Antes esto era un `except Exception: pass`, y cualquier tropiezo salía
    disfrazado de "el usuario cerró la ventana". El síntoma era ver
    «Navegador cerrado» en pantalla con la ventana todavía abierta, sin
    ninguna pista de qué había pasado.
    """
    while True:
        try:
            paginas = context.pages
        except PlaywrightError:
            return "cerrado"  # el contexto entero ya no existe

        if not paginas:
            return "cerrado"

        try:
            paginas[0].wait_for_timeout(500)
        except IndexError:
            # La última pestaña se cerró entre comprobar y esperar.
            return "cerrado"
        except PlaywrightError as e:
            mensaje = str(e).splitlines()[0]
            if "closed" in mensaje.lower():
                return "cerrado"
            _log.warning("La espera de cierre terminó por un fallo: %s", mensaje)
            return mensaje
