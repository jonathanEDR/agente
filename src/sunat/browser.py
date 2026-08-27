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
from pathlib import Path
from typing import Iterator

from playwright.sync_api import Browser, BrowserContext, Download, Page, sync_playwright
from playwright.sync_api import Error as PlaywrightError

from .config import Config
from .log import obtener

_log = obtener("browser")


def _elegir_ruta(destino: Path, nombre: str, reservados: set[Path]) -> Path:
    """El primer nombre libre en `destino` para `nombre`, reservándolo en
    `reservados` antes de devolverlo.

    Comprobar solo `ruta.exists()` no alcanza: los handlers de descarga de
    Playwright pueden intercalarse —uno queda esperando dentro de
    `save_as()` (que cede el control al loop de Playwright) mientras el
    otro ya arrancó—, así que dos descargas con el mismo nombre sugerido
    pueden verse la una a la otra como "todavía no existe" y la segunda
    pisa a la primera. Reservar el nombre en memoria, en una sola
    operación síncrona sin ningún punto de espera de por medio, es lo que
    lo evita: el llamador tiene que reservar ANTES de llamar a `save_as`.
    """
    ruta = destino / nombre
    if not ruta.exists() and ruta not in reservados:
        reservados.add(ruta)
        return ruta

    base, _, ext = nombre.rpartition(".")
    base, ext = (base, f".{ext}") if base else (nombre, "")
    contador = 1
    while True:
        candidata = destino / f"{base} ({contador}){ext}"
        if not candidata.exists() and candidata not in reservados:
            reservados.add(candidata)
            return candidata
        contador += 1


def _registrar_descargas(context: BrowserContext, destino: Path) -> None:
    """Copia cada descarga a `destino` con su nombre real.

    Sin esto, Playwright guarda el archivo con un GUID por nombre en una
    carpeta temporal propia, y lo **borra** al cerrar el contexto —
    documentado, no un bug: "the downloads are deleted when the browser
    context they were created in is closed". El síntoma es ver la descarga
    como "Hecho" en el historial de Chrome y no encontrarla nunca en la
    carpeta de Descargas real.

    Va en el contexto y no en una página: un enlace de SUNAT puede abrir la
    descarga en una pestaña nueva, y `page.on(...)` no vería esa pestaña.
    """
    destino.mkdir(parents=True, exist_ok=True)
    reservados: set[Path] = set()  # nombres ya usados EN ESTA SESIÓN

    def _guardar(descarga: Download) -> None:
        nombre = descarga.suggested_filename
        ruta = _elegir_ruta(destino, nombre, reservados)
        try:
            descarga.save_as(ruta)
            _log.info("Descarga guardada: %s", ruta)
        except PlaywrightError as e:
            _log.warning("No se pudo guardar la descarga %r: %s", nombre, e)

    context.on("download", _guardar)


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

        _registrar_descargas(context, cfg.descargas_dir)

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
