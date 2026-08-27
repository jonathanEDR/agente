"""Ícono en la bandeja del sistema.

Reemplaza la consola como interfaz por defecto del `.exe` empaquetado: en
vez de una ventana negra que hay que dejar abierta, un ícono junto al
reloj con "Abrir panel" y "Salir" — el mismo patrón que ya conoce cualquier
usuario de Windows por Dropbox o Zoom.

La consola no desaparece, se oculta. Si algo falla ANTES de que el ícono
llegue a mostrarse, la consola sigue ahí para verlo: ocultarla recién
cuando el ícono ya está listo es lo que preserva la regla de siempre —"si
falla, se ve el error"— sin obligar a mirar una ventana negra en el uso
normal.
"""

from __future__ import annotations

import ctypes
import os
import threading
import webbrowser
from typing import TYPE_CHECKING

from PIL import Image, ImageDraw
import pystray

from .config import Config
from .log import obtener

if TYPE_CHECKING:
    import uvicorn

_log = obtener("bandeja")


def _icono() -> Image.Image:
    """Un ícono simple, dibujado en memoria.

    Sin depender de un .ico empaquetado aparte: es un archivo binario más
    que PyInstaller tendría que encontrar y agregar con --add-data, para
    algo que un círculo de color resuelve en cuatro líneas.
    """
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    trazo = ImageDraw.Draw(img)
    trazo.ellipse((4, 4, 60, 60), fill="#2f6ba8")
    trazo.text((24, 20), "S", fill="white")
    return img


def _ventana_consola() -> int | None:
    """El HWND de la ventana de consola de este proceso, o None si no hay
    ninguna (por ejemplo, corriendo `pytest` o un build sin consola)."""
    if os.name != "nt":
        return None
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    return hwnd or None


def ocultar_consola() -> None:
    hwnd = _ventana_consola()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE


def mostrar_consola() -> None:
    hwnd = _ventana_consola()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 5)  # SW_SHOW


def _abrir_registro(cfg: Config) -> None:
    ruta = cfg.logs_dir / "sunat.log"
    try:
        os.startfile(ruta)  # noqa: S606 - ruta propia, no viene de afuera
    except OSError as e:
        _log.warning("No se pudo abrir el registro (%s): %s", ruta, e)


def ejecutar(cfg: Config, servidor: "uvicorn.Server") -> None:
    """Corre el ícono en el hilo principal; el servidor, en uno aparte.

    `pystray` necesita el hilo principal en Windows para su bucle de
    mensajes, y `uvicorn.Server.run()` bloquea armando el suyo propio — no
    pueden compartir hilo. Por eso el servidor va en un hilo daemon: si el
    ícono termina primero (clic en «Salir»), el proceso no se queda
    colgado esperando a que ese hilo se una.
    """
    hilo_servidor = threading.Thread(target=servidor.run, daemon=True)
    hilo_servidor.start()

    # Recién ahora: si `crear_servidor()` o el hilo fallan al arrancar, el
    # error todavía se ve en la consola.
    ocultar_consola()

    def salir(icon: pystray.Icon, _item: pystray.MenuItem) -> None:
        servidor.should_exit = True
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(
            "Abrir panel",
            lambda: webbrowser.open(cfg.panel_url),
            default=True,
        ),
        pystray.MenuItem("Ver registro", lambda: _abrir_registro(cfg)),
        pystray.MenuItem("Ver consola", lambda: mostrar_consola()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Salir", salir),
    )

    icono = pystray.Icon(
        "sunat-agente", _icono(), "SUNAT Launcher — agente", menu
    )
    icono.run()  # bloquea hasta "Salir"
