"""Ícono en la bandeja del sistema.

Es la única interfaz del `.exe` empaquetado: "Abrir panel" y "Salir",
junto al reloj — el mismo patrón que ya conoce cualquier usuario de
Windows por Dropbox o Zoom. No hay ventana de consola que gestionar: el
`.exe` se compila `--windowed` (ver `packaging/build.py`), así que
simplemente nunca existe una que ocultar.

Esa decisión reemplazó un primer intento que ocultaba la consola con
`GetConsoleWindow` + `ShowWindow` después de que el ícono arrancaba. No
funcionaba en Windows 11: el host de consola por defecto ahí es Windows
Terminal, que envuelve la consola real vía ConPTY — la ventana que ve el
usuario no es la misma que esa API alcanza a tocar, así que "ocultarla"
no hacía nada visible. Mejor no crear ninguna que perseguir ese caso.

Consecuencia: un fallo antes de que este módulo llegue a correr no tiene
consola donde mostrarse. Lo cubre `avisos.py` con un diálogo nativo, desde
`__main__._con_red_de_seguridad()`.
"""

from __future__ import annotations

import os
import threading
import webbrowser
from typing import TYPE_CHECKING

from PIL import Image, ImageDraw
import pystray

from . import __version__
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
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Salir", salir),
    )

    icono = pystray.Icon(
        "sunat-agente", _icono(), f"SUNAT Launcher — agente v{__version__}", menu
    )
    icono.run()  # bloquea hasta "Salir"
