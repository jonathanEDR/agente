"""Arranque para el instalador de un clic.

`python -m sunat` (modo desarrollo) y el `.exe` empaquetado con PyInstaller
pasan por aquí. La diferencia con `agente.iniciar()` a secas es que este
módulo se ocupa de lo que un desarrollador ya tiene resuelto a mano —
Chromium descargado, dependencias instaladas— y que un usuario que solo
hizo doble clic en un `.exe` no tiene.

Separado de `browser.py` a propósito: aquello es ciclo de vida de una
sesión ya lista para navegar; esto es "¿hay algo que preparar antes de la
primera sesión de la vida de esta instalación?", que solo pasa una vez.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from . import avisos

# --- dónde vive el navegador -------------------------------------------------
#
# Tiene que fijarse ANTES de que cualquier módulo importe playwright —por
# eso vive al nivel de módulo y este archivo se importa antes que
# `browser.py` en cualquier camino de arranque.
#
# Sin esto, Playwright decide solo dónde buscar el navegador, y esa
# decisión no es estable: un `.exe` empaquetado con PyInstaller cuenta como
# instalación "no estándar", y en ese caso Playwright busca el navegador
# *junto al propio paquete empaquetado* en vez de en la caché compartida
# del usuario. El síntoma es
# `Executable doesn't exist at ...\_internal\playwright\driver\...`
# incluso cuando el usuario ya tiene Chromium descargado — porque lo buscó
# en el lugar equivocado, no porque falte.
#
# Fijando la variable, tanto `python -m sunat` en un venv como el `.exe`
# empaquetado apuntan al mismo sitio: así uno no tiene que redescargar lo
# que el otro ya bajó.


def _cache_navegadores() -> Path:
    override = os.environ.get("SUNAT_BROWSERS_PATH", "").strip()
    if override:
        return Path(override).expanduser()

    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if local_appdata:
        return Path(local_appdata) / "ms-playwright"

    return Path.home() / ".cache" / "ms-playwright"  # Linux/macOS, por si acaso


_RUTA_NAVEGADORES = _cache_navegadores()
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_RUTA_NAVEGADORES))


from .config import cargar_config  # noqa: E402
from .log import configurar, obtener  # noqa: E402

_log = obtener("arranque")


def _chromium_instalado() -> bool:
    """Si ya se descargó el navegador, sin importar la versión exacta.

    No se compara contra una versión fija: Playwright cambia la carpeta
    (`chromium-1234`, etc.) con cada release del paquete, y fijar un número
    aquí solo garantizaría que este chequeo se desactualice antes que el
    propio Playwright.
    """
    if not _RUTA_NAVEGADORES.is_dir():
        return False
    return any(p.name.startswith("chromium-") for p in _RUTA_NAVEGADORES.iterdir())


def _informar(mensaje: str) -> None:
    """Muestra un mensaje donde se pueda: consola si hay, si no un dialogo.

    El `.exe` distribuido no tiene consola (se compila `--windowed`), así
    que `print()` no tiene a dónde escribir —en ese modo `sys.stdout` es
    `None`, y llamarlo igual sería un `AttributeError`—. `python -m sunat`
    en desarrollo sí tiene consola, y ahí basta con imprimir.
    """
    if sys.stdout is not None:
        print(mensaje)
    _log.info(mensaje)


def _instalar_chromium() -> None:
    """Descarga Chromium llamando al instalador de Playwright en el mismo
    proceso, sin pasar por una terminal ni por `pip`.

    Por qué en el mismo proceso y no con `subprocess.run([sys.executable,
    "-m", "playwright", "install", ...])`: dentro del `.exe` empaquetado,
    `sys.executable` ES el propio `.exe`, no un intérprete de Python — ese
    comando fallaría o, peor, relanzaría el agente entero con argumentos que
    no entiende.

    `playwright.__main__.main()` en cambio es solo Python: internamente
    invoca al driver (un `node.exe` empaquetado aparte, ver
    `playwright/driver/`), así que llamarlo directo funciona igual
    congelado que en un venv normal.
    """
    # Sin consola y sin ícono de bandeja todavía (recién se crea después de
    # esto), una descarga de minutos se ve como el programa colgado. El
    # diálogo es la única señal de vida posible en ese momento.
    avisos.avisar(
        "Preparando el navegador por primera vez.\n\n"
        "Puede tardar unos minutos según tu conexión — solo pasa una vez.\n\n"
        "Haz clic en Aceptar para continuar."
    )
    _informar("Preparando el navegador por primera vez...")

    import playwright.__main__ as pw_main

    argv_original = sys.argv
    try:
        sys.argv = ["playwright", "install", "chromium"]
        pw_main.main()
    except SystemExit as e:
        # `main()` de playwright termina con sys.exit(0) al lograrlo; solo
        # un código distinto de éxito es un fallo real de la descarga.
        if e.code not in (None, 0):
            raise RuntimeError(
                f"No se pudo descargar Chromium (código {e.code}). "
                "Revisa tu conexión a internet e intenta de nuevo."
            ) from e
    finally:
        sys.argv = argv_original

    _informar("Listo. Iniciando el agente...")


def _quiere_bandeja() -> bool:
    """Si hay que intentar el ícono de bandeja en vez de la consola pelada.

    Dos formas de desactivarlo: la variable de entorno, para quien prefiera
    la consola de siempre, y la ausencia de `pystray` — que en un venv de
    desarrollo puede no estar instalado sin que eso deba impedir arrancar.
    """
    if os.environ.get("SUNAT_SIN_BANDEJA", "").strip().lower() in ("1", "true"):
        return False
    try:
        import pystray  # noqa: F401
    except ImportError:
        return False
    return True


def _asegurar_consola() -> None:
    """Crea una consola si el proceso no tiene ninguna, para el modo
    `SUNAT_SIN_BANDEJA=1`.

    El `.exe` distribuido se compila `--windowed`: no arranca con consola
    propia, así que "volver al modo consola de siempre" necesita crear una
    a pedido con `AllocConsole`. En desarrollo (`python -m sunat` desde una
    terminal) ya hay una — `AllocConsole` simplemente no hace nada ahí, sin
    que haga falta distinguir los dos casos antes de llamarla.
    """
    if os.name != "nt":
        return
    kernel32 = ctypes.windll.kernel32
    if kernel32.GetConsoleWindow():
        return
    if not kernel32.AllocConsole():
        return
    sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
    sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115


def main(puerto: int | None = None) -> int:
    from .agente import PUERTO_POR_DEFECTO, crear_servidor, iniciar, preparar

    cfg = cargar_config()
    configurar(cfg)

    if not _chromium_instalado():
        _log.info("Chromium no está instalado; se descarga antes de arrancar.")
        _instalar_chromium()

    puerto = puerto or PUERTO_POR_DEFECTO

    if not _quiere_bandeja():
        _asegurar_consola()
        return iniciar(cfg, puerto=puerto)

    from . import bandeja

    cfg = preparar(cfg)
    servidor = crear_servidor(cfg, puerto)
    bandeja.ejecutar(cfg, servidor)
    return 0
