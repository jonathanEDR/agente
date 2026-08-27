"""Avisos nativos de Windows, para cuando no hay consola ni bandeja todavía.

El `.exe` se compila sin subsistema de consola (`--windowed`): no hay
ventana negra que ocultar, porque nunca se crea una. La contrapartida es
que dos momentos se quedan sin manera de avisar nada — la descarga de
Chromium en el primer arranque, y un fallo antes de que el ícono de
bandeja llegue a existir. Este módulo cubre esos dos casos con
`MessageBoxW`, sin depender de Tkinter ni de ninguna librería de UI.
"""

from __future__ import annotations

import ctypes

_MB_OK = 0x0
_MB_ICONINFORMATION = 0x40
_MB_ICONERROR = 0x10


def _mostrar(titulo: str, mensaje: str, icono: int) -> None:
    if not hasattr(ctypes, "windll"):  # no es Windows (tests, CI en Linux)
        return
    try:
        ctypes.windll.user32.MessageBoxW(0, mensaje, titulo, _MB_OK | icono)
    except OSError:
        # Sin consola NI escritorio interactivo (un servicio, una sesión
        # remota sin UI) MessageBoxW puede fallar. No hay a quién más
        # avisarle en ese caso; que siga y quede en el log.
        pass


def avisar(mensaje: str, titulo: str = "SUNAT Launcher") -> None:
    _mostrar(titulo, mensaje, _MB_ICONINFORMATION)


def avisar_error(mensaje: str, titulo: str = "SUNAT Launcher") -> None:
    _mostrar(titulo, mensaje, _MB_ICONERROR)
