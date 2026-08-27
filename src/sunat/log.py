"""Logging a archivo + consola.

El archivo es lo que te deja reconstruir qué pasó cuando el script corrió
sin que estuvieras mirando (y sobre todo en la Fase de scheduler).

Regla dura: aquí nunca se registran claves SOL ni la contraseña maestra.
Si en algún módulo necesitas loguear datos del formulario, loguea el
nombre del campo, no su valor.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .config import Config

_FORMATO = "%(asctime)s  %(levelname)-7s  %(name)-14s  %(message)s"
_NOMBRE_RAIZ = "sunat"


def configurar(cfg: Config) -> logging.Logger:
    raiz = logging.getLogger(_NOMBRE_RAIZ)
    if raiz.handlers:  # ya configurado en este proceso
        return raiz

    raiz.setLevel(getattr(logging, cfg.log_level, logging.INFO))
    raiz.propagate = False
    formato = logging.Formatter(_FORMATO, datefmt="%Y-%m-%d %H:%M:%S")

    archivo = RotatingFileHandler(
        cfg.logs_dir / "sunat.log",
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    archivo.setFormatter(formato)
    raiz.addHandler(archivo)

    consola = logging.StreamHandler()
    consola.setFormatter(logging.Formatter("%(message)s"))
    consola.setLevel(logging.INFO)
    raiz.addHandler(consola)

    return raiz


def obtener(nombre: str) -> logging.Logger:
    return logging.getLogger(f"{_NOMBRE_RAIZ}.{nombre}")
