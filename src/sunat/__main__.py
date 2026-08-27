"""Punto de entrada: `python -m sunat`, `sunat-agente`, o el `.exe` empaquetado.

Este paquete es solo el agente que sirve al panel del SaaS. No tiene la
CLI completa de gestión manual (`sunat login`, `sunat doctor`, etc.) ni la
ventana de escritorio — esas siguen viviendo en el prototipo original del
que se separó este repo, que ya no se ejecuta pero queda como referencia
local.

Si en algún momento hace falta esa CLI de nuevo, está intacta ahí: portarla
es copiar `cli.py` y ajustar los imports, no reescribirla.
"""

from __future__ import annotations

import sys

from .arranque import main as arrancar


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    puerto = None
    if argv and argv[0] in ("-p", "--puerto"):
        puerto = int(argv[1])

    return arrancar(puerto=puerto)


if __name__ == "__main__":
    sys.exit(main())
