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


def _con_red_de_seguridad() -> int:
    """Envuelve `main()` para que un fallo temprano no desaparezca en
    silencio.

    El `.exe` distribuido no tiene consola: sin esto, una excepción antes
    de que exista el ícono de bandeja simplemente cierra el proceso sin
    dejar rastro visible —el usuario ve el ícono que nunca llegó a
    aparecer, y ninguna pista de por qué. Con esto, al menos queda un
    diálogo y una línea en el log.
    """
    try:
        return main()
    except Exception as e:  # noqa: BLE001 - esto es precisamente el manejador de última instancia
        from . import avisos
        from .log import obtener

        try:
            obtener("__main__").exception("Fallo no manejado al arrancar")
        except Exception:  # el logging mismo pudo no estar configurado aun
            pass

        avisos.avisar_error(
            f"El agente no pudo iniciar:\n\n{e}\n\n"
            "Revisa el registro en "
            "%LOCALAPPDATA%\\sunat-launcher\\logs\\sunat.log para más detalle."
        )
        return 1


if __name__ == "__main__":
    sys.exit(_con_red_de_seguridad())
