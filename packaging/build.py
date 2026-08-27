"""Compila el agente en un .exe de doble clic, sin terminal ni Python visible.

Uso, desde agent/, con el venv activado:

    python packaging/build.py

El resultado queda en dist/sunat-agente/. Lo único que un usuario final
necesita de esa carpeta es sunat-agente.exe: PyInstaller la deja
autocontenida, sin depender de un Python ni un venv instalados aparte.

Por qué --add-data para el driver de Playwright: sin él, el .exe
empaquetado no tiene el binario de Node que Playwright usa por debajo
(playwright/driver/node.exe + cli.js), y falla con un error de "Executable
doesn't exist" que no menciona Node en ningún lado — hay que saber que el
driver vive ahí para entender el mensaje.

Por qué --collect-all para fastapi y uvicorn: los dos cargan módulos por
nombre en tiempo de ejecución (rutas, workers), y el análisis estático de
PyInstaller no los detecta solo. Sin esto, el .exe arranca y falla recién
al primer request con un ModuleNotFoundError que no dice cuál falta.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def ruta_driver_playwright() -> Path:
    import playwright

    return Path(playwright.__file__).parent / "driver"


def main() -> int:
    driver = ruta_driver_playwright()
    if not driver.is_dir():
        print(f"No se encontró el driver de Playwright en {driver}.")
        print("¿Corriste esto con el venv del proyecto activado?")
        return 1

    comando = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        "sunat-agente",
        "--onedir",
        "--console",
        "--paths",
        str(RAIZ / "src"),
        "--add-data",
        f"{driver}{';' if sys.platform == 'win32' else ':'}playwright/driver",
        "--collect-all",
        "uvicorn",
        "--collect-all",
        "fastapi",
        "--workpath",
        str(RAIZ / "build"),
        "--distpath",
        str(RAIZ / "dist"),
        "--specpath",
        str(RAIZ / "build"),
        "--clean",
        "--noconfirm",
        str(Path(__file__).parent / "lanzador.py"),
    ]

    print("Compilando...")
    resultado = subprocess.run(comando, cwd=RAIZ)
    if resultado.returncode != 0:
        return resultado.returncode

    print()
    print(f"Listo: {RAIZ / 'dist' / 'sunat-agente' / 'sunat-agente.exe'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
