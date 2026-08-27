"""Punto de entrada para PyInstaller.

Un archivo aparte del paquete: PyInstaller analiza estaticamente el script
que le pasas para descubrir que importar, y hacerlo apuntar directo a
`sunat/__main__.py` (que usa imports relativos, pensados para `python -m`)
le complica ese analisis. Este wrapper es el unico proposito de este
archivo.
"""

from sunat.__main__ import main
import sys

sys.exit(main())
